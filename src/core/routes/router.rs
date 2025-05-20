use crate::core::config::configer::Methods;
use std::{
    collections::HashMap,
    sync::Arc,
    pin::Pin
};
use crate::core::servers::HttpError;

#[derive(Debug, Clone)]
pub struct Request {
    pub method: Methods,
    pub path: String,
    pub headers: Vec<(String, String)>,
    pub body: String,
    pub cookies: Vec<(String, String)>,
    pub path_params: Arc<HashMap<String, String>>,
    pub query_string: Option<String>,
}

fn decode_str(s: &str) -> String {
    percent_encoding::percent_decode_str(s)
        .decode_utf8_lossy()
        .into_owned()
}

impl Request {
    pub fn new(method: Methods, path: String) -> Self {
        Request {
            method,
            path,
            headers: Vec::new(),
            body: String::new(),
            cookies: Vec::new(),
            path_params: Arc::new(HashMap::new()),
            query_string: None,
        }
    }

    pub fn query_param(&self, key: &str) -> Result<String, HttpError> {
        if let Some(qs) = &self.query_string {
            for pair in qs.split('&') {
                let mut parts = pair.splitn(2, '=');
                if parts.next() == Some(key) {
                    if let Some(value) = parts.next() {
                        return Ok(decode_str(value));
                    }
                }
            }
        }
        Err("Key not found".into())
    }

    pub fn query_params(&self) -> HashMap<String, String> {
        let mut params_map = HashMap::new();
        if let Some(qs) = &self.query_string {
            for pair in qs.split('&') {
                let mut parts = pair.splitn(2, '=');
                if let Some(key_encoded) = parts.next() {
                    let key = decode_str(key_encoded);
                    if let Some(value_encoded) = parts.next() {
                        params_map.insert(key, decode_str(value_encoded));
                    } else {
                        params_map.insert(key, "".to_string());
                    }
                }
            }
        }
        params_map
    }

    pub fn header(&self, key: &str) -> Result<String, HttpError> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(key))
            .map(|(_, v)| v.clone())
            .ok_or_else(|| HttpError::BadRequest(format!("Header not found: {}", key)))
    }

    pub fn headers(&self) -> HashMap<String, String> {
        let mut headers_map = HashMap::new();
        for (key, value) in &self.headers {
            headers_map.insert(key.clone(), value.clone());
        }
        headers_map
    }
}

#[derive(Debug, Clone)]
pub struct Response {
    pub status_code: u16,
    pub headers: Vec<(String, String)>,
    pub body: String,
    pub cookies: Vec<(String, String)>,
}

impl Response {
    pub fn new(status_code: u16) -> Self {
        Response {
            status_code,
            headers: Vec::new(),
            body: String::new(),
            cookies: Vec::new(),
        }
    }

    pub fn status(mut self, status_code: u16) -> Self {
        self.status_code = status_code;
        self
    }

    pub fn body(mut self, body_content: impl Into<String>) -> Self {
        self.body = body_content.into();
        self
    }

    pub fn header(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.headers.push((key.into(), value.into()));
        self
    }

    pub fn cookie(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.cookies.push((key.into(), value.into()));
        self
    }
}

pub trait Responder: Send + 'static {
    fn into_response(self) -> Response;
}

impl Responder for Response {
    fn into_response(self) -> Response {
        self
    }
}

impl Responder for &'static str {
    fn into_response(self) -> Response {
        Response::new(200)
            .header("Content-Type", "text/plain; charset=utf-8")
            .body(self)
    }
}

impl Responder for String {
    fn into_response(self) -> Response {
        Response::new(200)
            .header("Content-Type", "text/plain; charset=utf-8")
            .body(self)
    }
}

impl<T: Responder> Responder for Result<T, crate::core::servers::HttpError> {
    fn into_response(self) -> Response {
        match self {
            Ok(responder) => responder.into_response(),
            Err(err) => {
                Response::new(err.status_code())
                    .header("Content-Type", "application/json")
                    .body(format!("{{\"error\":\"{}\"}}", err.message()))
            }
        }
    }
}

pub type GenericHandler = Box<
    dyn Fn(Request) -> Pin<Box<dyn Future<Output = Response> + Send>> + Send + Sync + 'static,
>;

pub mod handler_adapters {
    use super::*;

    pub fn adapt_responder_fn<F, Fut, R>(user_fn: F) -> GenericHandler
    where
    F: Fn(Request) -> Fut + Send + Sync + Copy + 'static,
    Fut: Future<Output = R> + Send + 'static,
    R: Responder + Send + 'static,
    {
    Box::new(move |request: Request| {
        let fut = user_fn(request);
        Box::pin(async move {
            let responder_result = fut.await;
            responder_result.into_response()
        })
    })
    }
}

#[derive(Clone)]
pub struct RouteInfo {
    pub method: Methods,
    pub path_pattern: String,
    pub handler: Arc<GenericHandler>,
    param_names: Vec<String>,
}

impl RouteInfo {
    pub fn new(method: Methods, path_pattern: String, handler: GenericHandler) -> Self {
        let mut param_names = Vec::new();
        for segment in path_pattern.split('/') {
            if segment.starts_with('{') && segment.ends_with('}') && segment.len() > 2 {
                param_names.push(segment[1..segment.len() - 1].to_string());
            }
        }
        RouteInfo {
            method,
            path_pattern,
            handler: Arc::new(handler),
            param_names,
        }
    }
}

#[derive(Default, Clone)]
pub struct RouterConfig {
    routes_by_method: HashMap<Methods, Vec<Arc<RouteInfo>>>,
}

impl RouterConfig {
    pub fn new() -> Self {
        RouterConfig::default()
    }

    pub fn service<F: RouteFactory>(&mut self, factory: F) -> &mut Self {
        factory.register_route_service(self);
        self
    }

    pub fn match_route(
        &self,
        method: Methods,
        path: &str
    ) -> Option<(Arc<GenericHandler>, HashMap<String, String>)> {
        if let Some(routes_for_method) = self.routes_by_method.get(&method) {
            for route_info in routes_for_method {
                let pattern_segments: Vec<&str> = route_info.path_pattern.split('/').collect();
                let request_segments: Vec<&str> = path.split('/').collect();

                if pattern_segments.len() != request_segments.len() {
                    continue;
                }

                let mut params = HashMap::new();
                let mut matched = true;
                let mut param_idx = 0;

                for (i, pattern_segment) in pattern_segments.iter().enumerate() {
                    let request_segment = request_segments[i];
                    if pattern_segment.starts_with('{') && pattern_segment.ends_with('}') && pattern_segment.len() > 2 {
                        if param_idx < route_info.param_names.len() {
                            let param_name = &route_info.param_names[param_idx];
                            params.insert(param_name.clone(), request_segment.to_string());
                            param_idx += 1;
                        } else {
                            matched = false;
                            break;
                        }
                    } else if *pattern_segment != request_segment {
                        matched = false;
                        break;
                    }
                }

                if matched {
                    return Some((route_info.handler.clone(), params));
                }
            }
        }
        None
    }
}

pub trait RouteFactory {
    fn register_route_service(self, config: &mut RouterConfig);
}

pub mod internal_routing {
    use super::*;

    pub fn add_route(
        config: &mut RouterConfig,
        method: Methods,
        path_pattern: String,
        handler: GenericHandler,
    ) {
        let route_info = Arc::new(RouteInfo::new(
            method,
            path_pattern.clone(),
            handler,
        ));

        config.routes_by_method
            .entry(method)
            .or_default()
            .push(route_info);

        println!(
            "Route added to RouterConfig: {:?} {}",
            method, path_pattern
        );
    }
}