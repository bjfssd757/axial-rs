use std::collections::HashMap;
use std::convert::Infallible;
use std::error::Error;
use std::net::SocketAddr;
use std::sync::Arc;
use hyper::body::{Body as HyperBodyTrait, Bytes as HyperBytes, Incoming as HyperIncoming};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request as HyperRequest, Response as HyperResponse, StatusCode as HyperStatusCode, Method as HyperMethod, header as HyperHeader};
use tokio::net::TcpListener;
use http_body_util::{BodyExt, Full};
use hyper_util::rt::TokioIo;
use crate::core::routes::router::{
    handler_adapters, GenericHandler, Request as CoreRequest, Response as CoreResponse, RouterConfig
};
use crate::core::config::configer::Methods as CoreHttpMethod;
pub use crate::core::config::configer::Methods;


pub trait ServerTrait {
    type Error: std::error::Error + Send + Sync + 'static;

    fn build(host: String, port: u16) -> Result<Self, Self::Error>
    where
        Self: Sized;
    async fn start(self) -> Result<(), Self::Error>;
}

#[derive(Clone)]
pub struct HttpServer {
    host: String,
    port: u16,
    router_config: Arc<RouterConfig>,
    settings: Arc<HashMap<String, HttpServerSettings>>,
}

#[derive(Debug)]
pub enum HttpServerErrors {
    InvalidHost(String),
    InvalidPort(u16),
    HyperDetailedError(hyper::Error),
    IOError(std::io::Error),
    AddrParseError(std::net::AddrParseError),
    BodyReadError(Box<dyn std::error::Error + Send + Sync>),
}

impl std::fmt::Display for HttpServerErrors {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HttpServerErrors::InvalidHost(host) => write!(f, "Invalid host: {}", host),
            HttpServerErrors::InvalidPort(port) => write!(f, "Invalid port: {}", port),
            HttpServerErrors::HyperDetailedError(err) => write!(f, "Hyper error: {}", err),
            HttpServerErrors::IOError(err) => write!(f, "IO error: {}", err),
            HttpServerErrors::AddrParseError(err) => write!(f, "Address parse error: {}", err),
            HttpServerErrors::BodyReadError(err) => write!(f, "Failed to read request body: {}", err),
        }
    }
}

impl std::error::Error for HttpServerErrors {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            HttpServerErrors::HyperDetailedError(err) => Some(err),
            HttpServerErrors::IOError(err) => Some(err),
            HttpServerErrors::AddrParseError(err) => Some(err),
            HttpServerErrors::BodyReadError(err) => Some(err.as_ref()),
            _ => None,
        }
    }
}

impl From<hyper::Error> for HttpServerErrors {
    fn from(err: hyper::Error) -> Self {
        HttpServerErrors::HyperDetailedError(err)
    }
}
impl From<std::io::Error> for HttpServerErrors {
    fn from(err: std::io::Error) -> Self {
        HttpServerErrors::IOError(err)
    }
}
impl From<std::net::AddrParseError> for HttpServerErrors {
    fn from(err: std::net::AddrParseError) -> Self {
        HttpServerErrors::AddrParseError(err)
    }
}


#[derive(Clone, Debug)]
pub enum HttpServerSettings {
    MaxConnections(u32),
    Timeout(u32),
    KeepAlive(bool),
}


impl HttpServer {
    pub fn new(host: String, port: u16) -> Self {
        HttpServer {
            host,
            port,
            router_config: Arc::new(RouterConfig::new()),
            settings: Arc::new(HashMap::new()),
        }
    }

    pub fn service<F: crate::core::routes::router::RouteFactory>(mut self, factory: F) -> Self {
        let mut config_mut = Arc::try_unwrap(self.router_config)
            .map_err(|_| eprintln!("Failed to get exclusive access to RouterConfig. Ensure Arc<RouterConfig> is not cloned before all services are registered."))
            .unwrap();
        factory.register_route_service(&mut config_mut);
        self.router_config = Arc::new(config_mut);
        self
    }

    async fn handle_hyper_request(
        self: Arc<Self>,
        hyper_req: HyperRequest<HyperIncoming>,
    ) -> Result<HyperResponse<Full<HyperBytes>>, Infallible> {
        let (parts, incoming_body) = hyper_req.into_parts();

        let core_method = match parts.method {
            HyperMethod::GET => CoreHttpMethod::GET,
            HyperMethod::POST => CoreHttpMethod::POST,
            HyperMethod::PUT => CoreHttpMethod::PUT,
            HyperMethod::DELETE => CoreHttpMethod::DELETE,
            _ => {
                let mut response = HyperResponse::new(Full::new(HyperBytes::from_static(b"Unsupported HTTP method")));
                *response.status_mut() = HyperStatusCode::METHOD_NOT_ALLOWED;
                return Ok(response);
            }
        };

        let request_path_str = parts.uri.path().to_string();

        let query_string_option = parts.uri.query().map(|s| s.to_string());

        let mut core_headers = Vec::new();
        for (name, value) in parts.headers.iter() {
            core_headers.push((
                name.as_str().to_string(),
                value.to_str().unwrap_or("").to_string(),
            ));
        }

        let collected_body = match incoming_body.collect().await {
            Ok(collected) => collected,
            Err(e) => {
                eprintln!("Failed to collect request body: {}", e);
                let mut response = HyperResponse::new(Full::new(HyperBytes::from_static(b"Failed to read request body")));
                *response.status_mut() = HyperStatusCode::BAD_REQUEST;
                return Ok(response);
            }
        };
        let body_bytes = collected_body.to_bytes();
        let core_body_str = String::from_utf8_lossy(&body_bytes).to_string();


        let router_cfg = self.router_config.clone();
        if let Some((handler_arc, path_params_map)) = router_cfg.match_route(core_method, &request_path_str) {
            let handler_fn = handler_arc.clone();

            let core_request = CoreRequest {
                method: core_method,
                path: request_path_str,
                headers: core_headers,
                body: core_body_str,
                cookies: Vec::new(),
                path_params: Arc::new(path_params_map),
                query_string: query_string_option,
            };

            let core_response = (handler_fn)(core_request).await;

            let mut hyper_response = HyperResponse::new(Full::new(HyperBytes::from(core_response.body.into_bytes())));
            *hyper_response.status_mut() =
                HyperStatusCode::from_u16(core_response.status_code).unwrap_or(HyperStatusCode::INTERNAL_SERVER_ERROR);
            for (key, value) in core_response.headers {
                match HyperHeader::HeaderName::from_bytes(key.as_bytes()) {
                    Ok(header_name) => {
                        match HyperHeader::HeaderValue::from_str(&value) {
                            Ok(header_value) => {
                                hyper_response.headers_mut().insert(header_name, header_value);
                            }
                            Err(e) => eprintln!("Invalid header value for key '{}': {} (value: '{}')", key, e, value),
                        }
                    }
                    Err(e) => eprintln!("Invalid header name: {} (name: '{}')", e, key),
                }
            }
            Ok(hyper_response)

        } else {
            let mut response = HyperResponse::new(Full::new(HyperBytes::from_static(b"Not Found")));
            *response.status_mut() = HyperStatusCode::NOT_FOUND;
            Ok(response)
        }
    }
}


impl ServerTrait for HttpServer {
    type Error = HttpServerErrors;

    fn build(host: String, port: u16) -> Result<Self, Self::Error> {
        if port == 0 {
            return Err(HttpServerErrors::InvalidPort(port));
        }
        Ok(HttpServer::new(host, port))
    }

    async fn start(self) -> Result<(), Self::Error> {
        let addr_str = format!("{}:{}", self.host, self.port);
        let addr: SocketAddr = addr_str.parse()?;

        let listener = TcpListener::bind(addr).await?;
        println!("HTTP server listening on http://{}", addr);

        let server_arc = Arc::new(self);

        loop {
            let (tcp_stream, remote_addr) = match listener.accept().await {
                Ok(conn) => conn,
                Err(e) => {
                    eprintln!("Failed to accept connection: {}", e);
                    continue;
                }
            };
            println!("Accepted connection from: {}", remote_addr);

            let io = TokioIo::new(tcp_stream);
            let app_capture = server_arc.clone();

            tokio::task::spawn(async move {
                let service = service_fn(move |req: HyperRequest<HyperIncoming>| {
                    app_capture.clone().handle_hyper_request(req)
                });

                if let Err(err) = http1::Builder::new()
                    .serve_connection(io, service)
                    .await
                {
                    if !is_common_hyper_connection_error(&err) {
                         eprintln!("Error serving connection from {}: {:?}", remote_addr, err);
                    }
                }
            });
        }
    }
}

fn is_common_hyper_connection_error(err: &hyper::Error) -> bool {
    if err.is_timeout() {
        return true;
    }

    if let Some(source) = err.source() {
        if let Some(io_err) = source.downcast_ref::<std::io::Error>() {
            return matches!(
                io_err.kind(),
                std::io::ErrorKind::ConnectionReset
                    | std::io::ErrorKind::BrokenPipe
                    | std::io::ErrorKind::UnexpectedEof
            );
        }
    }

    false
}