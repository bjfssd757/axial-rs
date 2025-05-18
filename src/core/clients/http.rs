#![cfg(feature = "client")]

pub trait Client {
    fn get(&self, url: &str) -> impl std::future::Future<Output = Result<String, String>> + Send;
    fn post(&self, url: &str, body: &String) -> impl std::future::Future<Output = Result<String, String>> + Send;
    fn put(&self, url: &str, body: &String) -> impl std::future::Future<Output = Result<String, String>> + Send;
    fn delete(&self, url: &str) -> impl std::future::Future<Output = Result<String, String>> + Send;
}

pub struct HttpClient {
    pub timeout: Option<std::time::Duration>,
    pub headers: Option<Vec<(String, String)>>,
    pub cookies: Option<Vec<(String, String)>>,
    pub user_agent: Option<String>,
    pub response: Option<String>,
}

#[cfg(target_os = "windows")] pub const USER_AGENT_CHROME: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36";
#[cfg(target_os = "linux")] pub const USER_AGENT_CHROME: &str = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36";
#[cfg(target_os = "macos")] pub const USER_AGENT_CHROME: &str = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36";

#[cfg(target_os = "windows")] pub const USER_AGENT_FIREFOX: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:137.0) Gecko/20100101 Firefox/137.0";
#[cfg(target_os = "macos")] pub const USER_AGENT_FIREFOX: &str = "Mozilla/5.0 (Macintosh; Intel Mac OS X 14.7; rv:128.0) Gecko/20100101 Firefox/128.0";
#[cfg(target_os = "linux")] pub const USER_AGENT_FIREFOX: &str = "Mozilla/5.0 (X11; Linux i686; rv:128.0) Gecko/20100101 Firefox/128.0";


impl HttpClient {
    pub fn new() -> Self {
        HttpClient {
            timeout: None,
            headers: None,
            cookies: None,
            user_agent: None,
            response: None,
        }
    }

    pub fn timeout(mut self, timeout: Option<std::time::Duration>) -> Self {
        self.timeout = timeout;
        self
    }

    pub fn header(mut self, key: &str, value: &str) -> Self {
        if self.headers.is_none() {
            self.headers = Some(Vec::new());
        }
        if let Some(ref mut headers) = self.headers {
            headers.push((key.to_string(), value.to_string()));
        }
        self
    }

    pub fn cookie(mut self, key: &str, value: &str) -> Self {
        if self.cookies.is_none() {
            self.cookies = Some(Vec::new());
        }
        if let Some(ref mut cookies) = self.cookies {
            cookies.push((key.to_string(), value.to_string()));
        }
        self
    }

    pub fn user_agent(mut self, user_agent: Option<String>) -> Self {
        self.user_agent = user_agent;
        self
    }

    pub fn build(mut self) -> Result<Self, String> {
        if self.user_agent.is_none() {
            self.user_agent = Some(USER_AGENT_CHROME.to_string());
        }
        Ok(self)
    }
}

impl Client for HttpClient {
    async fn get(&self, url: &str) -> Result<String, String> {
        use reqwest::header::HeaderMap;

        let mut builder = reqwest::ClientBuilder::new();
        if let Some(duration) = self.timeout {
            builder = builder.timeout(duration);
        }

        if let Some(ref heads) = self.headers {
            let mut headers = HeaderMap::new();
            for (key, value) in heads {
                let name: reqwest::header::HeaderName = key.parse().unwrap();
                headers.insert(
                    name,
                    reqwest::header::HeaderValue::from_str(value).unwrap(),
                );
            }
            builder = builder.default_headers(headers);
        }

        if let Some(ref ua) = self.user_agent {
            builder = builder.user_agent(ua);
        }

        let client = builder.build().map_err(|e| e.to_string())?;

        let response = client.get(url).send().await.map_err(|e| e.to_string())?;

        Ok(response.text().await.map_err(|e| e.to_string())?)
    }

    async fn post(&self, url: &str, body: &String) -> Result<String, String> {
        use reqwest::header::HeaderMap;

        let mut builder = reqwest::ClientBuilder::new();
        if let Some(duration) = self.timeout {
            builder = builder.timeout(duration);
        }

        if let Some(ref heads) = self.headers {
            let mut headers = HeaderMap::new();
            for (key, value) in heads {
                let name: reqwest::header::HeaderName = key.parse().unwrap();
                headers.insert(
                    name,
                    reqwest::header::HeaderValue::from_str(value).unwrap(),
                );
            }
            builder = builder.default_headers(headers);
        }

        if let Some(ref ua) = self.user_agent {
            builder = builder.user_agent(ua);
        }

        let client = builder.build().map_err(|e| e.to_string())?;

        let response = client.post(url).body(body.clone()).send().await.map_err(|e| e.to_string())?;

        Ok(response.text().await.map_err(|e| e.to_string())?)
    }

    async fn put(&self, url: &str, body: &String) -> Result<String, String> {
        use reqwest::header::HeaderMap;

        let mut builder = reqwest::ClientBuilder::new();
        if let Some(duration) = self.timeout {
            builder = builder.timeout(duration);
        }

        if let Some(ref heads) = self.headers {
            let mut headers = HeaderMap::new();
            for (key, value) in heads {
                let name: reqwest::header::HeaderName = key.parse().unwrap();
                headers.insert(
                    name,
                    reqwest::header::HeaderValue::from_str(value).unwrap(),
                );
            }
            builder = builder.default_headers(headers);
        }

        if let Some(ref ua) = self.user_agent {
            builder = builder.user_agent(ua);
        }

        let client = builder.build().map_err(|e| e.to_string())?;

        let response = client.put(url).body(body.clone()).send().await.map_err(|e| e.to_string())?;

        Ok(response.text().await.map_err(|e| e.to_string())?)
    }

    async fn delete(&self, url: &str) -> Result<String, String> {
        use reqwest::header::HeaderMap;

        let mut builder = reqwest::ClientBuilder::new();
        if let Some(duration) = self.timeout {
            builder = builder.timeout(duration);
        }

        if let Some(ref heads) = self.headers {
            let mut headers = HeaderMap::new();
            for (key, value) in heads {
                let name: reqwest::header::HeaderName = key.parse().unwrap();
                headers.insert(
                    name,
                    reqwest::header::HeaderValue::from_str(value).unwrap(),
                );
            }
            builder = builder.default_headers(headers);
        }

        if let Some(ref ua) = self.user_agent {
            builder = builder.user_agent(ua);
        }

        let client = builder.build().map_err(|e| e.to_string())?;

        let response = client.delete(url).send().await.map_err(|e| e.to_string())?;

        Ok(response.text().await.map_err(|e| e.to_string())?)
    }
}