use std::sync::{Arc, Mutex};
use once_cell::sync::Lazy;
use tokio::sync::Semaphore;

pub struct HttpServerConfig {
    pub max_connections: Option<u32>,
    pub timeout: Option<std::time::Duration>,
    pub keep_alive: Option<bool>,
    max_conn_semaphore: Option<Arc<Semaphore>>,
}

impl Default for HttpServerConfig {
    fn default() -> Self {
        Self {
            max_connections: None,
            timeout: None,
            keep_alive: None,
            max_conn_semaphore: None,
        }
    }
}

impl HttpServerConfig {
    pub fn initialize_semaphore(&mut self) {
        if let Some(max_conn) = self.max_connections {
            if self.max_conn_semaphore.is_none() {
                self.max_conn_semaphore = Some(Arc::new(Semaphore::new(max_conn as usize)));
            }
        }
    }

    pub fn get_connection_semaphore(&self) -> Option<Arc<Semaphore>> {
        self.max_conn_semaphore.clone()
    }
}

pub static HTTP_CONFIG: Lazy<Mutex<HttpServerConfig>> = Lazy::new(|| {
    Mutex::new(HttpServerConfig::default())
});