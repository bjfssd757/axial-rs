use std::collections::HashMap;
use std::sync::{Arc, Mutex, PoisonError, RwLock};

#[allow(dead_code)]
pub trait Config {
    type Error: std::error::Error + Send + Sync + 'static;

    fn get(&self, key: &str) -> Result<ConfigValues, Self::Error>;
    fn add(&self, item: HashMap<String, ConfigValues>) -> Result<(), Self::Error>;
    fn remove(&self, key: &str) -> Result<(), Self::Error>;
    fn clear(&self) -> Result<(), Self::Error>;
    fn get_all(&self) -> Result<HashMap<String, ConfigValues>, Self::Error>;
}

#[derive(Clone)]
#[allow(dead_code)]
pub enum ConfigValues {
    Http {
        host: String,
        port: u16,
    },
    Https {
        host: String,
        port: u16,
        cert: String,
        key: String,
    },
    Redis {
        host: String,
        port: u16,
        db: u8,
        password: Option<String>,
    },
    Routes {
        route: HashMap<String, Methods>, // url - method
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[allow(dead_code)]
pub enum Methods {
    GET,
    POST,
    PUT,
    DELETE,
}

#[allow(dead_code)]
pub enum ConfigErrors {
    KeyNotFound(String),
    InvalidValue(String),
    InvalidType(String),
    InvalidKey(String),
    InvalidConfig(String),
    IsEmpty,
    MutexPoisoned(String),
}

#[derive(Clone)]
pub struct Configer {
    config: Arc<Mutex<HashMap<String, ConfigValues>>>
}

#[allow(dead_code)]
impl Configer {
    pub fn new() -> Self {
        Configer {
            config: Arc::new(Mutex::new(HashMap::new()))
        }
    }
}

impl std::error::Error for ConfigErrors {}

fn map_poison_error<G>(err: PoisonError<G>) -> ConfigErrors {
    ConfigErrors::MutexPoisoned(err.to_string())
}

impl Config for Configer {
    type Error = ConfigErrors;

    fn get(&self, key: &str) -> Result<ConfigValues, Self::Error> {
        let config_guard = self.config.lock()
            .map_err(map_poison_error)?;

        config_guard.get(key)
            .cloned()
            .ok_or_else(|| ConfigErrors::KeyNotFound(key.to_string()))
    }

    fn add(&self, item: HashMap<String, ConfigValues>) -> Result<(), Self::Error> {
        let mut config_guard = self.config.lock()
            .map_err(map_poison_error)?;

        for (key, value) in item.into_iter() {
            config_guard.insert(key, value);
        }
        Ok(())
    }

    fn remove(&self, key: &str) -> Result<(), Self::Error> {
        let mut config_guard = self.config.lock()
            .map_err(map_poison_error)?;

        if config_guard.remove(key).is_some() {
            Ok(())
        } else {
            Err(ConfigErrors::KeyNotFound(key.to_string()))
        }
    }

    fn clear(&self) -> Result<(), Self::Error> {
        let mut config_guard = self.config.lock()
            .map_err(map_poison_error)?;

        config_guard.clear();
        Ok(())
    }

    fn get_all(&self) -> Result<HashMap<String, ConfigValues>, Self::Error> {
        let config_guard = self.config.lock()
            .map_err(map_poison_error)?;

        Ok(config_guard.clone())
    }
}

impl std::fmt::Display for ConfigErrors {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConfigErrors::KeyNotFound(key) => write!(f, "Key not found: {}", key),
            ConfigErrors::InvalidValue(value) => write!(f, "Invalid value: {}", value),
            ConfigErrors::InvalidType(ty) => write!(f, "Invalid type: {}", ty),
            ConfigErrors::InvalidKey(key) => write!(f, "Invalid key: {}", key),
            ConfigErrors::InvalidConfig(config) => write!(f, "Invalid config: {}", config),
            ConfigErrors::IsEmpty => write!(f, "Config is empty"),
            ConfigErrors::MutexPoisoned(err) => write!(f, "Mutex poisoned: {}", err),
        }
    }
}

impl std::fmt::Debug for ConfigErrors {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConfigErrors::KeyNotFound(key) => write!(f, "Key not found: {}", key),
            ConfigErrors::InvalidValue(value) => write!(f, "Invalid value: {}", value),
            ConfigErrors::InvalidType(ty) => write!(f, "Invalid type: {}", ty),
            ConfigErrors::InvalidKey(key) => write!(f, "Invalid key: {}", key),
            ConfigErrors::InvalidConfig(config) => write!(f, "Invalid config: {}", config),
            ConfigErrors::IsEmpty => write!(f, "Config is empty"),
            ConfigErrors::MutexPoisoned(err) => write!(f, "Mutex poisoned: {}", err),
        }
    }
}