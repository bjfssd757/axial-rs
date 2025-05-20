pub mod http;
pub(crate) mod http_config;

#[derive(Debug)]
pub enum HttpError {
    NotFound(String),
    BadRequest(String),
    InternalServerError(String),
    Unauthorized(String),
    Forbidden(String),
}

impl HttpError {
    pub fn status_code(&self) -> u16 {
        match self {
            HttpError::NotFound(_) => 404,
            HttpError::BadRequest(_) => 400,
            HttpError::InternalServerError(_) => 500,
            HttpError::Unauthorized(_) => 401,
            HttpError::Forbidden(_) => 403,
        }
    }

    pub fn message(&self) -> &str {
        match self {
            HttpError::NotFound(msg) => msg,
            HttpError::BadRequest(msg) => msg,
            HttpError::InternalServerError(msg) => msg,
            HttpError::Unauthorized(msg) => msg,
            HttpError::Forbidden(msg) => msg,
        }
    }
}

impl From<std::io::Error> for HttpError {
    fn from(e: std::io::Error) -> Self {
        HttpError::InternalServerError(e.to_string())
    }
}

impl From<Box<dyn std::error::Error>> for HttpError {
    fn from(e: Box<dyn std::error::Error>) -> Self {
        HttpError::InternalServerError(e.to_string())
    }
}

impl From<&str> for HttpError {
    fn from(e: &str) -> Self {
        HttpError::BadRequest(e.to_string())
    }
}

impl From<String> for HttpError {
    fn from(e: String) -> Self {
        HttpError::BadRequest(e)
    }
}