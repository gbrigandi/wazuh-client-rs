use thiserror::Error;

#[derive(Error, Debug)]
#[allow(dead_code)]
pub enum WazuhApiError {
    #[error("Failed to create HTTP client: {0}")]
    HttpClientCreationError(reqwest::Error),

    #[error("HTTP request error: {0}")]
    RequestError(#[from] reqwest::Error),

    #[error("JWT token not found in Wazuh API response")]
    JwtNotFound,

    #[error("Wazuh API Authentication failed: {0}")]
    AuthenticationError(String),

    #[error("JSON parsing error: {0}")]
    JsonError(#[from] serde_json::Error),

    #[error("Wazuh API error: {0}")]
    ApiError(String),

    #[error("HTTP error: Status {status} from {url}: {message}")]
    HttpError {
        status: reqwest::StatusCode,
        message: String,
        url: String,
    },

    #[error("Alert with ID '{0}' not found")]
    AlertNotFound(String),
}
