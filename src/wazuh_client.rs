use reqwest::{header, Client, Method};
use serde::Deserialize;
use serde_json::Value;
use std::time::Duration;
use tracing::{debug, error, info, warn};

use super::error::WazuhApiError;

#[derive(Debug, Clone, Deserialize)]
pub struct AuthData {
    pub token: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct AuthResponse {
    pub data: AuthData,
    pub error: i32,
}

#[derive(Debug, Clone)]
pub struct WazuhApiClient {
    username: String,
    password: String,
    base_url: String,
    http_client: Client,
    token: Option<String>,
}

impl WazuhApiClient {
    pub fn new(
        host: String,
        api_port: u16,
        username: String,
        password: String,
        verify_ssl: bool,
    ) -> Self {
        Self::new_with_protocol(host, api_port, username, password, verify_ssl, "https")
    }

    pub fn new_with_protocol(
        host: String,
        api_port: u16,
        username: String,
        password: String,
        verify_ssl: bool,
        protocol: &str,
    ) -> Self {
        debug!(%host, api_port, %username, %verify_ssl, %protocol, "Creating new WazuhApiClient");
        let base_url = format!("{}://{}:{}", protocol, host, api_port);
        debug!(%base_url, "Wazuh API base URL set");

        let http_client = Client::builder()
            .danger_accept_invalid_certs(!verify_ssl)
            .timeout(Duration::from_secs(30))
            .build()
            .expect("Failed to create HTTP client");

        Self {
            username,
            password,
            base_url,
            http_client,
            token: None,
        }
    }

    pub async fn authenticate(&mut self) -> Result<(), WazuhApiError> {
        debug!("Authenticating with Wazuh API");
        let auth_url = format!("{}/security/user/authenticate", self.base_url);

        let response = self
            .http_client
            .post(&auth_url)
            .basic_auth(&self.username, Some(&self.password))
            .send()
            .await?;

        let status = response.status();

        if !status.is_success() {
            let error_text = response
                .text()
                .await
                .unwrap_or_else(|_| "Unknown authentication error".to_string());
            error!(%auth_url, %status, %error_text, "Authentication failed");
            return Err(WazuhApiError::ApiError(format!(
                "Authentication failed with status {}: {}",
                status, error_text
            )));
        }

        let response_text = response.text().await?;
        debug!(?response_text, "Raw authentication response text");
        
        let auth_response: AuthResponse = serde_json::from_str(&response_text)?;
        debug!(?auth_response, "Parsed authentication response");
        self.token = Some(auth_response.data.token);
        info!("Successfully authenticated with Wazuh API");
        Ok(())
    }

    pub async fn make_request(
        &mut self,
        method: Method,
        endpoint: &str,
        body: Option<Value>,
        query_params: Option<&[(&str, &str)]>,
    ) -> Result<Value, WazuhApiError> {
        // Ensure we have a valid token
        if self.token.is_none() {
            debug!("No token available, authenticating first");
            self.authenticate().await?;
        }

        let mut url = format!("{}{}", self.base_url, endpoint);

        if let Some(params) = query_params {
            let query_string: Vec<String> = params
                .iter()
                .map(|(key, value)| format!("{}={}", key, value))
                .collect();
            if !query_string.is_empty() {
                url = format!("{}?{}", url, query_string.join("&"));
            }
        }

        debug!(?method, %url, ?body, "Making request to Wazuh API");

        let token = self.token.as_ref().unwrap();
        let mut request_builder = self
            .http_client
            .request(method.clone(), &url)
            .bearer_auth(token);

        if let Some(json_body) = &body {
            request_builder = request_builder
                .header(header::CONTENT_TYPE, "application/json")
                .json(json_body);
        }

        let response = request_builder.send().await?;

        let status = response.status();
        debug!(%status, "Received response from API endpoint");

        let response_text = response.text().await?;
        debug!(?response_text, "Raw API response text");

        if status == 401 {
            warn!("Token expired, re-authenticating");
            self.token = None;
            self.authenticate().await?;

            let token = self.token.as_ref().unwrap();
            let mut retry_request = self.http_client.request(method, &url).bearer_auth(token);

            if let Some(json_body) = &body {
                retry_request = retry_request
                    .header(header::CONTENT_TYPE, "application/json")
                    .json(json_body);
            }

            let retry_response = retry_request.send().await?;
            let retry_status = retry_response.status();
            
            let retry_response_text = retry_response.text().await?;
            debug!(?retry_response_text, "Raw retry API response text");

            if !retry_status.is_success() {
                error!(%url, %retry_status, %retry_response_text, "API request failed after retry");
                return Err(WazuhApiError::HttpError {
                    status: retry_status,
                    message: retry_response_text,
                    url: url.to_string(),
                });
            }

            let retry_json_response: Value = serde_json::from_str(&retry_response_text).map_err(|e| {
                error!("Failed to parse JSON retry response: {}", e);
                WazuhApiError::ApiError(format!("Failed to parse JSON retry response: {}", e))
            })?;
            
            debug!(?retry_json_response, "Parsed retry JSON response");
            return Ok(retry_json_response);
        }

        if !status.is_success() {
            error!(%url, %status, %response_text, "API request failed");
            return Err(WazuhApiError::HttpError {
                status,
                message: response_text,
                url: url.to_string(),
            });
        }

        debug!("API request successful");
        
        let json_response: Value = serde_json::from_str(&response_text).map_err(|e| {
            error!("Failed to parse JSON response: {}", e);
            WazuhApiError::ApiError(format!("Failed to parse JSON response: {}", e))
        })?;
        
        debug!(?json_response, "Parsed JSON response");
        Ok(json_response)
    }
}

