use reqwest::{header, Client, Method};
use serde_json::{json, Value};
use std::time::Duration;
use tracing::{debug, error, info};

use super::error::WazuhApiError;

#[derive(Debug, Clone)]
pub struct WazuhIndexerClient {
    username: String,
    password: String,
    base_url: String,
    http_client: Client,
}

impl WazuhIndexerClient {
    #[allow(dead_code)]
    pub fn new(
        host: String,
        indexer_port: u16,
        username: String,
        password: String,
        verify_ssl: bool,
    ) -> Self {
        Self::new_with_protocol(host, indexer_port, username, password, verify_ssl, "https")
    }

    pub fn new_with_protocol(
        host: String,
        indexer_port: u16,
        username: String,
        password: String,
        verify_ssl: bool,
        protocol: &str,
    ) -> Self {
        debug!(%host, indexer_port, %username, %verify_ssl, %protocol, "Creating new WazuhIndexerClient");
        let base_url = format!("{}://{}:{}", protocol, host, indexer_port);
        debug!(%base_url, "Wazuh Indexer base URL set");

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
        }
    }

    pub async fn make_indexer_request(
        &self,
        method: Method,
        endpoint: &str,
        body: Option<Value>,
    ) -> Result<Value, WazuhApiError> {
        debug!(?method, %endpoint, ?body, "Making request to Wazuh Indexer");
        let url = format!("{}{}", self.base_url, endpoint);
        debug!(%url, "Constructed Indexer request URL");

        let mut request_builder = self
            .http_client
            .request(method.clone(), &url)
            .basic_auth(&self.username, Some(&self.password)); // Use Basic Auth

        if let Some(json_body) = &body {
            request_builder = request_builder
                .header(header::CONTENT_TYPE, "application/json")
                .json(json_body);
        }
        debug!("Request builder configured with Basic Auth");

        let response = request_builder.send().await?;
        let status = response.status();
        debug!(%status, "Received response from Indexer endpoint");

        if !status.is_success() {
            let error_text = response
                .text()
                .await
                .unwrap_or_else(|_| "Unknown error reading response body".to_string());
            error!(%url, %status, %error_text, "Indexer API request failed");
            // Provide more context in the error
            return Err(WazuhApiError::ApiError(format!(
                "Indexer request to {} failed with status {}: {}",
                url, status, error_text
            )));
        }

        debug!("Indexer API request successful");
        response.json().await.map_err(|e| {
            error!("Failed to parse JSON response from Indexer: {}", e);
            WazuhApiError::RequestError(e) // Use appropriate error variant
        })
    }

    pub async fn get_alerts(&self, limit: Option<u32>) -> Result<Vec<Value>, WazuhApiError> {
        let endpoint = "/wazuh-alerts*/_search";
        let size = limit.unwrap_or(100);
        let query_body = json!({
            "size": size,
            "query": {
                "match_all": {}
            },
        });

        debug!(%endpoint, ?query_body, "Preparing to get alerts from Wazuh Indexer");
        info!("Retrieving up to {} alerts from Wazuh Indexer", size);

        let response = self
            .make_indexer_request(Method::POST, endpoint, Some(query_body))
            .await?;

        let hits = response
            .get("hits")
            .and_then(|h| h.get("hits"))
            .and_then(|h_array| h_array.as_array())
            .ok_or_else(|| {
                error!(
                    ?response,
                    "Failed to find 'hits.hits' array in Indexer response"
                );
                WazuhApiError::ApiError("Indexer response missing 'hits.hits' array".to_string())
            })?;

        let alerts: Vec<Value> = hits
            .iter()
            .filter_map(|hit| hit.get("_source").cloned())
            .collect();

        debug!(
            "Successfully retrieved {} alerts from Indexer",
            alerts.len()
        );
        Ok(alerts)
    }
}
