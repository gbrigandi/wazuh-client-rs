use tracing::{debug, info};

use super::active_response::ActiveResponseClient;
use super::agents::AgentsClient;
use super::cluster::ClusterClient;
use super::configuration::ConfigurationClient;
use super::error::WazuhApiError;
use super::indexer_client::WazuhIndexerClient;
use super::logs::LogsClient;
use super::rules::RulesClient;
use super::vulnerability::VulnerabilityClient;
use super::wazuh_client::WazuhApiClient;

#[derive(Debug, Clone)]
pub struct WazuhClientFactory {
    api_host: String,
    api_port: u16,
    api_username: String,
    api_password: String,
    indexer_host: String,
    indexer_port: u16,
    indexer_username: String,
    indexer_password: String,
    verify_ssl: bool,
    protocol: String,
}

impl WazuhClientFactory {
    #![allow(clippy::too_many_arguments)]
    pub fn new(
        api_host: String,
        api_port: u16,
        api_username: String,
        api_password: String,
        indexer_host: String,
        indexer_port: u16,
        indexer_username: String,
        indexer_password: String,
        verify_ssl: bool,
        protocol: Option<String>,
    ) -> Self {
        debug!("Creating WazuhClientFactory");

        Self {
            api_host,
            api_port,
            api_username,
            api_password,
            indexer_host,
            indexer_port,
            indexer_username,
            indexer_password,
            verify_ssl,
            protocol: protocol.unwrap_or_else(|| "https".to_string()),
        }
    }

    pub fn create_api_client(&self) -> WazuhApiClient {
        debug!("Creating base Wazuh API client");
        WazuhApiClient::new_with_protocol(
            self.api_host.clone(),
            self.api_port,
            self.api_username.clone(),
            self.api_password.clone(),
            self.verify_ssl,
            &self.protocol,
        )
    }

    pub fn create_indexer_client(&self) -> WazuhIndexerClient {
        debug!("Creating Wazuh Indexer client");
        WazuhIndexerClient::new_with_protocol(
            self.indexer_host.clone(),
            self.indexer_port,
            self.indexer_username.clone(),
            self.indexer_password.clone(),
            self.verify_ssl,
            &self.protocol,
        )
    }

    pub fn create_agents_client(&self) -> AgentsClient {
        debug!("Creating Agents client");
        let api_client = self.create_api_client();
        AgentsClient::new(api_client)
    }

    pub fn create_rules_client(&self) -> RulesClient {
        debug!("Creating Rules client");
        let api_client = self.create_api_client();
        RulesClient::new(api_client)
    }

    pub fn create_configuration_client(&self) -> ConfigurationClient {
        debug!("Creating Configuration client");
        let api_client = self.create_api_client();
        ConfigurationClient::new(api_client)
    }

    pub fn create_vulnerability_client(&self) -> VulnerabilityClient {
        debug!("Creating Vulnerability client");
        let api_client = self.create_api_client();
        VulnerabilityClient::new(api_client)
    }

    pub fn create_active_response_client(&self) -> ActiveResponseClient {
        debug!("Creating Active Response client");
        let api_client = self.create_api_client();
        ActiveResponseClient::new(api_client)
    }

    pub fn create_cluster_client(&self) -> ClusterClient {
        debug!("Creating Cluster client");
        let api_client = self.create_api_client();
        ClusterClient::new(api_client)
    }

    pub fn create_logs_client(&self) -> LogsClient {
        debug!("Creating Logs client");
        let api_client = self.create_api_client();
        LogsClient::new(api_client)
    }

    pub fn create_all_clients(&self) -> WazuhClients {
        debug!("Creating all Wazuh clients");

        WazuhClients {
            indexer: self.create_indexer_client(),
            agents: self.create_agents_client(),
            rules: self.create_rules_client(),
            configuration: self.create_configuration_client(),
            vulnerability: self.create_vulnerability_client(),
            active_response: self.create_active_response_client(),
            cluster: self.create_cluster_client(),
            logs: self.create_logs_client(),
        }
    }

    pub async fn test_connectivity(&self) -> Result<ConnectivityStatus, WazuhApiError> {
        debug!("Testing connectivity to Wazuh API and Indexer");

        let mut api_status = false;
        let mut indexer_status = false;
        let mut api_error = None;
        let mut indexer_error = None;

        // Test API connectivity
        let mut cluster_client = self.create_cluster_client();
        match cluster_client.get_manager_info().await {
            Ok(_) => {
                api_status = true;
                info!("Wazuh API connectivity test: SUCCESS");
            }
            Err(e) => {
                api_error = Some(format!("API connectivity failed: {}", e));
                debug!("Wazuh API connectivity test: FAILED - {}", e);
            }
        }

        let indexer_client = self.create_indexer_client();
        match indexer_client.get_alerts().await {
            Ok(_) => {
                indexer_status = true;
                info!("Wazuh Indexer connectivity test: SUCCESS");
            }
            Err(e) => {
                indexer_error = Some(format!("Indexer connectivity failed: {}", e));
                debug!("Wazuh Indexer connectivity test: FAILED - {}", e);
            }
        }

        Ok(ConnectivityStatus {
            api_connected: api_status,
            indexer_connected: indexer_status,
            api_error,
            indexer_error,
        })
    }
}

#[derive(Debug)]
pub struct WazuhClients {
    pub indexer: WazuhIndexerClient,
    pub agents: AgentsClient,
    pub rules: RulesClient,
    pub configuration: ConfigurationClient,
    pub vulnerability: VulnerabilityClient,
    pub active_response: ActiveResponseClient,
    pub cluster: ClusterClient,
    pub logs: LogsClient,
}

#[derive(Debug, Clone)]
pub struct ConnectivityStatus {
    pub api_connected: bool,
    pub indexer_connected: bool,
    pub api_error: Option<String>,
    pub indexer_error: Option<String>,
}

impl ConnectivityStatus {
    pub fn is_fully_connected(&self) -> bool {
        self.api_connected && self.indexer_connected
    }

    pub fn has_any_connection(&self) -> bool {
        self.api_connected || self.indexer_connected
    }

    pub fn get_status_summary(&self) -> String {
        match (self.api_connected, self.indexer_connected) {
            (true, true) => "All services connected".to_string(),
            (true, false) => format!(
                "API connected, Indexer failed: {}",
                self.indexer_error.as_deref().unwrap_or("Unknown error")
            ),
            (false, true) => format!(
                "Indexer connected, API failed: {}",
                self.api_error.as_deref().unwrap_or("Unknown error")
            ),
            (false, false) => format!(
                "All services failed - API: {}, Indexer: {}",
                self.api_error.as_deref().unwrap_or("Unknown error"),
                self.indexer_error.as_deref().unwrap_or("Unknown error")
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_client_factory_creation() {
        let factory = WazuhClientFactory::new(
            "localhost".to_string(),
            55000,
            "wazuh".to_string(),
            "password".to_string(),
            "localhost".to_string(),
            9200,
            "admin".to_string(),
            "admin".to_string(),
            false,
            Some("https".to_string()),
        );

        let _agents_client = factory.create_agents_client();
        let _rules_client = factory.create_rules_client();
        let _config_client = factory.create_configuration_client();
        let _vuln_client = factory.create_vulnerability_client();
        let _ar_client = factory.create_active_response_client();
        let _cluster_client = factory.create_cluster_client();
        let _logs_client = factory.create_logs_client();
        let _indexer_client = factory.create_indexer_client();
    }

    #[test]
    fn test_connectivity_status() {
        let status = ConnectivityStatus {
            api_connected: true,
            indexer_connected: false,
            api_error: None,
            indexer_error: Some("Connection refused".to_string()),
        };

        assert!(status.has_any_connection());
        assert!(!status.is_fully_connected());
        assert!(status.get_status_summary().contains("API connected"));
        assert!(status.get_status_summary().contains("Indexer failed"));
    }
}
