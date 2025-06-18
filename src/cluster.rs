use reqwest::Method;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tracing::{debug, info};

use super::error::WazuhApiError;
use super::wazuh_client::WazuhApiClient;

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ClusterStatus {
    pub enabled: String,
    pub running: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ClusterNode {
    pub name: String,
    pub node_type: String,
    pub version: String,
    pub ip: String,
    pub status: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ManagerStatus {
    pub wazuh_version: String,
    pub openssl_version: String,
    pub compilation_date: String,
    pub version: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ProcessStatus {
    #[serde(rename = "wazuh-agentlessd")]
    pub wazuh_agentlessd: String,
    #[serde(rename = "wazuh-analysisd")]
    pub wazuh_analysisd: String,
    #[serde(rename = "wazuh-authd")]
    pub wazuh_authd: String,
    #[serde(rename = "wazuh-csyslogd")]
    pub wazuh_csyslogd: String,
    #[serde(rename = "wazuh-dbd")]
    pub wazuh_dbd: String,
    #[serde(rename = "wazuh-monitord")]
    pub wazuh_monitord: String,
    #[serde(rename = "wazuh-execd")]
    pub wazuh_execd: String,
    #[serde(rename = "wazuh-integratord")]
    pub wazuh_integratord: String,
    #[serde(rename = "wazuh-logcollector")]
    pub wazuh_logcollector: String,
    #[serde(rename = "wazuh-maild")]
    pub wazuh_maild: String,
    #[serde(rename = "wazuh-remoted")]
    pub wazuh_remoted: String,
    #[serde(rename = "wazuh-reportd")]
    pub wazuh_reportd: String,
    #[serde(rename = "wazuh-syscheckd")]
    pub wazuh_syscheckd: String,
    #[serde(rename = "wazuh-clusterd")]
    pub wazuh_clusterd: String,
    #[serde(rename = "wazuh-modulesd")]
    pub wazuh_modulesd: String,
    #[serde(rename = "wazuh-db")]
    pub wazuh_db: String,
    #[serde(rename = "wazuh-apid")]
    pub wazuh_apid: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ManagerInfo {
    pub path: String,
    pub version: String,
    #[serde(rename = "type")]
    pub node_type: String,
    pub max_agents: String,
    pub openssl_support: Option<String>,
    pub tz_offset: Option<String>,
    pub tz_name: Option<String>,
    pub installation_date: Option<String>,
    pub revision: Option<String>,
    pub license_version: Option<String>,
    pub license_path: Option<String>,
    pub home_path: Option<String>,
    pub share_path: Option<String>,
    pub openssl_version: Option<String>,
    pub node_name: Option<String>,
    pub cluster_name: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ClusterHealthcheck {
    pub nodes: Vec<ClusterNodeHealth>,
    pub n_connected_nodes: u32,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ClusterNodeHealth {
    pub info: ClusterNodeInfo,
    pub status: ClusterNodeStatus,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ClusterNodeInfo {
    pub name: String,
    pub node_type: String,
    pub version: String,
    pub ip: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ClusterNodeStatus {
    pub last_keep_alive: String,
    pub sync_integrity_free: bool,
    pub sync_agent_info_free: bool,
    pub sync_extravalid_free: bool,
}

#[derive(Debug, Clone)]
pub struct ClusterClient {
    api_client: WazuhApiClient,
}

impl ClusterClient {
    pub fn new(api_client: WazuhApiClient) -> Self {
        Self { api_client }
    }

    pub async fn get_cluster_status(&mut self) -> Result<ClusterStatus, WazuhApiError> {
        debug!("Getting cluster status");

        let response = self
            .api_client
            .make_request(Method::GET, "/cluster/status", None, None)
            .await?;

        let status_data = response.get("data").ok_or_else(|| {
            WazuhApiError::ApiError("Missing 'data' in cluster status response".to_string())
        })?;

        let status: ClusterStatus = serde_json::from_value(status_data.clone())?;
        info!(
            "Retrieved cluster status: enabled={}, running={}",
            status.enabled, status.running
        );
        Ok(status)
    }

    pub async fn get_cluster_nodes(
        &mut self,
        limit: Option<u32>,
        offset: Option<u32>,
        node_type: Option<&str>,
    ) -> Result<Vec<ClusterNode>, WazuhApiError> {
        debug!(?node_type, "Getting cluster nodes");

        let mut query_params = Vec::new();

        if let Some(limit) = limit {
            query_params.push(("limit", limit.to_string()));
        }
        if let Some(offset) = offset {
            query_params.push(("offset", offset.to_string()));
        }
        if let Some(node_type) = node_type {
            query_params.push(("type", node_type.to_string()));
        }

        let query_params_ref: Vec<(&str, &str)> =
            query_params.iter().map(|(k, v)| (*k, v.as_str())).collect();

        let response = self
            .api_client
            .make_request(
                Method::GET,
                "/cluster/nodes",
                None,
                if query_params_ref.is_empty() {
                    None
                } else {
                    Some(&query_params_ref)
                },
            )
            .await?;

        let nodes_data = response
            .get("data")
            .and_then(|d| d.get("affected_items"))
            .ok_or_else(|| {
                WazuhApiError::ApiError(
                    "Missing 'data.affected_items' in cluster nodes response".to_string(),
                )
            })?;

        let nodes: Vec<ClusterNode> = serde_json::from_value(nodes_data.clone())?;
        info!("Retrieved {} cluster nodes", nodes.len());
        Ok(nodes)
    }

    pub async fn get_cluster_node(
        &mut self,
        node_name: &str,
    ) -> Result<ClusterNode, WazuhApiError> {
        debug!(%node_name, "Getting specific cluster node");

        let endpoint = format!("/cluster/nodes/{}", node_name);
        let response = self
            .api_client
            .make_request(Method::GET, &endpoint, None, None)
            .await?;

        let node_data = response
            .get("data")
            .and_then(|d| d.get("affected_items"))
            .and_then(|items| items.as_array())
            .and_then(|arr| arr.first())
            .ok_or_else(|| {
                WazuhApiError::ApiError(format!("Cluster node {} not found", node_name))
            })?;

        let node: ClusterNode = serde_json::from_value(node_data.clone())?;
        info!(%node_name, "Retrieved cluster node details");
        Ok(node)
    }

    pub async fn get_cluster_healthcheck(&mut self) -> Result<ClusterHealthcheck, WazuhApiError> {
        debug!("Getting cluster healthcheck");

        let response = self
            .api_client
            .make_request(Method::GET, "/cluster/healthcheck", None, None)
            .await?;

        let healthcheck_data = response
            .get("data")
            .and_then(|d| d.get("affected_items"))
            .and_then(|items| items.as_array())
            .and_then(|arr| arr.first())
            .ok_or_else(|| {
                WazuhApiError::ApiError("Missing cluster healthcheck data".to_string())
            })?;

        let healthcheck: ClusterHealthcheck = serde_json::from_value(healthcheck_data.clone())?;
        info!(
            "Retrieved cluster healthcheck: {} connected nodes",
            healthcheck.n_connected_nodes
        );
        Ok(healthcheck)
    }

    pub async fn get_manager_process_status(&mut self) -> Result<ProcessStatus, WazuhApiError> {
        debug!("Getting manager process status");

        let response = self
            .api_client
            .make_request(Method::GET, "/manager/status", None, None)
            .await?;

        let status_data = response
            .get("data")
            .and_then(|d| d.get("affected_items"))
            .and_then(|items| items.as_array())
            .and_then(|arr| arr.first())
            .ok_or_else(|| {
                WazuhApiError::ApiError("Missing manager process status data".to_string())
            })?;

        let status: ProcessStatus = serde_json::from_value(status_data.clone())?;
        info!("Retrieved manager process status");
        Ok(status)
    }

    pub async fn get_manager_status(&mut self) -> Result<ManagerStatus, WazuhApiError> {
        debug!("Getting manager status");

        let response = self
            .api_client
            .make_request(Method::GET, "/manager/info", None, None)
            .await?;

        let status_data = response
            .get("data")
            .and_then(|d| d.get("affected_items"))
            .and_then(|items| items.as_array())
            .and_then(|arr| arr.first())
            .ok_or_else(|| WazuhApiError::ApiError("Missing manager status data".to_string()))?;

        let manager_info: ManagerInfo = serde_json::from_value(status_data.clone())?;

        let status = ManagerStatus {
            wazuh_version: manager_info.version.clone(),
            // Ensure ManagerInfo.openssl_version is what's needed or adjust source
            openssl_version: manager_info.openssl_version.unwrap_or_default(),
            // Ensure ManagerInfo.installation_date is what's needed or adjust source
            compilation_date: manager_info.installation_date.unwrap_or_default(),
            version: manager_info.version,
        };

        info!("Retrieved manager status: version={}", status.wazuh_version);
        Ok(status)
    }

    pub async fn get_manager_info(&mut self) -> Result<ManagerInfo, WazuhApiError> {
        debug!("Getting manager information");

        let response = self
            .api_client
            .make_request(Method::GET, "/manager/info", None, None)
            .await?;

        let info_data = response
            .get("data")
            .and_then(|d| d.get("affected_items"))
            .and_then(|items| items.as_array())
            .and_then(|arr| arr.first())
            .ok_or_else(|| WazuhApiError::ApiError("Missing manager info data".to_string()))?;

        let info: ManagerInfo = serde_json::from_value(info_data.clone())?;
        info!(
            "Retrieved manager info: version={}, node_name={}",
            info.version,
            info.node_name.as_deref().unwrap_or("unknown")
        );
        Ok(info)
    }

    pub async fn get_cluster_configuration(&mut self) -> Result<Value, WazuhApiError> {
        debug!("Getting cluster configuration");

        let response = self
            .api_client
            .make_request(Method::GET, "/cluster/configuration", None, None)
            .await?;

        info!("Retrieved cluster configuration");
        Ok(response)
    }

    pub async fn get_master_nodes(&mut self) -> Result<Vec<ClusterNode>, WazuhApiError> {
        debug!("Getting master nodes");
        self.get_cluster_nodes(None, None, Some("master")).await
    }

    pub async fn get_worker_nodes(&mut self) -> Result<Vec<ClusterNode>, WazuhApiError> {
        debug!("Getting worker nodes");
        self.get_cluster_nodes(None, None, Some("worker")).await
    }

    pub async fn is_cluster_healthy(&mut self) -> Result<bool, WazuhApiError> {
        debug!("Checking cluster health");

        let status = self.get_cluster_status().await?;
        let is_enabled = status.enabled.eq_ignore_ascii_case("yes");
        let is_running = status.running.eq_ignore_ascii_case("yes");
        let is_healthy = is_enabled && is_running;

        if is_healthy {
            // Additional check: verify nodes are connected
            match self.get_cluster_healthcheck().await {
                Ok(healthcheck) => {
                    let healthy = healthcheck.n_connected_nodes > 0;
                    info!("Cluster health check: enabled={}, running={}, connected_nodes={}, healthy={}", 
                          is_enabled, is_running, healthcheck.n_connected_nodes, healthy);
                    Ok(healthy)
                }
                Err(_) => {
                    info!(
                        "Cluster health check: enabled={}, running={}, healthcheck_failed=true",
                        is_enabled, is_running
                    );
                    Ok(false) // Or handle error more explicitly if healthcheck failure means unhealthy
                }
            }
        } else {
            info!(
                "Cluster health check: enabled={}, running={}, healthy=false",
                is_enabled, is_running
            );
            Ok(false)
        }
    }

    pub async fn get_cluster_statistics(&mut self) -> Result<Value, WazuhApiError> {
        debug!("Getting cluster statistics");

        let response = self
            .api_client
            .make_request(Method::GET, "/cluster/stats", None, None)
            .await?;

        info!("Retrieved cluster statistics");
        Ok(response)
    }

    pub async fn get_local_node_info(&mut self) -> Result<Value, WazuhApiError> {
        debug!("Getting local node information");

        let response = self
            .api_client
            .make_request(Method::GET, "/cluster/local/info", None, None)
            .await?;

        info!("Retrieved local node information");
        Ok(response)
    }

    pub async fn restart_manager(&mut self) -> Result<Value, WazuhApiError> {
        debug!("Restarting manager");

        let response = self
            .api_client
            .make_request(Method::PUT, "/manager/restart", None, None)
            .await?;

        info!("Manager restart command sent");
        Ok(response)
    }

    pub async fn get_manager_logs_summary(&mut self) -> Result<Value, WazuhApiError> {
        debug!("Getting manager logs summary");

        let response = self
            .api_client
            .make_request(Method::GET, "/manager/logs/summary", None, None)
            .await?;

        info!("Retrieved manager logs summary");
        Ok(response)
    }
}
