use std::fmt::Display;

use reqwest::Method;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use tracing::{debug, info};

use super::error::WazuhApiError;
use super::wazuh_client::WazuhApiClient;

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Agent {
    pub id: String,
    pub name: String,
    pub ip: Option<String>,
    #[serde(rename = "registerIP")]
    pub register_ip: Option<String>,
    pub status: String,
    #[serde(rename = "status_code")]
    pub status_code: Option<i32>,
    #[serde(rename = "configSum")]
    pub config_sum: Option<String>,
    #[serde(rename = "mergedSum")]
    pub merged_sum: Option<String>,
    #[serde(rename = "dateAdd")]
    pub date_add: Option<String>,
    #[serde(rename = "lastKeepAlive")]
    pub last_keep_alive: Option<String>,
    pub os: Option<AgentOs>,
    pub version: Option<String>,
    pub manager: Option<String>,
    pub group: Option<Vec<String>>,
    pub node_name: Option<String>,
    #[serde(rename = "group_config_status")]
    pub group_config_status: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AgentOs {
    pub arch: Option<String>,
    pub major: Option<String>,
    pub minor: Option<String>,
    pub name: Option<String>,
    pub platform: Option<String>,
    pub uname: Option<String>,
    pub version: Option<String>,
    pub codename: Option<String>,
}

impl Display for AgentOs {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} {} {}",
            self.platform.as_deref().unwrap_or("unknown"),
            self.version.as_deref().unwrap_or("unknown"),
            self.arch.as_deref().unwrap_or("unknown")
        )
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AgentConnectionSummary {
    pub total: u32,
    pub active: u32,
    pub disconnected: u32,
    #[serde(rename = "never_connected")]
    pub never_connected: u32,
    pub pending: u32,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AgentConfigurationSummary {
    pub total: u32,
    pub synced: u32,
    #[serde(rename = "not_synced")]
    pub not_synced: u32,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AgentSummary {
    pub connection: AgentConnectionSummary,
    pub configuration: AgentConfigurationSummary,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AgentKey {
    pub id: String,
    pub key: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AgentAddBody {
    pub name: String,
    pub ip: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AgentInsertBody {
    pub name: String,
    pub ip: Option<String>,
    pub id: Option<String>,
    pub key: Option<String>,
    pub force: Option<AgentForceOptions>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AgentForceOptions {
    pub enabled: bool,
    pub disconnected_time: Option<AgentDisconnectedTime>,
    pub after_registration_time: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AgentDisconnectedTime {
    pub enabled: bool,
    pub value: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AgentIdKey {
    pub id: String,
    pub key: String,
}

#[derive(Debug, Clone)]
pub struct AgentsClient {
    api_client: WazuhApiClient,
}

impl AgentsClient {
    pub fn new(api_client: WazuhApiClient) -> Self {
        Self { api_client }
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn get_agents(
        &mut self,
        limit: Option<u32>,
        offset: Option<u32>,
        select: Option<&str>,
        sort: Option<&str>,
        search: Option<&str>,
        status: Option<&str>,
        query: Option<&str>,
        older_than: Option<&str>,
        os_platform: Option<&str>,
        os_version: Option<&str>,
        os_name: Option<&str>,
        manager_host: Option<&str>,
        version: Option<&str>,
        group: Option<&str>,
        node_name: Option<&str>,
        name: Option<&str>,
        ip: Option<&str>,
        register_ip: Option<&str>,
        group_config_status: Option<&str>,
        distinct: Option<bool>,
    ) -> Result<Vec<Agent>, WazuhApiError> {
        debug!("Getting agents list with comprehensive filters");

        let mut query_params = Vec::new();

        if let Some(limit) = limit {
            query_params.push(("limit", limit.to_string()));
        }
        if let Some(offset) = offset {
            query_params.push(("offset", offset.to_string()));
        }
        if let Some(select) = select {
            query_params.push(("select", select.to_string()));
        }
        if let Some(sort) = sort {
            query_params.push(("sort", sort.to_string()));
        }
        if let Some(search) = search {
            query_params.push(("search", search.to_string()));
        }
        if let Some(status) = status {
            query_params.push(("status", status.to_string()));
        }
        if let Some(query) = query {
            query_params.push(("q", query.to_string()));
        }
        if let Some(older_than) = older_than {
            query_params.push(("older_than", older_than.to_string()));
        }
        if let Some(os_platform) = os_platform {
            query_params.push(("os.platform", os_platform.to_string()));
        }
        if let Some(os_version) = os_version {
            query_params.push(("os.version", os_version.to_string()));
        }
        if let Some(os_name) = os_name {
            query_params.push(("os.name", os_name.to_string()));
        }
        if let Some(manager_host) = manager_host {
            query_params.push(("manager_host", manager_host.to_string()));
        }
        if let Some(version) = version {
            query_params.push(("version", version.to_string()));
        }
        if let Some(group) = group {
            query_params.push(("group", group.to_string()));
        }
        if let Some(node_name) = node_name {
            query_params.push(("node_name", node_name.to_string()));
        }
        if let Some(name) = name {
            query_params.push(("name", name.to_string()));
        }
        if let Some(ip) = ip {
            query_params.push(("ip", ip.to_string()));
        }
        if let Some(register_ip) = register_ip {
            query_params.push(("registerIP", register_ip.to_string()));
        }
        if let Some(group_config_status) = group_config_status {
            query_params.push(("group_config_status", group_config_status.to_string()));
        }
        if let Some(distinct) = distinct {
            query_params.push(("distinct", distinct.to_string()));
        }

        let query_params_ref: Vec<(&str, &str)> =
            query_params.iter().map(|(k, v)| (*k, v.as_str())).collect();

        let response = self
            .api_client
            .make_request(
                Method::GET,
                "/agents",
                None,
                if query_params_ref.is_empty() {
                    None
                } else {
                    Some(&query_params_ref)
                },
            )
            .await?;

        let agents_data = response
            .get("data")
            .and_then(|d| d.get("affected_items"))
            .ok_or_else(|| {
                WazuhApiError::ApiError(
                    "Missing 'data.affected_items' in agents response".to_string(),
                )
            })?;

        let agents: Vec<Agent> = serde_json::from_value(agents_data.clone())?;
        info!("Retrieved {} agents", agents.len());
        Ok(agents)
    }

    pub async fn get_agent(&mut self, agent_id: &str) -> Result<Agent, WazuhApiError> {
        debug!(%agent_id, "Getting specific agent");

        let endpoint = format!("/agents/{}", agent_id);
        let response = self
            .api_client
            .make_request(Method::GET, &endpoint, None, None)
            .await?;

        let agent_data = response
            .get("data")
            .and_then(|d| d.get("affected_items"))
            .and_then(|items| items.as_array())
            .and_then(|arr| arr.first())
            .ok_or_else(|| WazuhApiError::ApiError(format!("Agent {} not found", agent_id)))?;

        let agent: Agent = serde_json::from_value(agent_data.clone())?;
        info!(%agent_id, "Retrieved agent details");
        Ok(agent)
    }

    pub async fn get_agents_summary(&mut self) -> Result<AgentSummary, WazuhApiError> {
        debug!("Getting agents summary");

        let response = self
            .api_client
            .make_request(Method::GET, "/agents/summary/status", None, None)
            .await?;

        let summary_data = response.get("data").ok_or_else(|| {
            WazuhApiError::ApiError("Missing 'data' in agents summary response".to_string())
        })?;

        let summary: AgentSummary = serde_json::from_value(summary_data.clone())?;
        info!(
            "Retrieved agents summary: {} total agents",
            summary.connection.total
        );
        Ok(summary)
    }

    pub async fn get_agent_key(&mut self, agent_id: &str) -> Result<AgentKey, WazuhApiError> {
        debug!(%agent_id, "Getting agent key");

        let endpoint = format!("/agents/{}/key", agent_id);
        let response = self
            .api_client
            .make_request(Method::GET, &endpoint, None, None)
            .await?;

        let key_data = response
            .get("data")
            .and_then(|d| d.get("affected_items"))
            .and_then(|items| items.as_array())
            .and_then(|arr| arr.first())
            .ok_or_else(|| {
                WazuhApiError::ApiError(format!("Agent key for {} not found", agent_id))
            })?;

        let agent_key: AgentKey = serde_json::from_value(key_data.clone())?;
        info!(%agent_id, "Retrieved agent key");
        Ok(agent_key)
    }

    pub async fn get_agent_config(
        &mut self,
        agent_id: &str,
        component: &str,
        configuration: &str,
    ) -> Result<Value, WazuhApiError> {
        debug!(%agent_id, %component, %configuration, "Getting agent configuration");

        let endpoint = format!(
            "/agents/{}/config/{}/{}",
            agent_id, component, configuration
        );
        let response = self
            .api_client
            .make_request(Method::GET, &endpoint, None, None)
            .await?;

        let config_data = response.get("data").ok_or_else(|| {
            WazuhApiError::ApiError("Missing 'data' in agent config response".to_string())
        })?;

        info!(%agent_id, %component, %configuration, "Retrieved agent configuration");
        Ok(config_data.clone())
    }

    pub async fn add_agent(
        &mut self,
        agent_data: AgentAddBody,
    ) -> Result<AgentIdKey, WazuhApiError> {
        debug!(?agent_data, "Adding new agent");

        let body = serde_json::to_value(agent_data)?;
        let response = self
            .api_client
            .make_request(Method::POST, "/agents", Some(body), None)
            .await?;

        let agent_id_key_data = response.get("data").ok_or_else(|| {
            WazuhApiError::ApiError("Missing 'data' in add agent response".to_string())
        })?;

        let agent_id_key: AgentIdKey = serde_json::from_value(agent_id_key_data.clone())?;
        info!(agent_id = %agent_id_key.id, "Agent added successfully");
        Ok(agent_id_key)
    }

    pub async fn insert_agent(
        &mut self,
        agent_data: AgentInsertBody,
    ) -> Result<AgentIdKey, WazuhApiError> {
        debug!(?agent_data, "Inserting agent with full details");

        let body = serde_json::to_value(agent_data)?;
        let response = self
            .api_client
            .make_request(Method::POST, "/agents/insert", Some(body), None)
            .await?;

        let agent_id_key_data = response.get("data").ok_or_else(|| {
            WazuhApiError::ApiError("Missing 'data' in insert agent response".to_string())
        })?;

        let agent_id_key: AgentIdKey = serde_json::from_value(agent_id_key_data.clone())?;
        info!(agent_id = %agent_id_key.id, "Agent inserted successfully");
        Ok(agent_id_key)
    }

    pub async fn add_agent_quick(&mut self, agent_name: &str) -> Result<AgentIdKey, WazuhApiError> {
        debug!(%agent_name, "Quick adding agent");

        let query_params = [("agent_name", agent_name)];
        let response = self
            .api_client
            .make_request(
                Method::POST,
                "/agents/insert/quick",
                None,
                Some(&query_params),
            )
            .await?;

        let agent_id_key_data = response.get("data").ok_or_else(|| {
            WazuhApiError::ApiError("Missing 'data' in quick add agent response".to_string())
        })?;

        let agent_id_key: AgentIdKey = serde_json::from_value(agent_id_key_data.clone())?;
        info!(agent_id = %agent_id_key.id, %agent_name, "Agent quick added successfully");
        Ok(agent_id_key)
    }

    pub async fn delete_agents(&mut self, agent_ids: &[String]) -> Result<Value, WazuhApiError> {
        debug!(?agent_ids, "Deleting agents");

        let agents_list = agent_ids.join(",");
        let query_params = [("agents_list", agents_list.as_str())];

        let response = self
            .api_client
            .make_request(Method::DELETE, "/agents", None, Some(&query_params))
            .await?;

        info!("Deleted {} agents", agent_ids.len());
        Ok(response)
    }

    pub async fn get_agents_no_group(&mut self) -> Result<Vec<Agent>, WazuhApiError> {
        debug!("Getting agents without group");

        let response = self
            .api_client
            .make_request(Method::GET, "/agents/no_group", None, None)
            .await?;

        let agents_data = response
            .get("data")
            .and_then(|d| d.get("affected_items"))
            .ok_or_else(|| {
                WazuhApiError::ApiError(
                    "Missing 'data.affected_items' in agents no group response".to_string(),
                )
            })?;

        let agents: Vec<Agent> = serde_json::from_value(agents_data.clone())?;
        info!("Retrieved {} agents without group", agents.len());
        Ok(agents)
    }

    pub async fn get_agent_group_sync_status(
        &mut self,
        agent_id: &str,
    ) -> Result<Value, WazuhApiError> {
        debug!(%agent_id, "Checking agent group sync status");

        let endpoint = format!("/agents/{}/group/is_sync", agent_id);
        let response = self
            .api_client
            .make_request(Method::GET, &endpoint, None, None)
            .await?;

        info!(%agent_id, "Retrieved agent group sync status");
        Ok(response)
    }

    pub async fn remove_agent_from_group(
        &mut self,
        agent_id: &str,
        group_id: Option<&str>,
    ) -> Result<Value, WazuhApiError> {
        let endpoint = if let Some(group_id) = group_id {
            debug!(%agent_id, %group_id, "Removing agent from specific group");
            format!("/agents/{}/group/{}", agent_id, group_id)
        } else {
            debug!(%agent_id, "Removing agent from all groups");
            format!("/agents/{}/group", agent_id)
        };

        let response = self
            .api_client
            .make_request(Method::DELETE, &endpoint, None, None)
            .await?;

        info!(%agent_id, "Agent removed from group(s)");
        Ok(response)
    }

    pub async fn get_outdated_agents(&mut self) -> Result<Vec<Agent>, WazuhApiError> {
        debug!("Getting outdated agents");

        let response = self
            .api_client
            .make_request(Method::GET, "/agents/outdated", None, None)
            .await?;

        let agents_data = response
            .get("data")
            .and_then(|d| d.get("affected_items"))
            .ok_or_else(|| {
                WazuhApiError::ApiError(
                    "Missing 'data.affected_items' in outdated agents response".to_string(),
                )
            })?;

        let agents: Vec<Agent> = serde_json::from_value(agents_data.clone())?;
        info!("Retrieved {} outdated agents", agents.len());
        Ok(agents)
    }

    pub async fn restart_agent(&mut self, agent_id: &str) -> Result<Value, WazuhApiError> {
        debug!(%agent_id, "Restarting agent");

        let endpoint = format!("/agents/{}/restart", agent_id);
        let response = self
            .api_client
            .make_request(Method::PUT, &endpoint, None, None)
            .await?;

        info!(%agent_id, "Agent restart command sent");
        Ok(response)
    }

    pub async fn restart_agents(&mut self, agent_ids: &[String]) -> Result<Value, WazuhApiError> {
        debug!(?agent_ids, "Restarting multiple agents");

        let body = json!({
            "agents_list": agent_ids
        });

        let response = self
            .api_client
            .make_request(Method::PUT, "/agents/restart", Some(body), None)
            .await?;

        info!("Restart command sent to {} agents", agent_ids.len());
        Ok(response)
    }

    pub async fn reconnect_agents(&mut self, agent_ids: &[String]) -> Result<Value, WazuhApiError> {
        debug!(?agent_ids, "Reconnecting agents");

        let agents_list = agent_ids.join(",");
        let query_params = [("agents_list", agents_list.as_str())];

        let response = self
            .api_client
            .make_request(Method::PUT, "/agents/reconnect", None, Some(&query_params))
            .await?;

        info!("Reconnect command sent to {} agents", agent_ids.len());
        Ok(response)
    }

    pub async fn upgrade_agents(&mut self, agent_ids: &[String]) -> Result<Value, WazuhApiError> {
        debug!(?agent_ids, "Upgrading agents");

        let agents_list = agent_ids.join(",");
        let query_params = [("agents_list", agents_list.as_str())];

        let response = self
            .api_client
            .make_request(Method::PUT, "/agents/upgrade", None, Some(&query_params))
            .await?;

        info!("Upgrade command sent to {} agents", agent_ids.len());
        Ok(response)
    }

    pub async fn upgrade_agents_custom(
        &mut self,
        agent_ids: &[String],
        custom_params: Value,
    ) -> Result<Value, WazuhApiError> {
        debug!(?agent_ids, "Custom upgrading agents");

        let agents_list = agent_ids.join(",");
        let query_params = [("agents_list", agents_list.as_str())];

        let response = self
            .api_client
            .make_request(
                Method::PUT,
                "/agents/upgrade_custom",
                Some(custom_params),
                Some(&query_params),
            )
            .await?;

        info!("Custom upgrade command sent to {} agents", agent_ids.len());
        Ok(response)
    }

    pub async fn get_upgrade_results(
        &mut self,
        agent_ids: &[String],
    ) -> Result<Value, WazuhApiError> {
        debug!(?agent_ids, "Getting upgrade results");

        let agents_list = agent_ids.join(",");
        let query_params = [("agents_list", agents_list.as_str())];

        let response = self
            .api_client
            .make_request(
                Method::GET,
                "/agents/upgrade_result",
                None,
                Some(&query_params),
            )
            .await?;

        info!("Retrieved upgrade results for {} agents", agent_ids.len());
        Ok(response)
    }

    pub async fn get_agent_daemon_stats(&mut self, agent_id: &str) -> Result<Value, WazuhApiError> {
        debug!(%agent_id, "Getting agent daemon stats");

        let endpoint = format!("/agents/{}/daemons/stats", agent_id);
        let response = self
            .api_client
            .make_request(Method::GET, &endpoint, None, None)
            .await?;

        info!(%agent_id, "Retrieved agent daemon stats");
        Ok(response)
    }

    pub async fn get_agent_component_stats(
        &mut self,
        agent_id: &str,
        component: &str,
    ) -> Result<Value, WazuhApiError> {
        debug!(%agent_id, %component, "Getting agent component stats");

        let endpoint = format!("/agents/{}/stats/{}", agent_id, component);
        let response = self
            .api_client
            .make_request(Method::GET, &endpoint, None, None)
            .await?;

        info!(%agent_id, %component, "Retrieved agent component stats");
        Ok(response)
    }

    pub async fn get_agents_by_group(
        &mut self,
        group_name: &str,
    ) -> Result<Vec<Agent>, WazuhApiError> {
        debug!(%group_name, "Getting agents by group");

        let query_params = [("group", group_name)];
        let response = self
            .api_client
            .make_request(Method::GET, "/agents", None, Some(&query_params))
            .await?;

        let agents_data = response
            .get("data")
            .and_then(|d| d.get("affected_items"))
            .ok_or_else(|| {
                WazuhApiError::ApiError(
                    "Missing 'data.affected_items' in agents by group response".to_string(),
                )
            })?;

        let agents: Vec<Agent> = serde_json::from_value(agents_data.clone())?;
        info!(%group_name, "Retrieved {} agents from group", agents.len());
        Ok(agents)
    }

    pub async fn get_disconnected_agents(&mut self) -> Result<Vec<Agent>, WazuhApiError> {
        debug!("Getting disconnected agents");
        self.get_agents(
            None,
            None,
            None,
            None,
            None,
            Some("disconnected"),
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
        )
        .await
    }

    pub async fn get_active_agents(&mut self) -> Result<Vec<Agent>, WazuhApiError> {
        debug!("Getting active agents");
        self.get_agents(
            None,
            None,
            None,
            None,
            None,
            Some("active"),
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
        )
        .await
    }

    pub async fn get_pending_agents(&mut self) -> Result<Vec<Agent>, WazuhApiError> {
        debug!("Getting pending agents");
        self.get_agents(
            None,
            None,
            None,
            None,
            None,
            Some("pending"),
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
        )
        .await
    }

    pub async fn get_never_connected_agents(&mut self) -> Result<Vec<Agent>, WazuhApiError> {
        debug!("Getting never connected agents");
        self.get_agents(
            None,
            None,
            None,
            None,
            None,
            Some("never_connected"),
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
        )
        .await
    }
}
