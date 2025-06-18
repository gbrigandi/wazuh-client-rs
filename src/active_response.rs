use reqwest::Method;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use tracing::{debug, info, warn};

use super::error::WazuhApiError;
use super::wazuh_client::WazuhApiClient;

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ActiveResponseCommand {
    pub name: String,
    pub description: Option<String>,
    pub command: String,
    pub location: String,
    pub timeout_allowed: Option<bool>,
    pub expect: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ActiveResponseExecution {
    pub command: String,
    pub arguments: Vec<String>,
    pub alert: Option<Value>,
    pub custom: Option<bool>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ActiveResponseResult {
    pub message: String,
    pub error: Option<String>,
    pub data: Option<Value>,
}

#[derive(Debug, Clone)]
pub struct ActiveResponseClient {
    api_client: WazuhApiClient,
}

impl ActiveResponseClient {
    pub fn new(api_client: WazuhApiClient) -> Self {
        Self { api_client }
    }

    pub async fn get_active_response_commands(
        &mut self,
    ) -> Result<Vec<ActiveResponseCommand>, WazuhApiError> {
        debug!("Getting available active response commands");

        let response = self
            .api_client
            .make_request(Method::GET, "/active-response", None, None)
            .await?;

        let commands_data = response
            .get("data")
            .and_then(|d| d.get("affected_items"))
            .ok_or_else(|| {
                WazuhApiError::ApiError(
                    "Missing 'data.affected_items' in active response commands response"
                        .to_string(),
                )
            })?;

        let commands: Vec<ActiveResponseCommand> = serde_json::from_value(commands_data.clone())?;
        info!("Retrieved {} active response commands", commands.len());
        Ok(commands)
    }

    pub async fn execute_command_on_agent(
        &mut self,
        agent_id: &str,
        command: &str,
        arguments: Option<Vec<String>>,
        custom: Option<bool>,
        alert: Option<Value>,
    ) -> Result<ActiveResponseResult, WazuhApiError> {
        debug!(%agent_id, %command, ?arguments, "Executing active response command on agent");

        let mut body = json!({
            "command": command,
            "agents_list": [agent_id]
        });

        if let Some(args) = arguments {
            body["arguments"] = json!(args);
        }

        if let Some(custom_flag) = custom {
            body["custom"] = json!(custom_flag);
        }

        if let Some(alert_data) = alert {
            body["alert"] = alert_data;
        }

        let response = self
            .api_client
            .make_request(Method::PUT, "/active-response", Some(body), None)
            .await?;

        let result = ActiveResponseResult {
            message: response
                .get("message")
                .and_then(|m| m.as_str())
                .unwrap_or("Command executed")
                .to_string(),
            error: response
                .get("error")
                .and_then(|e| e.as_str())
                .map(|s| s.to_string()),
            data: response.get("data").cloned(),
        };

        info!(%agent_id, %command, "Active response command executed");
        Ok(result)
    }

    pub async fn execute_command_on_agents(
        &mut self,
        agent_ids: &[String],
        command: &str,
        arguments: Option<Vec<String>>,
        custom: Option<bool>,
        alert: Option<Value>,
    ) -> Result<ActiveResponseResult, WazuhApiError> {
        debug!(?agent_ids, %command, ?arguments, "Executing active response command on multiple agents");

        let mut body = json!({
            "command": command,
            "agents_list": agent_ids
        });

        if let Some(args) = arguments {
            body["arguments"] = json!(args);
        }

        if let Some(custom_flag) = custom {
            body["custom"] = json!(custom_flag);
        }

        if let Some(alert_data) = alert {
            body["alert"] = alert_data;
        }

        let response = self
            .api_client
            .make_request(Method::PUT, "/active-response", Some(body), None)
            .await?;

        let result = ActiveResponseResult {
            message: response
                .get("message")
                .and_then(|m| m.as_str())
                .unwrap_or("Command executed")
                .to_string(),
            error: response
                .get("error")
                .and_then(|e| e.as_str())
                .map(|s| s.to_string()),
            data: response.get("data").cloned(),
        };

        info!(
            "Active response command executed on {} agents",
            agent_ids.len()
        );
        Ok(result)
    }

    pub async fn block_ip(
        &mut self,
        agent_id: &str,
        ip_address: &str,
        timeout: Option<u32>,
    ) -> Result<ActiveResponseResult, WazuhApiError> {
        debug!(%agent_id, %ip_address, ?timeout, "Blocking IP address");

        let mut arguments = vec![ip_address.to_string()];
        if let Some(timeout_val) = timeout {
            arguments.push(timeout_val.to_string());
        }

        self.execute_command_on_agent(agent_id, "firewall-drop", Some(arguments), Some(true), None)
            .await
    }

    pub async fn unblock_ip(
        &mut self,
        agent_id: &str,
        ip_address: &str,
    ) -> Result<ActiveResponseResult, WazuhApiError> {
        debug!(%agent_id, %ip_address, "Unblocking IP address");

        let arguments = vec![ip_address.to_string()];

        self.execute_command_on_agent(agent_id, "firewall-drop", Some(arguments), Some(true), None)
            .await
    }

    pub async fn isolate_host(
        &mut self,
        agent_id: &str,
        interface: Option<&str>,
    ) -> Result<ActiveResponseResult, WazuhApiError> {
        debug!(%agent_id, ?interface, "Isolating host");

        let arguments = if let Some(iface) = interface {
            vec![iface.to_string()]
        } else {
            vec!["eth0".to_string()] // Default interface
        };

        self.execute_command_on_agent(
            agent_id,
            "host-isolate", // Changed command name to be more appropriate
            Some(arguments),
            Some(true),
            None,
        )
        .await
    }

    pub async fn kill_process(
        &mut self,
        agent_id: &str,
        pid: u32,
    ) -> Result<ActiveResponseResult, WazuhApiError> {
        debug!(%agent_id, %pid, "Killing process");

        let arguments = vec![pid.to_string()];

        self.execute_command_on_agent(agent_id, "kill", Some(arguments), Some(true), None)
            .await
    }

    pub async fn disable_user_account(
        &mut self,
        agent_id: &str,
        username: &str,
    ) -> Result<ActiveResponseResult, WazuhApiError> {
        debug!(%agent_id, %username, "Disabling user account");

        let arguments = vec![username.to_string()];

        self.execute_command_on_agent(
            agent_id,
            "disable-account",
            Some(arguments),
            Some(true),
            None,
        )
        .await
    }

    pub async fn execute_custom_script(
        &mut self,
        agent_id: &str,
        script_name: &str,
        script_arguments: Option<Vec<String>>,
    ) -> Result<ActiveResponseResult, WazuhApiError> {
        debug!(%agent_id, %script_name, ?script_arguments, "Executing custom script");

        let mut arguments = vec![script_name.to_string()];
        if let Some(script_args) = script_arguments {
            arguments.extend(script_args);
        }

        self.execute_command_on_agent(agent_id, "custom-script", Some(arguments), Some(true), None)
            .await
    }

    pub async fn execute_response_for_alert(
        &mut self,
        agent_id: &str,
        alert: Value,
        command: &str,
    ) -> Result<ActiveResponseResult, WazuhApiError> {
        debug!(%agent_id, %command, "Executing active response for alert");

        let mut arguments = Vec::new();

        if let Some(src_ip) = alert
            .get("data")
            .and_then(|d| d.get("srcip"))
            .and_then(|ip| ip.as_str())
        {
            arguments.push(src_ip.to_string());
        }

        if let Some(user) = alert
            .get("data")
            .and_then(|d| d.get("srcuser"))
            .and_then(|u| u.as_str())
        {
            arguments.push(user.to_string());
        }

        self.execute_command_on_agent(
            agent_id,
            command,
            if arguments.is_empty() {
                None
            } else {
                Some(arguments)
            },
            Some(false), 
            Some(alert),
        )
        .await
    }

    pub async fn get_execution_history(
        &mut self,
        agent_id: Option<&str>,
        limit: Option<u32>,
    ) -> Result<Vec<Value>, WazuhApiError> {
        debug!(
            ?agent_id,
            ?limit,
            "Getting active response execution history"
        );

        let mut query_params = Vec::new();

        if let Some(agent) = agent_id {
            query_params.push(("agents_list", agent.to_string()));
        }
        if let Some(limit_val) = limit {
            query_params.push(("limit", limit_val.to_string()));
        }

        let query_params_ref: Vec<(&str, &str)> =
            query_params.iter().map(|(k, v)| (*k, v.as_str())).collect();

        let response = self
            .api_client
            .make_request(
                Method::GET,
                "/active-response/history",
                None,
                if query_params_ref.is_empty() {
                    None
                } else {
                    Some(&query_params_ref)
                },
            )
            .await?;

        let history_data = response
            .get("data")
            .and_then(|d| d.get("affected_items"))
            .and_then(|items| items.as_array())
            .ok_or_else(|| {
                WazuhApiError::ApiError(
                    "Missing 'data.affected_items' in active response history response".to_string(),
                )
            })?;

        info!(
            "Retrieved {} active response history entries",
            history_data.len()
        );
        Ok(history_data.clone())
    }

    pub async fn validate_command(
        &mut self,
        command: &str,
        arguments: Option<&[String]>,
    ) -> Result<bool, WazuhApiError> {
        debug!(%command, ?arguments, "Validating active response command");

        let available_commands = self.get_active_response_commands().await?;

        let command_exists = available_commands.iter().any(|cmd| cmd.name == command);

        if !command_exists {
            warn!(%command, "Active response command not found");
            return Ok(false);
        }

        info!(%command, "Active response command validated successfully");
        Ok(true)
    }
}
