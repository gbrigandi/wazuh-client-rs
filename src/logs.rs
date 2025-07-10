use reqwest::Method;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tracing::{debug, info};

use super::error::WazuhApiError;
use super::wazuh_client::WazuhApiClient;

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct LogEntry {
    pub timestamp: String,
    pub tag: String,
    pub level: String,
    pub description: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct LogCollectorStats {
    pub global: LogCollectorPeriod,
    pub interval: LogCollectorPeriod,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct LogCollectorPeriod {
    pub start: String,
    pub end: String,
    pub files: Vec<LogFile>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct LogFile {
    pub location: String,
    pub events: u64,
    pub bytes: u64,
    pub targets: Vec<LogTarget>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct LogTarget {
    pub name: String,
    pub drops: u64,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AnalysisdStats {
    pub total_events_decoded: u64,
    pub syscheck_events_decoded: u64,
    pub syscheck_edps: f64,
    pub syscollector_events_decoded: u64,
    pub syscollector_edps: f64,
    pub rootcheck_events_decoded: u64,
    pub rootcheck_edps: f64,
    pub sca_events_decoded: u64,
    pub sca_edps: f64,
    pub hostinfo_events_decoded: u64,
    pub hostinfo_edps: f64,
    pub winevt_events_decoded: u64,
    pub winevt_edps: f64,
    pub other_events_decoded: u64,
    pub other_edps: f64,
    pub events_processed: u64,
    pub events_edps: f64,
    pub events_received: u64,
    pub events_dropped: u64,
    pub alerts_written: u64,
    pub firewall_written: u64,
    pub fts_written: u64,
    pub syscheck_queue_usage: f64,
    pub syscheck_queue_size: u64,
    pub syscollector_queue_usage: f64,
    pub syscollector_queue_size: u64,
    pub rootcheck_queue_usage: f64,
    pub rootcheck_queue_size: u64,
    pub sca_queue_usage: f64,
    pub sca_queue_size: u64,
    pub hostinfo_queue_usage: f64,
    pub hostinfo_queue_size: u64,
    pub winevt_queue_usage: f64,
    pub winevt_queue_size: u64,
    pub dbsync_queue_usage: f64,
    pub dbsync_queue_size: u64,
    pub upgrade_queue_usage: f64,
    pub upgrade_queue_size: u64,
    pub event_queue_usage: f64,
    pub event_queue_size: u64,
    pub rule_matching_queue_usage: f64,
    pub rule_matching_queue_size: u64,
    pub alerts_queue_usage: f64,
    pub alerts_queue_size: u64,
    pub firewall_queue_usage: f64,
    pub firewall_queue_size: u64,
    pub statistical_queue_usage: f64,
    pub statistical_queue_size: u64,
    pub archives_queue_usage: f64,
    pub archives_queue_size: u64,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RemotedStats {
    pub queue_size: f64,
    pub total_queue_size: f64,
    pub tcp_sessions: f64,
    pub ctrl_msg_count: f64,
    pub discarded_count: f64,
    pub sent_bytes: f64,
    pub recv_bytes: f64,
    pub dequeued_after_close: f64,
}

#[derive(Debug, Clone)]
pub struct LogsClient {
    api_client: WazuhApiClient,
}

impl LogsClient {
    pub fn new(api_client: WazuhApiClient) -> Self {
        Self { api_client }
    }

    pub async fn get_manager_logs(
        &mut self,
        limit: Option<u32>,
        offset: Option<u32>,
        level: Option<&str>,
        tag: Option<&str>,
        search: Option<&str>,
    ) -> Result<Vec<LogEntry>, WazuhApiError> {
        debug!(?level, ?tag, ?search, "Getting manager logs");

        let mut query_params = Vec::new();

        if let Some(limit) = limit {
            query_params.push(("limit", limit.to_string()));
        }
        if let Some(offset) = offset {
            query_params.push(("offset", offset.to_string()));
        }
        if let Some(level) = level {
            query_params.push(("level", level.to_string()));
        }
        if let Some(tag) = tag {
            query_params.push(("tag", tag.to_string()));
        }
        if let Some(search) = search {
            query_params.push(("search", search.to_string()));
        }

        let query_params_ref: Vec<(&str, &str)> =
            query_params.iter().map(|(k, v)| (*k, v.as_str())).collect();

        let response = self
            .api_client
            .make_request(
                Method::GET,
                "/manager/logs",
                None,
                if query_params_ref.is_empty() {
                    None
                } else {
                    Some(&query_params_ref)
                },
            )
            .await?;

        let logs_data = response
            .get("data")
            .and_then(|d| d.get("affected_items"))
            .ok_or_else(|| {
                WazuhApiError::ApiError(
                    "Missing 'data.affected_items' in manager logs response".to_string(),
                )
            })?;

        let logs: Vec<LogEntry> = serde_json::from_value(logs_data.clone())?;
        info!("Retrieved {} manager log entries", logs.len());
        Ok(logs)
    }

    pub async fn get_error_logs(
        &mut self,
        limit: Option<u32>,
    ) -> Result<Vec<LogEntry>, WazuhApiError> {
        debug!("Getting error logs");
        self.get_manager_logs(limit, None, Some("error"), None, None)
            .await
    }

    pub async fn get_warning_logs(
        &mut self,
        limit: Option<u32>,
    ) -> Result<Vec<LogEntry>, WazuhApiError> {
        debug!("Getting warning logs");
        self.get_manager_logs(limit, None, Some("warning"), None, None)
            .await
    }

    pub async fn get_critical_logs(
        &mut self,
        limit: Option<u32>,
    ) -> Result<Vec<LogEntry>, WazuhApiError> {
        debug!("Getting critical logs");
        self.get_manager_logs(limit, None, Some("critical"), None, None)
            .await
    }

    pub async fn get_logs_by_tag(
        &mut self,
        tag: &str,
        limit: Option<u32>,
    ) -> Result<Vec<LogEntry>, WazuhApiError> {
        debug!(%tag, "Getting logs by tag");
        self.get_manager_logs(limit, None, None, Some(tag), None)
            .await
    }

    pub async fn search_logs(
        &mut self,
        search_term: &str,
        limit: Option<u32>,
    ) -> Result<Vec<LogEntry>, WazuhApiError> {
        debug!(%search_term, "Searching logs");
        self.get_manager_logs(limit, None, None, None, Some(search_term))
            .await
    }

    pub async fn get_logcollector_stats(
        &mut self,
        agent_id: &str,
    ) -> Result<LogCollectorStats, WazuhApiError> {
        debug!(%agent_id, "Getting log collector statistics");

        let endpoint = format!("/agents/{}/stats/logcollector", agent_id);
        let response = self
            .api_client
            .make_request(Method::GET, &endpoint, None, None)
            .await?;

        let stats_data = response
            .get("data")
            .and_then(|d| d.get("affected_items"))
            .and_then(|items| items.as_array())
            .and_then(|arr| arr.first())
            .ok_or_else(|| {
                WazuhApiError::ApiError(format!(
                    "Log collector stats for agent {} not found",
                    agent_id
                ))
            })?;

        let stats: LogCollectorStats = serde_json::from_value(stats_data.clone())?;

        info!(%agent_id, "Retrieved log collector statistics");
        Ok(stats)
    }

    pub async fn get_analysisd_stats(&mut self) -> Result<AnalysisdStats, WazuhApiError> {
        debug!("Getting analysis daemon statistics");

        let response = self
            .api_client
            .make_request(Method::GET, "/manager/stats/analysisd", None, None)
            .await?;

        let stats_data = response
            .get("data")
            .and_then(|d| d.get("affected_items"))
            .and_then(|items| items.as_array())
            .and_then(|arr| arr.first())
            .ok_or_else(|| {
                WazuhApiError::ApiError("Analysis daemon statistics not found".to_string())
            })?;

        let stats: AnalysisdStats = serde_json::from_value(stats_data.clone())?;
        info!("Retrieved analysis daemon statistics");
        Ok(stats)
    }

    pub async fn get_remoted_stats(&mut self) -> Result<RemotedStats, WazuhApiError> {
        debug!("Getting remote daemon statistics");

        let response = self
            .api_client
            .make_request(Method::GET, "/manager/stats/remoted", None, None)
            .await?;

        let stats_data = response
            .get("data")
            .and_then(|d| d.get("affected_items"))
            .and_then(|items| items.as_array())
            .and_then(|arr| arr.first())
            .ok_or_else(|| {
                WazuhApiError::ApiError("Remote daemon statistics not found".to_string())
            })?;

        let stats: RemotedStats = serde_json::from_value(stats_data.clone())?;
        info!("Retrieved remote daemon statistics");
        Ok(stats)
    }

    pub async fn get_hourly_stats(&mut self) -> Result<Value, WazuhApiError> {
        debug!("Getting hourly statistics");

        let response = self
            .api_client
            .make_request(Method::GET, "/manager/stats/hourly", None, None)
            .await?;

        info!("Retrieved hourly statistics");
        Ok(response)
    }

    pub async fn get_weekly_stats(&mut self) -> Result<Value, WazuhApiError> {
        debug!("Getting weekly statistics");

        let response = self
            .api_client
            .make_request(Method::GET, "/manager/stats/weekly", None, None)
            .await?;

        info!("Retrieved weekly statistics");
        Ok(response)
    }

    pub async fn get_logs_summary(&mut self) -> Result<Value, WazuhApiError> {
        debug!("Getting logs summary");

        let response = self
            .api_client
            .make_request(Method::GET, "/manager/logs/summary", None, None)
            .await?;

        info!("Retrieved logs summary");
        Ok(response)
    }

    pub async fn get_recent_errors(
        &mut self,
        limit: Option<u32>,
    ) -> Result<Vec<LogEntry>, WazuhApiError> {
        debug!("Getting recent error logs");
        self.get_error_logs(limit).await
    }

    pub async fn get_recent_warnings(
        &mut self,
        limit: Option<u32>,
    ) -> Result<Vec<LogEntry>, WazuhApiError> {
        debug!("Getting recent warning logs");
        self.get_warning_logs(limit).await
    }

    pub async fn get_performance_metrics(&mut self) -> Result<Value, WazuhApiError> {
        debug!("Getting performance metrics");

        let analysisd_stats = self.get_analysisd_stats().await?;
        let remoted_stats = self.get_remoted_stats().await?;

        let metrics = serde_json::json!({
            "analysisd": {
                "events_per_second": analysisd_stats.events_edps,
                "total_events_processed": analysisd_stats.events_processed,
                "events_dropped": analysisd_stats.events_dropped,
                "alerts_written": analysisd_stats.alerts_written,
                "queue_usage": {
                    "event_queue": analysisd_stats.event_queue_usage,
                    "alerts_queue": analysisd_stats.alerts_queue_usage,
                    "rule_matching_queue": analysisd_stats.rule_matching_queue_usage
                }
            },
            "remoted": {
                "tcp_sessions": remoted_stats.tcp_sessions,
                "bytes_sent": remoted_stats.sent_bytes,
                "bytes_received": remoted_stats.recv_bytes,
                "discarded_count": remoted_stats.discarded_count
            }
        });

        info!("Retrieved performance metrics");
        Ok(metrics)
    }

    pub async fn monitor_agent_ingestion(
        &mut self,
        agent_id: &str,
    ) -> Result<Value, WazuhApiError> {
        debug!(%agent_id, "Monitoring agent log ingestion");

        let logcollector_stats = self.get_logcollector_stats(agent_id).await?;

        let total_events: u64 = logcollector_stats.global.files.iter().map(|f| f.events).sum();
        let total_bytes: u64 = logcollector_stats.global.files.iter().map(|f| f.bytes).sum();
        let total_drops: u64 = logcollector_stats.global.files.iter()
            .flat_map(|f| &f.targets)
            .map(|t| t.drops)
            .sum();

        let ingestion_info = serde_json::json!({
            "agent_id": agent_id,
            "total_events": total_events,
            "events_dropped": total_drops,
            "bytes_processed": total_bytes,
            "drop_rate": if total_events > 0 {
                (total_drops as f64 / total_events as f64) * 100.0
            } else {
                0.0
            },
            "global_period": {
                "start": logcollector_stats.global.start,
                "end": logcollector_stats.global.end,
                "files": logcollector_stats.global.files
            },
            "interval_period": {
                "start": logcollector_stats.interval.start,
                "end": logcollector_stats.interval.end,
                "files": logcollector_stats.interval.files
            }
        });

        info!(%agent_id, "Retrieved agent ingestion monitoring data");
        Ok(ingestion_info)
    }
}
