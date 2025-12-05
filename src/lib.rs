pub mod active_response;
pub mod agents;
pub mod client_factory;
pub mod cluster;
pub mod configuration;
pub mod error;
pub mod indexer_client;
pub mod logs;
pub mod rules;
pub mod vulnerability;
pub mod wazuh_client;

pub use active_response::{ActiveResponseClient, ActiveResponseCommand, ActiveResponseResult};
pub use agents::{
    Agent, AgentAddBody, AgentConfigurationSummary, AgentConnectionSummary, AgentDisconnectedTime,
    AgentForceOptions, AgentIdKey, AgentInsertBody, AgentKey, AgentOs, AgentSummary, AgentsClient,
};
pub use client_factory::{ConnectivityStatus, WazuhClientFactory, WazuhClients};
pub use cluster::{ClusterClient, ClusterNode, ClusterStatus, ManagerInfo, ManagerStatus};
pub use configuration::{
    AgentConfiguration, ConfigurationClient, GroupConfiguration, ManagerConfiguration,
};

pub use error::WazuhApiError;
pub type Result<T> = std::result::Result<T, WazuhApiError>;

pub use indexer_client::WazuhIndexerClient;
pub use logs::{AnalysisdStats, LogCollectorStats, LogEntry, LogsClient, RemotedStats};
pub use rules::{
    Decoder, DecoderDetails, DecoderPatternDetail, InfoDetail, PatternDetail, Rule, RuleDetails,
    RulesClient,
};
pub use vulnerability::{
    Package, Port, PortInfo, Process, Vulnerability, VulnerabilityClient, VulnerabilitySeverity,
};
pub use wazuh_client::WazuhApiClient;

pub use serde_json::Value as JsonValue;
