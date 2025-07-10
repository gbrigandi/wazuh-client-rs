//! Basic usage example for the Wazuh Rust client
//!
//! This example demonstrates:
//! - Setting up the client factory with configuration
//! - Basic authentication and connectivity testing
//! - Getting system information
//! - Error handling

use std::env;
use tracing::{error, info, warn};
use wazuh_client::WazuhClientFactory;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    println!("🚀 Wazuh Rust Client - Basic Usage Example");
    println!("==========================================");

    // Load configuration from environment variables or use defaults
    let api_host = env::var("WAZUH_API_HOST").unwrap_or_else(|_| "localhost".to_string());
    let api_port: u16 = env::var("WAZUH_API_PORT")
        .unwrap_or_else(|_| "55000".to_string())
        .parse()
        .unwrap_or(55000);
    let api_username = env::var("WAZUH_API_USERNAME").unwrap_or_else(|_| "wazuh".to_string());
    let api_password = env::var("WAZUH_API_PASSWORD").unwrap_or_else(|_| "wazuh".to_string());

    let indexer_host = env::var("WAZUH_INDEXER_HOST").unwrap_or_else(|_| "localhost".to_string());
    let indexer_port: u16 = env::var("WAZUH_INDEXER_PORT")
        .unwrap_or_else(|_| "9200".to_string())
        .parse()
        .unwrap_or(9200);
    let indexer_username =
        env::var("WAZUH_INDEXER_USERNAME").unwrap_or_else(|_| "admin".to_string());
    let indexer_password =
        env::var("WAZUH_INDEXER_PASSWORD").unwrap_or_else(|_| "admin".to_string());

    let verify_ssl = env::var("WAZUH_VERIFY_SSL")
        .unwrap_or_else(|_| "false".to_string())
        .parse()
        .unwrap_or(false);

    println!(
        "📡 Connecting to Wazuh Manager at {}:{}",
        api_host, api_port
    );
    println!(
        "📊 Connecting to Wazuh Indexer at {}:{}",
        indexer_host, indexer_port
    );

    let factory = WazuhClientFactory::builder()
        .api_host(api_host)
        .api_port(api_port)
        .api_credentials(api_username, api_password)
        .indexer_host(indexer_host)
        .indexer_port(indexer_port)
        .indexer_credentials(indexer_username, indexer_password)
        .verify_ssl(verify_ssl)
        .protocol("https")
        .build();

    println!("\n🔍 Testing connectivity...");
    match factory.test_connectivity().await {
        Ok(status) => {
            println!("✅ Connectivity test results:");
            println!("   {}", status.get_status_summary());

            if !status.has_any_connection() {
                error!("❌ No services are accessible. Please check your configuration.");
                return Err("No connectivity".into());
            }
        }
        Err(e) => {
            error!("❌ Connectivity test failed: {}", e);
            return Err(e.into());
        }
    }

    let mut agents_client = factory.create_agents_client();
    let mut cluster_client = factory.create_cluster_client();
    let mut rules_client = factory.create_rules_client();

    println!("\n📊 System Information:");
    println!("----------------------");

    match cluster_client.get_manager_info().await {
        Ok(manager_info) => {
            println!("🏢 Manager Information:");
            println!("   Version: {}", manager_info.version);
            println!(
                "   Node Name: {}",
                manager_info.node_name.as_deref().unwrap_or("N/A")
            );
            println!("   Node Type: {}", manager_info.node_type);
            println!(
                "   Installation Date: {}",
                manager_info.installation_date.as_deref().unwrap_or("N/A")
            );
            if let Some(cluster_name) = &manager_info.cluster_name {
                println!("   Cluster Name: {}", cluster_name);
            }
        }
        Err(e) => {
            warn!("⚠️  Failed to get manager info: {}", e);
        }
    }

    match agents_client.get_agents_summary().await {
        Ok(summary) => {
            println!("\n👥 Agent Summary:");
            println!("   Total: {}", summary.connection.total);
            println!("   Active: {}", summary.connection.active);
            println!("   Disconnected: {}", summary.connection.disconnected);
            println!("   Never Connected: {}", summary.connection.never_connected);
            println!("   Pending: {}", summary.connection.pending);
            println!("   Configuration Synced: {}", summary.configuration.synced);
            println!(
                "   Configuration Not Synced: {}",
                summary.configuration.not_synced
            );
        }
        Err(e) => {
            warn!("⚠️  Failed to get agent summary: {}", e);
        }
    }

    match cluster_client.get_cluster_status().await {
        Ok(status) => {
            println!("\n🔗 Cluster Status:");
            println!("   Enabled: {}", status.enabled);
            println!("   Running: {}", status.running);
        }
        Err(e) => {
            info!(
                "ℹ️  Cluster information not available (single node setup): {}",
                e
            );
        }
    }

    println!("\n🤖 Recent Agents:");
    println!("-----------------");
    match agents_client
        .get_agents(
            Some(5),                                 // limit
            None,                                    // offset
            Some("id,name,ip,status,lastKeepAlive"), // select: changed last_keep_alive to lastKeepAlive
            Some("-lastKeepAlive"), // sort by last keep alive desc: changed last_keep_alive to lastKeepAlive
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
            None,
            None,
        )
        .await
    {
        Ok(agents) => {
            if agents.is_empty() {
                println!("   No agents found");
            } else {
                for agent in agents.iter().take(5) {
                    let last_seen = agent
                        .last_keep_alive
                        .as_deref()
                        .filter(|date| !date.starts_with("9999-"))
                        .unwrap_or("Never");
                    println!(
                        "   ID: {} | Name: {} | IP: {} | Status: {} | Last Seen: {}",
                        agent.id,
                        agent.name,
                        agent.ip.as_deref().unwrap_or("N/A"),
                        agent.status,
                        last_seen
                    );
                }
            }
        }
        Err(e) => {
            warn!("⚠️  Failed to get agents: {}", e);
        }
    }

    println!("\n📋 Rule Statistics:");
    println!("-------------------");
    match rules_client
        .get_rules(Some(1), None, None, None, None)
        .await
    {
        Ok(rules) => {
            println!("   Sample rules retrieved: {}", rules.len());
            if let Some(rule) = rules.first() {
                println!("   Example rule: ID {} - {}", rule.id, rule.description);
            }
        }
        Err(e) => {
            warn!("⚠️  Failed to get rules: {}", e);
        }
    }

    match rules_client.get_high_level_rules().await {
        Ok(high_rules) => {
            println!("   High-level rules: {}", high_rules.len());
        }
        Err(e) => {
            warn!("⚠️  Failed to get high-level rules: {}", e);
        }
    }

    Ok(())
}
