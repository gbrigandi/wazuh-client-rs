//! Agent management example for the Wazuh Rust client
//!
//! This example demonstrates:
//! - Comprehensive agent lifecycle management
//! - Agent registration and configuration
//! - Agent monitoring and health checks
//! - Group management and policy assignment
//! - Agent maintenance operations

use std::env;
use tracing::{error, trace, warn};
use wazuh_client::WazuhClientFactory;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    trace!("Starting example execution");

    println!("🤖 Wazuh Rust Client - Agent Management Example");
    println!("===============================================");

    let factory = create_client_factory();

    trace!("Testing connectivity");
    println!("🔍 Testing connectivity...");
    let connectivity = factory.test_connectivity().await?;
    if !connectivity.api_connected {
        error!(
            "❌ Cannot connect to Wazuh API: {}",
            connectivity.api_error.as_deref().unwrap_or("Unknown error")
        );
        return Err("API connectivity failed".into());
    }
    println!("✅ Connected to Wazuh API");

    let mut agents_client = factory.create_agents_client();

    println!("\n📊 Agent Overview");
    println!("==================");

    let summary = agents_client.get_agents_summary().await?;
    println!("📈 Agent Statistics:");
    println!("   Total Agents: {}", summary.connection.total);
    println!(
        "   Active: {} ({:.1}%)",
        summary.connection.active,
        (summary.connection.active as f64 / summary.connection.total as f64) * 100.0
    );
    println!(
        "   Disconnected: {} ({:.1}%)",
        summary.connection.disconnected,
        (summary.connection.disconnected as f64 / summary.connection.total as f64) * 100.0
    );
    println!("   Never Connected: {}", summary.connection.never_connected);
    println!("   Pending: {}", summary.connection.pending);

    println!("\n⚙️  Configuration Status:");
    println!(
        "   Synced: {} ({:.1}%)",
        summary.configuration.synced,
        (summary.configuration.synced as f64 / summary.configuration.total as f64) * 100.0
    );
    println!("   Not Synced: {}", summary.configuration.not_synced);

    println!("\n👥 Agent Inventory");
    println!("==================");

    let agents = agents_client
        .get_agents(
            Some(20),                                                                 // limit
            None,                                                                     // offset
            Some("id,name,ip,status,os.name,os.version,version,lastKeepAlive,group"), // select
            Some("status,name"),                                                      // sort
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
        .await?;

    if agents.is_empty() {
        println!("No agents found in the system");
    } else {
        println!("Found {} agents:", agents.len());
        for agent in &agents {
            let os_info = agent
                .os
                .as_ref()
                .map(|os| {
                    format!(
                        "{} {}",
                        os.name.as_deref().unwrap_or("Unknown"),
                        os.version.as_deref().unwrap_or("")
                    )
                })
                .unwrap_or_else(|| "Unknown OS".to_string());

            let groups = agent
                .group
                .as_ref()
                .map(|g| g.join(", "))
                .unwrap_or_else(|| "default".to_string());

            println!(
                "   🔹 Agent {}: {} ({})",
                agent.id, agent.name, agent.status
            );
            println!(
                "      IP: {} | OS: {} | Version: {}",
                agent.ip.as_deref().unwrap_or("N/A"),
                os_info,
                agent.version.as_deref().unwrap_or("N/A")
            );
            let last_seen = agent
                .last_keep_alive
                .as_deref()
                .filter(|date| !date.starts_with("9999-"))
                .unwrap_or("Never");
            println!("      Groups: {} | Last Seen: {}", groups, last_seen);
        }
    }

    println!("\n🔍 Agent State Analysis");
    println!("========================");

    match agents_client.get_active_agents().await {
        Ok(active_agents) => {
            println!("✅ Active Agents: {}", active_agents.len());
            for agent in active_agents.iter().take(3) {
                let last_seen = agent
                    .last_keep_alive
                    .as_deref()
                    .filter(|date| !date.starts_with("9999-"))
                    .unwrap_or("Never");
                println!(
                    "   • {} ({}) - Last seen: {}",
                    agent.name,
                    agent.ip.as_deref().unwrap_or("N/A"),
                    last_seen
                );
            }
        }
        Err(e) => warn!("Failed to get active agents: {}", e),
    }

    match agents_client.get_disconnected_agents().await {
        Ok(disconnected_agents) => {
            println!("\n⚠️  Disconnected Agents: {}", disconnected_agents.len());
            for agent in disconnected_agents.iter().take(3) {
                let last_seen = agent
                    .last_keep_alive
                    .as_deref()
                    .filter(|date| !date.starts_with("9999-"))
                    .unwrap_or("Never");
                println!(
                    "   • {} ({}) - Last seen: {}",
                    agent.name,
                    agent.ip.as_deref().unwrap_or("N/A"),
                    last_seen
                );
            }
        }
        Err(e) => warn!("Failed to get disconnected agents: {}", e),
    }

    match agents_client.get_never_connected_agents().await {
        Ok(never_connected) => {
            if !never_connected.is_empty() {
                println!("\n❓ Never Connected Agents: {}", never_connected.len());
                for agent in never_connected.iter().take(3) {
                    println!("   • {} ({})", agent.name, agent.id);
                }
            }
        }
        Err(e) => warn!("Failed to get never connected agents: {}", e),
    }

    match agents_client.get_pending_agents().await {
        Ok(pending_agents) => {
            if !pending_agents.is_empty() {
                println!("\n⏳ Pending Agents: {}", pending_agents.len());
                for agent in pending_agents.iter().take(3) {
                    println!("   • {} ({})", agent.name, agent.id);
                }
            }
        }
        Err(e) => warn!("Failed to get pending agents: {}", e),
    }
    if !agents.is_empty() {
        println!("\n🔧 Agent Maintenance");
        println!("====================");

        // Get the first active agent (not the manager 000) for demonstration
        if let Some(agent) = agents
            .iter()
            .find(|a| a.status == "active" && a.id != "000")
        {
            println!(
                "🔍 Detailed information for agent: {} ({})",
                agent.name, agent.id
            );

            // Get detailed agent information
            match agents_client.get_agent(&agent.id).await {
                Ok(detailed_agent) => {
                    println!("   📋 Agent Details:");
                    println!(
                        "      Registration IP: {}",
                        detailed_agent.register_ip.as_deref().unwrap_or("N/A")
                    );
                    println!(
                        "      Config Sum: {}",
                        detailed_agent.config_sum.as_deref().unwrap_or("N/A")
                    );
                    println!(
                        "      Merged Sum: {}",
                        detailed_agent.merged_sum.as_deref().unwrap_or("N/A")
                    );
                    println!(
                        "      Date Added: {}",
                        detailed_agent.date_add.as_deref().unwrap_or("N/A")
                    );
                    if let Some(os) = &detailed_agent.os {
                        println!(
                            "      OS Details: {} {} ({})",
                            os.name.as_deref().unwrap_or("Unknown"),
                            os.version.as_deref().unwrap_or(""),
                            os.arch.as_deref().unwrap_or("Unknown arch")
                        );
                    }
                }
                Err(e) => warn!("Failed to get detailed agent info: {}", e),
            }

            // Get agent key
            match agents_client.get_agent_key(&agent.id).await {
                Ok(key_info) => {
                    println!("   🔑 Agent Key: Available (ID: {})", key_info.id);
                }
                Err(e) => warn!("Failed to get agent key: {}", e),
            }

            // Check group sync status
            match agents_client.get_agent_group_sync_status(&agent.id).await {
                Ok(sync_status) => {
                    println!("   🔄 Group Sync Status: {:?}", sync_status);
                }
                Err(e) => warn!("Failed to get group sync status: {}", e),
            }
        }
    }

    println!("\n👥 Group Management");
    println!("===================");

    match agents_client.get_agents_no_group().await {
        Ok(no_group_agents) => {
            if !no_group_agents.is_empty() {
                println!("📋 Agents without groups: {}", no_group_agents.len());
                for agent in no_group_agents.iter().take(3) {
                    println!("   • {} ({})", agent.name, agent.id);
                }
            } else {
                println!("✅ All agents are assigned to groups");
            }
        }
        Err(e) => warn!("Failed to get agents without groups: {}", e),
    }

    println!("\n🔄 Update Status");
    println!("================");

    match agents_client.get_outdated_agents().await {
        Ok(outdated_agents) => {
            if !outdated_agents.is_empty() {
                println!("⚠️  Outdated agents found: {}", outdated_agents.len());
                for agent in outdated_agents.iter().take(5) {
                    println!(
                        "   • {} ({}) - Version: {}",
                        agent.name,
                        agent.id,
                        agent.version.as_deref().unwrap_or("Unknown")
                    );
                }
                println!("\n💡 Consider upgrading these agents for latest security updates");
            } else {
                println!("✅ All agents are up to date");
            }
        }
        Err(e) => warn!("Failed to get outdated agents: {}", e),
    }

    Ok(())
}

fn create_client_factory() -> WazuhClientFactory {
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

    WazuhClientFactory::builder()
        .api_host(api_host)
        .api_port(api_port)
        .api_credentials(api_username, api_password)
        .indexer_host(indexer_host)
        .indexer_port(indexer_port)
        .indexer_credentials(indexer_username, indexer_password)
        .verify_ssl(verify_ssl)
        .protocol("https")
        .build()
}
