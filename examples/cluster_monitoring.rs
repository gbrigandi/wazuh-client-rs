//! Cluster monitoring example for the Wazuh Rust client
//!
//! This example demonstrates:
//! - Cluster health monitoring and diagnostics
//! - Node management and status tracking
//! - Manager information and statistics
//! - Cluster configuration analysis
//! - Performance monitoring

use std::env;
use tracing::{error, trace, warn};
use wazuh_client::WazuhClientFactory;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();
    trace!("Starting example execution");

    println!("🔗 Wazuh Rust Client - Cluster Monitoring Example");
    println!("=================================================");

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

    let mut cluster_client = factory.create_cluster_client();

    println!("\n🏢 Manager Information");
    println!("======================");

    match cluster_client.get_manager_info().await {
        Ok(manager_info) => {
            println!("📋 Manager Details:");
            println!("   Version: {}", manager_info.version);
            println!(
                "   Revision: {}",
                manager_info.revision.as_deref().unwrap_or("N/A")
            );
            println!(
                "   License Version: {}",
                manager_info.license_version.as_deref().unwrap_or("N/A")
            );
            println!(
                "   Installation Date: {}",
                manager_info.installation_date.as_deref().unwrap_or("N/A")
            );
            println!(
                "   OpenSSL Version: {}",
                manager_info.openssl_version.as_deref().unwrap_or("N/A")
            );
            println!("   Max Agents: {}", manager_info.max_agents);
            println!(
                "   Node Name: {}",
                manager_info.node_name.as_deref().unwrap_or("N/A")
            );
            println!("   Node Type: {}", manager_info.node_type);

            if let Some(cluster_name) = &manager_info.cluster_name {
                println!("   Cluster Name: {}", cluster_name);
            } else {
                println!("   Cluster: Not configured (single node)");
            }

            println!("\n📁 Paths:");
            println!("   Installation Path: {}", manager_info.path);
            println!(
                "   Home Path: {}",
                manager_info.home_path.as_deref().unwrap_or("N/A")
            );
            println!(
                "   Share Path: {}",
                manager_info.share_path.as_deref().unwrap_or("N/A")
            );
            println!(
                "   License Path: {}",
                manager_info.license_path.as_deref().unwrap_or("N/A")
            );
        }
        Err(e) => {
            error!("❌ Failed to get manager information: {}", e);
            return Err(e.into());
        }
    }

    println!("\n📊 Manager Status");
    println!("=================");

    match cluster_client.get_manager_status().await {
        Ok(status) => {
            println!("✅ Manager is running");
            println!("   Wazuh Version: {}", status.wazuh_version);
            println!("   OpenSSL Version: {}", status.openssl_version);
            println!("   Compilation Date: {}", status.compilation_date);
            println!("   Version: {}", status.version);
        }
        Err(e) => {
            error!("❌ Manager status check failed: {}", e);
        }
    }

    println!("\n🔗 Cluster Status");
    println!("=================");

    match cluster_client.get_cluster_status().await {
        Ok(cluster_status) => {
            println!("📈 Cluster Configuration:");
            println!("   Enabled: {}", cluster_status.enabled);
            println!("   Running: {}", cluster_status.running);

            if cluster_status.enabled == "yes" {
                println!("\n✅ Cluster is enabled and operational");

                // Get cluster configuration details
                match cluster_client.get_cluster_configuration().await {
                    Ok(config) => {
                        println!("\n⚙️  Cluster Configuration:");
                        println!("   Configuration: {:?}", config);
                    }
                    Err(e) => warn!("Failed to get cluster configuration: {}", e),
                }
            } else {
                println!("\nℹ️  Single node deployment (cluster disabled)");
            }
        }
        Err(e) => {
            warn!("Cluster status not available: {}", e);
            println!("ℹ️  This appears to be a single-node Wazuh deployment");
        }
    }
    println!("\n🏥 Cluster Health Check");
    println!("=======================");

    match cluster_client.get_cluster_healthcheck().await {
        Ok(health) => {
            println!("✅ Cluster health check successful");
            println!("   Connected Nodes: {}", health.n_connected_nodes);
            println!("   Node Details:");

            for node_health in &health.nodes {
                println!("   🔹 Node: {}", node_health.info.name);
                println!("      Type: {}", node_health.info.node_type);
                println!("      Version: {}", node_health.info.version);
                println!("      IP: {}", node_health.info.ip);
                let last_keep_alive = if node_health.status.last_keep_alive.starts_with("9999-") {
                    "Never"
                } else {
                    &node_health.status.last_keep_alive
                };
                println!("      Last Keep Alive: {}", last_keep_alive);
                println!("      Sync Status:");
                println!(
                    "        - Integrity Free: {}",
                    node_health.status.sync_integrity_free
                );
                println!(
                    "        - Agent Info Free: {}",
                    node_health.status.sync_agent_info_free
                );
                println!(
                    "        - Extra Valid Free: {}",
                    node_health.status.sync_extravalid_free
                );
            }
        }
        Err(e) => {
            let error_msg = e.to_string();
            if error_msg.contains("Cluster is not running") || error_msg.contains("error\": 3013") {
                println!("ℹ️  Cluster is not running (single-node deployment)");
                println!("   This is normal for standalone Wazuh installations");
                println!("   💡 To enable clustering, configure it in ossec.conf");
                println!("   📖 Documentation: https://documentation.wazuh.com/4.12/user-manual/configuring-cluster/index.html");
            } else {
                warn!("Cluster health check failed: {}", e);
            }
        }
    }

    println!("\n🖥️  Cluster Nodes");
    println!("=================");

    match cluster_client.get_cluster_nodes(None, None, None).await {
        Ok(nodes) => {
            if nodes.is_empty() {
                println!("ℹ️  No cluster nodes found (single node deployment)");
            } else {
                println!("Found {} cluster nodes:", nodes.len());

                for node in &nodes {
                    println!("   🔹 Node: {}", node.name);
                    println!("      Type: {}", node.node_type);
                    println!("      Version: {}", node.version);
                    println!("      IP: {}", node.ip);
                    println!("      Status: {}", node.status);
                }

                match cluster_client.get_master_nodes().await {
                    Ok(master_nodes) => {
                        println!("\n👑 Master Nodes: {}", master_nodes.len());
                        for master in &master_nodes {
                            println!("   • {} ({})", master.name, master.ip);
                        }
                    }
                    Err(e) => warn!("Failed to get master nodes: {}", e),
                }

                match cluster_client.get_worker_nodes().await {
                    Ok(worker_nodes) => {
                        println!("\n👷 Worker Nodes: {}", worker_nodes.len());
                        for worker in &worker_nodes {
                            println!("   • {} ({})", worker.name, worker.ip);
                        }
                    }
                    Err(e) => warn!("Failed to get worker nodes: {}", e),
                }
            }
        }
        Err(e) => {
            let error_msg = e.to_string();
            if error_msg.contains("Cluster is not running") || error_msg.contains("error\": 3013") {
                println!("ℹ️  Cluster is not running (single-node deployment)");
                println!("   This is normal for standalone Wazuh installations");
                println!("   💡 To enable clustering, configure it in ossec.conf");
                println!("   📖 Documentation: https://documentation.wazuh.com/4.12/user-manual/configuring-cluster/index.html");
            } else {
                warn!("Failed to get cluster nodes: {}", e);
            }
        }
    }

    println!("\n🏠 Local Node Information");
    println!("=========================");

    match cluster_client.get_local_node_info().await {
        Ok(local_info) => {
            println!("📍 Local Node Details:");
            println!("   Information: {:?}", local_info);
        }
        Err(e) => {
            let error_msg = e.to_string();
            if error_msg.contains("Cluster is not running") || error_msg.contains("error\": 3013") {
                println!("ℹ️  Local node information not available (cluster disabled)");
                println!("   This is normal for standalone Wazuh installations");
                println!("   💡 To enable clustering, configure it in ossec.conf");
                println!("   📖 Documentation: https://documentation.wazuh.com/4.12/user-manual/configuring-cluster/index.html");
            } else {
                warn!("Failed to get local node info: {}", e);
            }
        }
    }

    println!("\n📊 Cluster Statistics");
    println!("\n🎯 Overall Health Assessment");
    println!("============================");

    match cluster_client.is_cluster_healthy().await {
        Ok(is_healthy) => {
            if is_healthy {
                println!("✅ Cluster is healthy and operating normally");
            } else {
                println!("⚠️  Cluster health issues detected");
            }
        }
        Err(e) => {
            let error_msg = e.to_string();
            if error_msg.contains("Cluster is not running") || error_msg.contains("error\": 3013") {
                println!("ℹ️  Single-node deployment detected (cluster disabled)");
                println!("   This is a normal configuration for standalone installations");
            } else {
                warn!("Failed to assess cluster health: {}", e);
            }
        }
    }
    match cluster_client.is_cluster_healthy().await {
        Ok(is_healthy) => {
            if is_healthy {
                println!("✅ Cluster is healthy and operating normally");
            } else {
                println!("⚠️  Cluster health issues detected");
            }
        }
        Err(e) => {
            warn!("Failed to assess cluster health: {}", e);
        }
    }

    println!("\n📝 Manager Logs Summary");
    println!("=======================");

    match cluster_client.get_manager_logs_summary().await {
        Ok(logs_summary) => {
            println!("📋 Recent Log Activity by Component:");

            if let Some(data) = logs_summary.as_object() {
                if let Some(data_obj) = data.get("data").and_then(|d| d.as_object()) {
                    if let Some(affected_items) =
                        data_obj.get("affected_items").and_then(|a| a.as_array())
                    {
                        let mut total_logs = 0;
                        let mut total_errors = 0;
                        let mut total_warnings = 0;

                        for item in affected_items {
                            if let Some(item_obj) = item.as_object() {
                                for (component, stats) in item_obj {
                                    if let Some(stats_obj) = stats.as_object() {
                                        let all = stats_obj
                                            .get("all")
                                            .and_then(|v| v.as_u64())
                                            .unwrap_or(0);
                                        let critical = stats_obj
                                            .get("critical")
                                            .and_then(|v| v.as_u64())
                                            .unwrap_or(0);
                                        let error = stats_obj
                                            .get("error")
                                            .and_then(|v| v.as_u64())
                                            .unwrap_or(0);
                                        let warning = stats_obj
                                            .get("warning")
                                            .and_then(|v| v.as_u64())
                                            .unwrap_or(0);
                                        let info = stats_obj
                                            .get("info")
                                            .and_then(|v| v.as_u64())
                                            .unwrap_or(0);
                                        let debug = stats_obj
                                            .get("debug")
                                            .and_then(|v| v.as_u64())
                                            .unwrap_or(0);

                                        total_logs += all;
                                        total_errors += critical + error;
                                        total_warnings += warning;

                                        println!("   🔹 {}: {} total logs", component, all);
                                        if critical > 0 || error > 0 || warning > 0 {
                                            println!(
                                                "      ⚠️  Critical: {}, Errors: {}, Warnings: {}",
                                                critical, error, warning
                                            );
                                        }
                                        if info > 0 || debug > 0 {
                                            println!("      ℹ️  Info: {}, Debug: {}", info, debug);
                                        }
                                        println!();
                                    }
                                }
                            }
                        }

                        println!("📊 Overall Summary:");
                        println!("   Total Log Entries: {}", total_logs);
                        if total_errors > 0 {
                            println!("   ⚠️  Total Errors/Critical: {}", total_errors);
                        }
                        if total_warnings > 0 {
                            println!("   ⚠️  Total Warnings: {}", total_warnings);
                        }
                        if total_errors == 0 && total_warnings == 0 {
                            println!("   ✅ No errors or warnings detected");
                        }
                    }
                }
            }
        }
        Err(e) => {
            warn!("Failed to get manager logs summary: {}", e);
        }
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
