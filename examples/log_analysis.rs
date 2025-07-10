//! Log analysis example for the Wazuh Rust client
//!
//! This example demonstrates:
//! - Security log analysis and monitoring
//! - Log statistics and performance monitoring
//! - Manager log analysis and filtering
//! - Agent log collection statistics
//! - Performance metrics and optimization

use std::collections::HashMap;
use std::env;
use tracing::{error, trace, warn};
use wazuh_client::WazuhClientFactory;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    trace!("Starting example execution");

    println!("📊 Wazuh Rust Client - Log Analysis Example");
    println!("============================================");

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

    if !connectivity.indexer_connected {
        warn!(
            "⚠️  Cannot connect to Wazuh Indexer: {}",
            connectivity
                .indexer_error
                .as_deref()
                .unwrap_or("Unknown error")
        );
        println!("ℹ️  Some log analysis features will be limited without Indexer access");
    }

    println!("✅ Connected to Wazuh API");
    if connectivity.indexer_connected {
        println!("✅ Connected to Wazuh Indexer");
    }

    let mut logs_client = factory.create_logs_client();
    let indexer_client = factory.create_indexer_client();
    let mut agents_client = factory.create_agents_client();

    println!("\n🤖 Agent Log Sources");
    println!("====================");

    let agents = agents_client.get_active_agents().await?;

    if agents.is_empty() {
        println!("❌ No active agents found for log analysis");
        return Ok(());
    }

    println!("✅ Found {} active agents generating logs", agents.len());
    for agent in agents.iter().take(5) {
        println!(
            "   🔹 Agent {}: {} ({})",
            agent.id,
            agent.name,
            agent.ip.as_deref().unwrap_or("N/A")
        );
    }

    println!("\n📊 Analysis Daemon Statistics");
    println!("=============================");

    match logs_client.get_analysisd_stats().await {
        Ok(analysisd_stats) => {
            println!("🔍 Analysis Daemon Performance:");
            println!("   Events Received: {}", analysisd_stats.events_received);
            println!("   Events Processed: {}", analysisd_stats.events_processed);
            println!("   Events Dropped: {}", analysisd_stats.events_dropped);
            println!("   Alerts Written: {}", analysisd_stats.alerts_written);
            println!("   Firewall Alerts: {}", analysisd_stats.firewall_written);
            println!("   FTS Alerts: {}", analysisd_stats.fts_written);

            if analysisd_stats.events_received > 0 {
                let processing_rate = (analysisd_stats.events_processed as f64
                    / analysisd_stats.events_received as f64)
                    * 100.0;
                let alert_rate = (analysisd_stats.alerts_written as f64
                    / analysisd_stats.events_processed as f64)
                    * 100.0;

                println!("\n📈 Performance Metrics:");
                println!("   Processing Rate: {:.2}%", processing_rate);
                println!("   Alert Generation Rate: {:.2}%", alert_rate);

                if analysisd_stats.events_dropped > 0 {
                    let drop_rate = (analysisd_stats.events_dropped as f64
                        / analysisd_stats.events_received as f64)
                        * 100.0;
                    println!("   ⚠️  Event Drop Rate: {:.2}%", drop_rate);
                    if drop_rate > 5.0 {
                        println!("   💡 Consider tuning analysis performance");
                    }
                }
            }

            println!("\n📊 Queue Utilization:");
            println!(
                "   Event Queue: {:.1}% ({}/{})",
                analysisd_stats.event_queue_usage,
                (analysisd_stats.event_queue_size as f64 * analysisd_stats.event_queue_usage
                    / 100.0) as u64,
                analysisd_stats.event_queue_size
            );
            println!(
                "   Alerts Queue: {:.1}% ({}/{})",
                analysisd_stats.alerts_queue_usage,
                (analysisd_stats.alerts_queue_size as f64 * analysisd_stats.alerts_queue_usage
                    / 100.0) as u64,
                analysisd_stats.alerts_queue_size
            );
            println!(
                "   Syscheck Queue: {:.1}% ({}/{})",
                analysisd_stats.syscheck_queue_usage,
                (analysisd_stats.syscheck_queue_size as f64 * analysisd_stats.syscheck_queue_usage
                    / 100.0) as u64,
                analysisd_stats.syscheck_queue_size
            );

            println!("\n🔧 Component Statistics:");
            println!(
                "   Syscheck Events: {} (EPS: {:.1})",
                analysisd_stats.syscheck_events_decoded, analysisd_stats.syscheck_edps
            );
            println!(
                "   Syscollector Events: {} (EPS: {:.1})",
                analysisd_stats.syscollector_events_decoded, analysisd_stats.syscollector_edps
            );
            println!(
                "   Rootcheck Events: {} (EPS: {:.1})",
                analysisd_stats.rootcheck_events_decoded, analysisd_stats.rootcheck_edps
            );
            println!(
                "   SCA Events: {} (EPS: {:.1})",
                analysisd_stats.sca_events_decoded, analysisd_stats.sca_edps
            );
            println!(
                "   Windows Events: {} (EPS: {:.1})",
                analysisd_stats.winevt_events_decoded, analysisd_stats.winevt_edps
            );
        }
        Err(e) => warn!("Failed to get analysis daemon stats: {}", e),
    }

    println!("\n🌐 Remote Daemon Statistics");
    println!("===========================");

    match logs_client.get_remoted_stats().await {
        Ok(remoted_stats) => {
            println!("📡 Remote Communication Metrics:");
            println!("   TCP Sessions: {}", remoted_stats.tcp_sessions);
            println!("   Bytes Received: {}", remoted_stats.recv_bytes);
            println!("   Bytes Sent: {}", remoted_stats.sent_bytes);
            println!("   Discarded Messages: {}", remoted_stats.discarded_count);
            println!("   Queue Size: {}", remoted_stats.total_queue_size);
        }
        Err(e) => warn!("Failed to get remote daemon stats: {}", e),
    }

    println!("\n📥 Log Collector Statistics");
    println!("===========================");

    for agent in agents.iter().take(3) {
        match logs_client.get_logcollector_stats(&agent.id).await {
            Ok(logcollector_stats) => {
                println!("📋 Agent {} ({}) Log Collection:", agent.name, agent.id);
                
                // Calculate totals from global period
                let total_events: u64 = logcollector_stats.global.files.iter().map(|f| f.events).sum();
                let total_bytes: u64 = logcollector_stats.global.files.iter().map(|f| f.bytes).sum();
                let total_drops: u64 = logcollector_stats.global.files.iter()
                    .flat_map(|f| &f.targets)
                    .map(|t| t.drops)
                    .sum();

                println!("   📊 Global Period ({} to {}):", 
                    logcollector_stats.global.start, logcollector_stats.global.end);
                println!("   Events Collected: {}", total_events);
                println!("   Events Dropped: {}", total_drops);
                println!("   Bytes Processed: {}", total_bytes);

                if total_events > 0 {
                    let avg_event_size = total_bytes as f64 / total_events as f64;
                    println!("   Average Event Size: {:.1} bytes", avg_event_size);

                    if total_drops > 0 {
                        let drop_rate = (total_drops as f64 / total_events as f64) * 100.0;
                        println!("   ⚠️  Drop Rate: {:.2}%", drop_rate);
                    }
                }

                // Show file breakdown
                if !logcollector_stats.global.files.is_empty() {
                    println!("   📁 Log Files:");
                    for file in &logcollector_stats.global.files {
                        println!("     • {}: {} events, {} bytes", 
                            file.location, file.events, file.bytes);
                        
                        if !file.targets.is_empty() {
                            for target in &file.targets {
                                if target.drops > 0 {
                                    println!("       └─ {}: {} drops", target.name, target.drops);
                                }
                            }
                        }
                    }
                }

                // Show interval period if different from global
                let interval_events: u64 = logcollector_stats.interval.files.iter().map(|f| f.events).sum();
                if interval_events > 0 {
                    let interval_bytes: u64 = logcollector_stats.interval.files.iter().map(|f| f.bytes).sum();
                    println!("   ⏱️  Recent Interval ({} to {}):", 
                        logcollector_stats.interval.start, logcollector_stats.interval.end);
                    println!("     Events: {}, Bytes: {}", interval_events, interval_bytes);
                }
                
                println!();
            }
            Err(e) => warn!(
                "Failed to get log collector stats for agent {}: {}",
                agent.id, e
            ),
        }
    }

    println!("\n📝 Manager Log Analysis");
    println!("=======================");

    match logs_client
        .get_manager_logs(Some(20), None, None, None, None)
        .await
    {
        Ok(manager_logs) => {
            if manager_logs.is_empty() {
                println!("ℹ️  No recent manager logs found");
            } else {
                println!("📋 Found {} recent manager log entries", manager_logs.len());

                let mut level_counts = HashMap::new();
                let mut tag_counts = HashMap::new();

                for log_entry in &manager_logs {
                    *level_counts.entry(log_entry.level.clone()).or_insert(0) += 1;
                    *tag_counts.entry(log_entry.tag.clone()).or_insert(0) += 1;
                }

                println!("\n📊 Log Level Distribution:");
                for (level, count) in &level_counts {
                    println!("   {}: {} entries", level, count);
                }

                println!("\n🏷️  Log Tag Distribution:");
                for (tag, count) in tag_counts.iter().take(5) {
                    println!("   {}: {} entries", tag, count);
                }

                println!("\n📝 Sample Manager Logs:");
                for log_entry in manager_logs.iter().take(5) {
                    println!(
                        "   🔹 [{}] [{}] {}",
                        log_entry.timestamp, log_entry.level, log_entry.description
                    );
                    println!("      Tag: {}", log_entry.tag);

                    match serde_json::to_string_pretty(&log_entry) {
                        Ok(json_str) => {
                            println!("      📄 Full Log Entry:");
                            for line in json_str.lines() {
                                println!("         {}", line);
                            }
                        }
                        Err(_) => {
                            println!("      📄 Raw Log Entry: {:?}", log_entry);
                        }
                    }
                    println!();
                }
            }
        }
        Err(e) => warn!("Failed to get manager logs: {}", e),
    }

    println!("\n🚨 Error and Warning Analysis");
    println!("==============================");

    match logs_client.get_error_logs(Some(10)).await {
        Ok(error_logs) => {
            if !error_logs.is_empty() {
                println!("❌ Recent Error Logs: {}", error_logs.len());
                for log_entry in error_logs.iter().take(3) {
                    println!("   🔹 [{}] {}", log_entry.timestamp, log_entry.description);
                    println!("      Tag: {}", log_entry.tag);
                }
            } else {
                println!("✅ No recent error logs found");
            }
        }
        Err(e) => warn!("Failed to get error logs: {}", e),
    }

    match logs_client.get_warning_logs(Some(10)).await {
        Ok(warning_logs) => {
            if !warning_logs.is_empty() {
                println!("\n⚠️  Recent Warning Logs: {}", warning_logs.len());
                for log_entry in warning_logs.iter().take(3) {
                    println!("   🔹 [{}] {}", log_entry.timestamp, log_entry.description);
                    println!("      Tag: {}", log_entry.tag);

                    // Pretty print warning log as JSON
                    match serde_json::to_string_pretty(&log_entry) {
                        Ok(json_str) => {
                            println!("      ⚠️  Warning Details:");
                            for line in json_str.lines() {
                                println!("         {}", line);
                            }
                        }
                        Err(_) => {
                            println!("      ⚠️  Raw Warning: {:?}", log_entry);
                        }
                    }
                    println!();
                }
            } else {
                println!("\n✅ No recent warning logs found");
            }
        }
        Err(e) => warn!("Failed to get warning logs: {}", e),
    }

    println!("\n🔍 Log Search Examples");
    println!("======================");

    let search_terms = vec!["authentication", "failed", "error", "connection"];

    for term in search_terms {
        match logs_client.search_logs(term, Some(5)).await {
            Ok(search_results) => {
                if !search_results.is_empty() {
                    println!("🔍 Search for '{}': {} results", term, search_results.len());
                    for log_entry in search_results.iter().take(2) {
                        println!("   • [{}] {}", log_entry.timestamp, log_entry.description);

                        // Pretty print search result as JSON
                        match serde_json::to_string_pretty(&log_entry) {
                            Ok(json_str) => {
                                println!("     🔎 Match Details:");
                                for line in json_str.lines() {
                                    println!("        {}", line);
                                }
                            }
                            Err(_) => {
                                println!("     🔎 Raw Match: {:?}", log_entry);
                            }
                        }
                        println!();
                    }
                } else {
                    println!("🔍 Search for '{}': No results found", term);
                }
            }
            Err(e) => warn!("Failed to search for '{}': {}", term, e),
        }
    }

    println!("\n🔍 Agent Ingestion Monitoring");
    println!("==============================");

    // Use the new monitor_agent_ingestion method
    for agent in agents.iter().take(2) {
        match logs_client.monitor_agent_ingestion(&agent.id).await {
            Ok(ingestion_info) => {
                println!("📊 Agent {} ({}) Ingestion Analysis:", agent.name, agent.id);
                
                if let Some(total_events) = ingestion_info.get("total_events").and_then(|v| v.as_u64()) {
                    println!("   Total Events: {}", total_events);
                }
                
                if let Some(bytes_processed) = ingestion_info.get("bytes_processed").and_then(|v| v.as_u64()) {
                    println!("   Bytes Processed: {}", bytes_processed);
                }
                
                if let Some(events_dropped) = ingestion_info.get("events_dropped").and_then(|v| v.as_u64()) {
                    println!("   Events Dropped: {}", events_dropped);
                }
                
                if let Some(drop_rate) = ingestion_info.get("drop_rate").and_then(|v| v.as_f64()) {
                    if drop_rate > 0.0 {
                        println!("   ⚠️  Drop Rate: {:.2}%", drop_rate);
                        if drop_rate > 5.0 {
                            println!("   💡 Consider investigating high drop rate");
                        }
                    }
                }

                // Show global period details
                if let Some(global_period) = ingestion_info.get("global_period") {
                    if let Some(files) = global_period.get("files").and_then(|v| v.as_array()) {
                        println!("   📁 Active Log Sources: {}", files.len());
                        for file in files.iter().take(3) {
                            if let (Some(location), Some(events)) = (
                                file.get("location").and_then(|v| v.as_str()),
                                file.get("events").and_then(|v| v.as_u64())
                            ) {
                                if events > 0 {
                                    println!("     • {}: {} events", location, events);
                                }
                            }
                        }
                    }
                }
                
                println!();
            }
            Err(e) => warn!("Failed to monitor agent {} ingestion: {}", agent.id, e),
        }
    }

    println!("\n📈 Performance Statistics");
    println!("=========================");

    match logs_client.get_hourly_stats().await {
        Ok(hourly_stats) => {
            println!("⏰ Hourly Performance Metrics:");

            // Parse and display hourly statistics in a user-friendly format
            if let Ok(json_value) = serde_json::to_value(&hourly_stats) {
                if let Some(data) = json_value.get("data") {
                    if let Some(affected_items) =
                        data.get("affected_items").and_then(|v| v.as_array())
                    {
                        if let Some(hourly_data) = affected_items.first() {
                            if let Some(averages) =
                                hourly_data.get("averages").and_then(|v| v.as_array())
                            {
                                let interactions = hourly_data
                                    .get("interactions")
                                    .and_then(|v| v.as_u64())
                                    .unwrap_or(0);

                                println!("   📊 24-Hour Activity Pattern:");
                                println!("   Total Interactions: {}", interactions);
                                println!("   Hourly Averages (0-23h):");

                                // Display hourly data in a formatted grid
                                for (hour, avg) in averages.iter().enumerate() {
                                    if let Some(value) = avg.as_u64() {
                                        let bar_length = (value / 50).min(20) as usize; // Scale for display
                                        let bar = "█".repeat(bar_length);
                                        println!("     {:02}:00 │ {:>4} │ {}", hour, value, bar);
                                    }
                                }

                                // Calculate peak hours
                                let max_value = averages
                                    .iter()
                                    .filter_map(|v| v.as_u64())
                                    .max()
                                    .unwrap_or(0);
                                let peak_hours: Vec<usize> = averages
                                    .iter()
                                    .enumerate()
                                    .filter_map(|(i, v)| {
                                        if v.as_u64() == Some(max_value) {
                                            Some(i)
                                        } else {
                                            None
                                        }
                                    })
                                    .collect();

                                if !peak_hours.is_empty() {
                                    println!(
                                        "   🔥 Peak Activity Hours: {}:00 ({})",
                                        peak_hours
                                            .iter()
                                            .map(|h| format!("{:02}", h))
                                            .collect::<Vec<_>>()
                                            .join(", "),
                                        max_value
                                    );
                                }
                            }
                        }
                    }

                    // Display summary information
                    if let Some(total_affected) =
                        data.get("total_affected_items").and_then(|v| v.as_u64())
                    {
                        println!("   📈 Summary: {} node(s) analyzed", total_affected);
                    }
                }
            } else {
                // Fallback to pretty JSON if parsing fails
                match serde_json::to_string_pretty(&hourly_stats) {
                    Ok(json_str) => {
                        println!("📈 Hourly Statistics (JSON):");
                        println!("┌─────────────────────────────────────────────────────────────────────────────────┐");
                        for line in json_str.lines() {
                            println!("│ {:<79} │", line);
                        }
                        println!("└─────────────────────────────────────────────────────────────────────────────────┘");
                    }
                    Err(_) => {
                        println!("   Statistics: {:?}", hourly_stats);
                    }
                }
            }
        }
        Err(e) => warn!("Failed to get hourly stats: {}", e),
    }

    match logs_client.get_weekly_stats().await {
        Ok(weekly_stats) => {
            println!("\n📅 Weekly Performance Metrics:");

            if let Ok(json_value) = serde_json::to_value(&weekly_stats) {
                if let Some(data) = json_value.get("data") {
                    if let Some(affected_items) =
                        data.get("affected_items").and_then(|v| v.as_array())
                    {
                        println!("   📊 7-Day Activity Breakdown:");

                        let days = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];
                        let mut weekly_totals = Vec::new();

                        for day_data in affected_items {
                            for day_name in &days {
                                if let Some(day_info) = day_data.get(day_name) {
                                    if let Some(hours) =
                                        day_info.get("hours").and_then(|v| v.as_array())
                                    {
                                        let interactions = day_info
                                            .get("interactions")
                                            .and_then(|v| v.as_u64())
                                            .unwrap_or(0);

                                        let daily_total: u64 =
                                            hours.iter().filter_map(|v| v.as_u64()).sum();

                                        let daily_avg = if !hours.is_empty() {
                                            daily_total / hours.len() as u64
                                        } else {
                                            0
                                        };

                                        weekly_totals.push((
                                            day_name,
                                            daily_total,
                                            daily_avg,
                                            interactions,
                                        ));

                                        let bar_length = (daily_avg / 50).min(20) as usize;
                                        let bar = "█".repeat(bar_length);

                                        println!(
                                            "   {} │ Total: {:>5} │ Avg: {:>3} │ Int: {:>2} │ {}",
                                            day_name, daily_total, daily_avg, interactions, bar
                                        );
                                    }
                                }
                            }
                        }

                        let week_total: u64 =
                            weekly_totals.iter().map(|(_, total, _, _)| *total).sum();
                        let week_avg = if !weekly_totals.is_empty() {
                            week_total / weekly_totals.len() as u64
                        } else {
                            0
                        };

                        // Find busiest day
                        if let Some((busiest_day, max_total, _, _)) =
                            weekly_totals.iter().max_by_key(|(_, total, _, _)| *total)
                        {
                            println!("   🔥 Busiest Day: {} ({} events)", busiest_day, max_total);
                        }

                        println!(
                            "   📈 Weekly Summary: {} total events, {} daily average",
                            week_total, week_avg
                        );
                    }

                    // Display summary information
                    if let Some(total_affected) =
                        data.get("total_affected_items").and_then(|v| v.as_u64())
                    {
                        println!("   📊 Analysis Coverage: {} day(s) of data", total_affected);
                    }
                }
            } else {
                match serde_json::to_string_pretty(&weekly_stats) {
                    Ok(json_str) => {
                        println!("📊 Weekly Statistics (JSON):");
                        println!("┌─────────────────────────────────────────────────────────────────────────────────┐");
                        for line in json_str.lines() {
                            println!("│ {:<79} │", line);
                        }
                        println!("└─────────────────────────────────────────────────────────────────────────────────┘");
                    }
                    Err(_) => {
                        println!("   Statistics: {:?}", weekly_stats);
                    }
                }
            }
        }
        Err(e) => warn!("Failed to get weekly stats: {}", e),
    }

    if connectivity.indexer_connected {
        println!("\n🚨 Security Event Analysis");
        println!("===========================");

        match indexer_client.get_alerts(None).await {
            Ok(alerts) => {
                println!("🔔 Recent security alerts retrieved from Indexer");

                // Pretty print alerts as JSON
                match serde_json::to_string_pretty(&alerts) {
                    Ok(json_str) => {
                        println!("🚨 Security Alerts (JSON):");
                        println!("┌─────────────────────────────────────────────────────────────────────────────────┐");
                        for line in json_str.lines() {
                            println!("│ {:<79} │", line);
                        }
                        println!("└─────────────────────────────────────────────────────────────────────────────────┘");
                    }
                    Err(_) => {
                        println!("   Alert data: {:?}", alerts);
                    }
                }
            }
            Err(e) => warn!("Failed to get alerts from Indexer: {}", e),
        }
    }

    // 10. Log Analysis Summary and Recommendations
    println!("\n📊 Log Analysis Summary");
    println!("=======================");

    match logs_client.get_logs_summary().await {
        Ok(summary) => {
            println!("📋 Overall Log Summary:");

            // Pretty print summary as JSON
            match serde_json::to_string_pretty(&summary) {
                Ok(json_str) => {
                    println!("📊 Log Summary (JSON):");
                    println!("┌─────────────────────────────────────────────────────────────────────────────────┐");
                    for line in json_str.lines() {
                        println!("│ {:<79} │", line);
                    }
                    println!("└─────────────────────────────────────────────────────────────────────────────────┘");
                }
                Err(_) => {
                    println!("   Summary: {:?}", summary);
                }
            }
        }
        Err(e) => warn!("Failed to get logs summary: {}", e),
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
