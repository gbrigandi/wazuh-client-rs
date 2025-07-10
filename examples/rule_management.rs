//! Rule management example for the Wazuh Rust client
//!
//! This example demonstrates:
//! - Comprehensive rule analysis and categorization
//! - Decoder management and configuration
//! - Rule searching and filtering capabilities
//! - Security rule optimization
//! - Compliance framework mapping

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

    println!("📋 Wazuh Rust Client - Rule Management Example");
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

    let mut rules_client = factory.create_rules_client();

    println!("\n📊 Rule Overview");
    println!("================");

    let all_rules = rules_client.get_rules(None, None, None, None, None).await?;
    println!("📈 Rule Statistics:");
    println!("   Total Rules: {}", all_rules.len());

    let mut level_counts: HashMap<u32, u32> = HashMap::new();
    let mut group_counts: HashMap<String, u32> = HashMap::new();
    let mut filename_counts: HashMap<String, u32> = HashMap::new();

    for rule in &all_rules {
        *level_counts.entry(rule.level).or_insert(0) += 1;
        *filename_counts.entry(rule.filename.clone()).or_insert(0) += 1;

        for group in &rule.groups {
            *group_counts.entry(group.clone()).or_insert(0) += 1;
        }
    }

    println!("\n📊 Rule Distribution by Level:");
    let mut sorted_levels: Vec<_> = level_counts.iter().collect();
    sorted_levels.sort_by_key(|(level, _)| *level);
    for (level, count) in sorted_levels {
        let severity = match level {
            0..=3 => "Low",
            4..=7 => "Medium",
            8..=12 => "High",
            13..=15 => "Critical",
            _ => "Unknown",
        };
        println!("   Level {}: {} rules ({})", level, count, severity);
    }

    println!("\n📁 Top Rule Files:");
    let mut sorted_files: Vec<_> = filename_counts.iter().collect();
    sorted_files.sort_by_key(|(_, count)| std::cmp::Reverse(**count));
    for (filename, count) in sorted_files.iter().take(10) {
        println!("   {}: {} rules", filename, count);
    }

    println!("\n🏷️  Top Rule Groups:");
    let mut sorted_groups: Vec<_> = group_counts.iter().collect();
    sorted_groups.sort_by_key(|(_, count)| std::cmp::Reverse(**count));
    for (group, count) in sorted_groups.iter().take(10) {
        println!("   {}: {} rules", group, count);
    }

    println!("\n🚨 High-Level Security Rules");
    println!("============================");

    match rules_client.get_high_level_rules().await {
        Ok(high_level_rules) => {
            println!("🔥 Critical Security Rules: {}", high_level_rules.len());

            for rule in high_level_rules.iter().take(10) {
                println!(
                    "   🔹 Rule {}: Level {} - {}",
                    rule.id, rule.level, rule.description
                );
                println!("      Groups: {}", rule.groups.join(", "));
                if let Some(details) = &rule.details {
                    if let Some(category) = &details.category {
                        println!("      Category: {}", category);
                    }
                }

                let mut compliance = Vec::new();
                if let Some(gdpr) = &rule.gdpr {
                    compliance.push(format!("GDPR: {}", gdpr.join(", ")));
                }
                if let Some(hipaa) = &rule.hipaa {
                    compliance.push(format!("HIPAA: {}", hipaa.join(", ")));
                }
                if let Some(pci) = &rule.pci_dss {
                    compliance.push(format!("PCI DSS: {}", pci.join(", ")));
                }
                if let Some(nist) = &rule.nist_800_53 {
                    compliance.push(format!("NIST 800-53: {}", nist.join(", ")));
                }

                if !compliance.is_empty() {
                    println!("      Compliance: {}", compliance.join(" | "));
                }
                println!();
            }
        }
        Err(e) => warn!("Failed to get high-level rules: {}", e),
    }

    println!("\n🛡️  Security Category Analysis");
    println!("===============================");

    // Analyze rules by common security categories
    let security_groups = vec![
        "authentication_failed",
        "authentication_success",
        "attack",
        "web",
        "firewall",
        "intrusion_detection",
        "malware",
        "vulnerability-detector",
        "rootcheck",
        "syscheck",
        "policy_violation",
    ];

    for group in security_groups {
        match rules_client.get_rules_by_group(group).await {
            Ok(group_rules) => {
                if !group_rules.is_empty() {
                    println!("🔍 {} rules: {}", group, group_rules.len());

                    // Show a sample rule from this group
                    if let Some(sample_rule) = group_rules.first() {
                        println!(
                            "   Example: Rule {} - {}",
                            sample_rule.id, sample_rule.description
                        );
                    }
                }
            }
            Err(e) => warn!("Failed to get rules for group {}: {}", group, e),
        }
    }

    println!("\n📊 Rule Level Analysis");
    println!("======================");

    let critical_levels = vec![10, 12, 15];
    for level in critical_levels {
        match rules_client.get_rules_by_level(level).await {
            Ok(level_rules) => {
                println!("⚠️  Level {} rules: {}", level, level_rules.len());

                for rule in level_rules.iter().take(3) {
                    println!("   • Rule {}: {}", rule.id, rule.description);
                }
                if level_rules.len() > 3 {
                    println!("   ... and {} more", level_rules.len() - 3);
                }
            }
            Err(e) => warn!("Failed to get level {} rules: {}", level, e),
        }
    }

    println!("\n🏷️  Rule Groups Analysis");
    println!("=========================");

    match rules_client.get_rule_groups().await {
        Ok(groups) => {
            println!("📋 Available Rule Groups: {}", groups.len());

            // Show groups with their counts
            for group in groups.iter().take(15) {
                if let Some(count) = group_counts.get(group) {
                    println!("   • {}: {} rules", group, count);
                }
            }
        }
        Err(e) => warn!("Failed to get rule groups: {}", e),
    }

    println!("\n🔧 Decoder Analysis");
    println!("===================");

    match rules_client.get_decoders(Some(20), None, None).await {
        Ok(decoders) => {
            println!("🔍 Sample Decoders: {}", decoders.len());

            let mut decoder_files: HashMap<String, u32> = HashMap::new();
            for decoder in &decoders {
                *decoder_files.entry(decoder.filename.clone()).or_insert(0) += 1;
            }

            println!("\n📁 Decoder Files:");
            for (filename, count) in decoder_files.iter() {
                println!("   {}: {} decoders", filename, count);
            }

            // Show sample decoders
            println!("\n🔍 Sample Decoders:");
            for decoder in decoders.iter().take(5) {
                println!("   🔹 {}: {}", decoder.name, decoder.status);
                println!(
                    "      File: {} | Position: {}",
                    decoder.filename,
                    decoder
                        .position
                        .map(|p| p.to_string())
                        .unwrap_or_else(|| "N/A".to_string())
                );

                if let Some(details) = &decoder.details {
                    if let Some(program) = &details.program_name {
                        println!("      Program: {}", program);
                    }
                    if let Some(regex) = &details.regex {
                        println!("      Regex: {:?}", regex);
                    }
                }
                println!();
            }
        }
        Err(e) => warn!("Failed to get decoders: {}", e),
    }

    println!("\n🔍 Rule Search Examples");
    println!("=======================");

    let search_terms = vec!["ssh", "login", "attack", "web"];

    for term in search_terms {
        match rules_client.search_rules(term).await {
            Ok(search_results) => {
                println!("🔍 Search for '{}': {} results", term, search_results.len());

                for rule in search_results.iter().take(3) {
                    println!("   • Rule {}: {}", rule.id, rule.description);
                }
                if search_results.len() > 3 {
                    println!("   ... and {} more", search_results.len() - 3);
                }
            }
            Err(e) => warn!("Failed to search for '{}': {}", term, e),
        }
    }

    println!("\n📜 Compliance Framework Analysis");
    println!("=================================");

    let mut gdpr_rules = 0;
    let mut hipaa_rules = 0;
    let mut pci_rules = 0;
    let mut nist_rules = 0;

    for rule in &all_rules {
        if rule.gdpr.is_some() {
            gdpr_rules += 1;
        }
        if rule.hipaa.is_some() {
            hipaa_rules += 1;
        }
        if rule.pci_dss.is_some() {
            pci_rules += 1;
        }
        if rule.nist_800_53.is_some() {
            nist_rules += 1;
        }
    }

    println!("📊 Compliance Coverage:");
    println!("   GDPR: {} rules", gdpr_rules);
    println!("   HIPAA: {} rules", hipaa_rules);
    println!("   PCI DSS: {} rules", pci_rules);
    println!("   NIST 800-53: {} rules", nist_rules);

    println!("\n💡 Rule Optimization Recommendations");
    println!("====================================");

    let low_level_rules = all_rules.iter().filter(|r| r.level <= 3).count();
    let medium_level_rules = all_rules
        .iter()
        .filter(|r| r.level >= 4 && r.level <= 7)
        .count();
    let high_level_rules = all_rules.iter().filter(|r| r.level >= 8).count();

    println!("🎯 Rule Distribution Analysis:");
    println!(
        "   Low Priority (0-3): {} rules ({:.1}%)",
        low_level_rules,
        (low_level_rules as f64 / all_rules.len() as f64) * 100.0
    );
    println!(
        "   Medium Priority (4-7): {} rules ({:.1}%)",
        medium_level_rules,
        (medium_level_rules as f64 / all_rules.len() as f64) * 100.0
    );
    println!(
        "   High Priority (8+): {} rules ({:.1}%)",
        high_level_rules,
        (high_level_rules as f64 / all_rules.len() as f64) * 100.0
    );

    println!("\n✅ Optimization Suggestions:");
    if high_level_rules < all_rules.len() / 10 {
        println!("   • Consider reviewing high-priority rule coverage");
    }
    if low_level_rules > all_rules.len() / 2 {
        println!("   • Many low-priority rules - consider tuning for noise reduction");
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
