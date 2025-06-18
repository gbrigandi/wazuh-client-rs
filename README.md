# Wazuh Client for Rust

[![Crates.io](https://img.shields.io/crates/v/wazuh-client.svg)](https://crates.io/crates/wazuh-client-rs)
[![Documentation](https://docs.rs/wazuh-client/badge.svg)](https://docs.rs/wazuh-client-rs)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

A comprehensive Rust client library for interacting with Wazuh API and Wazuh Indexer. This library provides a type-safe, async interface for managing Wazuh deployments, agents, rules, and security monitoring.

## Features

- 🚀 **Async/Await Support** - Built on tokio for high-performance async operations
- 🔒 **Type Safety** - Strongly typed API with comprehensive error handling
- 🛡️ **Security First** - Support for TLS/SSL with certificate validation
- 📊 **Comprehensive API Coverage** - Full Wazuh Manager API support plus core Indexer operations
- 🔧 **Flexible Configuration** - Easy configuration with builder patterns

## Supported Wazuh Components

### Wazuh Manager API
- **Agent Management** - Add, remove, configure, and monitor agents
- **Rule Management** - Create, update, and manage detection rules
- **Cluster Operations** - Monitor and manage cluster nodes
- **Configuration Management** - Update and retrieve configurations
- **Active Response** - Trigger and manage active responses
- **Log Analysis** - Query and analyze security logs

### Wazuh Indexer
- **Alert Queries** - Search and retrieve security alerts

## Quick Start

Add this to your `Cargo.toml`:

```toml
[dependencies]
wazuh-client = "0.1.0"
tokio = { version = "1.0", features = ["full"] }
```

### Basic Usage

```rust
use wazuh_client_rs::{WazuhClientFactory, WazuhClients}; // Updated imports
use std::env; // For environment variables if you choose to load them

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Setup the factory with your Wazuh API and Indexer credentials/details
    // For a real application, load these from config files or environment variables
    let factory = WazuhClientFactory::new(
        env::var("WAZUH_API_HOST").unwrap_or_else(|_| "127.0.0.1".to_string()),
        env::var("WAZUH_API_PORT").unwrap_or_else(|_| "55000".to_string()).parse().unwrap_or(55000),
        env::var("WAZUH_API_USERNAME").unwrap_or_else(|_| "wazuh".to_string()),
        env::var("WAZUH_API_PASSWORD").unwrap_or_else(|_| "wazuh".to_string()),
        env::var("WAZUH_INDEXER_HOST").unwrap_or_else(|_| "127.0.0.1".to_string()),
        env::var("WAZUH_INDEXER_PORT").unwrap_or_else(|_| "9200".to_string()).parse().unwrap_or(9200),
        env::var("WAZUH_INDEXER_USERNAME").unwrap_or_else(|_| "admin".to_string()),
        env::var("WAZUH_INDEXER_PASSWORD").unwrap_or_else(|_| "admin".to_string()),
        env::var("WAZUH_VERIFY_SSL").unwrap_or_else(|_| "false".to_string()).parse().unwrap_or(false),
        Some("https".to_string()) // Or "http" if not using SSL
    );

    // Create a collection of clients
    // Note: create_all_clients() itself is not async. Methods on the individual clients are.
    let mut clients: WazuhClients = factory.create_all_clients();

    // Get agent summary using the agents client
    let summary = clients.agents.get_agents_summary().await?;
    println!("Total agents: {}", summary.connection.total);
    println!("Active agents: {}", summary.connection.active);

    // Get a few rules
    // The get_rules method takes: limit, offset, level, group, filename
    let rules = clients.rules.get_rules(Some(5), None, None, None, None).await?;
    println!("Fetched {} rules. First rule ID (if any): {:?}", rules.len(), rules.first().map(|r| r.id));

    Ok(())
}
```

### Agent Management

```rust
use wazuh_client_rs::{WazuhClientFactory, WazuhClients, agents::AgentAddBody};
use std::env;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Assume `factory` is initialized as shown in the Basic Usage example
    let factory = WazuhClientFactory::new(
        env::var("WAZUH_API_HOST").unwrap_or_else(|_| "127.0.0.1".to_string()),
        env::var("WAZUH_API_PORT").unwrap_or_else(|_| "55000".to_string()).parse().unwrap_or(55000),
        env::var("WAZUH_API_USERNAME").unwrap_or_else(|_| "wazuh".to_string()),
        env::var("WAZUH_API_PASSWORD").unwrap_or_else(|_| "wazuh".to_string()),
        env::var("WAZUH_INDEXER_HOST").unwrap_or_else(|_| "127.0.0.1".to_string()),
        env::var("WAZUH_INDEXER_PORT").unwrap_or_else(|_| "9200".to_string()).parse().unwrap_or(9200),
        env::var("WAZUH_INDEXER_USERNAME").unwrap_or_else(|_| "admin".to_string()),
        env::var("WAZUH_INDEXER_PASSWORD").unwrap_or_else(|_| "admin".to_string()),
        env::var("WAZUH_VERIFY_SSL").unwrap_or_else(|_| "false".to_string()).parse().unwrap_or(false),
        Some("https".to_string())
    );
    let mut clients: WazuhClients = factory.create_all_clients();

    // Get agent details (ensure agent "001" exists or use a dynamic ID)
    match clients.agents.get_agent("001").await {
        Ok(agent) => {
            println!("Agent 001 Status: {}", agent.status);
            println!("Agent 001 Name: {}", agent.name);
        }
        Err(e) => {
            eprintln!("Error getting agent 001: {}", e);
        }
    }
    
    // Example: Add a new agent (use with caution in production examples)
    // let new_agent_body = AgentAddBody {
    //     name: "my-new-agent".to_string(),
    //     ip: Some("any".to_string()), // "any" or a specific IP
    // };
    // match clients.agents.add_agent(new_agent_body).await {
    //    Ok(added_agent_key) => println!("Added agent. ID: {}, Key: {}", added_agent_key.id, added_agent_key.key),
    //    Err(e) => eprintln!("Error adding agent: {}", e),
    // }

    Ok(())
}
```

### Rule Management

```rust
use wazuh_client_rs::{WazuhClientFactory, WazuhClients};
use std::env;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Assume `factory` is initialized as shown in the Basic Usage example
    let factory = WazuhClientFactory::new(
        env::var("WAZUH_API_HOST").unwrap_or_else(|_| "127.0.0.1".to_string()),
        env::var("WAZUH_API_PORT").unwrap_or_else(|_| "55000".to_string()).parse().unwrap_or(55000),
        env::var("WAZUH_API_USERNAME").unwrap_or_else(|_| "wazuh".to_string()),
        env::var("WAZUH_API_PASSWORD").unwrap_or_else(|_| "wazuh".to_string()),
        env::var("WAZUH_INDEXER_HOST").unwrap_or_else(|_| "127.0.0.1".to_string()),
        env::var("WAZUH_INDEXER_PORT").unwrap_or_else(|_| "9200".to_string()).parse().unwrap_or(9200),
        env::var("WAZUH_INDEXER_USERNAME").unwrap_or_else(|_| "admin".to_string()),
        env::var("WAZUH_INDEXER_PASSWORD").unwrap_or_else(|_| "admin".to_string()),
        env::var("WAZUH_VERIFY_SSL").unwrap_or_else(|_| "false".to_string()).parse().unwrap_or(false),
        Some("https".to_string())
    );
    let mut clients: WazuhClients = factory.create_all_clients();

    // Get a few rules (limit, offset, level, group, filename)
    let rules = clients.rules.get_rules(Some(5), None, None, None, None).await?;
    println!("Fetched {} rules.", rules.len());

    if let Some(rule) = rules.first() {
        println!("Example Rule ID: {}, Description: {}", rule.id, rule.description);
    }

    // Search for rules containing "ssh" in their description (or other indexed fields)
    // Note: The `search` parameter for `get_rules` is not directly in its signature.
    // The general `search` parameter is usually part of a more generic query structure if supported.
    // The `src/rules.rs` `get_rules` method does not have a `search` parameter.
    // To search, you might need to iterate or use a different endpoint if available.
    // For simplicity, this example will fetch rules by group.
    let ssh_rules = clients.rules.get_rules_by_group("ssh").await?;
    println!("Found {} rules in the 'ssh' group.", ssh_rules.len());
    if let Some(rule) = ssh_rules.first() {
        println!("Example SSH Rule ID: {}, Description: {}", rule.id, rule.description);
    }


    Ok(())
}
```

### Cluster Monitoring

```rust
use wazuh_client_rs::{WazuhClientFactory, WazuhClients};
use std::env;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Assume `factory` is initialized as shown in the Basic Usage example
    let factory = WazuhClientFactory::new(
        env::var("WAZUH_API_HOST").unwrap_or_else(|_| "127.0.0.1".to_string()),
        env::var("WAZUH_API_PORT").unwrap_or_else(|_| "55000".to_string()).parse().unwrap_or(55000),
        env::var("WAZUH_API_USERNAME").unwrap_or_else(|_| "wazuh".to_string()),
        env::var("WAZUH_API_PASSWORD").unwrap_or_else(|_| "wazuh".to_string()),
        env::var("WAZUH_INDEXER_HOST").unwrap_or_else(|_| "127.0.0.1".to_string()),
        env::var("WAZUH_INDEXER_PORT").unwrap_or_else(|_| "9200".to_string()).parse().unwrap_or(9200),
        env::var("WAZUH_INDEXER_USERNAME").unwrap_or_else(|_| "admin".to_string()),
        env::var("WAZUH_INDEXER_PASSWORD").unwrap_or_else(|_| "admin".to_string()),
        env::var("WAZUH_VERIFY_SSL").unwrap_or_else(|_| "false".to_string()).parse().unwrap_or(false),
        Some("https".to_string())
    );
    let mut clients: WazuhClients = factory.create_all_clients();

    // Get cluster status
    match clients.cluster.get_cluster_status().await {
        Ok(status) => {
            println!("Cluster enabled: {}", status.enabled);
            println!("Cluster running: {}", status.running);
        }
        Err(e) => {
            eprintln!("Error getting cluster status (this is expected in non-clustered environments): {}", e);
        }
    }

    // Get cluster nodes (limit, offset, node_type)
    // This will likely error in a single-node setup.
    match clients.cluster.get_cluster_nodes(None, None, None).await {
        Ok(nodes) => {
            if nodes.is_empty() {
                println!("No cluster nodes found (or single node deployment).");
            } else {
                println!("Cluster Nodes:");
                for node in nodes {
                    println!("  Node: {}, Type: {}, Status: {}", node.name, node.node_type, node.status);
                }
            }
        }
        Err(e) => {
             eprintln!("Error getting cluster nodes (this is expected in non-clustered environments): {}", e);
        }
    }

    Ok(())
}
```

### Log Analysis with Indexer

```rust
use wazuh_client_rs::{WazuhClientFactory, WazuhClients}; // WazuhIndexerClient is part of WazuhClients
use std::env;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Assume `factory` is initialized as shown in the Basic Usage example
    // Ensure indexer details are correctly set in the factory
    let factory = WazuhClientFactory::new(
        env::var("WAZUH_API_HOST").unwrap_or_else(|_| "127.0.0.1".to_string()),
        env::var("WAZUH_API_PORT").unwrap_or_else(|_| "55000".to_string()).parse().unwrap_or(55000),
        env::var("WAZUH_API_USERNAME").unwrap_or_else(|_| "wazuh".to_string()),
        env::var("WAZUH_API_PASSWORD").unwrap_or_else(|_| "wazuh".to_string()),
        env::var("WAZUH_INDEXER_HOST").unwrap_or_else(|_| "127.0.0.1".to_string()),
        env::var("WAZUH_INDEXER_PORT").unwrap_or_else(|_| "9200".to_string()).parse().unwrap_or(9200),
        env::var("WAZUH_INDEXER_USERNAME").unwrap_or_else(|_| "admin".to_string()),
        env::var("WAZUH_INDEXER_PASSWORD").unwrap_or_else(|_| "admin".to_string()),
        env::var("WAZUH_VERIFY_SSL").unwrap_or_else(|_| "false".to_string()).parse().unwrap_or(false),
        Some("https".to_string())
    );
    let clients: WazuhClients = factory.create_all_clients(); // Indexer client is part of WazuhClients

    // Get recent alerts using the indexer client from WazuhClients
    match clients.indexer.get_alerts().await {
        Ok(alerts) => {
            println!("Retrieved {} alerts from the indexer.", alerts.len());
            if let Some(alert) = alerts.first() {
                // Alerts are serde_json::Value, you can explore them
                println!("Example alert (first 50 chars): {:.50}", serde_json::to_string(alert)?);
            }
        }
        Err(e) => {
            eprintln!("Error getting alerts from indexer: {}", e);
        }
    }

    Ok(())
}
```

## Configuration

### Environment Variables

You can configure the client using environment variables:

```bash
export WAZUH_HOST="https://your-wazuh-manager.com"
export WAZUH_PORT="55000"
export WAZUH_USERNAME="wazuh"
export WAZUH_PASSWORD="your-password"
export WAZUH_VERIFY_SSL="true"

export WAZUH_INDEXER_HOST="your-wazuh-indexer.com"
export WAZUH_INDEXER_PORT="9200"
export WAZUH_INDEXER_USERNAME="admin"
export WAZUH_INDEXER_PASSWORD="admin"
```

### Client Factory Initialization

The `WazuhClientFactory` is used to configure and create clients.

```rust
use wazuh_client_rs::WazuhClientFactory;
use std::env;

// Example of initializing the factory
// In a real application, load these from a configuration file or environment variables.
let factory = WazuhClientFactory::new(
    env::var("WAZUH_API_HOST").unwrap_or_else(|_| "127.0.0.1".to_string()),
    env::var("WAZUH_API_PORT").unwrap_or_else(|_| "55000".to_string()).parse().unwrap_or(55000),
    env::var("WAZUH_API_USERNAME").unwrap_or_else(|_| "wazuh".to_string()),
    env::var("WAZUH_API_PASSWORD").unwrap_or_else(|_| "wazuh".to_string()),
    env::var("WAZUH_INDEXER_HOST").unwrap_or_else(|_| "127.0.0.1".to_string()),
    env::var("WAZUH_INDEXER_PORT").unwrap_or_else(|_| "9200".to_string()).parse().unwrap_or(9200),
    env::var("WAZUH_INDEXER_USERNAME").unwrap_or_else(|_| "admin".to_string()),
    env::var("WAZUH_INDEXER_PASSWORD").unwrap_or_else(|_| "admin".to_string()),
    env::var("WAZUH_VERIFY_SSL").unwrap_or_else(|_| "false".to_string()).parse().unwrap_or(false), // Set to true in production with valid certs
    Some("https".to_string()) // Protocol: "http" or "https"
);

// Then, create specific clients or all clients:
// let mut agents_client = factory.create_agents_client();
// let mut rules_client = factory.create_rules_client();
// OR
// let mut all_clients = factory.create_all_clients();
// let agent_summary = all_clients.agents.get_agents_summary().await?;
```

## Error Handling

The library provides comprehensive error handling with detailed error types:

```rust
use wazuh_client_rs::{WazuhClientFactory, WazuhClients, WazuhApiError};
use std::env;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Assume `factory` is initialized as shown in the Basic Usage example
    let factory = WazuhClientFactory::new(
        env::var("WAZUH_API_HOST").unwrap_or_else(|_| "127.0.0.1".to_string()),
        env::var("WAZUH_API_PORT").unwrap_or_else(|_| "55000".to_string()).parse().unwrap_or(55000),
        env::var("WAZUH_API_USERNAME").unwrap_or_else(|_| "wazuh".to_string()),
        env::var("WAZUH_API_PASSWORD").unwrap_or_else(|_| "wazuh".to_string()),
        env::var("WAZUH_INDEXER_HOST").unwrap_or_else(|_| "127.0.0.1".to_string()),
        env::var("WAZUH_INDEXER_PORT").unwrap_or_else(|_| "9200".to_string()).parse().unwrap_or(9200),
        env::var("WAZUH_INDEXER_USERNAME").unwrap_or_else(|_| "admin".to_string()),
        env::var("WAZUH_INDEXER_PASSWORD").unwrap_or_else(|_| "admin".to_string()),
        env::var("WAZUH_VERIFY_SSL").unwrap_or_else(|_| "false".to_string()).parse().unwrap_or(false),
        Some("https".to_string())
    );
    let mut clients: WazuhClients = factory.create_all_clients();

    match clients.agents.get_agent("invalid-id-123").await {
        Ok(agent) => println!("Agent: {:?}", agent.name),
        Err(WazuhApiError::HttpError { status, message, .. }) => {
            // Specific HTTP errors, e.g. 404 Not Found, 401 Unauthorized
            eprintln!("HTTP Error {}: {}", status, message);
            if status == reqwest::StatusCode::NOT_FOUND {
                eprintln!("The agent 'invalid-id-123' was not found.");
            } else if status == reqwest::StatusCode::UNAUTHORIZED {
                eprintln!("Authentication failed. Check your API credentials.");
            }
        }
        Err(WazuhApiError::AuthenticationError(msg)) => {
            eprintln!("Wazuh API Authentication Error: {}", msg);
        }
        Err(WazuhApiError::ApiError(msg)) => {
            // General API errors reported by Wazuh
            eprintln!("Wazuh API Error: {}", msg);
        }
        Err(WazuhApiError::RequestError(reqwest_err)) => {
            // Errors from the underlying reqwest client (network issues, timeouts)
            eprintln!("Network or Request Error: {}", reqwest_err);
        }
        Err(WazuhApiError::JsonError(json_err)) => {
            eprintln!("JSON Parsing Error: {}", json_err);
        }
        // Handle other variants as needed
        Err(e) => eprintln!("An unexpected error occurred: {}", e),
    }
    Ok(())
}
```

## Examples

The `examples/` directory contains comprehensive examples:

- [`basic_usage.rs`](examples/basic_usage.rs) - Basic client setup and usage
- [`agent_management.rs`](examples/agent_management.rs) - Complete agent lifecycle management
- [`cluster_monitoring.rs`](examples/cluster_monitoring.rs) - Cluster health and monitoring
- [`rule_management.rs`](examples/rule_management.rs) - Rule creation and management
- [`log_analysis.rs`](examples/log_analysis.rs) - Log querying and analysis
- [`vulnerability_detection.rs`](examples/vulnerability_detection.rs) - Vulnerability scanning

Run examples with:

```bash
cargo run --example basic_usage
cargo run --example agent_management
```


## Features

### Default Features
- `tls` - Enable TLS support using native TLS

### Optional Features
- `rustls` - Use rustls instead of native TLS

Enable features in your `Cargo.toml`:

```toml
[dependencies]
wazuh-client = { version = "0.1.0", features = ["rustls"] }
```

## Compatibility

- **Rust**: 1.70.0 or later
- **Wazuh**: 4.12 or later 

## Contributing

Contributions are welcome! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add test
5. Submit a pull request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Support

- 📖 [Documentation](https://docs.rs/wazuh-client)
- 🐛 [Issue Tracker](https://github.com/gbrigandi/wazuh-client-rs/issues)
- 💬 [Discussions](https://github.com/gbrigandi/wazuh-client-rs/discussions)
