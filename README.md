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
wazuh-client = "0.1.7"
tokio = { version = "1.0", features = ["full"] }
```

### Basic Usage

```rust
use wazuh_client_rs::{WazuhClientFactory, WazuhClients};
use std::env;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Setup the factory with your Wazuh API and Indexer credentials
    let factory = WazuhClientFactory::builder()
        .api_host(env::var("WAZUH_API_HOST").unwrap_or_else(|_| "127.0.0.1".to_string()))
        .api_port(env::var("WAZUH_API_PORT").unwrap_or_else(|_| "55000".to_string()).parse().unwrap_or(55000))
        .api_credentials(
            env::var("WAZUH_API_USERNAME").unwrap_or_else(|_| "wazuh".to_string()),
            env::var("WAZUH_API_PASSWORD").unwrap_or_else(|_| "wazuh".to_string()),
        )
        .indexer_host(env::var("WAZUH_INDEXER_HOST").unwrap_or_else(|_| "127.0.0.1".to_string()))
        .indexer_port(env::var("WAZUH_INDEXER_PORT").unwrap_or_else(|_| "9200".to_string()).parse().unwrap_or(9200))
        .indexer_credentials(
            env::var("WAZUH_INDEXER_USERNAME").unwrap_or_else(|_| "admin".to_string()),
            env::var("WAZUH_INDEXER_PASSWORD").unwrap_or_else(|_| "admin".to_string()),
        )
        .verify_ssl(env::var("WAZUH_VERIFY_SSL").unwrap_or_else(|_| "false".to_string()).parse().unwrap_or(false))
        .protocol("https") // Or "http" if not using SSL
        .build();

    // Create a collection of clients
    let mut clients: WazuhClients = factory.create_all_clients();

    // Get agent summary
    let summary = clients.agents.get_agents_summary().await?;
    println!("Total agents: {}", summary.connection.total);

    // Get a few rules
    let rules = clients.rules.get_rules(Some(5), None, None, None, None).await?;
    println!("Fetched {} rules.", rules.len());

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
    let factory = WazuhClientFactory::builder()
        .api_host("127.0.0.1")
        .api_credentials("wazuh", "wazuh")
        .build();
    let mut clients: WazuhClients = factory.create_all_clients();

    // Get agent details
    match clients.agents.get_agent("001").await {
        Ok(agent) => println!("Agent 001 Status: {}", agent.status),
        Err(e) => eprintln!("Error getting agent 001: {}", e),
    }
    
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
    let factory = WazuhClientFactory::builder()
        .api_host("127.0.0.1")
        .api_credentials("wazuh", "wazuh")
        .build();
    let mut clients: WazuhClients = factory.create_all_clients();

    // Get a few rules
    let rules = clients.rules.get_rules(Some(5), None, None, None, None).await?;
    println!("Fetched {} rules.", rules.len());

    // Get rules by group
    let ssh_rules = clients.rules.get_rules_by_group("ssh").await?;
    println!("Found {} rules in the 'ssh' group.", ssh_rules.len());

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
    let factory = WazuhClientFactory::builder()
        .api_host("127.0.0.1")
        .api_credentials("wazuh", "wazuh")
        .build();
    let mut clients: WazuhClients = factory.create_all_clients();

    // Get cluster status
    match clients.cluster.get_cluster_status().await {
        Ok(status) => println!("Cluster enabled: {}", status.enabled),
        Err(e) => eprintln!("Error getting cluster status: {}", e),
    }

    // Get cluster nodes
    match clients.cluster.get_cluster_nodes(None, None, None).await {
        Ok(nodes) => println!("Found {} cluster nodes.", nodes.len()),
        Err(e) => eprintln!("Error getting cluster nodes: {}", e),
    }

    Ok(())
}
```

### Log Analysis with Indexer

```rust
use wazuh_client_rs::{WazuhClientFactory, WazuhClients};
use std::env;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Ensure indexer details are correctly set
    let factory = WazuhClientFactory::builder()
        .indexer_host("127.0.0.1")
        .indexer_credentials("admin", "admin")
        .build();
    let clients: WazuhClients = factory.create_all_clients();

    // Get recent alerts
    match clients.indexer.get_alerts(Some(10)).await {
        Ok(alerts) => println!("Retrieved {} alerts.", alerts.len()),
        Err(e) => eprintln!("Error getting alerts: {}", e),
    }

    Ok(())
}
```

## Configuration

### Environment Variables

You can configure the client using environment variables:

```bash
export WAZUH_API_HOST="https://your-wazuh-manager.com"
export WAZUH_API_PORT="55000"
export WAZUH_API_USERNAME="wazuh"
export WAZUH_API_PASSWORD="your-password"
export WAZUH_VERIFY_SSL="true"

export WAZUH_INDEXER_HOST="your-wazuh-indexer.com"
export WAZUH_INDEXER_PORT="9200"
export WAZUH_INDEXER_USERNAME="admin"
export WAZUH_INDEXER_PASSWORD="admin"
```

### Client Factory Initialization

The `WazuhClientFactory` is used to configure and create clients using a builder pattern.

```rust
use wazuh_client_rs::WazuhClientFactory;
use std::env;

// Example of initializing the factory using the builder
let factory = WazuhClientFactory::builder()
    .api_host(env::var("WAZUH_API_HOST").unwrap_or_else(|_| "127.0.0.1".to_string()))
    .api_port(env::var("WAZUH_API_PORT").unwrap_or_else(|_| "55000".to_string()).parse().unwrap_or(55000))
    .api_credentials(
        env::var("WAZUH_API_USERNAME").unwrap_or_else(|_| "wazuh".to_string()),
        env::var("WAZUH_API_PASSWORD").unwrap_or_else(|_| "wazuh".to_string()),
    )
    .indexer_host(env::var("WAZUH_INDEXER_HOST").unwrap_or_else(|_| "127.0.0.1".to_string()))
    .indexer_port(env::var("WAZUH_INDEXER_PORT").unwrap_or_else(|_| "9200".to_string()).parse().unwrap_or(9200))
    .indexer_credentials(
        env::var("WAZUH_INDEXER_USERNAME").unwrap_or_else(|_| "admin".to_string()),
        env::var("WAZUH_INDEXER_PASSWORD").unwrap_or_else(|_| "admin".to_string()),
    )
    .verify_ssl(env::var("WAZUH_VERIFY_SSL").unwrap_or_else(|_| "false".to_string()).parse().unwrap_or(false))
    .protocol("https")
    .build();

// Then, create specific clients or all clients:
// let mut agents_client = factory.create_agents_client();
// let mut all_clients = factory.create_all_clients();
```

## Error Handling

The library provides comprehensive error handling with detailed error types:

```rust
use wazuh_client_rs::{WazuhClientFactory, WazuhClients, WazuhApiError};
use std::env;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Assume `factory` is initialized
    let factory = WazuhClientFactory::builder().build();
    let mut clients: WazuhClients = factory.create_all_clients();

    match clients.agents.get_agent("invalid-id-123").await {
        Ok(agent) => println!("Agent: {:?}", agent.name),
        Err(WazuhApiError::HttpError { status, message, .. }) => {
            eprintln!("HTTP Error {}: {}", status, message);
        }
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
