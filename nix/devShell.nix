{ pkgs, rustVersion }:
let
  rustDevEnv = pkgs.rust-bin.stable."${rustVersion}".default.override {
    extensions = [ "rust-src" "rust-analyzer" ];
  };
in
pkgs.mkShell {
  packages = with pkgs; [
    # Rust toolchain
    rustDevEnv

    # Build dependencies (required by reqwest and other deps)
    pkg-config
    openssl

    # Development tools
    just
    cargo-nextest
    cargo-watch
    cargo-audit

    # Debugging
    lldb

    # Git hooks
    pre-commit
  ];

  shellHook = ''
    # Unset rustup environment variables to prevent conflicts with Nix-managed Rust
    unset RUSTUP_TOOLCHAIN
    unset RUSTUP_HOME
    
    echo ""
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "  Wazuh Client Library - Rust Development Environment"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo ""
    echo "  Project          : wazuh-client-rs (library)"
    echo "  Rust version     : ${rustVersion}"
    echo "  Toolchain        : ${rustDevEnv}/bin"
    echo "  Standard Library : ${rustDevEnv}/lib/rustlib/src/rust"
    echo ""
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo ""

    export RUST_SRC_PATH="${rustDevEnv}/lib/rustlib/src/rust/library"

    echo "Available commands:"
    echo "  cargo build              - Build the library"
    echo "  cargo test               - Run tests"
    echo "  cargo nextest run        - Run tests with nextest"
    echo "  cargo doc --open         - Generate and open documentation"
    echo "  cargo run --example NAME - Run an example"
    echo ""
    echo "Examples: basic_usage, agent_management, cluster_monitoring,"
    echo "          rule_management, log_analysis, vulnerability_detection"
    echo ""
  '';

  # Environment variables for SSL/TLS (required by reqwest)
  SSL_CERT_FILE = "${pkgs.cacert}/etc/ssl/certs/ca-bundle.crt";
}
