use shadow_core_rust_proxy::{serve, ProxyConfig};
use std::env;
use std::net::SocketAddr;

#[tokio::main]
async fn main() {
    let config = ProxyConfig::from_env().unwrap_or_else(|error| {
        eprintln!("configuration error: {error}");
        std::process::exit(2);
    });
    let addr = env::var("SHADOW_PROXY_ADDR")
        .unwrap_or_else(|_| "127.0.0.1:8080".into())
        .parse::<SocketAddr>()
        .unwrap_or_else(|_| {
            eprintln!("invalid SHADOW_PROXY_ADDR");
            std::process::exit(2);
        });
    println!("shadow-core-rust-proxy listening on {addr}");
    if let Err(error) = serve(config, addr).await {
        eprintln!("proxy server failed: {error}");
        std::process::exit(1);
    }
}
