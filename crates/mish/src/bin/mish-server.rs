//! `mish-server`: spawn a shell on a PTY and serve it over QUIC.
//!
//! Demo bootstrap: binds a QUIC endpoint and prints the address to connect to.
//! A production deployment would exchange the server certificate over SSH (as
//! upstream mosh exchanges its key); here the client uses insecure verification,
//! so this is for trusted/local use only.
//!
//! Usage: `mish-server [bind-port] [-- command...]`  (defaults: ephemeral port,
//! `$SHELL`).

use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::{Context, Result};
use mish::pty::PtyProcess;
use mish::server::run_server;
use mish_quic::transport;
use mish_ssp::clock::SystemClock;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let args: Vec<String> = std::env::args().skip(1).collect();
    let port: u16 = args.first().and_then(|a| a.parse().ok()).unwrap_or(0);
    let command = parse_command(&args)
        .unwrap_or_else(|| std::env::var("SHELL").unwrap_or_else(|_| "/bin/sh".into()));

    // Initial geometry; the client resizes us as soon as it connects.
    let (cols, rows) = (80u16, 24u16);

    let bind: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
    let (endpoint, addr, _cert) = {
        let (ep, cert) = transport::server_endpoint(bind)?;
        let addr = ep.local_addr()?;
        (ep, addr, cert)
    };

    println!("mish server listening on {addr}");
    println!("connect with:  mish-client {addr}");
    eprintln!("(demo: insecure TLS verification — use over trusted networks only)");

    // Serve a single connection (one shell per server invocation, like mosh).
    let t = transport::accept(&endpoint)
        .await
        .context("accepting QUIC connection")?;
    eprintln!("client connected from {}", t.remote_address());

    let pty = PtyProcess::spawn(&command, cols, rows).context("spawning PTY child")?;
    let clock = Arc::new(SystemClock::new());

    run_server(Arc::new(t), cols, rows, clock, pty.output, pty.control).await;
    eprintln!("session ended");
    Ok(())
}

/// Extract a command after a `--` separator, if present.
fn parse_command(args: &[String]) -> Option<String> {
    let idx = args.iter().position(|a| a == "--")?;
    let rest = &args[idx + 1..];
    if rest.is_empty() {
        None
    } else {
        Some(rest.join(" "))
    }
}
