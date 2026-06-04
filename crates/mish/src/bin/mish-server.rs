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

    // Bind on all interfaces so a remote client (post-SSH bootstrap) can reach
    // us; the client learns the actual port from the line we print.
    let bind: SocketAddr = format!("0.0.0.0:{port}").parse().unwrap();
    let (endpoint, addr, cert) = {
        let (ep, cert) = transport::server_endpoint(bind)?;
        let addr = ep.local_addr()?;
        (ep, addr, cert)
    };

    // Machine-parseable bootstrap line on stdout (mosh prints `MISH CONNECT
    // <port> <key>`); we carry the self-signed cert (DER, hex) so the client can
    // trust exactly this server over the already-authenticated SSH channel.
    println!(
        "MISH CONNECT {} {}",
        addr.port(),
        mish::bootstrap::to_hex(cert.as_ref())
    );
    use std::io::Write;
    std::io::stdout().flush().ok();
    eprintln!("mish server listening on UDP port {}", addr.port());

    // Serve a single connection (one shell per server invocation, like mosh).
    let t = transport::accept(&endpoint)
        .await
        .context("accepting QUIC connection")?;
    eprintln!("client connected from {}", t.remote_address());

    let pty = PtyProcess::spawn(&command, cols, rows).context("spawning PTY child")?;
    let clock = Arc::new(SystemClock::new());

    // Idle network timeout (mosh's MOSH_SERVER_NETWORK_TMOUT); default 5 minutes.
    let network_timeout = std::env::var("MOSH_SERVER_NETWORK_TMOUT")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .map(std::time::Duration::from_secs)
        .or(Some(std::time::Duration::from_secs(300)));

    run_server(
        Arc::new(t),
        cols,
        rows,
        clock,
        network_timeout,
        pty.output,
        pty.control,
    )
    .await;
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
