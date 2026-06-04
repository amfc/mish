//! `mish-server`: spawn a shell on a PTY and serve it over QUIC datagrams.
//!
//! Binds a UDP socket, prints `MISH CONNECT <port> <hex-cert>` on stdout (the
//! client trusts exactly this cert, exchanged over the authenticated SSH
//! channel), then — with `--detach` — daemonizes (fork + setsid + redirect
//! stdio) so the SSH session can fully close while the server keeps serving.
//!
//! The socket is bound and the line printed *before* any tokio runtime exists,
//! so the fork happens in a single-threaded process (forking a live
//! multi-threaded async runtime is unsafe). The child then builds the runtime
//! and constructs the Quinn endpoint from the inherited socket.
//!
//! Usage: `mish-server [--detach] [bind-port] [-- command...]`
//! (defaults: ephemeral port, `$SHELL`).

use std::io::Write;
use std::sync::Arc;

use anyhow::{Context, Result};
use mish::pty::PtyProcess;
use mish::server::run_server;
use mish_ssp::clock::SystemClock;

struct Options {
    detach: bool,
    port: u16,
    command: Option<String>,
}

fn parse_args() -> Options {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let detach = args.iter().any(|a| a == "--detach");
    // First non-flag argument before `--` is the port.
    let dashdash = args.iter().position(|a| a == "--");
    let pre = &args[..dashdash.unwrap_or(args.len())];
    let port = pre
        .iter()
        .find(|a| !a.starts_with("--"))
        .and_then(|a| a.parse().ok())
        .unwrap_or(0);
    let command = dashdash.and_then(|i| {
        let rest = &args[i + 1..];
        (!rest.is_empty()).then(|| rest.join(" "))
    });
    Options {
        detach,
        port,
        command,
    }
}

fn main() -> Result<()> {
    let opts = parse_args();

    // Build the cert/config and bind the socket up front, before forking.
    mish_quic::config::init_crypto();
    let (server_config, cert) = mish_quic::config::self_signed_server_config();
    let socket = std::net::UdpSocket::bind(("0.0.0.0", opts.port))
        .context("binding UDP socket")?;
    let port = socket.local_addr()?.port();

    // Bootstrap line on stdout; human logs on stderr.
    println!("MISH CONNECT {port} {}", mish::bootstrap::to_hex(cert.as_ref()));
    std::io::stdout().flush().ok();
    eprintln!("mish server listening on UDP port {port}");

    if opts.detach {
        // Detach from the controlling terminal / SSH session. The parent exits
        // (so `ssh host mish-server …` returns and SSH closes); the child keeps
        // the inherited socket and serves on.
        daemonize().context("daemonizing")?;
    }

    // Now (in the daemon child, or in the foreground for --local) start tokio.
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("building tokio runtime")?;
    runtime.block_on(serve(socket, server_config, opts.command))
}

async fn serve(
    socket: std::net::UdpSocket,
    server_config: mish_quic::ServerConfig,
    command: Option<String>,
) -> Result<()> {
    let command =
        command.unwrap_or_else(|| std::env::var("SHELL").unwrap_or_else(|_| "/bin/sh".into()));
    let (cols, rows) = (80u16, 24u16);

    let endpoint = mish_quic::transport::server_from_socket(socket, server_config)
        .context("building QUIC endpoint")?;

    let t = mish_quic::transport::accept(&endpoint)
        .await
        .context("accepting QUIC connection")?;
    eprintln!("client connected from {}", t.remote_address());

    let pty = PtyProcess::spawn(&command, cols, rows).context("spawning PTY child")?;
    let clock = Arc::new(SystemClock::new());

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

/// Standard daemonize: fork (parent exits), setsid (new session, no controlling
/// tty), then redirect stdio to /dev/null. Called before the tokio runtime
/// exists, so the process is single-threaded and fork is safe.
#[cfg(unix)]
fn daemonize() -> std::io::Result<()> {
    use std::io::Error;
    unsafe {
        match libc::fork() {
            -1 => return Err(Error::last_os_error()),
            0 => {}                          // child continues
            _ => std::process::exit(0),      // parent returns to SSH and exits
        }
        if libc::setsid() == -1 {
            return Err(Error::last_os_error());
        }
        let devnull = libc::open(c"/dev/null".as_ptr(), libc::O_RDWR);
        if devnull >= 0 {
            libc::dup2(devnull, 0);
            libc::dup2(devnull, 1);
            libc::dup2(devnull, 2);
            if devnull > 2 {
                libc::close(devnull);
            }
        }
    }
    Ok(())
}

#[cfg(not(unix))]
fn daemonize() -> std::io::Result<()> {
    Ok(())
}
