//! `mish-server`: spawn a shell on a PTY and serve it over QUIC datagrams.
//!
//! Binds a UDP socket, prints `MISH CONNECT <port> <hex-cert>` on stdout (the
//! client trusts exactly this cert, exchanged over the authenticated SSH
//! channel), then — with `--detach` — daemonizes (fork + setsid + redirect
//! stdio) so the SSH session can fully close while the server keeps serving.
//!
//! The socket is bound and the line printed *before* any tokio runtime exists,
//! so the fork happens in a single-threaded process. The child then builds the
//! runtime and constructs the Quinn endpoint from the inherited socket.
//!
//! Usage: `mish-server [--detach] [-p PORT|-p LOW:HIGH] [-l KEY=VAL]... [bind-port] [-- command]`
//!
//! Env: `MOSH_SERVER_NETWORK_TMOUT` (mid-session idle, default 300s),
//! `MOSH_SERVER_SIGNAL_TMOUT` (wait for the first connection, default 60s).

use std::io::Write;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use mish::pty::PtyProcess;
use mish::server::run_server;
use mish_ssp::clock::SystemClock;

struct Options {
    detach: bool,
    /// Candidate ports to try, in order (`[0]` = ephemeral).
    ports: Vec<u16>,
    /// Locale/env assignments to export to the child (`-l KEY=VAL`).
    locale: Vec<(String, String)>,
    command: Option<String>,
}

fn parse_args() -> Result<Options> {
    let mut opts = Options {
        detach: false,
        ports: Vec::new(),
        locale: Vec::new(),
        command: None,
    };
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--detach" => opts.detach = true,
            "-p" => {
                let spec = args.next().context("-p needs a value")?;
                opts.ports = parse_ports(&spec)?;
            }
            "-l" => {
                let kv = args.next().context("-l needs KEY=VAL")?;
                let (k, v) = kv.split_once('=').context("-l expects KEY=VAL")?;
                opts.locale.push((k.to_string(), v.to_string()));
            }
            "--" => {
                let rest: Vec<String> = args.by_ref().collect();
                if !rest.is_empty() {
                    opts.command = Some(rest.join(" "));
                }
            }
            // Legacy positional port.
            other if !other.starts_with('-') => {
                if let Ok(p) = other.parse::<u16>() {
                    opts.ports = vec![p];
                }
            }
            other => bail!("unknown option: {other}"),
        }
    }
    if opts.ports.is_empty() {
        opts.ports = vec![0]; // ephemeral
    }
    Ok(opts)
}

/// Parse `-p` value: a single port or an inclusive `LOW:HIGH` range.
fn parse_ports(spec: &str) -> Result<Vec<u16>> {
    if let Some((lo, hi)) = spec.split_once(':') {
        let lo: u16 = lo.parse().context("bad port-range low")?;
        let hi: u16 = hi.parse().context("bad port-range high")?;
        Ok((lo..=hi).collect())
    } else {
        Ok(vec![spec.parse().context("bad port")?])
    }
}

fn bind_in_range(ports: &[u16]) -> Result<std::net::UdpSocket> {
    let mut last_err = None;
    for &p in ports {
        match std::net::UdpSocket::bind(("0.0.0.0", p)) {
            Ok(s) => return Ok(s),
            Err(e) => last_err = Some(e),
        }
    }
    Err(last_err.unwrap().into())
}

fn main() -> Result<()> {
    let opts = parse_args()?;

    // Export locale/env for the child shell.
    for (k, v) in &opts.locale {
        std::env::set_var(k, v);
    }

    mish_quic::config::init_crypto();
    let (server_config, cert) = mish_quic::config::self_signed_server_config();
    let socket = bind_in_range(&opts.ports).context("binding UDP socket")?;
    let port = socket.local_addr()?.port();

    println!("MISH CONNECT {port} {}", mish::bootstrap::to_hex(cert.as_ref()));
    std::io::stdout().flush().ok();
    eprintln!("mish server listening on UDP port {port}");

    if opts.detach {
        daemonize().context("daemonizing")?;
    }

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

    // Signal timeout: give up if no client connects within the window.
    let signal_timeout = env_secs("MOSH_SERVER_SIGNAL_TMOUT", 60);
    let t = match tokio::time::timeout(signal_timeout, mish_quic::transport::accept(&endpoint)).await
    {
        Ok(conn) => conn.context("accepting QUIC connection")?,
        Err(_) => {
            eprintln!("no client connected within the signal timeout; exiting");
            return Ok(());
        }
    };
    eprintln!("client connected from {}", t.remote_address());

    let pty = PtyProcess::spawn(&command, cols, rows).context("spawning PTY child")?;
    let clock = Arc::new(SystemClock::new());
    let network_timeout = Some(env_secs("MOSH_SERVER_NETWORK_TMOUT", 300));

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

fn env_secs(var: &str, default: u64) -> Duration {
    let secs = std::env::var(var)
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(default);
    Duration::from_secs(secs)
}

/// Standard daemonize: fork (parent exits), setsid, redirect stdio to /dev/null.
/// Called before the tokio runtime exists, so the process is single-threaded.
#[cfg(unix)]
fn daemonize() -> std::io::Result<()> {
    use std::io::Error;
    unsafe {
        match libc::fork() {
            -1 => return Err(Error::last_os_error()),
            0 => {}
            _ => std::process::exit(0),
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
