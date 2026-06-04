//! `mish-client`: bootstrap a session like mosh, then attach the local TTY.
//!
//! Like the upstream `mosh` wrapper, this SSHes to the host, starts
//! `mish-server` there, reads the `MISH CONNECT <port> <cert>` line it prints,
//! and opens the QUIC/UDP session to that port — trusting exactly that
//! certificate (exchanged over the authenticated SSH channel). It then captures
//! raw keystrokes (forwarded as a `UserStream`), repaints received screens, and
//! tracks SIGWINCH resizes. Detach with `Ctrl-]`.
//!
//! Usage:
//! ```text
//! mish-client [user@]host [-- command]      # SSH bootstrap (like `mosh host`)
//! mish-client --local [-- command]          # run the server locally (testing)
//!
//! Options:
//!   --local            start mish-server as a local child (no SSH)
//!   --ssh <cmd>        ssh command to use (default: ssh)
//!   --server <cmd>     mish-server command to run (default: mish-server,
//!                      or the sibling binary in --local mode)
//! ```

use std::sync::Arc;

use anyhow::{bail, Context, Result};
use mish::bootstrap::{self, Bootstrap};
use mish::client::{run_client, ClientInput};
use mish_quic::{transport, CertificateDer};
use mish_ssp::clock::SystemClock;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::mpsc;

/// Detach key: Ctrl-] (0x1d), same as telnet's escape.
const DETACH: u8 = 0x1d;

struct Options {
    local: bool,
    ssh_cmd: String,
    server_cmd: Option<String>,
    host: Option<String>,
    command: Option<String>,
}

fn parse_args() -> Result<Options> {
    let mut opts = Options {
        local: false,
        ssh_cmd: "ssh".into(),
        server_cmd: None,
        host: None,
        command: None,
    };
    let mut args = std::env::args().skip(1).peekable();
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--local" => opts.local = true,
            "--ssh" => opts.ssh_cmd = args.next().context("--ssh needs a value")?,
            "--server" => opts.server_cmd = Some(args.next().context("--server needs a value")?),
            "--" => {
                let rest: Vec<String> = args.by_ref().collect();
                if !rest.is_empty() {
                    opts.command = Some(rest.join(" "));
                }
            }
            "-h" | "--help" => {
                print_usage();
                std::process::exit(0);
            }
            other if other.starts_with('-') => bail!("unknown option: {other}"),
            other => opts.host = Some(other.to_string()),
        }
    }
    if !opts.local && opts.host.is_none() {
        print_usage();
        bail!("a host is required (or use --local)");
    }
    Ok(opts)
}

fn print_usage() {
    eprintln!(
        "usage: mish-client [user@]host [-- command]\n       mish-client --local [-- command]\n\noptions: --local  --ssh <cmd>  --server <cmd>"
    );
}

/// Default `mish-server` command for local mode: the sibling binary next to this
/// executable, falling back to `mish-server` on PATH.
fn default_local_server() -> String {
    std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|d| d.join("mish-server")))
        .filter(|p| p.exists())
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_else(|| "mish-server".into())
}

#[tokio::main]
async fn main() -> Result<()> {
    let opts = parse_args()?;

    // 1. Bootstrap: get (udp addr, cert) by starting mish-server locally or via SSH.
    let boot: Bootstrap = if opts.local {
        let server = opts.server_cmd.unwrap_or_else(default_local_server);
        eprintln!("[mish-client] starting local server `{server}`…");
        bootstrap::local(&server, opts.command.as_deref())
            .await
            .context("local bootstrap")?
    } else {
        let host = opts.host.clone().unwrap();
        let server = opts.server_cmd.unwrap_or_else(|| "mish-server".into());
        eprintln!("[mish-client] {} {host} {server}…", opts.ssh_cmd);
        bootstrap::ssh(&opts.ssh_cmd, &host, &server, opts.command.as_deref())
            .await
            .context("ssh bootstrap")?
    };
    eprintln!("[mish-client] connecting to {} …", boot.addr);

    // 2. Open the QUIC session to the bootstrapped port, trusting its cert.
    let cert = CertificateDer::from(boot.cert_der.clone());
    let endpoint = transport::client_endpoint("0.0.0.0:0".parse().unwrap(), cert)
        .context("creating QUIC client endpoint")?;
    let t = transport::connect(&endpoint, boot.addr, "localhost")
        .await
        .context("connecting to server")?;

    // 3. Drive the local terminal.
    run_terminal(t).await;

    // Dropping `boot` tears down the server / ssh channel.
    drop(boot);
    Ok(())
}

/// Put the TTY in raw mode and run the client session until detach or close.
async fn run_terminal(t: transport::QuicTransport) {
    let (cols, rows) = crossterm::terminal::size().unwrap_or((80, 24));

    if crossterm::terminal::enable_raw_mode().is_err() {
        eprintln!("[mish-client] not a terminal; cannot enter raw mode");
        return;
    }
    // Enter alternate screen so we don't clobber the user's scrollback.
    print!("\x1b[?1049h");
    use std::io::Write;
    std::io::stdout().flush().ok();
    let _guard = TerminalGuard;

    let (in_tx, in_rx) = mpsc::channel::<ClientInput>(256);
    let (out_tx, mut out_rx) = mpsc::unbounded_channel::<Vec<u8>>();

    // stdout: write rendered frames.
    let writer = tokio::spawn(async move {
        let mut stdout = tokio::io::stdout();
        while let Some(bytes) = out_rx.recv().await {
            if stdout.write_all(&bytes).await.is_err() || stdout.flush().await.is_err() {
                break;
            }
        }
    });

    // stdin: forward raw keystrokes; Ctrl-] requests a clean detach.
    let key_tx = in_tx.clone();
    tokio::spawn(async move {
        let mut stdin = tokio::io::stdin();
        let mut buf = [0u8; 1024];
        loop {
            match stdin.read(&mut buf).await {
                Ok(0) | Err(_) => {
                    let _ = key_tx.send(ClientInput::Detach).await;
                    break;
                }
                Ok(n) => {
                    if buf[..n].contains(&DETACH) {
                        let _ = key_tx.send(ClientInput::Detach).await;
                        break;
                    }
                    if key_tx
                        .send(ClientInput::Keys(buf[..n].to_vec()))
                        .await
                        .is_err()
                    {
                        break;
                    }
                }
            }
        }
    });

    // SIGWINCH: report new terminal size.
    let resize_tx = in_tx.clone();
    tokio::spawn(async move {
        let mut sig =
            match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::window_change()) {
                Ok(s) => s,
                Err(_) => return,
            };
        while sig.recv().await.is_some() {
            if let Ok((cols, rows)) = crossterm::terminal::size() {
                if resize_tx
                    .send(ClientInput::Resize { cols, rows })
                    .await
                    .is_err()
                {
                    break;
                }
            }
        }
    });

    let clock = Arc::new(SystemClock::new());

    // Run until the session ends or the user detaches (Ctrl-] → ClientInput::
    // Detach, which triggers a clean shutdown handshake inside run_client).
    // Predictive echo is adaptive (mosh's default --predict=adaptive).
    run_client(
        Arc::new(t),
        cols,
        rows,
        clock,
        mish_terminal::predict::PredictMode::Adaptive,
        in_rx,
        out_tx,
    )
    .await;

    drop(_guard);
    writer.abort();
}

/// Restores cooked mode and leaves the alternate screen on drop.
struct TerminalGuard;
impl Drop for TerminalGuard {
    fn drop(&mut self) {
        let _ = crossterm::terminal::disable_raw_mode();
        print!("\x1b[?1049l\x1b[?25h");
        use std::io::Write;
        let _ = std::io::stdout().flush();
    }
}
