//! `mish-client`: bootstrap a session like mosh, then attach the local TTY.
//!
//! Like the upstream `mosh` wrapper, this SSHes to the host, starts
//! `mish-server` there, reads the `MISH CONNECT <port> <cert>` line it prints,
//! and opens the QUIC/UDP session to that port — trusting exactly that
//! certificate (exchanged over the authenticated SSH channel). It then captures
//! raw keystrokes (forwarded as a `UserStream`), repaints received screens, and
//! tracks SIGWINCH resizes. Quick-detach with `Ctrl-]`. The escape prefix
//! `Ctrl-^` (configurable via `MOSH_ESCAPE_KEY`) then `.` quits, the prefix again
//! sends it literally, and `Ctrl-Z` suspends; on resume (`fg`/SIGCONT) raw mode
//! is restored and the screen repainted. **Shift-PageUp / Shift-PageDown** scroll
//! into the server's scrollback history (fetched over a reliable side-channel);
//! any other keystroke returns to the live screen.
//!
//! Usage:
//! ```text
//! mish-client [user@]host [-- command]    # SSH bootstrap (like `mosh host`)
//! mish-client --local [-- command]        # run the server locally (testing)
//!
//! Options:
//!   --local            start mish-server as a local child (no SSH)
//!   --ssh <cmd>        ssh command, shell-split (default: ssh); we append -n and
//!                      -tt and run `host -- <server …>`, like upstream mosh
//!   --no-ssh-pty       don't allocate a remote PTY (omit ssh -tt)
//!   --server <cmd>     mish-server command to run (default: mish-server,
//!                      or the sibling binary in --local mode)
//!   --predict <mode>   adaptive|always|never|experimental (default: adaptive);
//!     -a/-n            also via MOSH_PREDICTION_DISPLAY; -a=always, -n=never
//!   --no-init          don't enter the alternate screen (MOSH_NO_TERM_INIT)
//!   --version          print version and exit
//! ```

use std::sync::Arc;

use anyhow::{bail, Context, Result};
use mish::bootstrap::{self, shell_split, Bootstrap};
use mish::client::{run_client, ClientInput};
use mish_quic::transport;
use mish_ssp::clock::SystemClock;
use mish_terminal::predict::PredictMode;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::mpsc;

/// Name of the server binary this client bootstraps (locally or over SSH).
/// Change this one constant to rebrand the server process name.
const SERVER_BIN: &str = "mish-server";

/// Quick-detach key: Ctrl-] (0x1d), same as telnet's escape.
const DETACH: u8 = 0x1d;

/// Default escape prefix: Ctrl-^ (0x1e), as in upstream mosh. Followed by `.` to
/// quit, the prefix again to send it literally, or Ctrl-Z to suspend.
const DEFAULT_ESCAPE: u8 = 0x1e;
const CTRL_Z: u8 = 0x1a;

/// Resolve the escape prefix byte from `MOSH_ESCAPE_KEY` (its first byte; a bare
/// ASCII letter is taken as its control code, e.g. `a` → Ctrl-A), else the default.
fn escape_key() -> u8 {
    match std::env::var("MOSH_ESCAPE_KEY")
        .ok()
        .and_then(|s| s.bytes().next())
    {
        Some(b @ b'a'..=b'z') => b & 0x1f,
        Some(b @ b'A'..=b'Z') => b & 0x1f,
        Some(b) => b,
        None => DEFAULT_ESCAPE,
    }
}

/// Leave raw mode + the alternate screen, stop ourselves (SIGTSTP), and — once
/// resumed (SIGCONT) — the installed handler re-enters raw mode and repaints.
#[cfg(unix)]
fn suspend(no_init: bool) {
    use std::io::Write;
    let _ = crossterm::terminal::disable_raw_mode();
    // Show the cursor, and leave the alternate screen unless we never entered it.
    print!("{}\x1b[?25h", if no_init { "" } else { "\x1b[?1049l" });
    std::io::stdout().flush().ok();
    // Stop the whole process; execution resumes here on SIGCONT (`fg`).
    unsafe {
        libc::raise(libc::SIGTSTP);
    }
}

struct Options {
    local: bool,
    /// The ssh command, shell-split (e.g. `["ssh", "-p", "2222"]`).
    ssh_argv: Vec<String>,
    /// Allocate a remote PTY (`ssh -tt`); cleared by `--no-ssh-pty`.
    ssh_pty: bool,
    server_cmd: Option<String>,
    /// Speculative-echo mode (`--predict` / `-a` / `-n` / `MOSH_PREDICTION_DISPLAY`).
    predict: PredictMode,
    /// Suppress terminal initialization — don't enter the alternate screen
    /// (`--no-init` / `MOSH_NO_TERM_INIT`, mosh's smcup/rmcup suppression).
    no_init: bool,
    /// Named, reattachable session (`--session NAME`): the server keeps it alive
    /// across disconnects and reattaches to it on a later run (the "never lose
    /// your shell" mode). Opt-in; without it, a fresh session each time.
    session: Option<String>,
    /// Raw attach (`--attach IP PORT`): connect directly to an already-running
    /// server (no SSH/local bootstrap), with credentials in `$MISH_CONNECT`
    /// (the hex `<server-cert> <client-cert> <client-key>` from its MISH CONNECT
    /// line). Mirrors `mosh-client IP PORT` + `$MOSH_KEY`; used by test harnesses.
    attach: Option<(String, u16)>,
    host: Option<String>,
    command: Option<String>,
    /// Write a JSON event log here (`--log-file`); `None` disables logging.
    log_file: Option<std::path::PathBuf>,
    /// Max verbosity for the event log (`--log-level`, default debug).
    log_level: tracing::Level,
}

/// Resolve a `--predict` / `MOSH_PREDICTION_DISPLAY` mode name. `experimental`
/// is accepted but maps to `adaptive` (the aggressive mode isn't implemented).
fn parse_predict(name: &str) -> Result<PredictMode> {
    match name {
        "adaptive" => Ok(PredictMode::Adaptive),
        "always" => Ok(PredictMode::Always),
        "never" => Ok(PredictMode::Never),
        "experimental" => {
            eprintln!("[mish-client] --predict=experimental not implemented; using adaptive");
            Ok(PredictMode::Adaptive)
        }
        other => bail!("unknown --predict mode {other:?} (adaptive|always|never|experimental)"),
    }
}

fn parse_args() -> Result<Options> {
    let mut opts = Options {
        local: false,
        ssh_argv: vec!["ssh".into()],
        ssh_pty: true,
        server_cmd: None,
        // Default adaptive, overridable by env then by an explicit flag (mosh's
        // precedence: --predict > MOSH_PREDICTION_DISPLAY > adaptive).
        predict: match std::env::var("MOSH_PREDICTION_DISPLAY") {
            Ok(v) => parse_predict(&v).context("MOSH_PREDICTION_DISPLAY")?,
            Err(_) => PredictMode::Adaptive,
        },
        no_init: std::env::var_os("MOSH_NO_TERM_INIT").is_some(),
        session: None,
        attach: None,
        host: None,
        command: None,
        log_file: None,
        log_level: tracing::Level::DEBUG,
    };
    let mut args = std::env::args().skip(1).peekable();
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--local" => opts.local = true,
            "--ssh" => {
                let val = args.next().context("--ssh needs a value")?;
                opts.ssh_argv = shell_split(&val)?;
                if opts.ssh_argv.is_empty() {
                    bail!("--ssh value is empty");
                }
            }
            "--no-ssh-pty" => opts.ssh_pty = false,
            "--server" => opts.server_cmd = Some(args.next().context("--server needs a value")?),
            "--predict" => {
                let m = args.next().context("--predict needs a mode")?;
                opts.predict = parse_predict(&m)?;
            }
            "-a" | "--predict-always" => opts.predict = PredictMode::Always,
            "-n" | "--predict-never" => opts.predict = PredictMode::Never,
            "--no-init" => opts.no_init = true,
            "--session" => opts.session = Some(args.next().context("--session needs a NAME")?),
            "--attach" => {
                let ip = args.next().context("--attach needs IP PORT")?;
                let port: u16 = args
                    .next()
                    .context("--attach needs IP PORT")?
                    .parse()
                    .context("--attach PORT must be a number")?;
                opts.attach = Some((ip, port));
            }
            "--log-file" => {
                opts.log_file = Some(args.next().context("--log-file needs a PATH")?.into());
            }
            "--log-level" => {
                opts.log_level = mish::trace::parse_level(&args.next().context("--log-level needs a LEVEL")?);
            }
            "--version" => {
                println!("mish-client (mish) {}", env!("CARGO_PKG_VERSION"));
                std::process::exit(0);
            }
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
    if !opts.local && opts.host.is_none() && opts.attach.is_none() {
        print_usage();
        bail!("a host is required (or use --local / --attach)");
    }
    Ok(opts)
}

fn print_usage() {
    eprintln!(
        "usage: mish-client [user@]host [-- command]\n\
         \x20      mish-client --local [-- command]\n\n\
         options:\n\
         \x20 --local              run mish-server as a local child (no SSH)\n\
         \x20 --ssh <cmd>          ssh command, shell-split (default: ssh)\n\
         \x20 --no-ssh-pty         don't allocate a remote PTY (no ssh -tt)\n\
         \x20 --server <cmd>       mish-server command to run (default: mish-server)\n\
         \x20 --predict <mode>     adaptive|always|never|experimental (default: adaptive)\n\
         \x20 -a, --predict-always always echo locally; -n, --predict-never  disable\n\
         \x20 --no-init            don't enter the alternate screen (MOSH_NO_TERM_INIT)\n\
         \x20 --session <name>     reattachable persistent session (never lose your shell)\n\
         \x20 --attach IP PORT     attach to a running server ($MISH_CONNECT creds; for testing)\n\
         \x20 --log-file <path>    write a JSON event log (for debugging)\n\
         \x20 --log-level <lvl>    log verbosity: error|warn|info|debug|trace (default debug)\n\
         \x20 --version            print version and exit\n\
         \x20 -h, --help           show this help\n\n\
         env: MOSH_PREDICTION_DISPLAY, MOSH_NO_TERM_INIT, MOSH_ESCAPE_KEY"
    );
}

/// Default `mish-server` command for local mode: the sibling binary next to
/// this executable, falling back to `mish-server` on PATH.
fn default_local_server() -> String {
    std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|d| d.join(SERVER_BIN)))
        .filter(|p| p.exists())
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_else(|| SERVER_BIN.into())
}

#[tokio::main]
async fn main() -> Result<()> {
    let opts = parse_args()?;

    // Optional event log (--log-file): install before anything else so the whole
    // session — bootstrap, connect, run, disconnect — is captured.
    if let Some(path) = &opts.log_file {
        if let Err(e) = mish::trace::init_file_logging(path, "client", opts.log_level) {
            eprintln!("[mish-client] warning: could not open log file {}: {e}", path.display());
        }
    }
    tracing::info!(target: "mish::client", local = opts.local, "client starting");

    // Raw attach (--attach IP PORT): connect directly to a running server with
    // credentials from $MISH_CONNECT, no bootstrap. (Used by test harnesses;
    // mirrors `mosh-client IP PORT` + $MOSH_KEY.)
    if let Some((ip, port)) = opts.attach.clone() {
        return attach_session(&ip, port, opts.predict, opts.no_init).await;
    }

    // 1. Bootstrap: get (udp addr, cert) by starting mish-server locally or via SSH.
    let boot: Bootstrap = if opts.local {
        let server = opts.server_cmd.unwrap_or_else(default_local_server);
        eprintln!("[mish-client] starting local server `{server}`…");
        bootstrap::local(&server, opts.session.as_deref(), opts.command.as_deref())
            .await
            .context("local bootstrap")?
    } else {
        let host = opts.host.clone().unwrap();
        let server = opts.server_cmd.unwrap_or_else(|| SERVER_BIN.into());
        eprintln!("[mish-client] {} {host} {server}…", opts.ssh_argv.join(" "));
        bootstrap::ssh(
            &opts.ssh_argv,
            opts.ssh_pty,
            &host,
            &server,
            opts.session.as_deref(),
            opts.command.as_deref(),
        )
        .await
        .context("ssh bootstrap")?
    };
    eprintln!("[mish-client] connecting to {} …", boot.addr);

    // 2. Open the mutually-authenticated QUIC session: trust the server cert and
    //    present the minted client cert/key from the SSH-authenticated channel.
    let endpoint = transport::authenticated_client_endpoint(
        "0.0.0.0:0".parse().unwrap(),
        &boot.server_cert_der,
        &boot.client_cert_der,
        &boot.client_key_der,
    )
    .context("creating QUIC client endpoint")?;
    let t = transport::connect(&endpoint, boot.addr, "localhost")
        .await
        .context("connecting to server")?;
    tracing::info!(target: "mish::client", addr = %boot.addr, "connected to server");

    // 3. Drive the local terminal.
    run_terminal(t, opts.predict, opts.no_init).await;
    tracing::info!(target: "mish::client", "client session ended; tearing down");

    // Dropping `boot` tears down the server / ssh channel.
    drop(boot);
    Ok(())
}

/// Attach directly to a running server at `ip:port`, with the credential triple
/// (hex `server-cert client-cert client-key`) in `$MISH_CONNECT`. No bootstrap.
async fn attach_session(ip: &str, port: u16, predict: PredictMode, no_init: bool) -> Result<()> {
    let creds = std::env::var("MISH_CONNECT").context(
        "--attach requires $MISH_CONNECT = hex `<server-cert> <client-cert> <client-key>`",
    )?;
    let mut it = creds.split_whitespace();
    let mut next_der = |what: &str| -> Result<Vec<u8>> {
        let tok = it.next().with_context(|| format!("MISH_CONNECT: missing {what}"))?;
        bootstrap::from_hex(tok).with_context(|| format!("MISH_CONNECT: bad {what} hex"))
    };
    let server_cert = next_der("server cert")?;
    let client_cert = next_der("client cert")?;
    let client_key = next_der("client key")?;

    let addr: std::net::SocketAddr = format!("{ip}:{port}")
        .parse()
        .with_context(|| format!("bad --attach address {ip}:{port}"))?;
    let endpoint = transport::authenticated_client_endpoint(
        "0.0.0.0:0".parse().unwrap(),
        &server_cert,
        &client_cert,
        &client_key,
    )
    .context("creating QUIC client endpoint")?;
    eprintln!("[mish-client] attaching to {addr} …");
    let t = transport::connect(&endpoint, addr, "localhost")
        .await
        .context("connecting to server")?;
    run_terminal(t, predict, no_init).await;
    Ok(())
}

/// Put the TTY in raw mode and run the client session until detach or close.
async fn run_terminal(t: transport::QuicTransport, predict: PredictMode, no_init: bool) {
    let (cols, rows) = crossterm::terminal::size().unwrap_or((80, 24));

    if crossterm::terminal::enable_raw_mode().is_err() {
        eprintln!("[mish-client] not a terminal; cannot enter raw mode");
        return;
    }
    // Enter alternate screen so we don't clobber the user's scrollback — unless
    // --no-init (MOSH_NO_TERM_INIT) asks us to leave the main screen alone.
    if !no_init {
        print!("\x1b[?1049h");
        use std::io::Write;
        std::io::stdout().flush().ok();
    }
    let _guard = TerminalGuard { no_init };

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

    // stdin: forward raw keystrokes, with an escape state machine. The escape
    // prefix (Ctrl-^ by default, MOSH_ESCAPE_KEY-configurable) then: `.` quits,
    // the prefix again sends it literally, Ctrl-Z suspends. Ctrl-] is a quick
    // detach. The `escaping` flag persists across reads (the command byte may
    // arrive in the next chunk).
    let key_tx = in_tx.clone();
    let escape = escape_key();
    tokio::spawn(async move {
        let mut stdin = tokio::io::stdin();
        let mut buf = [0u8; 1024];
        let mut escaping = false;
        loop {
            let n = match stdin.read(&mut buf).await {
                Ok(0) | Err(_) => {
                    let _ = key_tx.send(ClientInput::Detach).await;
                    return;
                }
                Ok(n) => n,
            };
            let chunk = &buf[..n];
            // Scrollback keys: Shift-PageUp / Shift-PageDown (xterm modifier
            // encoding) drive the history viewer instead of being sent to the
            // shell. These arrive as one atomic read in practice; checking the
            // whole read keeps it out of the per-byte escape state machine.
            match chunk {
                b"\x1b[5;2~" => {
                    let _ = key_tx.send(ClientInput::ScrollUp).await;
                    continue;
                }
                b"\x1b[6;2~" => {
                    let _ = key_tx.send(ClientInput::ScrollDown).await;
                    continue;
                }
                _ => {}
            }
            let mut batch: Vec<u8> = Vec::with_capacity(n);
            let mut i = 0;
            while i < chunk.len() {
                // SGR mouse report (`ESC [ < … M/m`): pull it out whole so it
                // bypasses the keystroke path and reaches run_client, which
                // routes the wheel to scrollback / the app. Like a local
                // terminal, we assume the report arrives in one read; a report
                // split across reads falls through and is sent as plain bytes.
                if !escaping && chunk[i] == 0x1b && chunk[i + 1..].starts_with(b"[<") {
                    if let Some(rel) = chunk[i + 3..].iter().position(|&b| b == b'M' || b == b'm') {
                        let end = i + 3 + rel; // index of the M/m terminator
                        // Flush keystrokes that preceded the report, in order.
                        if !batch.is_empty()
                            && key_tx
                                .send(ClientInput::Keys(std::mem::take(&mut batch)))
                                .await
                                .is_err()
                        {
                            return;
                        }
                        if key_tx
                            .send(ClientInput::Mouse(chunk[i..=end].to_vec()))
                            .await
                            .is_err()
                        {
                            return;
                        }
                        i = end + 1;
                        continue;
                    }
                }
                let b = chunk[i];
                i += 1;
                if escaping {
                    escaping = false;
                    match b {
                        b'.' => {
                            if !batch.is_empty() {
                                let _ = key_tx
                                    .send(ClientInput::Keys(std::mem::take(&mut batch)))
                                    .await;
                            }
                            let _ = key_tx.send(ClientInput::Detach).await;
                            return;
                        }
                        x if x == escape => batch.push(escape), // literal prefix
                        CTRL_Z => {
                            // Flush pending keys, then suspend; on resume the
                            // SIGCONT handler restores raw mode + repaints.
                            if !batch.is_empty() {
                                let _ = key_tx
                                    .send(ClientInput::Keys(std::mem::take(&mut batch)))
                                    .await;
                            }
                            #[cfg(unix)]
                            suspend(no_init);
                        }
                        // Unknown escape command: ignore it (no passthrough).
                        _ => {}
                    }
                } else if b == escape {
                    escaping = true;
                } else if b == DETACH {
                    if !batch.is_empty() {
                        let _ = key_tx
                            .send(ClientInput::Keys(std::mem::take(&mut batch)))
                            .await;
                    }
                    let _ = key_tx.send(ClientInput::Detach).await;
                    return;
                } else {
                    batch.push(b);
                }
            }
            if !batch.is_empty() && key_tx.send(ClientInput::Keys(batch)).await.is_err() {
                return;
            }
        }
    });

    // SIGCONT: we were resumed (`fg`) after a stop. Re-enter raw mode + the
    // alternate screen and force a full repaint — the real terminal lost our
    // painted state while we were suspended (or stopped by any other means).
    #[cfg(unix)]
    {
        let redraw_tx = in_tx.clone();
        tokio::spawn(async move {
            let mut sig = match tokio::signal::unix::signal(
                tokio::signal::unix::SignalKind::from_raw(libc::SIGCONT),
            ) {
                Ok(s) => s,
                Err(_) => return,
            };
            while sig.recv().await.is_some() {
                let _ = crossterm::terminal::enable_raw_mode();
                if !no_init {
                    use std::io::Write;
                    print!("\x1b[?1049h");
                    std::io::stdout().flush().ok();
                }
                if redraw_tx.send(ClientInput::Redraw).await.is_err() {
                    break;
                }
            }
        });
    }

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

    // Share the transport with a scrollback fetcher (Shift-PgUp/PgDn pull history
    // over a reliable side-channel).
    let transport = Arc::new(t);
    let history: Arc<dyn mish::client::HistoryFetcher> =
        Arc::new(QuicHistory(transport.clone()));

    // Run until the session ends or the user detaches (Ctrl-] → ClientInput::
    // Detach, which triggers a clean shutdown handshake inside run_client).
    // Predictive echo mode comes from --predict / MOSH_PREDICTION_DISPLAY.
    run_client(
        transport,
        cols,
        rows,
        clock,
        predict,
        Some(history),
        in_rx,
        out_tx,
    )
    .await;

    drop(_guard);
    writer.abort();
}

/// Scrollback history fetcher backed by the session's QUIC connection: each
/// fetch opens a reliable side-channel and asks the server for a window of
/// history (see [`mish::scrollback::fetch_history`]).
struct QuicHistory(Arc<transport::QuicTransport>);

#[async_trait::async_trait]
impl mish::client::HistoryFetcher for QuicHistory {
    async fn fetch(
        &self,
        top_above: u32,
        count: u16,
    ) -> Option<mish_terminal::history::HistoryResponse> {
        let req = mish_terminal::history::HistoryRequest { top_above, count };
        mish::scrollback::fetch_history(&self.0, &req).await
    }
}

/// Restores cooked mode and the main screen on drop, and resets the input modes
/// a remote program may have left enabled so the local terminal isn't wedged
/// (mouse reporting, bracketed paste, reverse video) after the session ends.
struct TerminalGuard {
    /// Whether we entered the alternate screen (so we know to leave it).
    no_init: bool,
}
impl Drop for TerminalGuard {
    fn drop(&mut self) {
        let _ = crossterm::terminal::disable_raw_mode();
        // Disable mouse modes (incl. our wheel-capture baseline) and bracketed
        // paste, drop screen-reverse, restore alternate-scroll (which we force
        // off during the session), and show the cursor.
        print!(
            "\x1b[?1000l\x1b[?1002l\x1b[?1003l\x1b[?1006l\
             \x1b[?2004l\x1b[?5l\x1b[?1007h\x1b[?25h"
        );
        // Leave the alternate screen only if we entered it.
        if !self.no_init {
            print!("\x1b[?1049l");
        }
        use std::io::Write;
        let _ = std::io::stdout().flush();
    }
}
