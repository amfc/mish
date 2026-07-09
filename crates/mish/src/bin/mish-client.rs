//! `mish-client`: bootstrap a session like mosh, then attach the local TTY.
//!
//! Like the upstream `mosh` wrapper, this SSHes to the host, starts
//! `mish-server` there, reads the `MISH CONNECT <port> <cert>` line it prints,
//! and opens the QUIC/UDP session to that port — trusting exactly that
//! certificate (exchanged over the authenticated SSH channel). It then captures
//! raw keystrokes (forwarded as a `UserStream`), repaints received screens, and
//! tracks SIGWINCH resizes. Quick-detach with `Ctrl-]`. The escape prefix
//! `Ctrl-^` (configurable via `MOSH_ESCAPE_KEY`) then `.` quits, the prefix again
//! sends it literally, `Ctrl-Z` suspends, `u` toggles the network/prediction
//! status bar, and `l`/`Ctrl-L` forces a repaint; on resume (`fg`/SIGCONT) raw mode
//! is restored and the screen repainted. **Shift-Up / Shift-Down** (and
//! **Shift-PageUp / Shift-PageDown** for whole pages) scroll into the server's
//! scrollback history (fetched over a reliable side-channel); any other keystroke
//! returns to the live screen. The mouse wheel is left to the terminal (native
//! scrolling/selection); the Shift-Arrow keys pass through to full-screen apps.
//!
//! Usage:
//! ```text
//! mish-client [user@]host [-- command]    # SSH bootstrap (like `mosh host`)
//! mish-client --local [-- command]        # run the server locally (testing)
//! mish-client --connect host:port [-- command]  # ssh-less direct connect (see enroll)
//! mish-client enroll [user@]host          # exchange certs for direct connect
//!
//! Options:
//!   --local            start mish-server as a local child (no SSH)
//!   --bootstrap <how>  how to SSH in: auto|ssh|builtin (default: auto — use the
//!                      system ssh if present, else the builtin russh client)
//!   --ssh <cmd>        ssh command, shell-split (default: ssh); we append -n and
//!                      -tt and run `host -- <server …>`, like upstream mosh
//!   --ssh-port <n>     SSH port for the builtin client (default: 22)
//!   --no-ssh-pty       don't allocate a remote PTY (omit ssh -tt)
//!   --server <cmd>     mish-server command to run (default: mish-server,
//!                      or the sibling binary in --local mode)
//!   --predict <mode>   adaptive|always|never|experimental (default: adaptive);
//!     -a/-n            also via MOSH_PREDICTION_DISPLAY; -a=always, -n=never
//!   --no-init          don't enter the alternate screen (MOSH_NO_TERM_INIT)
//!   --perf-log <path>  record per-keystroke keypress→display latency (JSON lines)
//!   -L [bind:]port:host:hostport  forward a local port to a remote target (ssh -L)
//!   -R [bind:]port:host:hostport  forward a remote port to a local target (ssh -R)
//!   --version          print version and exit
//! ```

use std::sync::Arc;

use anyhow::{bail, Context, Result};
use mish::bootstrap::{self, shell_split, Bootstrap, BootstrapMode};
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
/// quit, the prefix again to send it literally, Ctrl-Z to suspend, `u` to toggle
/// the status bar, or `l`/Ctrl-L to force a repaint.
const DEFAULT_ESCAPE: u8 = 0x1e;
const CTRL_Z: u8 = 0x1a;
/// Ctrl-L (0x0c): after the escape prefix, force a full repaint (also `l`).
const CTRL_L: u8 = 0x0c;

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
    /// How to run the SSH bootstrap step (`--bootstrap`): the system `ssh`
    /// binary, the builtin russh client, or auto-detect.
    bootstrap: BootstrapMode,
    /// The ssh command, shell-split (e.g. `["ssh", "-p", "2222"]`). Used by the
    /// `ssh` bootstrap transport.
    ssh_argv: Vec<String>,
    /// SSH port for the builtin bootstrap transport (`--ssh-port`). `None` means
    /// "unset" — let `~/.ssh/config` (`Port`) decide, falling back to 22. An
    /// explicit value wins over the config. The system `ssh` transport takes its
    /// port from `--ssh "ssh -p N"` instead.
    ssh_port: Option<u16>,
    /// Allocate a remote PTY (`ssh -tt`); cleared by `--no-ssh-pty`. Applies to
    /// the `ssh` transport only.
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
    /// Start the remote session as a **shared** multi-client session (`--shared`,
    /// NEXT_FEATURES.md #3): this client is the read-write owner and additional
    /// clients (e.g. `mish host --session NAME`) may attach read-only. Only
    /// meaningful on the invocation that *starts* the daemon. Off → single-client.
    shared: bool,
    /// Raw attach (`--attach IP PORT`): connect directly to an already-running
    /// server (no SSH/local bootstrap), with credentials in `$MISH_CONNECT`
    /// (the hex `<server-cert> <client-cert> <client-key>` from its MISH CONNECT
    /// line). Mirrors `mosh-client IP PORT` + `$MOSH_KEY`; used by test harnesses.
    attach: Option<(String, u16)>,
    /// Direct connect (`--connect HOST:PORT`): dial an `mish-server --listen`
    /// with no SSH, using the enrolled client identity and the pinned server cert
    /// for HOST (established by `mish enroll HOST`). The ssh-less fast path.
    connect: Option<(String, u16)>,
    /// `-L [bind:]port:host:hostport` local forwards: listen locally, the server
    /// dials the target. Repeatable.
    local_forwards: Vec<mish::forward::ForwardSpec>,
    /// `-R [bind:]port:host:hostport` remote forwards: the server listens, the
    /// client dials the target. Repeatable.
    remote_forwards: Vec<mish::forward::ForwardSpec>,
    host: Option<String>,
    /// Explicit `-- command` argv, one token per element (empty = login shell).
    command: Vec<String>,
    /// Write a JSON event log here (`--log-file`); `None` disables logging.
    log_file: Option<std::path::PathBuf>,
    /// Max verbosity for the event log (`--log-level`, default debug).
    log_level: tracing::Level,
    /// Record per-keystroke keypress→display latency as JSON lines here
    /// (`--perf-log`); `None` disables it. Used to reproduce the Mosh paper's
    /// response-time graph from a real session (see `perf/`).
    perf_log: Option<std::path::PathBuf>,
    /// Prefix the client's window-title output with this string (`--title-prefix`).
    /// Empty or unset means pass the remote title through unchanged.
    title_prefix: Option<String>,
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

/// Parse an ssh-style `-L`/`-R` forward spec, defaulting the bind to loopback.
fn parse_forward(spec: &str) -> Result<mish::forward::ForwardSpec> {
    mish::forward::ForwardSpec::parse(spec, "127.0.0.1").map_err(anyhow::Error::msg)
}

fn parse_args() -> Result<Options> {
    let mut opts = Options {
        local: false,
        bootstrap: BootstrapMode::default(),
        ssh_argv: vec!["ssh".into()],
        ssh_port: None,
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
        shared: false,
        attach: None,
        connect: None,
        local_forwards: Vec::new(),
        remote_forwards: Vec::new(),
        host: None,
        command: Vec::new(),
        log_file: None,
        log_level: tracing::Level::DEBUG,
        perf_log: None,
        title_prefix: None,
    };
    let mut args = std::env::args().skip(1).peekable();
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--local" => opts.local = true,
            "--bootstrap" => {
                let val = args.next().context("--bootstrap needs auto|ssh|builtin")?;
                opts.bootstrap = BootstrapMode::parse(&val)?;
            }
            // Also accept the `--bootstrap=<how>` spelling.
            s if s.starts_with("--bootstrap=") => {
                opts.bootstrap = BootstrapMode::parse(&s["--bootstrap=".len()..])?;
            }
            "--ssh" => {
                let val = args.next().context("--ssh needs a value")?;
                opts.ssh_argv = shell_split(&val)?;
                if opts.ssh_argv.is_empty() {
                    bail!("--ssh value is empty");
                }
            }
            "--ssh-port" => {
                opts.ssh_port = Some(
                    args.next()
                        .context("--ssh-port needs a number")?
                        .parse()
                        .context("--ssh-port must be a number")?,
                );
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
            // Port forwarding, ssh-style: `-L [bind:]port:host:hostport` (local
            // listen, server dials) and `-R …` (server listen, client dials).
            // Accept both the separate (`-L spec`) and glued (`-Lspec`) forms.
            "-L" => {
                let spec = args.next().context("-L needs [bind:]port:host:hostport")?;
                opts.local_forwards.push(parse_forward(&spec)?);
            }
            "-R" => {
                let spec = args.next().context("-R needs [bind:]port:host:hostport")?;
                opts.remote_forwards.push(parse_forward(&spec)?);
            }
            s if s.starts_with("-L") => opts.local_forwards.push(parse_forward(&s[2..])?),
            s if s.starts_with("-R") => opts.remote_forwards.push(parse_forward(&s[2..])?),
            "--session" => opts.session = Some(args.next().context("--session needs a NAME")?),
            "--shared" => {
                #[cfg(feature = "multi-client")]
                {
                    opts.shared = true;
                }
                #[cfg(not(feature = "multi-client"))]
                bail!("--shared requires building mish with the `multi-client` feature");
            }
            "--attach" => {
                let ip = args.next().context("--attach needs IP PORT")?;
                let port: u16 = args
                    .next()
                    .context("--attach needs IP PORT")?
                    .parse()
                    .context("--attach PORT must be a number")?;
                opts.attach = Some((ip, port));
            }
            "--connect" => {
                let spec = args.next().context("--connect needs HOST:PORT")?;
                opts.connect = Some(parse_hostport(&spec)?);
            }
            "--log-file" => {
                opts.log_file = Some(args.next().context("--log-file needs a PATH")?.into());
            }
            "--log-level" => {
                opts.log_level =
                    mish::trace::parse_level(&args.next().context("--log-level needs a LEVEL")?);
            }
            "--perf-log" => {
                opts.perf_log = Some(args.next().context("--perf-log needs a PATH")?.into());
            }
            "--title-prefix" => {
                opts.title_prefix = Some(args.next().context("--title-prefix needs a STRING")?);
            }
            "--version" => {
                println!("mish-client (mish) {}", env!("CARGO_PKG_VERSION"));
                std::process::exit(0);
            }
            "--" => {
                // Preserve the trailing argv exactly; the server re-execs it
                // token-for-token. Joining here is what turned `-- htop -d 10`
                // into a single unspawnable program name.
                opts.command = args.by_ref().collect();
            }
            "-h" | "--help" => {
                print_usage();
                std::process::exit(0);
            }
            other if other.starts_with('-') => bail!("unknown option: {other}"),
            other => opts.host = Some(other.to_string()),
        }
    }
    if !opts.local && opts.host.is_none() && opts.attach.is_none() && opts.connect.is_none() {
        print_usage();
        bail!("a host is required (or use --local / --attach / --connect)");
    }
    Ok(opts)
}

/// Parse a `HOST:PORT` value into `(host, port)`. HOST may be a hostname, IPv4,
/// or a bracketed IPv6 `[addr]:port` (brackets required for IPv6). HOST is kept
/// verbatim (it keys the pinned server cert); resolution happens at dial time.
fn parse_hostport(spec: &str) -> Result<(String, u16)> {
    if let Some(rest) = spec.strip_prefix('[') {
        let (host, port) = rest
            .split_once("]:")
            .context("--connect [IPv6]:PORT needs a closing `]:PORT`")?;
        return Ok((
            host.to_string(),
            port.parse().context("bad --connect port")?,
        ));
    }
    let (host, port) = spec
        .rsplit_once(':')
        .context("--connect expects HOST:PORT (bracket IPv6 as [addr]:port)")?;
    Ok((
        host.to_string(),
        port.parse().context("bad --connect port")?,
    ))
}

fn print_usage() {
    eprintln!(
        "usage: mish-client [user@]host [-- command]\n\
         \x20      mish-client --local [-- command]\n\n\
         options:\n\
         \x20 --local              run mish-server as a local child (no SSH)\n\
         \x20 --bootstrap <how>    SSH transport: auto|ssh|builtin (default: auto)\n\
         \x20 --ssh <cmd>          ssh command, shell-split (default: ssh)\n\
         \x20 --ssh-port <n>       SSH port for the builtin transport (default: 22)\n\
         \x20 --no-ssh-pty         don't allocate a remote PTY (no ssh -tt)\n\
         \x20 --server <cmd>       mish-server command to run (default: mish-server)\n\
         \x20 --predict <mode>     adaptive|always|never|experimental (default: adaptive)\n\
         \x20 -a, --predict-always always echo locally; -n, --predict-never  disable\n\
         \x20 --no-init            don't enter the alternate screen (MOSH_NO_TERM_INIT)\n\
         \x20 -L [bind:]port:host:hostport  forward a local port to host:hostport (repeatable)\n\
         \x20 -R [bind:]port:host:hostport  forward a remote port to host:hostport (repeatable)\n\
         \x20 --session <name>     reattachable persistent session (never lose your shell)\n\
         \x20 --shared             shared session: you own it, others can attach read-only\n\
         \x20 --attach IP PORT     attach to a running server ($MISH_CONNECT creds; for testing)\n\
         \x20 --connect HOST:PORT  ssh-less direct connect to `mish-server --listen`, running\n\
         \x20                      the `-- command` if given (see enroll)\n\
         \x20 enroll [user@]host   one-shot: exchange certs with a direct-mode server over SSH\n\
         \x20 --log-file <path>    write a JSON event log (for debugging)\n\
         \x20 --log-level <lvl>    log verbosity: error|warn|info|debug|trace (default debug)\n\
         \x20 --perf-log <path>    record per-keystroke keypress->display latency (JSON lines)\n\
         \x20 --title-prefix <s>   prefix window titles on the host terminal (empty = passthrough)\n\
         \x20 --version            print version and exit\n\
         \x20 -h, --help           show this help\n\n\
         keys: Ctrl-] detach · Ctrl-^ then . quit / Ctrl-Z suspend / u status bar / l repaint\n\
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
    // `mish enroll [user@]host [options]`: a one-shot subcommand (no session), so
    // it's handled before the normal option parser. It SSHes once to exchange
    // certificates, then exits — see `run_enroll`.
    let argv: Vec<String> = std::env::args().collect();
    if argv.get(1).map(String::as_str) == Some("enroll") {
        return run_enroll(&argv[2..]);
    }

    let opts = parse_args()?;

    // Optional event log (--log-file): install before anything else so the whole
    // session — bootstrap, connect, run, disconnect — is captured.
    if let Some(path) = &opts.log_file {
        if let Err(e) = mish::trace::init_file_logging(path, "client", opts.log_level) {
            eprintln!(
                "[mish-client] warning: could not open log file {}: {e}",
                path.display()
            );
        }
    }
    tracing::info!(target: "mish::client", local = opts.local, "client starting");

    // Optional keystroke-latency recording (--perf-log): like the event log,
    // install the global recorder before the session runs so every keystroke is
    // captured. See `perf/` for turning the log into the Mosh-paper CDF.
    if let Some(path) = &opts.perf_log {
        if let Err(e) = mish::perf::init(path) {
            eprintln!(
                "[mish-client] warning: could not open perf log {}: {e}",
                path.display()
            );
        }
    }

    // Raw attach (--attach IP PORT): connect directly to a running server with
    // credentials from $MISH_CONNECT, no bootstrap. (Used by test harnesses;
    // mirrors `mosh-client IP PORT` + $MOSH_KEY.)
    if let Some((ip, port)) = opts.attach.clone() {
        attach_session(
            &ip,
            port,
            opts.predict,
            opts.no_init,
            opts.local_forwards,
            opts.remote_forwards,
            opts.session.clone(),
            opts.title_prefix.clone(),
        )
        .await?;
        exit_now();
    }

    // Direct connect (--connect HOST:PORT): dial an `mish-server --listen` with no
    // SSH, using the enrolled client identity and the pinned server cert for HOST.
    if let Some((host, port)) = opts.connect.clone() {
        connect_session(
            &host,
            port,
            opts.predict,
            opts.no_init,
            opts.local_forwards,
            opts.remote_forwards,
            opts.session.clone(),
            opts.title_prefix.clone(),
            &opts.command,
        )
        .await?;
        exit_now();
    }

    // Port forwarding is off on the server by default; if the user asked for any
    // -L/-R forward, tell the server we launch to allow it (--allow-forward).
    let want_forward = !opts.local_forwards.is_empty() || !opts.remote_forwards.is_empty();

    // 1. Bootstrap: get (udp addr, cert) by starting mish-server locally or via SSH.
    let boot: Bootstrap = if opts.local {
        let server = opts.server_cmd.unwrap_or_else(default_local_server);
        eprintln!("[mish-client] starting local server `{server}`…");
        bootstrap::local(
            &server,
            opts.shared,
            want_forward,
            opts.session.as_deref(),
            &opts.command,
        )
        .await
        .context("local bootstrap")?
    } else {
        let host = opts.host.clone().unwrap();
        let server = opts.server_cmd.unwrap_or_else(|| SERVER_BIN.into());
        // Pick the SSH transport: the system `ssh` binary, or the builtin russh
        // client. In `auto` mode we use `ssh` when it is on PATH, else builtin.
        if opts.bootstrap.use_builtin(&opts.ssh_argv[0]) {
            eprintln!("[mish-client] builtin ssh → {host} {server}…");
            bootstrap::builtin(
                &host,
                opts.ssh_port,
                &server,
                opts.shared,
                want_forward,
                opts.session.as_deref(),
                &opts.command,
            )
            .await
            .context("builtin ssh bootstrap")?
        } else {
            eprintln!("[mish-client] {} {host} {server}…", opts.ssh_argv.join(" "));
            bootstrap::ssh(
                &opts.ssh_argv,
                opts.ssh_pty,
                &host,
                &server,
                opts.shared,
                want_forward,
                opts.session.as_deref(),
                &opts.command,
            )
            .await
            .context("ssh bootstrap")?
        }
    };
    eprintln!("[mish-client] connecting to {} …", boot.addr);

    // 2. Open the mutually-authenticated QUIC session: trust the server cert and
    //    present the minted client cert/key from the SSH-authenticated channel.
    let endpoint = transport::authenticated_client_endpoint(
        client_bind_addr(boot.addr),
        &boot.server_cert_der,
        &boot.client_cert_der,
        &boot.client_key_der,
    )
    .context("creating QUIC client endpoint")?;
    let t = transport::connect(&endpoint, boot.addr, "localhost")
        .await
        .context("connecting to server")?;
    tracing::info!(target: "mish::client", addr = %boot.addr, "connected to server");

    // 3. Drive the local terminal (with any -L/-R forwards over the same conn).
    run_terminal(
        t,
        opts.predict,
        opts.no_init,
        opts.local_forwards,
        opts.remote_forwards,
        opts.session,
        opts.title_prefix,
    )
    .await;
    tracing::info!(target: "mish::client", "client session ended; tearing down");

    // Dropping `boot` tears down the server / ssh channel.
    drop(boot);
    exit_now();
}

/// Exit the process immediately after the session has ended and the terminal has
/// been restored.
///
/// The stdin reader runs a `tokio::io::stdin()` read on the blocking-thread pool,
/// parked in a `read(2)` syscall that can't be cancelled. If we returned from
/// `main` normally, the tokio runtime's shutdown would block on that thread until
/// the kernel delivers a line — so the process would appear to hang after
/// "connection closed" until the user pressed Enter. By the time we get here the
/// `TerminalGuard` has restored cooked mode and `drop(boot)` has torn down the
/// server/SSH child, so there is nothing left to clean up: exit now.
fn exit_now() -> ! {
    use std::io::Write;
    // Flush the perf log (no-op without --perf-log): we exit via `process::exit`,
    // which runs no destructors, so the recorder's buffered tail must be flushed
    // here. `run_client` already flushes on a clean session end; this covers the
    // `--attach` path and any early exit.
    mish::perf::finish();
    let _ = std::io::stdout().flush();
    std::process::exit(0);
}

/// Local address to bind the QUIC client endpoint to, matching the resolved
/// server's address family. A QUIC connection can't cross families, so an
/// IPv6 server needs an IPv6-bound endpoint; binding `0.0.0.0:0` (IPv4) and
/// then dialing an IPv6 address fails. `:0` lets the OS pick the port.
fn client_bind_addr(server: std::net::SocketAddr) -> std::net::SocketAddr {
    use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
    if server.is_ipv6() {
        SocketAddr::from((Ipv6Addr::UNSPECIFIED, 0))
    } else {
        SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0))
    }
}

/// Attach directly to a running server at `ip:port`, with the credential triple
/// (hex `server-cert client-cert client-key`) in `$MISH_CONNECT`. No bootstrap.
#[allow(clippy::too_many_arguments)] // session entry point: discrete wired-in pieces
async fn attach_session(
    ip: &str,
    port: u16,
    predict: PredictMode,
    no_init: bool,
    local_forwards: Vec<mish::forward::ForwardSpec>,
    remote_forwards: Vec<mish::forward::ForwardSpec>,
    session: Option<String>,
    title_prefix: Option<String>,
) -> Result<()> {
    let creds = std::env::var("MISH_CONNECT").context(
        "--attach requires $MISH_CONNECT = hex `<server-cert> <client-cert> <client-key>`",
    )?;
    let mut it = creds.split_whitespace();
    let mut next_der = |what: &str| -> Result<Vec<u8>> {
        let tok = it
            .next()
            .with_context(|| format!("MISH_CONNECT: missing {what}"))?;
        bootstrap::from_hex(tok).with_context(|| format!("MISH_CONNECT: bad {what} hex"))
    };
    let server_cert = next_der("server cert")?;
    let client_cert = next_der("client cert")?;
    // The private key from $MISH_CONNECT — zeroized on drop.
    let client_key = zeroize::Zeroizing::new(next_der("client key")?);

    let addr: std::net::SocketAddr = format!("{ip}:{port}")
        .parse()
        .with_context(|| format!("bad --attach address {ip}:{port}"))?;
    let endpoint = transport::authenticated_client_endpoint(
        client_bind_addr(addr),
        &server_cert,
        &client_cert,
        &client_key,
    )
    .context("creating QUIC client endpoint")?;
    eprintln!("[mish-client] attaching to {addr} …");
    let t = transport::connect(&endpoint, addr, "localhost")
        .await
        .context("connecting to server")?;
    run_terminal(
        t,
        predict,
        no_init,
        local_forwards,
        remote_forwards,
        session,
        title_prefix,
    )
    .await;
    Ok(())
}

/// Direct-connect to `host:port` (ssh-less): load the enrolled client identity
/// and the pinned server cert for `host`, dial, send the Exec hello naming the
/// `-- command` (empty = login shell), and run the terminal. Roaming rides QUIC
/// connection migration on this one connection, exactly as the SSH path does; a
/// new invocation is a new connection (a fresh server-side shell).
#[allow(clippy::too_many_arguments)] // session entry point: discrete wired-in pieces
async fn connect_session(
    host: &str,
    port: u16,
    predict: PredictMode,
    no_init: bool,
    local_forwards: Vec<mish::forward::ForwardSpec>,
    remote_forwards: Vec<mish::forward::ForwardSpec>,
    session: Option<String>,
    title_prefix: Option<String>,
    command: &[String],
) -> Result<()> {
    let id = mish::enroll::load_or_generate_client_identity()?;
    let server_cert = mish::enroll::load_server_cert(host)?;
    let addr = resolve_hostport(host, port)?;

    let endpoint = transport::authenticated_client_endpoint(
        client_bind_addr(addr),
        &server_cert,
        &id.cert,
        &id.key,
    )
    .context("creating QUIC client endpoint")?;
    eprintln!("[mish-client] direct-connecting to {addr} …");
    let t = transport::connect(&endpoint, addr, "localhost")
        .await
        .context("connecting to server")?;
    tracing::info!(target: "mish::client", %addr, "direct-connected to server");
    mish::direct::send_exec_hello(&t, command).await?;
    run_terminal(
        t,
        predict,
        no_init,
        local_forwards,
        remote_forwards,
        session,
        title_prefix,
    )
    .await;
    Ok(())
}

/// Resolve `host:port` to a single socket address (first result wins).
fn resolve_hostport(host: &str, port: u16) -> Result<std::net::SocketAddr> {
    use std::net::ToSocketAddrs;
    (host, port)
        .to_socket_addrs()
        .with_context(|| format!("resolving {host}:{port}"))?
        .next()
        .with_context(|| format!("no address found for {host}:{port}"))
}

/// `mish enroll [user@]host [--ssh CMD] [--server CMD] [--name LABEL]`: exchange
/// certificates with a direct-mode server over SSH. Generates/loads the client
/// identity, ships its cert to the server (which enrolls it and hands back its
/// own cert), and pins that server cert for later `--connect`. One-shot: SSHes
/// once and exits.
fn run_enroll(args: &[String]) -> Result<()> {
    let mut host: Option<String> = None;
    let mut ssh_argv: Vec<String> = vec!["ssh".into()];
    let mut server_cmd = SERVER_BIN.to_string();
    let mut name: Option<String> = None;
    let mut it = args.iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--ssh" => {
                ssh_argv = shell_split(it.next().context("--ssh needs a value")?)?;
                if ssh_argv.is_empty() {
                    bail!("--ssh value is empty");
                }
            }
            "--server" => server_cmd = it.next().context("--server needs a value")?.clone(),
            "--name" => name = Some(it.next().context("--name needs a value")?.clone()),
            "-h" | "--help" => {
                eprintln!(
                    "usage: mish enroll [user@]host [--ssh CMD] [--server CMD] [--name LABEL]"
                );
                return Ok(());
            }
            other if other.starts_with('-') => bail!("unknown enroll option: {other}"),
            other => host = Some(other.to_string()),
        }
    }
    let host = host.context("enroll needs a [user@]host")?;
    let label = name.unwrap_or_else(mish::enroll::client_label);

    let id = mish::enroll::load_or_generate_client_identity()?;
    let cert_hex = bootstrap::to_hex(&id.cert);

    // Remote one-shot; the label is quoted (the server also sanitizes it).
    let remote = format!(
        "{server_cmd} --enroll-client {cert_hex} --enroll-name {}",
        shell_quote(&label)
    );
    eprintln!("[mish enroll] {} {host} …", ssh_argv.join(" "));
    let out = std::process::Command::new(&ssh_argv[0])
        .args(&ssh_argv[1..])
        .arg(&host)
        .arg(&remote)
        .output()
        .with_context(|| format!("running ssh ({})", ssh_argv[0]))?;
    if !out.status.success() {
        bail!(
            "enroll ssh failed ({}): {}",
            out.status,
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    let server_cert = parse_identity_line(&String::from_utf8_lossy(&out.stdout))?;
    let path = mish::enroll::store_server_cert(&host, &server_cert)?;
    eprintln!(
        "[mish enroll] enrolled as {label:?}; pinned server cert for {} at {}",
        mish::enroll::host_only(&host),
        path.display()
    );
    Ok(())
}

/// Extract the server cert DER from the `MISH IDENTITY <hex>` line printed by
/// `mish-server --enroll-client`.
fn parse_identity_line(text: &str) -> Result<Vec<u8>> {
    for line in text.lines() {
        if let Some(hex) = line.strip_prefix("MISH IDENTITY ") {
            return bootstrap::from_hex(hex.trim()).context("bad server cert hex");
        }
    }
    bail!("server did not return a `MISH IDENTITY <hex>` line");
}

/// Single-quote a value for a POSIX remote shell command line.
fn shell_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}

/// Put the TTY in raw mode and run the client session until detach or close.
async fn run_terminal(
    t: transport::QuicTransport,
    predict: PredictMode,
    no_init: bool,
    local_forwards: Vec<mish::forward::ForwardSpec>,
    remote_forwards: Vec<mish::forward::ForwardSpec>,
    session: Option<String>,
    title_prefix: Option<String>,
) {
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
                // Shift-Up / Shift-Down (xterm modifier encoding): scroll mosh's
                // history at the shell prompt — a keyboard path that works on
                // laptops without a PageUp key and needs no mouse reporting.
                // `run_client` passes these through to full-screen apps instead.
                b"\x1b[1;2A" => {
                    let _ = key_tx
                        .send(ClientInput::ScrollKey {
                            up: true,
                            passthrough: chunk.to_vec(),
                        })
                        .await;
                    continue;
                }
                b"\x1b[1;2B" => {
                    let _ = key_tx
                        .send(ClientInput::ScrollKey {
                            up: false,
                            passthrough: chunk.to_vec(),
                        })
                        .await;
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
                        b'u' => {
                            // Toggle the network/prediction status bar. Flush any
                            // keystrokes typed before the prefix first, in order.
                            if !batch.is_empty() {
                                let _ = key_tx
                                    .send(ClientInput::Keys(std::mem::take(&mut batch)))
                                    .await;
                            }
                            let _ = key_tx.send(ClientInput::ToggleStats).await;
                        }
                        b'l' | CTRL_L => {
                            // Force a full repaint (e.g. after local corruption).
                            if !batch.is_empty() {
                                let _ = key_tx
                                    .send(ClientInput::Keys(std::mem::take(&mut batch)))
                                    .await;
                            }
                            let _ = key_tx.send(ClientInput::Redraw).await;
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
    let history: Arc<dyn mish::client::HistoryFetcher> = Arc::new(QuicHistory(transport.clone()));

    // Port forwarding (`-L`/`-R`): set up before the session runs, sharing the
    // same authenticated connection. These run as independent tasks; the held
    // `_remote_forwards` keep the server's `-R` listeners alive for the session.
    setup_local_forwards(&transport, local_forwards).await;
    let _remote_forwards = setup_remote_forwards(&transport, remote_forwards).await;

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
        session,
        title_prefix,
        in_rx,
        out_tx,
    )
    .await;

    drop(_guard);
    writer.abort();
}

/// Bind each `-L` local forward and start its accept loop. A bind failure (port
/// in use, etc.) is reported but doesn't abort the session — the rest of the
/// forwards and the shell still come up.
async fn setup_local_forwards(
    transport: &Arc<transport::QuicTransport>,
    specs: Vec<mish::forward::ForwardSpec>,
) {
    for spec in specs {
        let desc = format!(
            "{}:{} -> {}:{}",
            spec.bind_host, spec.bind_port, spec.target_host, spec.target_port
        );
        match mish::forward::run_local_forward(transport.clone(), spec).await {
            Ok(addr) => eprintln!("[mish-client] -L listening on {addr} (forwarding to {desc})"),
            Err(e) => eprintln!("[mish-client] -L {desc} failed: {e}"),
        }
    }
}

/// Request each `-R` remote forward from the server and, if any succeed, start
/// the accept loop that dials the client-local targets. Returns the live forward
/// handles, which must be kept alive for the forwards to persist.
async fn setup_remote_forwards(
    transport: &Arc<transport::QuicTransport>,
    specs: Vec<mish::forward::ForwardSpec>,
) -> Vec<mish::forward::RemoteForward> {
    if specs.is_empty() {
        return Vec::new();
    }
    // The accept loop only ever dials targets the user configured here.
    let targets = mish::forward::remote_targets(&specs);
    let mut handles = Vec::new();
    for spec in &specs {
        match mish::forward::request_remote_forward(transport, spec).await {
            Ok(rf) => {
                eprintln!(
                    "[mish-client] -R remote {}:{} -> {}:{}",
                    spec.bind_host, rf.bound_port, spec.target_host, spec.target_port
                );
                handles.push(rf);
            }
            Err(e) => eprintln!(
                "[mish-client] -R {}:{} -> {}:{} failed: {e}",
                spec.bind_host, spec.bind_port, spec.target_host, spec.target_port
            ),
        }
    }
    if !handles.is_empty() {
        tokio::spawn(mish::forward::serve_forwarded_connections(
            transport.clone(),
            targets,
        ));
    }
    handles
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

/// Terminal modes a remote program may have left enabled, reset on exit so the
/// local terminal isn't wedged: mouse reporting (DECRST 1000/1002/1003) and SGR
/// mouse encoding (1006), bracketed paste (2004), screen-reverse (5),
/// application-cursor-keys (DECCKM, 1); then restore alternate-scroll (1007,
/// which we force off during the session) and show the cursor (25).
const RESET_MODES: &str = "\x1b[?1000l\x1b[?1002l\x1b[?1003l\x1b[?1006l\
                           \x1b[?2004l\x1b[?5l\x1b[?1l\x1b[?1007h\x1b[?25h";

/// Restores cooked mode and the main screen on drop, and resets the input modes
/// a remote program may have left enabled (see [`RESET_MODES`]) so the local
/// terminal isn't wedged after the session ends.
struct TerminalGuard {
    /// Whether we entered the alternate screen (so we know to leave it).
    no_init: bool,
}
impl Drop for TerminalGuard {
    fn drop(&mut self) {
        let _ = crossterm::terminal::disable_raw_mode();
        print!("{RESET_MODES}");
        // Leave the alternate screen only if we entered it.
        if !self.no_init {
            print!("\x1b[?1049l");
        }
        use std::io::Write;
        let _ = std::io::stdout().flush();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddr;

    #[test]
    fn reset_modes_returns_cursor_keys_to_normal() {
        // DECCKM off (?1l) must be in the on-exit reset, alongside the mouse,
        // bracketed-paste, and reverse-video resets — so an app that left
        // application-cursor-keys on doesn't wedge the local terminal's arrows.
        assert!(RESET_MODES.contains("\x1b[?1l"), "app-cursor-keys reset");
        assert!(RESET_MODES.contains("\x1b[?1000l"), "mouse reset");
        assert!(RESET_MODES.contains("\x1b[?2004l"), "bracketed-paste reset");
        assert!(RESET_MODES.contains("\x1b[?5l"), "reverse-video reset");
        assert!(RESET_MODES.contains("\x1b[?25h"), "cursor shown");
    }

    #[test]
    fn client_bind_addr_matches_server_family() {
        let v4: SocketAddr = "203.0.113.5:60001".parse().unwrap();
        let v6: SocketAddr = "[2001:db8::1]:60001".parse().unwrap();
        assert!(client_bind_addr(v4).is_ipv4(), "IPv4 server ⇒ IPv4 bind");
        assert!(client_bind_addr(v6).is_ipv6(), "IPv6 server ⇒ IPv6 bind");
        // Ephemeral port in both cases.
        assert_eq!(client_bind_addr(v4).port(), 0);
        assert_eq!(client_bind_addr(v6).port(), 0);
    }
}
