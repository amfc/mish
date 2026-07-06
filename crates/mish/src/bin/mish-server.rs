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
//! Usage: `mish-server [--detach] [--persist] [--shared] [--allow-forward] [-4|-6|--family inet|inet6] [-p PORT|-p LOW:HIGH] [-l KEY=VAL]... [--log-file PATH] [--log-level LEVEL] [--listen [IP:]PORT] [--server-key PATH] [--authorized-certs DIR] [bind-port] [-- command]`
//!
//! ## Direct-connect mode (`--listen`)
//!
//! `--listen [IP:]PORT` runs a long-lived, **ssh-less** listener instead of the
//! SSH-bootstrap flow: it loads a **persistent** on-disk server identity
//! (`--server-key`, cert stored beside it) and a directory of **enrolled** client
//! certificates (`--authorized-certs`), then serves each authenticated connection
//! its own fresh, **non-persistent** shell (see [`mish::direct`]). There is no
//! `MISH CONNECT` handoff — an enrolled client already holds its credentials and
//! dials the QUIC port directly. The operator owns the listener's lifecycle
//! (systemd) and the bind IP's reachability (a WireGuard address on hosts).
//!
//! `--allow-forward` enables `ssh -L`/`-R`-style port forwarding, which is
//! **off by default**; the bootstrapping client passes it automatically when the
//! user requests a forward (see `docs/port-forwarding.md`).
//!
//! With no `-- command`, the user's `$SHELL` is started as a **login shell**
//! (`-l`). `-4`/`-6` select the bind address family (default IPv4 `0.0.0.0`).
//! With `--persist` the PTY + terminal state survive client disconnects and the
//! server accepts **reattach** connections (until the shell exits or no client
//! reattaches within `MISH_SERVER_REATTACH_TMOUT`). With `--shared` (a build-time
//! `multi-client` feature, on by default) several clients may attach at once — one
//! read-write owner + read-only viewers (NEXT_FEATURES.md #3); it implies
//! `--persist`.
//!
//! Env: `MOSH_SERVER_NETWORK_TMOUT` (mid-session idle, default 300s),
//! `MOSH_SERVER_SIGNAL_TMOUT` (wait for the first connection, default 60s),
//! `MISH_SERVER_REATTACH_TMOUT` (`--persist`: wait for a reattach, default 24h).

use std::io::Write;
use std::path::PathBuf;
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
    /// Address to bind: IPv4 `0.0.0.0` (default) or IPv6 `::`.
    bind_ip: String,
    /// Keep the session alive across client disconnects and accept reattaches
    /// (`--persist`), instead of exiting when the client leaves.
    persist: bool,
    /// Shared multi-client session (`--shared`): accept several concurrent
    /// clients — one read-write owner + read-only viewers (NEXT_FEATURES.md #3).
    /// Implies a persistent session. Always `false` without the `multi-client`
    /// build feature.
    shared: bool,
    /// Named, reattachable session (`--session NAME`): on start, reattach to an
    /// existing live session of this name (reprint its connect line and exit),
    /// else register a new one. Implies `--persist`.
    session: Option<String>,
    /// Explicit `-- command` argv (one program + args per element). Empty means
    /// no command was given, so the server starts the user's login shell.
    command: Vec<String>,
    /// Whether to honor client port-forwarding requests (`-L`/`-R`). **Off by
    /// default** (deny); enabled per session with `--allow-forward`. The
    /// SSH-bootstrapping client passes this automatically when the user asks for
    /// a forward, so `mish-client host -L …` still works out of the box while a
    /// manually-launched or reattached server stays locked down unless told.
    forward: bool,
    /// Write a JSON event log here (`--log-file`); `None` disables logging.
    log_file: Option<std::path::PathBuf>,
    /// Max verbosity for the event log (`--log-level`, default debug).
    log_level: tracing::Level,
    /// Direct-connect listener (`--listen [IP:]PORT`): run a long-lived,
    /// ssh-less listener bound to this address, using a **persistent** on-disk
    /// server identity and a directory of enrolled client certs, instead of the
    /// SSH-bootstrap flow. `None` = normal SSH-launched server.
    listen: Option<(String, u16)>,
    /// Persistent server-identity key path (`--server-key`, direct mode only).
    /// `None` = `<config>/server.key`.
    server_key: Option<std::path::PathBuf>,
    /// Directory of enrolled client certs (`--authorized-certs`, direct mode
    /// only). `None` = `<config>/authorized/`.
    authorized_certs: Option<std::path::PathBuf>,
    /// One-shot enrollment (`--enroll-client HEX`): add this hex-encoded client
    /// certificate to the allow-list, materialize the server identity, print
    /// `MISH IDENTITY <server-cert-hex>`, and exit. Run over SSH by `mish enroll`.
    enroll_client: Option<String>,
    /// Allow-list filename stem for `--enroll-client` (`--enroll-name NAME`,
    /// default `mish-client`). Sanitized before use.
    enroll_name: Option<String>,
}

/// Default allow-list slot name when `--enroll-name` is omitted.
const DEFAULT_ENROLL_NAME: &str = "mish-client";

/// Default bind address when `--listen` is given a bare port (no IP). In
/// containers this is safe (localhost-only without WireGuard); on WG hosts the
/// caller passes the WG IP explicitly as `IP:PORT`.
const DEFAULT_BIND_IP: &str = "0.0.0.0";

const USAGE: &str = "\
mish-server: spawn a shell on a PTY and serve it over QUIC datagrams.

Usage: mish-server [OPTIONS] [bind-port] [-- command]

Options:
  --detach            Daemonize (fork + setsid) so the SSH session can close.
  --persist           Keep the session alive across client disconnects and
                      accept reattaches.
  --shared            Allow several concurrent clients (one read-write owner +
                      read-only viewers); implies --persist. Requires the
                      `multi-client` build feature.
  --allow-forward     Enable ssh -L/-R-style port forwarding (off by default).
                      The bootstrapping client passes this automatically when a
                      -L/-R forward is requested.
  --session NAME      Start (or reattach to) a named, reattachable session.
                      Implies --persist.
  --listen [IP:]PORT  Direct-connect mode: run a long-lived, ssh-less listener
                      bound to this address, using a persistent on-disk identity
                      and a directory of enrolled client certs. Bracket IPv6 as
                      [addr]:port. A bare PORT binds 0.0.0.0.
  --server-key PATH   Direct mode: persistent server-identity key (default
                      <config>/server.key; the cert is stored beside it as .crt).
  --authorized-certs DIR
                      Direct mode: directory of enrolled client certs, one *.crt
                      DER file each (default <config>/authorized/).
  --enroll-client HEX Add a hex-encoded client cert to the allow-list, print the
                      server cert as `MISH IDENTITY <hex>`, and exit. Invoked over
                      SSH by `mish enroll`; not for direct use.
  --enroll-name NAME  Allow-list slot name for --enroll-client (default mish-client).
  -4 | -6             Bind IPv4 (0.0.0.0, default) or IPv6 (::).
  --family inet|inet6 Same as -4 / -6.
  -p PORT | -p LO:HI  Bind a specific port, or the first free port in a range.
  -l KEY=VAL          Export KEY=VAL to the child shell (repeatable).
  --log-file PATH     Write a JSON event log to PATH.
  --log-level LEVEL   Max verbosity for the event log (default: debug).
  -h, --help          Print this help and exit.
  -V, --version       Print version and exit.

With no `-- command`, the user's $SHELL is started as a login shell.

Env: MOSH_SERVER_NETWORK_TMOUT (mid-session idle, default 300s),
     MOSH_SERVER_SIGNAL_TMOUT (wait for first connection, default 60s),
     MISH_SERVER_REATTACH_TMOUT (--persist: wait for a reattach, default 24h),
     MISH_CONFIG_DIR / XDG_CONFIG_HOME (direct mode: identity/enrolled-cert dir).

Direct mode (--listen) has no MISH CONNECT handoff and no signal/reattach
timeout — the listener waits for clients indefinitely and each connection gets
its own fresh, non-persistent shell (roaming rides QUIC connection migration).
";

fn parse_args() -> Result<Options> {
    let mut opts = Options {
        detach: false,
        ports: Vec::new(),
        locale: Vec::new(),
        bind_ip: "0.0.0.0".to_string(),
        persist: false,
        shared: false,
        session: None,
        command: Vec::new(),
        forward: false,
        log_file: None,
        log_level: tracing::Level::DEBUG,
        listen: None,
        server_key: None,
        authorized_certs: None,
        enroll_client: None,
        enroll_name: None,
    };
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--version" | "-V" => {
                println!("mish-server {}", env!("CARGO_PKG_VERSION"));
                std::process::exit(0);
            }
            "--help" | "-h" => {
                print!("{USAGE}");
                std::process::exit(0);
            }
            "--detach" => opts.detach = true,
            "--persist" => opts.persist = true,
            "--allow-forward" => opts.forward = true,
            "--shared" => {
                #[cfg(feature = "multi-client")]
                {
                    opts.shared = true;
                    opts.persist = true; // a shared session must persist
                }
                #[cfg(not(feature = "multi-client"))]
                bail!("--shared requires building mish with the `multi-client` feature");
            }
            "--session" => {
                opts.session = Some(args.next().context("--session needs a NAME")?);
                opts.persist = true; // a reattachable session must persist
            }
            "-4" => opts.bind_ip = "0.0.0.0".to_string(),
            "-6" => opts.bind_ip = "::".to_string(),
            "--family" => {
                opts.bind_ip = match args.next().as_deref() {
                    Some("inet") | Some("4") => "0.0.0.0".to_string(),
                    Some("inet6") | Some("6") => "::".to_string(),
                    other => bail!("--family expects inet|inet6 (got {other:?})"),
                };
            }
            "-p" => {
                let spec = args.next().context("-p needs a value")?;
                opts.ports = parse_ports(&spec)?;
            }
            "-l" => {
                let kv = args.next().context("-l needs KEY=VAL")?;
                let (k, v) = kv.split_once('=').context("-l expects KEY=VAL")?;
                opts.locale.push((k.to_string(), v.to_string()));
            }
            "--listen" => {
                let spec = args.next().context("--listen needs [IP:]PORT")?;
                opts.listen = Some(parse_listen(&spec)?);
            }
            "--server-key" => {
                opts.server_key = Some(args.next().context("--server-key needs a PATH")?.into());
            }
            "--authorized-certs" => {
                opts.authorized_certs = Some(
                    args.next()
                        .context("--authorized-certs needs a DIR")?
                        .into(),
                );
            }
            "--enroll-client" => {
                opts.enroll_client = Some(args.next().context("--enroll-client needs a HEX cert")?);
            }
            "--enroll-name" => {
                opts.enroll_name = Some(args.next().context("--enroll-name needs a NAME")?);
            }
            "--log-file" => {
                opts.log_file = Some(args.next().context("--log-file needs a PATH")?.into());
            }
            "--log-level" => {
                opts.log_level =
                    mish::trace::parse_level(&args.next().context("--log-level needs a LEVEL")?);
            }
            "--" => {
                // Keep every trailing token as its own argv element; the PTY is
                // later `spawn_argv`d from these verbatim. Joining them here is
                // what made `-- htop -d 10` exec a program named "htop -d 10".
                opts.command = args.by_ref().collect();
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

/// Parse a `--listen` value into `(bind_ip, port)`. Accepts a bare `PORT`
/// (binds [`DEFAULT_BIND_IP`]), an IPv4 `IP:PORT`, or a bracketed IPv6
/// `[ADDR]:PORT` (brackets are required for IPv6 to disambiguate the colons).
fn parse_listen(spec: &str) -> Result<(String, u16)> {
    if let Ok(port) = spec.parse::<u16>() {
        return Ok((DEFAULT_BIND_IP.to_string(), port));
    }
    if let Some(rest) = spec.strip_prefix('[') {
        let (addr, port) = rest
            .split_once("]:")
            .context("--listen [IPv6]:PORT needs a closing `]:PORT`")?;
        return Ok((addr.to_string(), port.parse().context("bad --listen port")?));
    }
    let (addr, port) = spec
        .rsplit_once(':')
        .context("--listen expects [IP:]PORT (bracket IPv6 as [addr]:port)")?;
    Ok((addr.to_string(), port.parse().context("bad --listen port")?))
}

fn bind_in_range(ports: &[u16], bind_ip: &str) -> Result<std::net::UdpSocket> {
    let mut last_err = None;
    for &p in ports {
        match std::net::UdpSocket::bind((bind_ip, p)) {
            Ok(s) => {
                set_cloexec(&s);
                return Ok(s);
            }
            Err(e) => last_err = Some(e),
        }
    }
    Err(last_err.unwrap().into())
}

/// Mark the authenticated session socket close-on-exec so it is never inherited
/// by the login shell we later spawn (where a child program could read or inject
/// session datagrams). Rust's `std::net` sockets are already created `CLOEXEC` on
/// Linux, but nothing else guarantees it, so we assert it explicitly — and it
/// re-arms the flag should the fd ever be `dup()`'d (dup clears `FD_CLOEXEC`).
#[cfg(unix)]
fn set_cloexec(sock: &std::net::UdpSocket) {
    use std::os::unix::io::AsRawFd;
    let fd = sock.as_raw_fd();
    // SAFETY: `fd` is a valid socket fd owned by `sock` for the duration of this
    // call; `F_GETFD`/`F_SETFD` only read/modify the descriptor flags.
    unsafe {
        let flags = libc::fcntl(fd, libc::F_GETFD);
        if flags >= 0 {
            libc::fcntl(fd, libc::F_SETFD, flags | libc::FD_CLOEXEC);
        }
    }
}
#[cfg(not(unix))]
fn set_cloexec(_sock: &std::net::UdpSocket) {}

/// Disable core dumps: a core file could contain the per-session client private
/// key (and terminal contents). Best-effort; done before any secret is minted.
#[cfg(unix)]
fn suppress_core_dumps() {
    let zero = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    unsafe {
        libc::setrlimit(libc::RLIMIT_CORE, &zero);
    }
}
#[cfg(not(unix))]
fn suppress_core_dumps() {}

fn main() -> Result<()> {
    suppress_core_dumps();
    let mut opts = parse_args()?;

    // Optional event log (--log-file). Installed before the daemonize fork: the
    // file fd and the (thread-free, synchronous) subscriber are inherited by the
    // forked child, so logging keeps working after we detach.
    if let Some(path) = &opts.log_file {
        if let Err(e) = mish::trace::init_file_logging(path, "server", opts.log_level) {
            eprintln!(
                "mish: warning: could not open log file {}: {e}",
                path.display()
            );
        }
    }
    tracing::info!(target: "mish::server", detach = opts.detach, persist = opts.persist, "server starting");

    // Export locale/env overrides for the child shell.
    for (k, v) in &opts.locale {
        std::env::set_var(k, v);
    }
    // Ensure the child runs under a UTF-8 locale: the emulator decodes its output
    // as UTF-8, so a non-UTF-8 locale would render (and synchronize) corrupted
    // text. Done after the -l overrides so an explicit locale is respected.
    eprintln!("mish: {}", mish::locale::ensure_utf8_locale());

    // Running as root is unusual in the normal SSH-launch model (the server runs
    // as the connecting user); flag it since a root shell over the network is a
    // sharp edge and there's no target uid to drop to here.
    #[cfg(unix)]
    if unsafe { libc::geteuid() } == 0 {
        eprintln!(
            "mish: warning: running as root — mish-server normally runs as the \
             connecting user (launched over SSH)"
        );
    }

    mish_quic::config::init_crypto();

    // One-shot enrollment (`--enroll-client`): add a client cert to the allow-list
    // and hand back the server cert, then exit. Run over SSH by `mish enroll`;
    // it never binds a socket or serves a shell.
    if let Some(client_cert_hex) = opts.enroll_client.take() {
        return run_enroll_client(opts, client_cert_hex);
    }

    // Direct-connect mode (`--listen`): an ssh-less, long-lived listener with a
    // persistent on-disk identity and an enrolled-client allow-list. It shares
    // nothing with the SSH-bootstrap flow below — no `MISH CONNECT` handoff, no
    // per-session credentials, no session registry — so it returns straight from
    // its own accept loop.
    if let Some(listen) = opts.listen.take() {
        return run_direct(opts, listen);
    }

    // Reattach: if a named session is requested and a live one already exists,
    // reprint its connect line and exit — the running daemon keeps serving and
    // the client connects to it (with the recorded, reused credentials).
    if let Some(name) = &opts.session {
        if let Some(entry) = mish::registry::find_live(name) {
            println!("{}", entry.connect_line);
            std::io::stdout().flush().ok();
            eprintln!(
                "mish: reattaching to existing session '{name}' on port {}",
                entry.port().unwrap_or(0)
            );
            tracing::info!(target: "mish::server", session = %name, "reattach to existing session");
            return Ok(());
        }
    }

    // Mutual authentication: mint a per-session client cert/key the client must
    // present, and require it server-side. The credentials travel only over the
    // authenticated SSH channel (the MISH CONNECT line below), so only the
    // SSH-authenticated party can connect and inject input.
    let (server_config, auth) = mish_quic::config::authenticated_server_config();
    let socket = bind_in_range(&opts.ports, &opts.bind_ip).context("binding UDP socket")?;
    let port = socket.local_addr()?.port();

    use mish::bootstrap::to_hex;
    let connect_line = format!(
        "MISH CONNECT {port} {} {} {}",
        to_hex(&auth.server_cert_der),
        to_hex(&auth.client_cert_der),
        to_hex(&auth.client_key_der),
    );
    println!("{connect_line}");
    std::io::stdout().flush().ok();
    eprintln!("mish server listening on UDP port {port}");

    if opts.detach {
        daemonize().context("daemonizing")?;
    }

    // Register the (now post-fork) daemon so a later `--session NAME` can find it.
    // Done after daemonize so the recorded PID is the serving process.
    if let Some(name) = &opts.session {
        if let Err(e) = mish::registry::store(name, std::process::id() as i32, &connect_line) {
            eprintln!("mish: warning: could not record session '{name}': {e}");
        }
    }

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("building tokio runtime")?;
    let result = runtime.block_on(serve(
        socket,
        server_config,
        opts.command,
        opts.persist,
        opts.shared,
        opts.forward,
    ));

    // Deregister on a clean exit (shell quit / reattach window elapsed). A daemon
    // killed abruptly leaves a stale entry, which `find_live` reaps on next lookup.
    if let Some(name) = &opts.session {
        mish::registry::remove(name);
    }
    result
}

/// Accept the next client that **completes the mutual-TLS handshake**, logging
/// and skipping any peer whose handshake fails.
///
/// `transport::accept` resolves as soon as a QUIC Initial arrives and then drives
/// the handshake, so it returns `Err` for any stranger who reaches the UDP port
/// without the pinned client certificate (the check that authenticates a client).
/// Propagating that error out of a session loop would let *any* QUIC speaker —
/// with no mish credentials — remotely tear down a live `--persist`/`--shared`
/// session: an unauthenticated DoS against the legitimate user. Instead we treat a
/// failed handshake as a non-event and wait for the next connection; only a closed
/// endpoint (`NoConnection`) is fatal.
async fn accept_authenticated(
    endpoint: &mish_quic::Endpoint,
) -> Result<mish_quic::transport::QuicTransport> {
    loop {
        match mish_quic::transport::accept(endpoint).await {
            Ok(t) => return Ok(t),
            Err(mish_quic::QuicError::NoConnection) => bail!("QUIC endpoint closed"),
            Err(e) => {
                tracing::debug!(
                    target: "mish::server",
                    error = %e,
                    "ignoring failed/unauthenticated QUIC handshake while accepting",
                );
                continue;
            }
        }
    }
}

async fn serve(
    socket: std::net::UdpSocket,
    server_config: mish_quic::ServerConfig,
    command: Vec<String>,
    persist: bool,
    shared: bool,
    forward: bool,
) -> Result<()> {
    let (cols, rows) = (80u16, 24u16);

    let endpoint = mish_quic::transport::server_from_socket(socket, server_config)
        .context("building QUIC endpoint")?;

    // Signal timeout: give up if no client connects within the window.
    let signal_timeout = env_secs("MOSH_SERVER_SIGNAL_TMOUT", 60);
    let t = match tokio::time::timeout(signal_timeout, accept_authenticated(&endpoint)).await {
        Ok(conn) => conn.context("accepting QUIC connection")?,
        Err(_) => {
            eprintln!("no client connected within the signal timeout; exiting");
            tracing::info!(target: "mish::server", "no client within signal timeout; exiting");
            return Ok(());
        }
    };
    eprintln!("client connected from {}", t.remote_address());
    tracing::info!(target: "mish::server", remote = %t.remote_address(), persist, "client connected");

    // An explicit `-- command` runs as given; with no command we start the
    // user's $SHELL as a login shell (reads the login profile, like `mosh host`).
    let pty = if command.is_empty() {
        PtyProcess::spawn_login_shell(cols, rows)
    } else {
        PtyProcess::spawn_argv(command, cols, rows)
    }
    .context("spawning PTY child")?;
    let clock = Arc::new(SystemClock::new());
    let network_timeout = Some(env_secs("MOSH_SERVER_NETWORK_TMOUT", 300));
    // Shared emulator: the session loop feeds it; the scrollback server reads it.
    let emu = mish_terminal::emulator::Emulator::shared(cols, rows);

    #[cfg(feature = "multi-client")]
    if shared {
        return serve_shared(endpoint, t, emu, clock, network_timeout, pty, forward).await;
    }
    #[cfg(not(feature = "multi-client"))]
    let _ = shared;

    if persist {
        return serve_persistent(endpoint, t, emu, clock, network_timeout, pty, forward).await;
    }

    // Non-persistent (default): one connection, exit when the client or shell goes.
    let transport = Arc::new(t);
    tokio::spawn(mish::forward::serve_side_channels(
        transport.clone(),
        emu.clone(),
        forward,
    ));
    run_server(
        transport,
        emu,
        clock,
        network_timeout,
        pty.output,
        pty.control,
    )
    .await;
    eprintln!("session ended");
    tracing::info!(target: "mish::server", "session ended");
    Ok(())
}

/// Persistent server-identity key path: `--server-key`, else `<config>/server.key`.
fn server_key_path(explicit: Option<PathBuf>) -> Result<PathBuf> {
    match explicit {
        Some(p) => Ok(p),
        None => Ok(mish::direct::config_dir()?.join("server.key")),
    }
}

/// Enrolled-client cert directory: `--authorized-certs`, else `<config>/authorized`.
fn authorized_certs_dir(explicit: Option<PathBuf>) -> Result<PathBuf> {
    match explicit {
        Some(p) => Ok(p),
        None => Ok(mish::direct::config_dir()?.join("authorized")),
    }
}

/// One-shot enrollment side of `mish enroll`: decode the client cert, add it to
/// the allow-list under the client's chosen name, materialize the persistent
/// server identity, and print `MISH IDENTITY <server-cert-hex>` for the client to
/// pin. Runs over SSH — the authenticated channel is what authorizes adding a
/// client to the allow-list.
fn run_enroll_client(opts: Options, client_cert_hex: String) -> Result<()> {
    let key_path = server_key_path(opts.server_key)?;
    let certs_dir = authorized_certs_dir(opts.authorized_certs)?;
    let name = opts
        .enroll_name
        .unwrap_or_else(|| DEFAULT_ENROLL_NAME.to_string());
    let client_cert = mish::bootstrap::from_hex(&client_cert_hex)
        .context("--enroll-client expects a hex-encoded client certificate")?;

    // Materialize (or load) the server identity so we have a cert to hand back.
    let (server_cert, _key) =
        mish::direct::load_or_generate_identity(&key_path, mish::direct::SERVER_SUBJECT)
            .context("loading server identity")?;
    let path = mish::direct::enroll_client_cert(&certs_dir, &name, &client_cert)
        .context("enrolling client cert")?;
    eprintln!("mish: enrolled client {name:?} at {}", path.display());

    use mish::bootstrap::to_hex;
    println!("MISH IDENTITY {}", to_hex(&server_cert));
    std::io::stdout().flush().ok();
    Ok(())
}

/// Direct-connect mode: bind a long-lived listener with a persistent identity
/// and an enrolled-client allow-list, then serve each accepted connection its
/// own non-persistent shell. No `MISH CONNECT` handoff (the client already holds
/// its enrolled credentials) and no session registry.
fn run_direct(opts: Options, listen: (String, u16)) -> Result<()> {
    let (bind_ip, port) = listen;
    let key_path = server_key_path(opts.server_key)?;
    let certs_dir = authorized_certs_dir(opts.authorized_certs)?;

    let (server_cert, server_key) =
        mish::direct::load_or_generate_identity(&key_path, mish::direct::SERVER_SUBJECT)
            .context("loading server identity")?;
    let authorized =
        mish::direct::load_authorized_certs(&certs_dir).context("loading authorized certs")?;
    if authorized.is_empty() {
        eprintln!(
            "mish: warning: no enrolled client certs in {} — enroll a client before it can connect",
            certs_dir.display()
        );
    }
    // Re-read the allow-list on every handshake so enrolling or revoking a client
    // (adding/removing a *.crt) takes effect on the running listener without a
    // restart. A read failure fails closed (empty list ⇒ reject everyone).
    let loader_dir = certs_dir.clone();
    let authorized_loader: mish_quic::config::AuthorizedCertsLoader = Box::new(move || {
        mish::direct::load_authorized_certs(&loader_dir).unwrap_or_else(|e| {
            eprintln!(
                "mish: failed to reload authorized certs from {}: {e:#} — rejecting",
                loader_dir.display()
            );
            Vec::new()
        })
    });
    let server_config =
        mish_quic::config::stable_server_config(&server_cert, &server_key, authorized_loader);

    let socket = bind_in_range(&[port], &bind_ip).context("binding direct-mode UDP socket")?;
    let local = socket.local_addr()?;
    // Machine-readable bound address (no secret — just where we listen), so a
    // supervisor/test can discover an OS-assigned port (`--listen …:0`).
    println!("MISH LISTEN {local}");
    std::io::stdout().flush().ok();
    eprintln!("mish direct listener on {local}");
    tracing::info!(target: "mish::server", %local, "direct listener started");

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("building tokio runtime")?;
    // `serve_direct` speaks argv (`Vec<String>`), while this branch models the
    // optional `-- command` as a single joined string. A bare `--listen` (the
    // production path) collects to an empty argv, letting each connection's Exec
    // hello pick its command; an explicit `--listen -- command` pins it for every
    // connection instead (hellos must then carry an empty argv).
    let command: Vec<String> = opts.command.into_iter().collect();
    runtime.block_on(serve_direct(socket, server_config, command))
}

/// Direct-mode accept loop: one persistent endpoint multiplexes every connection
/// by QUIC Connection ID. Each authenticated connection is served its own fresh,
/// non-persistent shell on a spawned task, so a new invocation is always a new
/// shell and roaming rides QUIC connection migration on the existing one. The
/// loop runs until the endpoint is closed; there is deliberately no signal
/// timeout — a systemd-owned listener waits for clients indefinitely.
async fn serve_direct(
    socket: std::net::UdpSocket,
    server_config: mish_quic::ServerConfig,
    command: Vec<String>,
) -> Result<()> {
    let endpoint = mish_quic::transport::server_from_socket(socket, server_config)
        .context("building QUIC endpoint")?;
    let network_timeout = Some(env_secs("MOSH_SERVER_NETWORK_TMOUT", 300));
    loop {
        let transport = accept_authenticated(&endpoint)
            .await
            .context("accepting direct-mode connection")?;
        let remote = transport.remote_address();
        eprintln!("client connected from {remote}");
        tracing::info!(target: "mish::server", %remote, "direct client connected");
        let command = command.clone();
        tokio::spawn(async move {
            if let Err(e) =
                mish::direct::serve_connection(transport, command, network_timeout).await
            {
                tracing::warn!(target: "mish::server", error = %e, "direct connection ended with error");
            }
        });
    }
}

/// Persistent mode (`--persist`): keep the PTY + emulator alive across client
/// disconnects and accept reattaches, until the shell exits or no client
/// reattaches within the window (`MISH_SERVER_REATTACH_TMOUT`, default 24h).
async fn serve_persistent(
    endpoint: mish_quic::Endpoint,
    first: mish_quic::transport::QuicTransport,
    emu: std::sync::Arc<std::sync::Mutex<mish_terminal::emulator::Emulator>>,
    clock: Arc<SystemClock>,
    network_timeout: Option<Duration>,
    pty: PtyProcess,
    forward: bool,
) -> Result<()> {
    use mish::persist::{AttachEnd, PersistentSession, Role};

    let session = Arc::new(PersistentSession::spawn(
        emu.clone(),
        clock,
        pty.output,
        pty.control,
    ));
    let reattach_timeout = env_secs("MISH_SERVER_REATTACH_TMOUT", 86_400);

    let mut conn = first;
    loop {
        let transport = Arc::new(conn);
        // Side-channels (scrollback + forwarding) for this connection (aborted
        // when the attachment ends).
        let hist = tokio::spawn(mish::forward::serve_side_channels(
            transport.clone(),
            emu.clone(),
            forward,
        ));

        // Run this attachment, but let a *new* incoming connection preempt it. A
        // fresh connect is a strong signal the current client is gone — including
        // the hard-drop case where the old connection never closed (a sleeping
        // laptop, vanished Wi-Fi), which would otherwise pin `attach` in its idle
        // watchdog for up to `network_timeout` and block the reattach that whole
        // time. We race the attachment against `accept()`; whichever fires first
        // wins, and a newcomer cancels the attachment cleanly.
        let (preempt_tx, preempt_rx) = tokio::sync::oneshot::channel::<()>();
        let attaching = session.clone().attach(
            transport,
            network_timeout,
            async move {
                let _ = preempt_rx.await;
            },
            Role::Owner,
        );
        tokio::pin!(attaching);

        let end = tokio::select! {
            end = &mut attaching => end,
            incoming = accept_authenticated(&endpoint) => {
                // A new *authenticated* client arrived while we were still
                // attached → preempt the current one and switch to the newcomer.
                // (`accept_authenticated` stays pending on unauthenticated
                // handshakes, so a stranger can't trip this arm and preempt the
                // live client.)
                let next = incoming.context("accepting reattach (preempt)")?;
                let _ = preempt_tx.send(());
                let _ = (&mut attaching).await; // let `attach` abort its driver
                hist.abort();
                eprintln!("client reattached from {} (preempting previous)", next.remote_address());
                tracing::info!(target: "mish::server", remote = %next.remote_address(), "reattach preempts current client");
                conn = next;
                continue;
            }
        };
        hist.abort();

        match end {
            AttachEnd::ChildExited => {
                eprintln!("session ended (shell exited)");
                return Ok(());
            }
            AttachEnd::Disconnected => {
                // Clean detach (the old connection closed): wait for a reattach
                // within the window. A hard drop is handled by the preempt arm
                // above, so this path is the graceful case.
                eprintln!("client detached; awaiting reattach…");
                conn = match tokio::time::timeout(reattach_timeout, accept_authenticated(&endpoint))
                    .await
                {
                    Ok(c) => c.context("accepting reattach")?,
                    Err(_) => {
                        eprintln!("no reattach within the window; ending session");
                        return Ok(());
                    }
                };
                eprintln!("client reattached from {}", conn.remote_address());
            }
        }
    }
}

/// Shared mode (`--shared`): keep the PTY + emulator alive and accept **several
/// concurrent clients** — one read-write owner + read-only viewers
/// (NEXT_FEATURES.md #3). Each connection runs its own [`attach`] over the shared
/// [`PersistentSession`]; the first to claim the (single) writer slot is the
/// owner and the rest are viewers. Unlike [`serve_persistent`] a newcomer *joins*
/// rather than preempting. The session ends when the shell exits or no client is
/// attached for `MISH_SERVER_REATTACH_TMOUT`.
///
/// [`attach`]: mish::persist::PersistentSession::attach
/// [`PersistentSession`]: mish::persist::PersistentSession
#[cfg(feature = "multi-client")]
async fn serve_shared(
    endpoint: mish_quic::Endpoint,
    first: mish_quic::transport::QuicTransport,
    emu: std::sync::Arc<std::sync::Mutex<mish_terminal::emulator::Emulator>>,
    clock: Arc<SystemClock>,
    network_timeout: Option<Duration>,
    pty: PtyProcess,
    forward: bool,
) -> Result<()> {
    use mish::persist::{AttachEnd, PersistentSession};
    use std::sync::atomic::AtomicBool;
    use tokio::task::JoinSet;

    let session = Arc::new(PersistentSession::spawn(
        emu.clone(),
        clock,
        pty.output,
        pty.control,
    ));
    let reattach_timeout = env_secs("MISH_SERVER_REATTACH_TMOUT", 86_400);
    // The single read-write slot: the first attachment to claim it owns the
    // session; everyone else watches read-only until it's released.
    let has_owner = Arc::new(AtomicBool::new(false));
    let mut tasks: JoinSet<AttachEnd> = JoinSet::new();

    let role = spawn_attachment(
        &session,
        &emu,
        &has_owner,
        network_timeout,
        first,
        forward,
        &mut tasks,
    );
    eprintln!("client attached as {role:?} (shared session)");

    loop {
        tokio::select! {
            // A new client joins the shared session (owner if the writer slot is
            // free, else a read-only viewer).
            incoming = accept_authenticated(&endpoint) => {
                let conn = incoming.context("accepting a shared-session client")?;
                let remote = conn.remote_address();
                let role = spawn_attachment(
                    &session,
                    &emu,
                    &has_owner,
                    network_timeout,
                    conn,
                    forward,
                    &mut tasks,
                );
                eprintln!("client attached from {remote} as {role:?}");
                tracing::info!(target: "mish::server", %remote, ?role, "shared-session client attached");
            }
            // An attachment finished. ChildExited ends the whole session; a
            // Disconnected / idle just drops that one client (the writer slot, if
            // it held it, was already released by the task).
            joined = tasks.join_next(), if !tasks.is_empty() => {
                if let Some(Ok(AttachEnd::ChildExited)) = joined {
                    eprintln!("session ended (shell exited)");
                    return Ok(());
                }
            }
            // No clients attached: end the session unless one (re)attaches within
            // the window.
            _ = tokio::time::sleep(reattach_timeout), if tasks.is_empty() => {
                eprintln!("no clients within the reattach window; ending shared session");
                return Ok(());
            }
        }
    }
}

/// Spawn one shared-session attachment task and return the role it took. Claims
/// the writer slot ([`Role::Owner`]) if free, else attaches read-only
/// ([`Role::Viewer`]); the task releases the slot when an owner leaves. Each
/// attachment carries its own scrollback (+ forwarding, owner only) side-channel.
///
/// Port forwarding is granted **only to the owner** even when the server allows
/// it: a read-only viewer watches the terminal but cannot open tunnels through
/// the session.
///
/// [`Role::Owner`]: mish::persist::Role::Owner
/// [`Role::Viewer`]: mish::persist::Role::Viewer
#[cfg(feature = "multi-client")]
fn spawn_attachment(
    session: &Arc<mish::persist::PersistentSession>,
    emu: &std::sync::Arc<std::sync::Mutex<mish_terminal::emulator::Emulator>>,
    has_owner: &Arc<std::sync::atomic::AtomicBool>,
    network_timeout: Option<Duration>,
    conn: mish_quic::transport::QuicTransport,
    forward: bool,
    tasks: &mut tokio::task::JoinSet<mish::persist::AttachEnd>,
) -> mish::persist::Role {
    use mish::persist::Role;
    use std::sync::atomic::Ordering;

    let transport = Arc::new(conn);
    let is_owner = has_owner
        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
        .is_ok();
    let role = if is_owner { Role::Owner } else { Role::Viewer };
    // Only the read-write owner may open tunnels; viewers are read-only.
    let allow_forward = forward && matches!(role, Role::Owner);

    let session = session.clone();
    let emu = emu.clone();
    let has_owner = has_owner.clone();
    tasks.spawn(async move {
        let hist = tokio::spawn(mish::forward::serve_side_channels(
            transport.clone(),
            emu,
            allow_forward,
        ));
        let end = session
            .attach(
                transport,
                network_timeout,
                std::future::pending::<()>(),
                role,
            )
            .await;
        hist.abort();
        // Free the writer slot so a later client can become owner.
        if matches!(role, Role::Owner) {
            has_owner.store(false, Ordering::Release);
        }
        end
    });
    role
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_listen_accepts_bare_port_ipv4_and_bracketed_ipv6() {
        assert_eq!(
            parse_listen("6000").unwrap(),
            (DEFAULT_BIND_IP.to_string(), 6000)
        );
        assert_eq!(
            parse_listen("10.99.1.10:6000").unwrap(),
            ("10.99.1.10".to_string(), 6000)
        );
        assert_eq!(
            parse_listen("[fd00::1]:6000").unwrap(),
            ("fd00::1".to_string(), 6000)
        );
    }

    #[test]
    fn parse_listen_rejects_malformed_specs() {
        // Missing port, non-numeric port, and a bracketed IPv6 without the
        // closing `]:` all fail at parse time.
        assert!(parse_listen("10.99.1.10:").is_err());
        assert!(parse_listen("10.99.1.10:notaport").is_err());
        assert!(parse_listen("[fd00::1]6000").is_err());
        // A bare (unbracketed) IPv6 is *not* disambiguated here — its last colon
        // splits off "1" as the port, leaving a bogus bind IP that fails loudly
        // at bind time. Brackets are required for IPv6 (documented in USAGE).
        assert_eq!(parse_listen("fd00::1").unwrap(), ("fd00:".to_string(), 1));
    }
}
