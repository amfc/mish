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
//! Usage: `mish-server [--detach] [--persist] [--shared] [--no-forward] [-4|-6|--family inet|inet6] [-p PORT|-p LOW:HIGH] [-l KEY=VAL]... [--log-file PATH] [--log-level LEVEL] [bind-port] [-- command]`
//!
//! `--no-forward` hard-disables `ssh -L`/`-R`-style port forwarding (otherwise
//! the SSH-authenticated client may request forwards; see `docs/port-forwarding.md`).
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
    command: Option<String>,
    /// Whether to honor client port-forwarding requests (`-L`/`-R`). On by
    /// default — the connecting peer is the SSH-authenticated owner — and
    /// hard-disabled with `--no-forward`. Forwards are still only created when
    /// the client explicitly requests them.
    forward: bool,
    /// Write a JSON event log here (`--log-file`); `None` disables logging.
    log_file: Option<std::path::PathBuf>,
    /// Max verbosity for the event log (`--log-level`, default debug).
    log_level: tracing::Level,
}

fn parse_args() -> Result<Options> {
    let mut opts = Options {
        detach: false,
        ports: Vec::new(),
        locale: Vec::new(),
        bind_ip: "0.0.0.0".to_string(),
        persist: false,
        shared: false,
        session: None,
        command: None,
        forward: true,
        log_file: None,
        log_level: tracing::Level::DEBUG,
    };
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--detach" => opts.detach = true,
            "--persist" => opts.persist = true,
            "--no-forward" => opts.forward = false,
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
            "--log-file" => {
                opts.log_file = Some(args.next().context("--log-file needs a PATH")?.into());
            }
            "--log-level" => {
                opts.log_level =
                    mish::trace::parse_level(&args.next().context("--log-level needs a LEVEL")?);
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

fn bind_in_range(ports: &[u16], bind_ip: &str) -> Result<std::net::UdpSocket> {
    let mut last_err = None;
    for &p in ports {
        match std::net::UdpSocket::bind((bind_ip, p)) {
            Ok(s) => return Ok(s),
            Err(e) => last_err = Some(e),
        }
    }
    Err(last_err.unwrap().into())
}

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
    let opts = parse_args()?;

    // Optional event log (--log-file). Installed before the daemonize fork: the
    // file fd and the (thread-free, synchronous) subscriber are inherited by the
    // forked child, so logging keeps working after we detach.
    if let Some(path) = &opts.log_file {
        if let Err(e) = mish::trace::init_file_logging(path, "server", opts.log_level) {
            eprintln!("mish: warning: could not open log file {}: {e}", path.display());
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

async fn serve(
    socket: std::net::UdpSocket,
    server_config: mish_quic::ServerConfig,
    command: Option<String>,
    persist: bool,
    shared: bool,
    forward: bool,
) -> Result<()> {
    let (cols, rows) = (80u16, 24u16);

    let endpoint = mish_quic::transport::server_from_socket(socket, server_config)
        .context("building QUIC endpoint")?;

    // Signal timeout: give up if no client connects within the window.
    let signal_timeout = env_secs("MOSH_SERVER_SIGNAL_TMOUT", 60);
    let t =
        match tokio::time::timeout(signal_timeout, mish_quic::transport::accept(&endpoint)).await {
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
    let pty = match command {
        Some(cmd) => PtyProcess::spawn(&cmd, cols, rows),
        None => PtyProcess::spawn_login_shell(cols, rows),
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
        let attaching = session
            .clone()
            .attach(
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
            incoming = mish_quic::transport::accept(&endpoint) => {
                // A new client arrived while we were still attached → preempt the
                // current one and switch to the newcomer.
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
                conn = match tokio::time::timeout(
                    reattach_timeout,
                    mish_quic::transport::accept(&endpoint),
                )
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
            incoming = mish_quic::transport::accept(&endpoint) => {
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
            .attach(transport, network_timeout, std::future::pending::<()>(), role)
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
