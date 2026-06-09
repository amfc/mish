//! Connection bootstrap, mirroring how upstream mosh starts a session.
//!
//! The real `mosh` wrapper SSHes to the host, runs `mosh-server`, reads the
//! `MISH CONNECT <port> <key>` line it prints, then hands the port/key to
//! `mosh-client`, which opens the UDP session directly. We do the same: SSH (or,
//! in `--local` mode, a child process) starts `mish-server`, which prints
//!
//! ```text
//! MISH CONNECT <port> <server-cert-DER> <client-cert-DER> <client-key-DER>
//! ```
//!
//! (all hex-encoded) over the (SSH-encrypted) channel. We parse it, then open a
//! **mutually-authenticated** QUIC connection: the client trusts exactly the
//! server cert and presents the minted client cert/key, so the server accepts
//! input only from the party that read this line over the authenticated SSH
//! channel. Carrying the client private key over SSH is safe (the channel is
//! confidential and authenticated) and mirrors how upstream mosh ships its
//! shared session key.
//!
//! ## Two bootstrap transports
//!
//! There are two ways to run that initial SSH step, selected by
//! [`BootstrapMode`] (the client's `--bootstrap` flag):
//!
//! - [`BootstrapMode::Ssh`] — shell out to the system `ssh` binary (this is what
//!   upstream mosh does, and the default when `ssh` is on `PATH`).
//! - [`BootstrapMode::Builtin`] — a builtin, pure-Rust SSH client ([`russh`]),
//!   so no external `ssh` is required. This is the path that will let `mish`
//!   run on platforms where mosh never could (notably **Windows**, which has no
//!   `mosh` today); the Windows port itself is future work.
//! - [`BootstrapMode::Auto`] (the default) — use the system `ssh` if it is on
//!   `PATH`, otherwise fall back to the builtin client.
//!
//! The bootstrap handle (the local server process, the `ssh` process, or the
//! builtin SSH connection) is held for the lifetime of the [`Bootstrap`] and
//! torn down on drop. (Upstream mosh daemonizes the server so SSH can fully
//! close; we run the server with `--detach` over SSH, so the daemon survives
//! either transport closing.)

use std::io::IsTerminal;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use russh::client::{self, KeyboardInteractiveAuthResponse};
use russh::keys::{load_secret_key, HashAlg, PrivateKeyWithHashAlg, PublicKey};
use russh::{ChannelMsg, Disconnect};
use tokio::process::{Child, Command};
use zeroize::Zeroizing;

/// A bootstrapped session target: where to connect, the cert to trust, and the
/// handle keeping the server reachable.
pub struct Bootstrap {
    pub addr: SocketAddr,
    /// Server certificate (DER) the client pins to authenticate the server.
    pub server_cert_der: Vec<u8>,
    /// Client certificate (DER) the client presents for mutual auth.
    pub client_cert_der: Vec<u8>,
    /// Client private key (PKCS#8 DER) the client presents for mutual auth.
    /// Zeroized on drop ([`Zeroizing`] derefs to `&[u8]`, so callers are unchanged).
    pub client_key_der: Zeroizing<Vec<u8>>,
    /// The transport that started the server, held open for the session and torn
    /// down on drop.
    _guard: Guard,
}

/// Whatever needs to stay alive for the bootstrapped session: a child process
/// (local server, or the external `ssh`), or the builtin SSH connection.
enum Guard {
    /// A child process (the `--local` server, or the external `ssh`). Killed on
    /// drop — these are also spawned with `kill_on_drop`, so this is belt-and-
    /// braces.
    Child(Child),
    /// A builtin [`russh`] SSH connection, held open for the whole session and
    /// closed on drop. We deliberately keep it open rather than disconnecting
    /// once `MISH CONNECT` is read: the server prints that line, then writes one
    /// more diagnostic to stderr *before* it forks the `--detach` daemon, so
    /// closing the channel early could deliver SIGPIPE to the parent before it
    /// detaches. The daemon (post-fork, stdio redirected to /dev/null) outlives
    /// this connection regardless.
    ///
    /// For a `ProxyJump` connection the `jumps` handles must also stay alive: the
    /// target's stream rides a direct-tcpip channel on the last jump, which rides
    /// the previous jump, … back to the TCP connection on `jumps[0]`. Dropping any
    /// of them collapses the tunnel. Held only for their `Drop`; never read.
    #[allow(dead_code)]
    Connection {
        target: client::Handle<BuiltinHandler>,
        jumps: Vec<client::Handle<BuiltinHandler>>,
    },
}

impl Drop for Guard {
    fn drop(&mut self) {
        // Tear down the server / ssh channel when the session ends.
        if let Guard::Child(child) = self {
            let _ = child.start_kill();
        }
        // Guard::Connection: dropping the russh handle closes the connection.
    }
}

/// Which SSH transport the client uses to bootstrap the session (`--bootstrap`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum BootstrapMode {
    /// Prefer the system `ssh` binary; fall back to the builtin client if it is
    /// not on `PATH`. The default.
    #[default]
    Auto,
    /// Always shell out to the system `ssh` binary (upstream mosh's behaviour).
    Ssh,
    /// Always use the builtin, pure-Rust SSH client (no external `ssh`).
    Builtin,
}

impl BootstrapMode {
    /// Parse the `--bootstrap` value: `auto`, `ssh`, or `builtin`.
    pub fn parse(s: &str) -> Result<Self> {
        match s {
            "auto" => Ok(BootstrapMode::Auto),
            "ssh" => Ok(BootstrapMode::Ssh),
            "builtin" => Ok(BootstrapMode::Builtin),
            other => bail!("unknown --bootstrap mode {other:?} (auto|ssh|builtin)"),
        }
    }

    /// Decide whether to use the builtin client, given the system `ssh` program
    /// name (the first word of `--ssh`). In [`Auto`](Self::Auto) mode this checks
    /// whether that program is on `PATH`.
    pub fn use_builtin(self, ssh_prog: &str) -> bool {
        match self {
            BootstrapMode::Ssh => false,
            BootstrapMode::Builtin => true,
            BootstrapMode::Auto => !program_on_path(ssh_prog),
        }
    }
}

/// Best-effort check for whether `prog` can be executed: an absolute/relative
/// path is tested directly, otherwise every `PATH` entry is searched (honouring
/// `PATHEXT` on Windows). Used to drive [`BootstrapMode::Auto`].
pub fn program_on_path(prog: &str) -> bool {
    let p = Path::new(prog);
    if p.is_absolute() || prog.contains(std::path::MAIN_SEPARATOR) {
        return p.is_file();
    }
    // On Windows an executable is found by appending one of PATHEXT; elsewhere
    // the bare name is the file.
    #[cfg(windows)]
    let exts: Vec<String> = std::env::var("PATHEXT")
        .unwrap_or_else(|_| ".EXE;.CMD;.BAT;.COM".into())
        .split(';')
        .filter(|e| !e.is_empty())
        .map(|e| e.to_string())
        .collect();
    #[cfg(not(windows))]
    let exts: Vec<String> = vec![String::new()];

    let Some(path) = std::env::var_os("PATH") else {
        return false;
    };
    for dir in std::env::split_paths(&path) {
        for ext in &exts {
            if dir.join(format!("{prog}{ext}")).is_file() {
                return true;
            }
        }
    }
    false
}

/// Build the `mish-server` argument list: optional `--detach`, optional
/// `--shared` (multi-client), optional `--allow-forward` (port forwarding is
/// off on the server by default), an optional named reattachable
/// `--session NAME`, an ephemeral port, then an optional `-- command`.
fn server_args(
    detach: bool,
    shared: bool,
    forward: bool,
    session: Option<&str>,
    port: &str,
    command: Option<&str>,
) -> Vec<String> {
    let mut args = Vec::new();
    if detach {
        args.push("--detach".to_string());
    }
    if shared {
        args.push("--shared".to_string());
    }
    // The user requested a -L/-R forward, so enable forwarding on the server we
    // are launching for them (the server defaults to refusing it).
    if forward {
        args.push("--allow-forward".to_string());
    }
    if let Some(name) = session {
        args.push("--session".to_string());
        args.push(name.to_string());
    }
    args.push(port.to_string());
    if let Some(cmd) = command {
        args.push("--".into());
        args.push(cmd.into());
    }
    args
}

/// Start `mish-server` locally as a child process (no SSH). Used for `--local`.
pub async fn local(
    server_cmd: &str,
    shared: bool,
    forward: bool,
    session: Option<&str>,
    command: Option<&str>,
) -> Result<Bootstrap> {
    // Local mode: keep the server in the foreground as a managed child (no
    // detach — we kill it when the session ends).
    let mut child = Command::new(server_cmd)
        .args(server_args(false, shared, forward, session, "0", command))
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .kill_on_drop(true)
        .spawn()
        .with_context(|| format!("spawning local server `{server_cmd}`"))?;

    let creds = read_connect(&mut child).await?;
    Ok(Bootstrap {
        addr: SocketAddr::from(([127, 0, 0, 1], creds.port)),
        server_cert_der: creds.server_cert,
        client_cert_der: creds.client_cert,
        client_key_der: creds.client_key,
        _guard: Guard::Child(child),
    })
}

/// SSH to `host`, run `mish-server` there, and read its `MISH CONNECT` line.
///
/// `ssh_argv` is the (already shell-split) ssh command, e.g. `["ssh"]` or
/// `["ssh", "-p", "2222"]`. We append mosh's standard ssh options — `-n` (no
/// stdin, so the local TTY stays with us) and, unless `ssh_pty` is false, `-tt`
/// (force remote PTY allocation, needed for the login shell to behave) — then
/// `host -- <server …>`, matching upstream `mosh`'s wrapper.
#[allow(clippy::too_many_arguments)] // bootstrap entry point: discrete server flags
pub async fn ssh(
    ssh_argv: &[String],
    ssh_pty: bool,
    host: &str,
    server_cmd: &str,
    shared: bool,
    forward: bool,
    session: Option<&str>,
    command: Option<&str>,
) -> Result<Bootstrap> {
    let (prog, base) = ssh_argv
        .split_first()
        .ok_or_else(|| anyhow!("empty --ssh command"))?;
    // Over SSH: detach the server so it survives SSH closing (real mosh does
    // this). The `ssh` process exits once the server's parent returns; the
    // daemon keeps serving over UDP.
    let mut cmd = Command::new(prog);
    cmd.args(base).arg("-n");
    if ssh_pty {
        cmd.arg("-tt");
    }
    cmd.arg(host)
        .arg("--")
        .arg(server_cmd)
        .args(server_args(true, shared, forward, session, "0", command));
    let mut child = cmd
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .kill_on_drop(true)
        .spawn()
        .with_context(|| format!("spawning `{} {host} {server_cmd}`", ssh_argv.join(" ")))?;

    let creds = read_connect(&mut child).await?;

    // The UDP session goes to the same host SSH reached; resolve its address.
    let hostname = host.rsplit('@').next().unwrap_or(host);
    let ip = tokio::net::lookup_host((hostname, creds.port))
        .await
        .with_context(|| format!("resolving {hostname}"))?
        .next()
        .ok_or_else(|| anyhow!("no address for {hostname}"))?;

    Ok(Bootstrap {
        addr: ip,
        server_cert_der: creds.server_cert,
        client_cert_der: creds.client_cert,
        client_key_der: creds.client_key,
        _guard: Guard::Child(child),
    })
}

/// Bootstrap with the builtin, pure-Rust SSH client ([`russh`]) instead of the
/// system `ssh` binary — `--bootstrap=builtin`.
///
/// `host` is `[user@]alias` and `port` is the explicit `--ssh-port` (or `None`).
/// We resolve the alias through `~/.ssh/config` (`HostName`/`Port`/`User`/
/// `IdentityFile`/`ProxyJump`; an explicit command-line user/port wins), connect
/// — directly, or tunnelled through the `ProxyJump` chain — authenticate
/// (ssh-agent → identity files, prompting for a passphrase on an encrypted key →
/// keyboard-interactive → password), then `exec` `mish-server --detach …` and
/// read its `MISH CONNECT` line. The server daemonizes, so the QUIC/UDP session
/// outlives this connection.
///
/// Host keys are checked against `~/.ssh/known_hosts`: a mismatch is rejected, an
/// unknown host is accepted trust-on-first-use (logged, not persisted). Password
/// and passphrase prompts happen only when stdin is a real terminal.
///
/// `ProxyJump` tunnels only the **SSH bootstrap**; the mosh UDP session still
/// connects directly to the resolved target address (mosh roaming uses its own
/// path and is not tunnelled), so the target must be reachable by UDP.
pub async fn builtin(
    host: &str,
    port: Option<u16>,
    server_cmd: &str,
    shared: bool,
    forward: bool,
    session: Option<&str>,
    command: Option<&str>,
) -> Result<Bootstrap> {
    let (cli_user, alias) = split_user_host(host);
    let target = resolve_host(&alias, cli_user.as_deref(), port);

    let rconfig = Arc::new(client::Config::default());

    // Connect to the target — directly, or through the ProxyJump chain.
    let (mut handle, jumps) = if target.proxy_jump.is_empty() {
        let handler = BuiltinHandler {
            host: target.hostname.clone(),
            port: target.port,
            known_hosts_path: None,
        };
        let h = client::connect(
            rconfig.clone(),
            (target.hostname.as_str(), target.port),
            handler,
        )
        .await
        .with_context(|| format!("connecting to {}:{}", target.hostname, target.port))?;
        (h, Vec::new())
    } else {
        let (stream, jumps) = open_proxy_chain(&target, &rconfig).await?;
        let handler = BuiltinHandler {
            host: target.hostname.clone(),
            port: target.port,
            known_hosts_path: None,
        };
        let h = client::connect_stream(rconfig.clone(), stream, handler)
            .await
            .with_context(|| {
                format!(
                    "connecting to {}:{} via ProxyJump",
                    target.hostname, target.port
                )
            })?;
        (h, jumps)
    };

    authenticate(&mut handle, &target.user, &target.identities)
        .await
        .with_context(|| format!("authenticating to {}@{}", target.user, target.hostname))?;

    // Build the remote command line. The args mirror the `ssh` transport's
    // (`--detach` so the server survives this connection closing); each is
    // shell-quoted because sshd runs the whole string through the login shell.
    let argv = std::iter::once(server_cmd.to_string())
        .chain(server_args(true, shared, forward, session, "0", command))
        .map(|a| shell_quote(&a))
        .collect::<Vec<_>>()
        .join(" ");

    let mut channel = handle
        .channel_open_session()
        .await
        .context("opening ssh session channel")?;
    // No PTY request: the server daemonizes and runs its own PTY for the child
    // shell, so a clean pipe (separate stdout/stderr, no CRLF translation) is
    // better for parsing the MISH CONNECT line than a `ssh -tt` style PTY.
    channel
        .exec(true, argv.as_bytes())
        .await
        .context("running mish-server over the builtin SSH channel")?;

    let creds = read_connect_channel(&mut channel).await?;

    // The UDP session goes directly to the resolved target host (even when SSH was
    // tunnelled through a jump); resolve its address.
    let ip = tokio::net::lookup_host((target.hostname.as_str(), creds.port))
        .await
        .with_context(|| format!("resolving {}", target.hostname))?
        .next()
        .ok_or_else(|| anyhow!("no address for {}", target.hostname))?;

    Ok(Bootstrap {
        addr: ip,
        server_cert_der: creds.server_cert,
        client_cert_der: creds.client_cert,
        client_key_der: creds.client_key,
        _guard: Guard::Connection {
            target: handle,
            jumps,
        },
    })
}

/// Split `[user@]host` into an optional user and the bare hostname. Only the last
/// `@` separates them (an `@` can legitimately appear in a username).
fn split_user_host(host: &str) -> (Option<String>, String) {
    match host.rsplit_once('@') {
        Some((u, h)) => (Some(u.to_string()), h.to_string()),
        None => (None, host.to_string()),
    }
}

/// The local login name, used when `host` carries no `user@`. Falls back to
/// `USER` (Unix) / `USERNAME` (Windows), then to `"root"`.
fn default_user() -> String {
    std::env::var("USER")
        .or_else(|_| std::env::var("USERNAME"))
        .unwrap_or_else(|_| "root".to_string())
}

/// The user's home directory (`HOME`, or `USERPROFILE` on Windows), used to find
/// `~/.ssh/`.
fn home_dir() -> Option<PathBuf> {
    std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .map(PathBuf::from)
}

/// POSIX-shell-quote a single argument so the remote login shell sees it
/// verbatim. Safe characters are passed through; everything else is wrapped in
/// single quotes (with embedded `'` escaped the usual `'\''` way).
fn shell_quote(arg: &str) -> String {
    let safe = !arg.is_empty()
        && arg.bytes().all(|b| {
            b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'/' | b'.' | b':' | b'=' | b',')
        });
    if safe {
        arg.to_string()
    } else {
        format!("'{}'", arg.replace('\'', r"'\''"))
    }
}

/// The outcome of checking a server host key against `known_hosts`.
#[derive(Debug, PartialEq, Eq)]
enum HostKeyVerdict {
    /// The host is in `known_hosts` and the key matches — accept.
    Trusted,
    /// The host is not in `known_hosts` — first contact. The caller prompts the
    /// user (see [`confirm_and_record_new_host`]) and, on acceptance, **records**
    /// the key so a later key change is detected as a possible MITM.
    FirstUse,
    /// The host is known but the key **differs** (possible MITM), or
    /// `known_hosts` is unreadable — refuse.
    Rejected,
}

/// Classify a server key against `known_hosts` (the default file when `path` is
/// `None`, else the given file — the seam the tests drive). This centralizes the
/// security policy so it can be unit-tested without a live SSH server:
///
/// - match → [`Trusted`](HostKeyVerdict::Trusted)
/// - host absent → [`FirstUse`](HostKeyVerdict::FirstUse)
/// - key mismatch / unreadable file → [`Rejected`](HostKeyVerdict::Rejected)
///
/// `Rejected` is fail-closed: a known host whose key changed is the
/// security-critical case, so anything that isn't a clean match-or-absent is a
/// refusal.
fn classify_host_key(
    host: &str,
    port: u16,
    key: &PublicKey,
    path: Option<&Path>,
) -> HostKeyVerdict {
    let checked = match path {
        Some(p) => russh::keys::check_known_hosts_path(host, port, key, p),
        None => russh::keys::check_known_hosts(host, port, key),
    };
    match checked {
        Ok(true) => HostKeyVerdict::Trusted,
        Ok(false) => HostKeyVerdict::FirstUse,
        Err(_) => HostKeyVerdict::Rejected,
    }
}

/// russh client handler: verifies the server host key against
/// `~/.ssh/known_hosts` via [`classify_host_key`].
struct BuiltinHandler {
    host: String,
    port: u16,
    /// `known_hosts` file to consult and update. `None` = russh's default
    /// (`~/.ssh/known_hosts`); set to an explicit path in tests.
    known_hosts_path: Option<PathBuf>,
}

impl client::Handler for BuiltinHandler {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        server_public_key: &PublicKey,
    ) -> Result<bool, Self::Error> {
        let path = self.known_hosts_path.clone();
        match classify_host_key(&self.host, self.port, server_public_key, path.as_deref()) {
            HostKeyVerdict::Trusted => Ok(true),
            HostKeyVerdict::FirstUse => Ok(confirm_and_record_new_host(
                &self.host,
                self.port,
                server_public_key,
                path.as_deref(),
            )
            .await),
            HostKeyVerdict::Rejected => {
                eprintln!(
                    "[mish-client] HOST KEY VERIFICATION FAILED for {}:{} — the host's key \
                     does not match the one pinned in known_hosts (possible man-in-the-middle), \
                     or known_hosts could not be read. Refusing to connect.",
                    self.host, self.port
                );
                Ok(false)
            }
        }
    }
}

/// How to treat a host whose key is not yet in `known_hosts`. Mirrors OpenSSH's
/// `StrictHostKeyChecking`, selectable via `$MISH_STRICT_HOST_KEYS`:
///
/// - `ask` (default) — prompt on the controlling terminal; **refuse** if there is
///   no terminal to ask on (so non-interactive runs fail closed rather than
///   silently trusting an unverified host).
/// - `accept-new` (or `no`/`off`) — accept and record the key without prompting
///   (for automation that can't show a prompt).
/// - `yes` (or `strict`) — refuse any host not already in `known_hosts`.
enum NewHostPolicy {
    Ask,
    AcceptNew,
    Refuse,
}

fn new_host_policy() -> NewHostPolicy {
    match std::env::var("MISH_STRICT_HOST_KEYS").as_deref() {
        Ok("accept-new") | Ok("no") | Ok("off") => NewHostPolicy::AcceptNew,
        Ok("yes") | Ok("strict") => NewHostPolicy::Refuse,
        _ => NewHostPolicy::Ask,
    }
}

/// Decide whether to trust a host not yet in `known_hosts`, and — if so —
/// **persist** its key so a *future* connection whose key differs is detected as
/// a possible MITM (the gap this closes: TOFU acceptance was previously never
/// saved, so a changed key was never noticed). Returns whether to proceed.
async fn confirm_and_record_new_host(
    host: &str,
    port: u16,
    key: &PublicKey,
    known_hosts_path: Option<&Path>,
) -> bool {
    let algo = key.algorithm().to_string();
    let fingerprint = key.fingerprint(HashAlg::Sha256).to_string();

    let accept = match new_host_policy() {
        NewHostPolicy::AcceptNew => true,
        NewHostPolicy::Refuse => {
            eprintln!(
                "[mish-client] {host}:{port} is not in known_hosts and \
                 MISH_STRICT_HOST_KEYS=yes — refusing."
            );
            false
        }
        NewHostPolicy::Ask => {
            let (h, a, f) = (host.to_string(), algo.clone(), fingerprint.clone());
            // The prompt does blocking TTY I/O; keep it off the async runtime.
            tokio::task::spawn_blocking(move || prompt_accept_new_host(&h, port, &a, &f))
                .await
                .unwrap_or(false)
        }
    };

    if !accept {
        return false;
    }

    let recorded = match known_hosts_path {
        Some(p) => russh::keys::known_hosts::learn_known_hosts_path(host, port, key, p),
        None => russh::keys::known_hosts::learn_known_hosts(host, port, key),
    };
    match recorded {
        Ok(()) => {
            eprintln!("[mish-client] permanently added '{host}:{port}' ({algo}) to known_hosts.")
        }
        Err(e) => eprintln!(
            "[mish-client] warning: trusted {host}:{port} for this session but could not \
             save it to known_hosts ({e}); you will be asked again next time."
        ),
    }
    true
}

/// Ask the user, on the **controlling terminal** (`/dev/tty`, not stdin — which
/// may be redirected), whether to trust a previously-unseen host key. Returns
/// `true` only for an explicit `yes`/`y`. Returns `false` (refuse) when there is
/// no controlling terminal to prompt on.
fn prompt_accept_new_host(host: &str, port: u16, algo: &str, fingerprint: &str) -> bool {
    use std::io::{BufRead, BufReader, Write};

    // Prompt on the controlling terminal directly; if there is none (daemon, CI,
    // piped run), we can't get consent, so fail closed.
    let tty = match std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/tty")
    {
        Ok(f) => f,
        Err(_) => return false,
    };
    let mut out = &tty;
    let _ = write!(
        out,
        "The authenticity of host '{host}:{port}' can't be established.\n\
         {algo} key fingerprint is {fingerprint}.\n\
         Are you sure you want to continue connecting (yes/no)? "
    );
    let _ = out.flush();

    let mut line = String::new();
    if BufReader::new(&tty).read_line(&mut line).is_err() {
        return false;
    }
    matches!(line.trim().to_ascii_lowercase().as_str(), "yes" | "y")
}

// ---- host / config resolution -------------------------------------------------

/// A connection target resolved from the command line + `~/.ssh/config`.
struct ResolvedHost {
    hostname: String,
    port: u16,
    user: String,
    /// Identity files to try (config `IdentityFile`s, tilde-expanded).
    identities: Vec<PathBuf>,
    /// `ProxyJump` chain (`[user@]host[:port]` hops), nearest jump first.
    proxy_jump: Vec<String>,
}

/// Path to the ssh config to consult: `$MISH_SSH_CONFIG`, else `~/.ssh/config`.
fn ssh_config_path() -> Option<PathBuf> {
    std::env::var_os("MISH_SSH_CONFIG")
        .map(PathBuf::from)
        .or_else(|| home_dir().map(|h| h.join(".ssh").join("config")))
}

/// Parse the ssh config as it applies to `alias`. Returns empty defaults (the
/// alias used verbatim) when there is no config file or it won't parse.
fn ssh_config_for(alias: &str) -> russh_config::Config {
    if let Some(p) = ssh_config_path() {
        if p.is_file() {
            if let Ok(c) = russh_config::parse_path(&p, alias) {
                return c;
            }
        }
    }
    russh_config::Config::default(alias)
}

/// Resolve `alias` against the ssh config. A command-line `user`/`port` wins over
/// the config (mirroring OpenSSH); otherwise fall back to the config's
/// HostName/Port/User, then the literal alias, the local login, and port 22.
fn resolve_host(alias: &str, cli_user: Option<&str>, cli_port: Option<u16>) -> ResolvedHost {
    resolve_from(ssh_config_for(alias), cli_user, cli_port)
}

/// The precedence + field-mapping core of [`resolve_host`], split out so it can be
/// unit-tested against a parsed config without touching the filesystem.
fn resolve_from(
    c: russh_config::Config,
    cli_user: Option<&str>,
    cli_port: Option<u16>,
) -> ResolvedHost {
    ResolvedHost {
        // `host()` is the resolved HostName (falling back to the alias).
        hostname: c.host().to_string(),
        port: cli_port.or(c.host_config.port).or(c.port).unwrap_or(22),
        user: cli_user
            .map(str::to_string)
            .or_else(|| c.host_config.user.clone())
            .or_else(|| c.user.clone())
            .unwrap_or_else(default_user),
        identities: c
            .host_config
            .identity_file
            .clone()
            .unwrap_or_default()
            .iter()
            .map(|p| expand_tilde(p))
            .collect(),
        proxy_jump: c
            .host_config
            .proxy_jump
            .as_deref()
            .map(split_proxy_jump)
            .unwrap_or_default(),
    }
}

/// Split a `ProxyJump` value (`jump1, user@jump2:2222`) into hops, nearest first.
fn split_proxy_jump(s: &str) -> Vec<String> {
    s.split(',')
        .map(|h| h.trim().to_string())
        .filter(|h| !h.is_empty())
        .collect()
}

/// Parse one ProxyJump hop spec `[user@]host[:port]` into its parts. A trailing
/// `:NNNN` is a port only when it's numeric (so `host` without a port is left
/// intact). Pure, so it can be unit-tested.
fn parse_jump_spec(spec: &str) -> (Option<String>, String, Option<u16>) {
    let (user, rest) = split_user_host(spec);
    let (host, port) = match rest.rsplit_once(':') {
        Some((h, p)) if p.parse::<u16>().is_ok() => (h.to_string(), p.parse::<u16>().ok()),
        _ => (rest, None),
    };
    (user, host, port)
}

/// Resolve one `[user@]host[:port]` ProxyJump hop (the host is then looked up in
/// the ssh config too, so a jump can itself be a configured alias).
fn resolve_jump(spec: &str) -> ResolvedHost {
    let (user, host, port) = parse_jump_spec(spec);
    resolve_host(&host, user.as_deref(), port)
}

/// Expand a leading `~` / `~/…` in a path to the home directory.
fn expand_tilde(p: &Path) -> PathBuf {
    if let Ok(rest) = p.strip_prefix("~") {
        if let Some(home) = home_dir() {
            return home.join(rest);
        }
    }
    p.to_path_buf()
}

/// Establish the SSH tunnel through `target.proxy_jump` and return a stream to the
/// target (the last hop's direct-tcpip channel), plus the jump handles — which the
/// caller must keep alive, since the tunnel rides on them.
async fn open_proxy_chain(
    target: &ResolvedHost,
    rconfig: &Arc<client::Config>,
) -> Result<(
    russh::ChannelStream<client::Msg>,
    Vec<client::Handle<BuiltinHandler>>,
)> {
    let mut handles: Vec<client::Handle<BuiltinHandler>> = Vec::new();
    for (i, spec) in target.proxy_jump.iter().enumerate() {
        let hop = resolve_jump(spec);
        let handler = BuiltinHandler {
            host: hop.hostname.clone(),
            port: hop.port,
            known_hosts_path: None,
        };
        let mut h = if i == 0 {
            // First hop: a real TCP connection.
            client::connect(rconfig.clone(), (hop.hostname.as_str(), hop.port), handler)
                .await
                .with_context(|| format!("connecting to jump host {}:{}", hop.hostname, hop.port))?
        } else {
            // Subsequent hops ride a direct-tcpip channel on the previous hop.
            let chan = handles[i - 1]
                .channel_open_direct_tcpip(hop.hostname.clone(), hop.port as u32, "127.0.0.1", 0)
                .await
                .with_context(|| {
                    format!("tunnelling to jump host {}:{}", hop.hostname, hop.port)
                })?;
            client::connect_stream(rconfig.clone(), chan.into_stream(), handler)
                .await
                .with_context(|| format!("connecting to jump host {} via tunnel", hop.hostname))?
        };
        authenticate(&mut h, &hop.user, &hop.identities)
            .await
            .with_context(|| {
                format!("authenticating to jump host {}@{}", hop.user, hop.hostname)
            })?;
        handles.push(h);
    }
    // Final tunnel from the last jump to the real target.
    let last = handles.last().expect("proxy_jump is non-empty here");
    let chan = last
        .channel_open_direct_tcpip(target.hostname.clone(), target.port as u32, "127.0.0.1", 0)
        .await
        .with_context(|| format!("tunnelling to {}:{}", target.hostname, target.port))?;
    Ok((chan.into_stream(), handles))
}

// ---- authentication -----------------------------------------------------------

/// Authenticate `handle` as `user`, trying methods roughly in OpenSSH order:
/// discover what the server allows, then ssh-agent (Unix) → identity files
/// (prompting for a passphrase on an encrypted key) → keyboard-interactive →
/// password. The two interactive fallbacks only prompt when stdin is a terminal.
async fn authenticate(
    handle: &mut client::Handle<BuiltinHandler>,
    user: &str,
    identities: &[PathBuf],
) -> Result<()> {
    // Probe with the "none" method to learn the server's allowed methods (and to
    // catch the rare server that accepts no-auth outright).
    let mut allowed = match handle.authenticate_none(user).await {
        Ok(r) if r.success() => return Ok(()),
        Ok(r) => allowed_methods(&r),
        // Couldn't probe: assume the common set and let the attempts sort it out.
        Err(_) => vec![
            "publickey".into(),
            "keyboard-interactive".into(),
            "password".into(),
        ],
    };
    let pubkey_ok = |a: &[String]| a.iter().any(|m| m == "publickey");

    // 1. ssh-agent (Unix only for now — the Windows named-pipe agent is future work).
    #[cfg(unix)]
    if pubkey_ok(&allowed) {
        use russh::keys::agent::client::AgentClient;
        if let Ok(mut agent) = AgentClient::connect_env().await {
            if let Ok(ids) = agent.request_identities().await {
                for id in ids {
                    let pubkey = id.public_key().into_owned();
                    if let Ok(res) = handle
                        .authenticate_publickey_with(user, pubkey, None::<HashAlg>, &mut agent)
                        .await
                    {
                        if res.success() {
                            return Ok(());
                        }
                        allowed = allowed_methods(&res);
                    }
                }
            }
        }
    }

    // 2. Identity files: the config's `IdentityFile`s first, then the defaults.
    if pubkey_ok(&allowed) {
        // Negotiate the RSA signature hash once (None for ed25519/ecdsa keys).
        let rsa_hash = handle
            .best_supported_rsa_hash()
            .await
            .ok()
            .flatten()
            .flatten();
        let interactive = std::io::stdin().is_terminal();
        let mut tried = std::collections::HashSet::new();
        for path in identities.iter().cloned().chain(default_identity_files()) {
            if !path.is_file() || !tried.insert(path.clone()) {
                continue;
            }
            let Some(key) = load_identity(&path, interactive) else {
                continue;
            };
            let with_hash = PrivateKeyWithHashAlg::new(Arc::new(key), rsa_hash);
            if let Ok(res) = handle.authenticate_publickey(user, with_hash).await {
                if res.success() {
                    return Ok(());
                }
                allowed = allowed_methods(&res);
            }
        }
    }

    // 3 & 4. Interactive fallbacks — only with a real terminal to prompt on.
    if std::io::stdin().is_terminal() {
        if allowed.iter().any(|m| m == "keyboard-interactive")
            && try_keyboard_interactive(handle, user).await?
        {
            return Ok(());
        }
        if allowed.iter().any(|m| m == "password") && try_password(handle, user).await? {
            return Ok(());
        }
    }

    let _ = handle
        .disconnect(Disconnect::ByApplication, "auth failed", "")
        .await;
    let extra = if std::io::stdin().is_terminal() {
        ", keyboard-interactive, password"
    } else {
        " (no terminal available for passphrase/password prompts)"
    };
    bail!("authentication failed for {user} (tried ssh-agent, identity files{extra})")
}

/// The OpenSSH default identity files in `~/.ssh`, in preference order.
fn default_identity_files() -> Vec<PathBuf> {
    match home_dir().map(|h| h.join(".ssh")) {
        Some(ssh) => ["id_ed25519", "id_ecdsa", "id_rsa"]
            .iter()
            .map(|n| ssh.join(n))
            .collect(),
        None => Vec::new(),
    }
}

/// Load a private key, prompting up to 3× for a passphrase if it is encrypted and
/// we have a terminal. Returns `None` if it can't be loaded/decrypted.
fn load_identity(path: &Path, interactive: bool) -> Option<russh::keys::PrivateKey> {
    match load_secret_key(path, None) {
        Ok(k) => Some(k),
        Err(russh::keys::Error::KeyIsEncrypted) if interactive => {
            for _ in 0..3 {
                let pw = rpassword::prompt_password(format!(
                    "Enter passphrase for key '{}': ",
                    path.display()
                ))
                .ok()?;
                match load_secret_key(path, Some(&pw)) {
                    Ok(k) => return Some(k),
                    Err(_) => eprintln!("[mish-client] bad passphrase, try again"),
                }
            }
            None
        }
        // Encrypted but non-interactive, or unreadable: skip this key.
        Err(_) => None,
    }
}

/// Server-advertised remaining auth methods (lowercase names) from a failed
/// result; empty on success. Avoids naming russh's unexported `MethodKind` by
/// going through its `&str` conversion.
fn allowed_methods(r: &client::AuthResult) -> Vec<String> {
    match r {
        client::AuthResult::Success => Vec::new(),
        client::AuthResult::Failure {
            remaining_methods, ..
        } => remaining_methods
            .iter()
            .map(|m| {
                let s: &str = m.into();
                s.to_string()
            })
            .collect(),
    }
}

/// Run the keyboard-interactive exchange, prompting per server request (no-echo
/// for password-style prompts). `Ok(true)` on success.
async fn try_keyboard_interactive(
    handle: &mut client::Handle<BuiltinHandler>,
    user: &str,
) -> Result<bool> {
    let mut resp = handle
        .authenticate_keyboard_interactive_start(user, None::<String>)
        .await
        .context("starting keyboard-interactive auth")?;
    loop {
        match resp {
            KeyboardInteractiveAuthResponse::Success => return Ok(true),
            KeyboardInteractiveAuthResponse::Failure { .. } => return Ok(false),
            KeyboardInteractiveAuthResponse::InfoRequest {
                name,
                instructions,
                prompts,
            } => {
                if !name.is_empty() {
                    eprintln!("[mish-client] {name}");
                }
                if !instructions.is_empty() {
                    eprintln!("[mish-client] {instructions}");
                }
                let mut answers = Vec::with_capacity(prompts.len());
                for p in &prompts {
                    let a = if p.echo {
                        use std::io::Write;
                        eprint!("{}", p.prompt);
                        let _ = std::io::stderr().flush();
                        let mut line = String::new();
                        std::io::stdin()
                            .read_line(&mut line)
                            .context("reading prompt response")?;
                        line.trim_end_matches(['\r', '\n']).to_string()
                    } else {
                        rpassword::prompt_password(&p.prompt).context("reading prompt response")?
                    };
                    answers.push(a);
                }
                resp = handle
                    .authenticate_keyboard_interactive_respond(answers)
                    .await
                    .context("responding to keyboard-interactive auth")?;
            }
        }
    }
}

/// Prompt for a password (up to 3×) and try password auth. `Ok(true)` on success.
async fn try_password(handle: &mut client::Handle<BuiltinHandler>, user: &str) -> Result<bool> {
    for _ in 0..3 {
        let pw = rpassword::prompt_password(format!("{user}'s password: "))
            .context("reading password")?;
        let res = handle
            .authenticate_password(user, pw)
            .await
            .context("password auth")?;
        if res.success() {
            return Ok(true);
        }
        eprintln!("[mish-client] permission denied, please try again.");
    }
    Ok(false)
}

/// The parsed contents of a `MISH CONNECT` line.
struct ConnectInfo {
    port: u16,
    server_cert: Vec<u8>,
    client_cert: Vec<u8>,
    /// The transmitted client private key; zeroized on drop.
    client_key: Zeroizing<Vec<u8>>,
}

/// Cap on bytes buffered while scanning for the `MISH CONNECT` line. The real
/// line is a few KB (a port plus three hex-encoded DER blobs); a server that
/// sends far more without a newline is buggy or hostile, so we refuse rather
/// than buffer it unboundedly. Both transports read server-controlled stdout, so
/// both go through [`scan_connect`] and honour this. 256 KiB is comfortably above
/// any legitimate line.
const MAX_CONNECT_SCAN: usize = 256 * 1024;

/// Pull complete (`\n`-terminated) lines out of `buf`, draining them, and return
/// the first one that parses as a `MISH CONNECT` line.
///
/// - `Ok(Some(info))` — found it.
/// - `Ok(None)` — no connect line yet; keep reading (the unterminated tail stays
///   in `buf`, bounded below).
/// - `Err(_)` — the unterminated tail exceeded [`MAX_CONNECT_SCAN`]; refuse, so a
///   server that streams endless data with no newline can't exhaust memory.
fn scan_connect(buf: &mut Vec<u8>) -> Result<Option<ConnectInfo>> {
    while let Some(nl) = buf.iter().position(|&b| b == b'\n') {
        let line: Vec<u8> = buf.drain(..=nl).collect();
        let text = String::from_utf8_lossy(&line);
        if let Some(parsed) = parse_connect(text.trim_end()) {
            return Ok(Some(parsed));
        }
    }
    if buf.len() > MAX_CONNECT_SCAN {
        bail!(
            "server sent {} bytes with no MISH CONNECT line (cap {MAX_CONNECT_SCAN}); refusing",
            buf.len()
        );
    }
    Ok(None)
}

/// Read from `r` until [`scan_connect`] finds the `MISH CONNECT` line, EOF, the
/// 30s timeout, or the size cap. Generic over the reader so it is unit-testable
/// with an in-memory cursor (and shared by the `ssh`/local and builtin paths).
async fn read_connect_from<R: tokio::io::AsyncRead + Unpin>(r: &mut R) -> Result<ConnectInfo> {
    use tokio::io::AsyncReadExt;
    let mut buf: Vec<u8> = Vec::new();
    let mut chunk = [0u8; 4096];
    let read = async {
        loop {
            let n = r.read(&mut chunk).await?;
            if n == 0 {
                return Err(anyhow!("server exited before printing a MISH CONNECT line"));
            }
            buf.extend_from_slice(&chunk[..n]);
            if let Some(info) = scan_connect(&mut buf)? {
                return Ok(info);
            }
        }
    };
    tokio::time::timeout(Duration::from_secs(30), read)
        .await
        .context("timed out waiting for the server to start")?
}

/// Read the builtin SSH channel's stdout until the `MISH CONNECT` line appears,
/// forwarding the server's stderr to ours so its diagnostics aren't swallowed.
async fn read_connect_channel(channel: &mut russh::Channel<client::Msg>) -> Result<ConnectInfo> {
    use std::io::Write;

    let mut buf: Vec<u8> = Vec::new();
    let read = async {
        while let Some(msg) = channel.wait().await {
            match msg {
                ChannelMsg::Data { data } => {
                    buf.extend_from_slice(&data[..]);
                    if let Some(info) = scan_connect(&mut buf)? {
                        return Ok(info);
                    }
                }
                // ext == 1 is the remote stderr; surface it like the `ssh`
                // transport (which inherits stderr).
                ChannelMsg::ExtendedData { data, .. } => {
                    let _ = std::io::stderr().write_all(&data[..]);
                }
                _ => {}
            }
        }
        Err(anyhow!("server exited before printing a MISH CONNECT line"))
    };

    tokio::time::timeout(Duration::from_secs(30), read)
        .await
        .context("timed out waiting for the server to start")?
}

/// Read the child's stdout until the `MISH CONNECT` line appears.
async fn read_connect(child: &mut Child) -> Result<ConnectInfo> {
    let mut stdout = child
        .stdout
        .take()
        .context("bootstrap child has no stdout")?;
    read_connect_from(&mut stdout).await
}

/// Parse a `MISH CONNECT <port> <server-cert> <client-cert> <client-key>` line
/// (all hex). Older single-cert lines (no client credentials) are rejected, so a
/// stale server can't silently downgrade to no client auth.
fn parse_connect(line: &str) -> Option<ConnectInfo> {
    let mut it = line.split_whitespace();
    if it.next()? != "MISH" || it.next()? != "CONNECT" {
        return None;
    }
    let port: u16 = it.next()?.parse().ok()?;
    let server_cert = from_hex(it.next()?)?;
    let client_cert = from_hex(it.next()?)?;
    let client_key = Zeroizing::new(from_hex(it.next()?)?);
    Some(ConnectInfo {
        port,
        server_cert,
        client_cert,
        client_key,
    })
}

/// Fuzz entry point — **not** part of the public API (`#[doc(hidden)]`). Drives
/// every parser that consumes server- or config-controlled bytes during
/// bootstrap, plus the bounded line scanner, asserting no panic and that
/// [`scan_connect`] keeps the buffer within [`MAX_CONNECT_SCAN`]. Used by the
/// `bootstrap_parse` cargo-fuzz target.
#[doc(hidden)]
pub fn fuzz_parse(data: &[u8]) {
    let s = String::from_utf8_lossy(data);
    let _ = from_hex(&s);
    let _ = shell_split(&s);
    let _ = parse_connect(&s);
    // Stream the bytes through the scanner in small chunks, like the network
    // does; the buffer must stay bounded and the scanner must never panic.
    let mut buf = Vec::new();
    for chunk in data.chunks(8) {
        buf.extend_from_slice(chunk);
        match scan_connect(&mut buf) {
            Ok(_) => assert!(buf.len() <= MAX_CONNECT_SCAN),
            Err(_) => break, // hit the cap; refusal is the expected outcome
        }
    }
    // Quoting any string and splitting it back must round-trip (no shell
    // injection / mangling), exercised here on arbitrary bytes too.
    if let Ok(split) = shell_split(&shell_quote(&s)) {
        assert_eq!(split, vec![s.into_owned()]);
    }
}

/// Lowercase-hex encode (used by `mish-server` to print the cert DER).
pub fn to_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 0x0f) as usize] as char);
    }
    s
}

/// Decode lowercase/uppercase hex; `None` on malformed input.
pub fn from_hex(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    fn nibble(c: u8) -> Option<u8> {
        match c {
            b'0'..=b'9' => Some(c - b'0'),
            b'a'..=b'f' => Some(c - b'a' + 10),
            b'A'..=b'F' => Some(c - b'A' + 10),
            _ => None,
        }
    }
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(s.len() / 2);
    for pair in b.chunks(2) {
        out.push((nibble(pair[0])? << 4) | nibble(pair[1])?);
    }
    Some(out)
}

/// Split a command string into words like a POSIX shell (mosh's wrapper uses
/// Perl's `shellwords` on `--ssh`), honouring single quotes, double quotes, and
/// backslash escapes. Used so `--ssh "ssh -p 2222 -i key"` becomes separate argv
/// entries rather than one opaque program name. Returns an error on an unbalanced
/// quote.
pub fn shell_split(s: &str) -> Result<Vec<String>> {
    let mut words = Vec::new();
    let mut cur = String::new();
    let mut in_word = false;
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '\'' => {
                in_word = true;
                let mut closed = false;
                for q in chars.by_ref() {
                    if q == '\'' {
                        closed = true;
                        break;
                    }
                    cur.push(q);
                }
                if !closed {
                    return Err(anyhow!("unbalanced single quote in {s:?}"));
                }
            }
            '"' => {
                in_word = true;
                let mut closed = false;
                while let Some(q) = chars.next() {
                    if q == '"' {
                        closed = true;
                        break;
                    }
                    if q == '\\' {
                        // In double quotes, backslash escapes only " and \.
                        match chars.peek() {
                            Some('"') | Some('\\') => cur.push(chars.next().unwrap()),
                            _ => cur.push('\\'),
                        }
                    } else {
                        cur.push(q);
                    }
                }
                if !closed {
                    return Err(anyhow!("unbalanced double quote in {s:?}"));
                }
            }
            '\\' => {
                in_word = true;
                if let Some(n) = chars.next() {
                    cur.push(n);
                }
            }
            c if c.is_whitespace() => {
                if in_word {
                    words.push(std::mem::take(&mut cur));
                    in_word = false;
                }
            }
            c => {
                in_word = true;
                cur.push(c);
            }
        }
    }
    if in_word {
        words.push(cur);
    }
    Ok(words)
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        /// Security seam #1 — credential bootstrap parsing. The `MISH CONNECT`
        /// line and the ssh/server command strings are parsed before the QUIC
        /// session exists; they take input from the (SSH-authenticated, but
        /// possibly buggy or compromised) server's stdout and from user/script
        /// config. The parsers must never panic, and the hex codec carrying the
        /// certs/keys must be an exact inverse.
        #[test]
        fn from_hex_is_an_exact_inverse(bytes in prop::collection::vec(any::<u8>(), 0..512)) {
            let decoded = from_hex(&to_hex(&bytes));
            prop_assert_eq!(decoded.as_deref(), Some(bytes.as_slice()));
        }

        #[test]
        fn bootstrap_parsers_never_panic(s in ".*") {
            // Arbitrary input must not panic (results intentionally discarded).
            let _ = from_hex(&s);
            let _ = shell_split(&s);
            let _ = parse_connect(&s);
        }

        /// The whole bootstrap-parse fuzz body (same one the cargo-fuzz target
        /// drives) must not panic on arbitrary bytes, chunked arbitrarily.
        #[test]
        fn fuzz_parse_never_panics(bytes in prop::collection::vec(any::<u8>(), 0..2048)) {
            fuzz_parse(&bytes);
        }

        /// Security: shell-quoting any argument and splitting it back must yield
        /// exactly that argument — no word-splitting, no injection, no mangling.
        /// (`shell_split` is an independent POSIX-ish parser, so this cross-checks
        /// `shell_quote`; a real-`/bin/sh` check lives in
        /// `shell_quote_resists_injection_in_real_sh`.)
        #[test]
        fn shell_quote_round_trips_through_split(s in ".*") {
            let split = shell_split(&shell_quote(&s)).expect("quoted form parses");
            prop_assert_eq!(split, vec![s]);
        }

        /// Security/robustness: the connect-line scanner stays within its cap no
        /// matter how arbitrary bytes are chunked, and never panics.
        #[test]
        fn scan_connect_stays_bounded(
            bytes in prop::collection::vec(any::<u8>(), 0..4096),
            chunk in 1usize..64,
        ) {
            let mut buf = Vec::new();
            for piece in bytes.chunks(chunk) {
                buf.extend_from_slice(piece);
                match scan_connect(&mut buf) {
                    Ok(_) => prop_assert!(buf.len() <= MAX_CONNECT_SCAN),
                    Err(_) => break,
                }
            }
        }
    }

    #[test]
    fn hex_roundtrip() {
        let data = vec![0x00, 0x01, 0xfe, 0xff, 0xa5, 0x5a];
        assert_eq!(from_hex(&to_hex(&data)), Some(data));
    }

    #[test]
    fn parse_connect_line() {
        let line = format!(
            "MISH CONNECT 51234 {} {} {}",
            to_hex(&[0xde, 0xad]),
            to_hex(&[0xbe, 0xef]),
            to_hex(&[0x01, 0x02])
        );
        let info = parse_connect(&line).expect("valid line");
        assert_eq!(info.port, 51234);
        assert_eq!(info.server_cert, vec![0xde, 0xad]);
        assert_eq!(info.client_cert, vec![0xbe, 0xef]);
        assert_eq!(*info.client_key, vec![0x01, 0x02]);

        assert!(parse_connect("garbage").is_none());
        assert!(parse_connect("MISH CONNECT notaport ff ee dd").is_none());
        // A legacy single-cert line is rejected (no silent downgrade).
        assert!(parse_connect("MISH CONNECT 51234 dead").is_none());
    }

    #[test]
    fn bootstrap_mode_parse() {
        assert_eq!(BootstrapMode::parse("auto").unwrap(), BootstrapMode::Auto);
        assert_eq!(BootstrapMode::parse("ssh").unwrap(), BootstrapMode::Ssh);
        assert_eq!(
            BootstrapMode::parse("builtin").unwrap(),
            BootstrapMode::Builtin
        );
        assert!(BootstrapMode::parse("built-in").is_err()); // dashed form removed
        assert!(BootstrapMode::parse("nope").is_err());
        assert_eq!(BootstrapMode::default(), BootstrapMode::Auto);
    }

    #[test]
    fn use_builtin_respects_explicit_modes() {
        // Explicit modes ignore PATH entirely.
        assert!(!BootstrapMode::Ssh.use_builtin("definitely-not-a-real-program"));
        assert!(BootstrapMode::Builtin.use_builtin("ssh"));
        // Auto falls back to the builtin client when the program is missing.
        assert!(BootstrapMode::Auto.use_builtin("definitely-not-a-real-program-xyz"));
    }

    #[test]
    fn split_user_host_splits_on_last_at() {
        assert_eq!(
            split_user_host("alice@example.com"),
            (Some("alice".into()), "example.com".into())
        );
        assert_eq!(split_user_host("example.com"), (None, "example.com".into()));
        // Only the last @ separates (usernames may contain @).
        assert_eq!(
            split_user_host("a@b@host"),
            (Some("a@b".into()), "host".into())
        );
    }

    #[test]
    fn shell_quote_passes_safe_and_quotes_unsafe() {
        assert_eq!(shell_quote("mish-server"), "mish-server");
        assert_eq!(shell_quote("--session"), "--session");
        assert_eq!(shell_quote("/usr/bin/mish-server"), "/usr/bin/mish-server");
        // Spaces and quotes force quoting; embedded ' is escaped.
        assert_eq!(shell_quote("my session"), "'my session'");
        assert_eq!(shell_quote("it's"), r"'it'\''s'");
        assert_eq!(shell_quote(""), "''");
    }

    #[test]
    fn shell_split_basic_and_quoted() {
        assert_eq!(shell_split("ssh").unwrap(), vec!["ssh"]);
        assert_eq!(
            shell_split("ssh -p 2222 -i key").unwrap(),
            vec!["ssh", "-p", "2222", "-i", "key"]
        );
        // Quotes group words and are stripped.
        assert_eq!(
            shell_split("ssh -o 'ProxyCommand=nc %h %p'").unwrap(),
            vec!["ssh", "-o", "ProxyCommand=nc %h %p"]
        );
        assert_eq!(
            shell_split(r#"ssh -o "User Name=a b""#).unwrap(),
            vec!["ssh", "-o", "User Name=a b"]
        );
        // Backslash escapes a space.
        assert_eq!(
            shell_split(r"ssh /path/with\ space").unwrap(),
            vec!["ssh", "/path/with space"]
        );
        // Extra whitespace collapses; empty string yields no words.
        assert_eq!(shell_split("  ssh   host ").unwrap(), vec!["ssh", "host"]);
        assert!(shell_split("").unwrap().is_empty());
        // Unbalanced quotes are an error.
        assert!(shell_split("ssh 'oops").is_err());
        assert!(shell_split(r#"ssh "oops"#).is_err());
    }

    // ---- Security: host-key verification (the builtin transport's MITM guard) ----

    // Two real ed25519 public keys (throwaway, generated for these tests only).
    const K1: &str =
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDWO4UsqbDO6O4P3u0wxQaMf2sspfcwMcA6MZa0rjs9y k1";
    const K2: &str =
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINt84Un6pxLPKzOT9r80lD+p+PcKuq+S7ouwbTZV91Op k2";

    /// A temp file removed on drop (no `tempfile` dev-dep needed).
    struct TmpFile(PathBuf);
    impl Drop for TmpFile {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
        }
    }
    fn write_tmp(name: &str, content: &str) -> TmpFile {
        use std::sync::atomic::{AtomicU32, Ordering};
        static N: AtomicU32 = AtomicU32::new(0);
        let path = std::env::temp_dir().join(format!(
            "mish-test-{name}-{}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::write(&path, content).expect("write temp file");
        TmpFile(path)
    }

    fn pubkey(openssh: &str) -> PublicKey {
        let mut k = PublicKey::from_openssh(openssh).expect("valid openssh public key");
        // The key russh presents from the handshake (and the one parsed from a
        // known_hosts line) has no comment; `ssh_key::PublicKey`'s `==` compares
        // comments, so clear it here to mirror production and compare on key
        // material only.
        k.set_comment("");
        k
    }
    /// A `known_hosts` line: `host <alg> <base64>` (the pubkey's first two fields).
    fn known_hosts_line(host: &str, openssh: &str) -> String {
        let mut it = openssh.split_whitespace();
        let alg = it.next().unwrap();
        let data = it.next().unwrap();
        format!("{host} {alg} {data}\n")
    }

    #[test]
    fn host_key_matching_is_trusted() {
        let kh = write_tmp("kh", &known_hosts_line("testhost", K1));
        assert_eq!(
            classify_host_key("testhost", 22, &pubkey(K1), Some(&kh.0)),
            HostKeyVerdict::Trusted
        );
    }

    #[test]
    fn host_key_mismatch_is_rejected() {
        // testhost is pinned to K1; presenting K2 (a different key) MUST be
        // refused — this is the core MITM protection. Empirically confirms russh
        // surfaces a mismatch as an error (mapped to Rejected), not as "absent".
        let kh = write_tmp("kh", &known_hosts_line("testhost", K1));
        assert_eq!(
            classify_host_key("testhost", 22, &pubkey(K2), Some(&kh.0)),
            HostKeyVerdict::Rejected,
            "a changed host key must be rejected, not trusted"
        );
    }

    #[test]
    fn host_key_unknown_is_first_use() {
        let kh = write_tmp("kh", &known_hosts_line("testhost", K1));
        assert_eq!(
            classify_host_key("otherhost", 22, &pubkey(K1), Some(&kh.0)),
            HostKeyVerdict::FirstUse
        );
    }

    /// Recording a first-seen host key (what accept-on-first-use now does, via
    /// `learn_known_hosts_path` in `confirm_and_record_new_host`) must persist it
    /// so that (a) the same key is trusted next time and (b) a *changed* key is
    /// later caught as a possible MITM. The previous TOFU path never saved the
    /// key, so a changed key was silently re-accepted every run — this is the gap
    /// the write-back closes.
    #[test]
    fn learned_host_key_is_trusted_and_a_later_change_is_rejected() {
        let kh = write_tmp("kh-learn", ""); // start from an empty known_hosts
        let host = "newhost";

        // Unknown at first contact.
        assert_eq!(
            classify_host_key(host, 22, &pubkey(K1), Some(&kh.0)),
            HostKeyVerdict::FirstUse
        );

        // Persist the accepted key.
        russh::keys::known_hosts::learn_known_hosts_path(host, 22, &pubkey(K1), &kh.0)
            .expect("record host key");

        // The same key is now trusted without re-prompting.
        assert_eq!(
            classify_host_key(host, 22, &pubkey(K1), Some(&kh.0)),
            HostKeyVerdict::Trusted
        );

        // A different key for that host is now rejected as a possible MITM —
        // detection that plain (non-persisted) TOFU could never provide.
        assert_eq!(
            classify_host_key(host, 22, &pubkey(K2), Some(&kh.0)),
            HostKeyVerdict::Rejected,
            "a host key that changed after first use must be rejected"
        );
    }

    // ---- Robustness: the bounded MISH CONNECT scanner ----

    fn valid_connect_line() -> String {
        format!(
            "MISH CONNECT 51234 {} {} {}\n",
            to_hex(&[0xde, 0xad]),
            to_hex(&[0xbe, 0xef]),
            to_hex(&[0x01, 0x02])
        )
    }

    #[test]
    fn scan_connect_reassembles_split_line() {
        let line = valid_connect_line();
        let (a, b) = line.split_at(10); // mid-"MOSH CONN…"
        let mut buf = Vec::new();
        buf.extend_from_slice(a.as_bytes());
        assert!(scan_connect(&mut buf).unwrap().is_none()); // no newline yet
        buf.extend_from_slice(b.as_bytes());
        let info = scan_connect(&mut buf).unwrap().expect("line completed");
        assert_eq!(info.port, 51234);
        assert_eq!(*info.client_key, vec![0x01, 0x02]);
    }

    #[test]
    fn scan_connect_skips_junk_lines_and_handles_crlf() {
        let mut buf = Vec::new();
        // Junk line, then the real one with a CRLF terminator.
        buf.extend_from_slice(b"hello from the server\r\n");
        buf.extend_from_slice(valid_connect_line().trim_end().as_bytes());
        buf.extend_from_slice(b"\r\n");
        let info = scan_connect(&mut buf).unwrap().expect("found after junk");
        assert_eq!(info.port, 51234);
    }

    #[test]
    fn scan_connect_refuses_oversized_unterminated_input() {
        // A server streaming endless data with no newline must be refused, not
        // buffered unboundedly.
        let mut buf = vec![b'x'; MAX_CONNECT_SCAN + 1];
        assert!(scan_connect(&mut buf).is_err());
    }

    #[tokio::test]
    async fn read_connect_from_reads_line_then_errors_on_eof() {
        // Happy path: junk + the line over an in-memory reader.
        let mut input = format!("noise\n{}", valid_connect_line()).into_bytes();
        let mut slice: &[u8] = &input;
        let info = read_connect_from(&mut slice).await.expect("reads the line");
        assert_eq!(info.port, 51234);

        // EOF before any connect line is an error, not a hang.
        input = b"just some noise, no connect line\n".to_vec();
        let mut slice2: &[u8] = &input;
        assert!(read_connect_from(&mut slice2).await.is_err());
    }

    // ---- Security: real-/bin/sh proof that shell_quote can't be escaped ----

    #[cfg(unix)]
    #[test]
    fn shell_quote_resists_injection_in_real_sh() {
        use std::process::Command as PCommand;
        // Each payload, quoted, is handed to a real shell as a single argument;
        // the shell must reproduce it byte-for-byte with no expansion, no command
        // substitution, and no extra words — i.e. no injection.
        let payloads = [
            "; rm -rf /tmp/nope",
            "$(touch /tmp/mish_pwned)",
            "`id`",
            "a && b",
            "x | y",
            "two words",
            "quote'inside",
            "back\\slash",
            "tab\tand\nnewline",
            "$HOME ${PATH}",
            "*",
            "",
        ];
        for p in payloads {
            let q = shell_quote(p);
            let script = format!("printf '%s' {q}");
            let out = PCommand::new("/bin/sh")
                .arg("-c")
                .arg(&script)
                .output()
                .expect("run /bin/sh");
            assert!(out.status.success(), "sh failed for {p:?} (quoted {q})");
            assert_eq!(
                out.stdout,
                p.as_bytes(),
                "payload {p:?} was mangled/injected as {q}"
            );
            assert!(
                out.stderr.is_empty(),
                "payload {p:?} produced stderr: {}",
                String::from_utf8_lossy(&out.stderr)
            );
        }
    }

    // ---- ssh_config resolution + ProxyJump parsing ----

    fn parse_cfg(text: &str, host: &str) -> russh_config::Config {
        russh_config::parse(text, host).expect("parse ssh config")
    }

    #[test]
    fn resolve_from_config_maps_all_fields() {
        let text = "Host myhost\n  \
            HostName 10.0.0.5\n  Port 2200\n  User bob\n  \
            IdentityFile ~/.ssh/special_ed25519\n  \
            ProxyJump jumpuser@bastion:2222\n";
        let r = resolve_from(parse_cfg(text, "myhost"), None, None);
        assert_eq!(r.hostname, "10.0.0.5");
        assert_eq!(r.port, 2200);
        assert_eq!(r.user, "bob");
        assert_eq!(r.proxy_jump, vec!["jumpuser@bastion:2222".to_string()]);
        assert_eq!(r.identities.len(), 1);
        // The IdentityFile's leading ~ is expanded away.
        assert!(!r.identities[0].starts_with("~"));
        assert!(r.identities[0].ends_with("special_ed25519"));
    }

    #[test]
    fn resolve_cli_user_and_port_override_config() {
        let text = "Host h\n  HostName 10.0.0.5\n  Port 2200\n  User bob\n";
        let r = resolve_from(parse_cfg(text, "h"), Some("alice"), Some(22));
        assert_eq!(r.user, "alice"); // CLI wins
        assert_eq!(r.port, 22); // CLI wins
        assert_eq!(r.hostname, "10.0.0.5"); // still from config
    }

    #[test]
    fn resolve_unknown_host_falls_back_to_defaults() {
        let r = resolve_from(
            parse_cfg("Host other\n  HostName 1.2.3.4\n", "myhost"),
            None,
            None,
        );
        assert_eq!(r.hostname, "myhost"); // no matching block → literal alias
        assert_eq!(r.port, 22);
        assert!(r.proxy_jump.is_empty());
    }

    #[test]
    fn proxy_jump_value_splits_into_hops() {
        assert_eq!(split_proxy_jump("a"), vec!["a"]);
        assert_eq!(split_proxy_jump("a, b@h:22 ,c"), vec!["a", "b@h:22", "c"]);
        assert!(split_proxy_jump("").is_empty());
        assert!(split_proxy_jump(" , ").is_empty());
    }

    #[test]
    fn jump_spec_parses_user_host_port() {
        assert_eq!(
            parse_jump_spec("u@h:2222"),
            (Some("u".into()), "h".into(), Some(2222))
        );
        assert_eq!(parse_jump_spec("h2"), (None, "h2".into(), None));
        // A non-numeric trailing :foo is not a port.
        assert_eq!(parse_jump_spec("host:foo"), (None, "host:foo".into(), None));
    }

    #[test]
    fn tilde_expands_to_home() {
        if let Some(home) = home_dir() {
            assert_eq!(expand_tilde(Path::new("~/.ssh/id")), home.join(".ssh/id"));
        }
        // A non-tilde path is unchanged.
        assert_eq!(expand_tilde(Path::new("/etc/x")), PathBuf::from("/etc/x"));
    }

    // ---- Passphrase-protected key handling ----

    // Throwaway ed25519 keys generated for these tests only (the encrypted one's
    // passphrase is below). Flush-left so the PEM bytes are exact.
    const ENC_PASSPHRASE: &str = "hunter2";
    const ENC_KEY: &str = "\
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAACmFlczI1Ni1jdHIAAAAGYmNyeXB0AAAAGAAAABD/XgssQL
BCBpOU4NfzMuhTAAAAGAAAAAEAAAAzAAAAC3NzaC1lZDI1NTE5AAAAIJWfUrBAozPQvWDF
TDLMrX2cC6jgPXVuiNT9BgSj4t3tAAAAkDL+zlpUGQBDLnrd658BBzdiooWuNw4QnKp2Br
wCA4MKKNMCh4TcO1J3/9yCCGWAuNGaiRozTfRdqIDTA9uTu1D3R+trUqIXemZFAqC6UwMJ
Lzekn9otg+r8OMiEoBDYsmIebMsIy8jNV1cghtzzzb3ohtcgLrg0onjYq9F0IoPPq/QA77
0sfEl6DXxIVsYUaA==
-----END OPENSSH PRIVATE KEY-----
";
    const PLAIN_KEY: &str = "\
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACCXvd/0K+4SS2TXZlRSPLRzdvoptx+9jLFEm2F5Ui08RAAAAJAxwatLMcGr
SwAAAAtzc2gtZWQyNTUxOQAAACCXvd/0K+4SS2TXZlRSPLRzdvoptx+9jLFEm2F5Ui08RA
AAAEBpt/XlGq5seEbDVyFVFYlzPCxKPHEWzNNWmfKgjO8bE5e93/Qr7hJLZNdmVFI8tHN2
+im3H72MsUSbYXlSLTxEAAAADXBsYWluLWZpeHR1cmU=
-----END OPENSSH PRIVATE KEY-----
";

    #[test]
    fn encrypted_key_load_round_trip() {
        let f = write_tmp("enc", ENC_KEY);
        // Without a passphrase, russh signals the key is encrypted (so we know to
        // prompt) rather than failing opaquely.
        assert!(matches!(
            load_secret_key(&f.0, None),
            Err(russh::keys::Error::KeyIsEncrypted)
        ));
        // The right passphrase decrypts; a wrong one fails.
        assert!(load_secret_key(&f.0, Some(ENC_PASSPHRASE)).is_ok());
        assert!(load_secret_key(&f.0, Some("wrong-passphrase")).is_err());
    }

    #[test]
    fn load_identity_skips_encrypted_when_noninteractive() {
        // An encrypted key must be skipped (not block on a prompt) when there's no
        // terminal; an unencrypted one loads without prompting.
        let enc = write_tmp("enc2", ENC_KEY);
        assert!(load_identity(&enc.0, false).is_none());
        let plain = write_tmp("plain", PLAIN_KEY);
        assert!(load_identity(&plain.0, false).is_some());
    }
}
