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
//! - [`BootstrapMode::BuiltIn`] — a built-in, pure-Rust SSH client ([`russh`]),
//!   so no external `ssh` is required. This is the path that will let `mish`
//!   run on platforms where mosh never could (notably **Windows**, which has no
//!   `mosh` today); the Windows port itself is future work.
//! - [`BootstrapMode::Auto`] (the default) — use the system `ssh` if it is on
//!   `PATH`, otherwise fall back to the built-in client.
//!
//! The bootstrap handle (the local server process, the `ssh` process, or the
//! built-in SSH connection) is held for the lifetime of the [`Bootstrap`] and
//! torn down on drop. (Upstream mosh daemonizes the server so SSH can fully
//! close; we run the server with `--detach` over SSH, so the daemon survives
//! either transport closing.)

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use russh::client::{self};
use russh::keys::{load_secret_key, HashAlg, PrivateKeyWithHashAlg, PublicKey};
use russh::{ChannelMsg, Disconnect};
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::{Child, Command};

/// A bootstrapped session target: where to connect, the cert to trust, and the
/// handle keeping the server reachable.
pub struct Bootstrap {
    pub addr: SocketAddr,
    /// Server certificate (DER) the client pins to authenticate the server.
    pub server_cert_der: Vec<u8>,
    /// Client certificate (DER) the client presents for mutual auth.
    pub client_cert_der: Vec<u8>,
    /// Client private key (PKCS#8 DER) the client presents for mutual auth.
    pub client_key_der: Vec<u8>,
    /// The transport that started the server, held open for the session and torn
    /// down on drop.
    _guard: Guard,
}

/// Whatever needs to stay alive for the bootstrapped session: a child process
/// (local server, or the external `ssh`), or the built-in SSH connection.
enum Guard {
    /// A child process (the `--local` server, or the external `ssh`). Killed on
    /// drop — these are also spawned with `kill_on_drop`, so this is belt-and-
    /// braces.
    Child(Child),
    /// A built-in [`russh`] SSH connection, held open for the whole session and
    /// closed on drop. We deliberately keep it open rather than disconnecting
    /// once `MISH CONNECT` is read: the server prints that line, then writes one
    /// more diagnostic to stderr *before* it forks the `--detach` daemon, so
    /// closing the channel early could deliver SIGPIPE to the parent before it
    /// detaches. The daemon (post-fork, stdio redirected to /dev/null) outlives
    /// this connection regardless. Held only for its `Drop`; never read.
    #[allow(dead_code)]
    Connection(client::Handle<BuiltInHandler>),
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
    /// Prefer the system `ssh` binary; fall back to the built-in client if it is
    /// not on `PATH`. The default.
    #[default]
    Auto,
    /// Always shell out to the system `ssh` binary (upstream mosh's behaviour).
    Ssh,
    /// Always use the built-in, pure-Rust SSH client (no external `ssh`).
    BuiltIn,
}

impl BootstrapMode {
    /// Parse the `--bootstrap` value. Accepts `auto`, `ssh`, and `built-in`
    /// (also spelled `builtin`).
    pub fn parse(s: &str) -> Result<Self> {
        match s {
            "auto" => Ok(BootstrapMode::Auto),
            "ssh" => Ok(BootstrapMode::Ssh),
            "built-in" | "builtin" => Ok(BootstrapMode::BuiltIn),
            other => bail!("unknown --bootstrap mode {other:?} (auto|ssh|built-in)"),
        }
    }

    /// Decide whether to use the built-in client, given the system `ssh` program
    /// name (the first word of `--ssh`). In [`Auto`](Self::Auto) mode this checks
    /// whether that program is on `PATH`.
    pub fn use_built_in(self, ssh_prog: &str) -> bool {
        match self {
            BootstrapMode::Ssh => false,
            BootstrapMode::BuiltIn => true,
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

/// Build the `mish-server` argument list: optional `--detach`, an optional named
/// reattachable `--session NAME`, an ephemeral port, then an optional `-- command`.
fn server_args(
    detach: bool,
    session: Option<&str>,
    port: &str,
    command: Option<&str>,
) -> Vec<String> {
    let mut args = Vec::new();
    if detach {
        args.push("--detach".to_string());
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
    session: Option<&str>,
    command: Option<&str>,
) -> Result<Bootstrap> {
    // Local mode: keep the server in the foreground as a managed child (no
    // detach — we kill it when the session ends).
    let mut child = Command::new(server_cmd)
        .args(server_args(false, session, "0", command))
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
pub async fn ssh(
    ssh_argv: &[String],
    ssh_pty: bool,
    host: &str,
    server_cmd: &str,
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
        .args(server_args(true, session, "0", command));
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

/// Bootstrap with the built-in, pure-Rust SSH client ([`russh`]) instead of the
/// system `ssh` binary — `--bootstrap=built-in`.
///
/// `host` is `[user@]hostname` (no `ssh -p` parsing — the port comes from
/// `port`, the client's `--ssh-port`). We connect, authenticate (ssh-agent first,
/// then the default `~/.ssh/id_*` keys), `exec` `mish-server --detach …` over a
/// session channel, and read its `MISH CONNECT` line. As with the `ssh`
/// transport the server daemonizes, so the QUIC/UDP session outlives this
/// connection.
///
/// Auth is intentionally limited for this first pass: ssh-agent and unencrypted
/// on-disk keys only (no password / keyboard-interactive). Host keys are checked
/// against `~/.ssh/known_hosts` — a mismatch is rejected; an unknown host is
/// accepted on a trust-on-first-use basis (logged, but not written back).
pub async fn built_in(
    host: &str,
    port: u16,
    server_cmd: &str,
    session: Option<&str>,
    command: Option<&str>,
) -> Result<Bootstrap> {
    let (user, hostname) = split_user_host(host);
    let user = user.unwrap_or_else(default_user);

    let config = Arc::new(client::Config::default());
    let handler = BuiltInHandler {
        host: hostname.clone(),
        port,
    };
    let mut handle = client::connect(config, (hostname.as_str(), port), handler)
        .await
        .with_context(|| format!("connecting to {hostname}:{port}"))?;

    authenticate(&mut handle, &user)
        .await
        .with_context(|| format!("authenticating to {user}@{hostname}"))?;

    // Build the remote command line. The args mirror the `ssh` transport's
    // (`--detach` so the server survives this connection closing); each is
    // shell-quoted because sshd runs the whole string through the login shell.
    let argv = std::iter::once(server_cmd.to_string())
        .chain(server_args(true, session, "0", command))
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
        .context("running mish-server over the built-in SSH channel")?;

    let creds = read_connect_channel(&mut channel).await?;

    // The UDP session goes to the same host we SSHed to; resolve its address.
    let ip = tokio::net::lookup_host((hostname.as_str(), creds.port))
        .await
        .with_context(|| format!("resolving {hostname}"))?
        .next()
        .ok_or_else(|| anyhow!("no address for {hostname}"))?;

    Ok(Bootstrap {
        addr: ip,
        server_cert_der: creds.server_cert,
        client_cert_der: creds.client_cert,
        client_key_der: creds.client_key,
        _guard: Guard::Connection(handle),
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

/// russh client handler: verifies the server host key against
/// `~/.ssh/known_hosts`.
struct BuiltInHandler {
    host: String,
    port: u16,
}

impl client::Handler for BuiltInHandler {
    type Error = russh::Error;

    async fn check_server_key(&mut self, server_public_key: &PublicKey) -> Result<bool, Self::Error> {
        match russh::keys::check_known_hosts(&self.host, self.port, server_public_key) {
            // Known and matching.
            Ok(true) => Ok(true),
            // Not in known_hosts: trust on first use (logged, not persisted).
            Ok(false) => {
                eprintln!(
                    "[mish-client] warning: {}:{} is not in known_hosts; \
                     accepting its key on first use (not saved)",
                    self.host, self.port
                );
                Ok(true)
            }
            // A mismatch (or unreadable known_hosts): refuse — this is the
            // security-critical case (possible MITM).
            Err(e) => {
                eprintln!(
                    "[mish-client] host key verification failed for {}:{}: {e}",
                    self.host, self.port
                );
                Ok(false)
            }
        }
    }
}

/// Authenticate `handle` as `user`: try every ssh-agent identity first (Unix
/// only), then the default unencrypted `~/.ssh/id_*` keys. Errors if none work.
async fn authenticate(handle: &mut client::Handle<BuiltInHandler>, user: &str) -> Result<()> {
    // 1. ssh-agent (the common case: keys unlocked once, held by the agent).
    //    Unix-only for now — the Windows named-pipe agent is future work.
    #[cfg(unix)]
    {
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
                    }
                }
            }
        }
    }

    // 2. Default identity files on disk (unencrypted only — a passphrase-locked
    //    key is skipped, since we have no TTY prompt yet).
    if let Some(ssh_dir) = home_dir().map(|h| h.join(".ssh")) {
        // Negotiate the RSA signature hash once (None for ed25519/ecdsa keys).
        let rsa_hash = handle.best_supported_rsa_hash().await.ok().flatten().flatten();
        for name in ["id_ed25519", "id_ecdsa", "id_rsa"] {
            let path = ssh_dir.join(name);
            if !path.is_file() {
                continue;
            }
            let key = match load_secret_key(&path, None) {
                Ok(k) => k,
                Err(_) => continue, // encrypted or unreadable; try the next
            };
            let with_hash = PrivateKeyWithHashAlg::new(Arc::new(key), rsa_hash);
            if let Ok(res) = handle.authenticate_publickey(user, with_hash).await {
                if res.success() {
                    return Ok(());
                }
            }
        }
    }

    let _ = handle
        .disconnect(Disconnect::ByApplication, "auth failed", "")
        .await;
    bail!(
        "authentication failed for {user} (tried ssh-agent and ~/.ssh/id_ed25519, \
         id_ecdsa, id_rsa). The built-in bootstrap supports ssh-agent and \
         unencrypted key files only; for passwords or other methods use \
         --bootstrap=ssh."
    )
}

/// Read the built-in SSH channel's stdout until the `MISH CONNECT` line appears,
/// forwarding the server's stderr to ours so its diagnostics aren't swallowed.
async fn read_connect_channel(channel: &mut russh::Channel<client::Msg>) -> Result<ConnectInfo> {
    use std::io::Write;

    let mut buf: Vec<u8> = Vec::new();
    let read = async {
        while let Some(msg) = channel.wait().await {
            match msg {
                ChannelMsg::Data { data } => {
                    buf.extend_from_slice(&data[..]);
                    // Scan complete lines as they arrive.
                    while let Some(nl) = buf.iter().position(|&b| b == b'\n') {
                        let line: Vec<u8> = buf.drain(..=nl).collect();
                        let text = String::from_utf8_lossy(&line);
                        if let Some(parsed) = parse_connect(text.trim_end()) {
                            return Ok(parsed);
                        }
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

/// The parsed contents of a `MISH CONNECT` line.
struct ConnectInfo {
    port: u16,
    server_cert: Vec<u8>,
    client_cert: Vec<u8>,
    client_key: Vec<u8>,
}

/// Read the child's stdout until the `MISH CONNECT` line appears.
async fn read_connect(child: &mut Child) -> Result<ConnectInfo> {
    let stdout = child
        .stdout
        .take()
        .context("bootstrap child has no stdout")?;
    let mut lines = BufReader::new(stdout).lines();

    let read = async {
        while let Some(line) = lines.next_line().await? {
            if let Some(parsed) = parse_connect(&line) {
                return Ok(parsed);
            }
        }
        Err(anyhow!("server exited before printing a MISH CONNECT line"))
    };

    tokio::time::timeout(Duration::from_secs(30), read)
        .await
        .context("timed out waiting for the server to start")?
}

/// Parse a `MISH CONNECT <port> <server-cert> <client-cert> <client-key>` line
/// (all hex). Older single-cert lines (no client credentials) are rejected, so a
/// stale server can't silently downgrade to no client auth.
fn parse_connect(line: &str) -> Option<ConnectInfo> {
    let mut it = line.split_whitespace();
    if it.next()? != "MOSH" || it.next()? != "CONNECT" {
        return None;
    }
    let port: u16 = it.next()?.parse().ok()?;
    let server_cert = from_hex(it.next()?)?;
    let client_cert = from_hex(it.next()?)?;
    let client_key = from_hex(it.next()?)?;
    Some(ConnectInfo {
        port,
        server_cert,
        client_cert,
        client_key,
    })
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
        assert_eq!(info.client_key, vec![0x01, 0x02]);

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
            BootstrapMode::parse("built-in").unwrap(),
            BootstrapMode::BuiltIn
        );
        assert_eq!(
            BootstrapMode::parse("builtin").unwrap(),
            BootstrapMode::BuiltIn
        );
        assert!(BootstrapMode::parse("nope").is_err());
        assert_eq!(BootstrapMode::default(), BootstrapMode::Auto);
    }

    #[test]
    fn use_built_in_respects_explicit_modes() {
        // Explicit modes ignore PATH entirely.
        assert!(!BootstrapMode::Ssh.use_built_in("definitely-not-a-real-program"));
        assert!(BootstrapMode::BuiltIn.use_built_in("ssh"));
        // Auto falls back to the built-in client when the program is missing.
        assert!(BootstrapMode::Auto.use_built_in("definitely-not-a-real-program-xyz"));
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
}
