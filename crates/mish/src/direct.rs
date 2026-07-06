//! Direct-connect mode (`--listen`): an ssh-less fast path to a mish shell.
//!
//! The default mish flow bootstraps every session over SSH: the client SSHes in,
//! launches `mish-server`, and reads a one-shot `MISH CONNECT` line carrying a
//! freshly-minted, per-session credential triple. That round-trip is the slow
//! part. Direct mode removes it: a long-lived `mish-server --listen [IP:]PORT`
//! carries a **stable identity persisted on disk** and a directory of **enrolled
//! client certificates**, so an enrolled client dials the QUIC port straight away
//! with no SSH at all (see [`mish_quic::config::stable_server_config`]).
//!
//! The operator owns the daemon's lifecycle and reachability (a systemd unit, and
//! — on WireGuard hosts — a bind IP that only the WG interface exposes). This
//! module provides the pieces that are independent of that wiring: loading or
//! generating the persistent server identity, reading the enrolled client certs,
//! and serving a single accepted connection.
//!
//! Sessions here are **non-persistent**: each accepted QUIC connection gets its
//! own PTY and dies when the connection or the shell goes. The connection's
//! first stream carries a [`StreamHello::Exec`] naming the command to run
//! (empty = login shell), so one long-lived listener serves per-connection
//! commands the way each ssh-bootstrapped `mish-server -- command` process does. Roaming across network
//! changes is handled entirely at the transport layer (QUIC connection
//! migration), exactly as in the SSH-bootstrap path — a client that changes IP
//! keeps the *same* connection, so a brand-new invocation is always a brand-new
//! shell and never resurrects a previous one. Reattach/persistence is deliberately
//! absent (use tmux for that); port forwarding is off.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use zeroize::Zeroizing;

use crate::forward::{serve_side_channels, StreamHello};
use crate::pty::PtyProcess;
use crate::server::run_server;
use mish_quic::transport::QuicTransport;
use mish_ssp::clock::SystemClock;
use mish_ssp::framing::{read_message, write_message, MAX_MESSAGE_LEN};

/// File extension for an enrolled client certificate (DER) in the authorized-certs
/// directory. Only files with this suffix are read, so stray files (READMEs,
/// editor swap files) never derail the allow-list.
const CLIENT_CERT_EXT: &str = "crt";

/// The persistent server certificate lives beside its key: `--server-key foo.key`
/// stores the cert at `foo.crt`. Kept next to the key so one path configures both.
fn cert_path_for_key(key_path: &Path) -> PathBuf {
    key_path.with_extension(CLIENT_CERT_EXT)
}

/// Subject of a persistent **server** identity. The client passes this as the QUIC
/// `server_name` ([`mish_quic::transport::connect`]), so it must match.
pub const SERVER_SUBJECT: &str = "localhost";

/// Resolve mish's config dir: `$MISH_CONFIG_DIR`, else `$XDG_CONFIG_HOME/mish`,
/// else `~/.config/mish`. Holds the persistent server identity + enrolled-client
/// allow-list (server side) and the client identity + pinned server certs (client
/// side).
pub fn config_dir() -> Result<PathBuf> {
    if let Some(dir) = std::env::var_os("MISH_CONFIG_DIR") {
        return Ok(PathBuf::from(dir));
    }
    if let Some(xdg) = std::env::var_os("XDG_CONFIG_HOME") {
        return Ok(PathBuf::from(xdg).join("mish"));
    }
    let home = std::env::var_os("HOME").context("HOME is not set")?;
    Ok(PathBuf::from(home).join(".config").join("mish"))
}

/// Load the persistent identity from `key_path` (+ its sibling `.crt`), or — on
/// first run, when **both** files are absent — generate a fresh self-signed
/// identity with `subject` and persist it: the key `0600` (it is the long-term
/// secret) and the cert world-readable (it is public; the peer pins it).
///
/// A half-present identity (exactly one of key/cert on disk) is a corrupted
/// state, not a "regenerate" trigger: regenerating would silently rotate the
/// server's pin — breaking every enrolled client — and overwrite a private key
/// that may still be referenced. So it is refused loudly; the operator removes
/// both to start over.
pub fn load_or_generate_identity(
    key_path: &Path,
    subject: &str,
) -> Result<(Vec<u8>, Zeroizing<Vec<u8>>)> {
    let cert_path = cert_path_for_key(key_path);
    let key_exists = key_path.exists();
    let cert_exists = cert_path.exists();
    if key_exists && cert_exists {
        let key = Zeroizing::new(
            std::fs::read(key_path).with_context(|| format!("reading {}", key_path.display()))?,
        );
        let cert = std::fs::read(&cert_path)
            .with_context(|| format!("reading {}", cert_path.display()))?;
        return Ok((cert, key));
    }
    if key_exists != cert_exists {
        anyhow::bail!(
            "incomplete server identity: exactly one of {} / {} is present; \
             refusing to overwrite a live key or rotate the pin — remove both to regenerate",
            key_path.display(),
            cert_path.display()
        );
    }

    let (cert, key) = mish_quic::config::generate_identity(subject);
    if let Some(dir) = key_path.parent() {
        std::fs::create_dir_all(dir)
            .with_context(|| format!("creating identity dir {}", dir.display()))?;
    }
    write_new(key_path, &key, 0o600).with_context(|| format!("writing {}", key_path.display()))?;
    write_new(&cert_path, &cert, 0o644)
        .with_context(|| format!("writing {}", cert_path.display()))?;
    Ok((cert, key))
}

/// Write `bytes` to a **newly created** `path` with `mode` (`O_EXCL`), never
/// following a symlink and never truncating an existing file — so a long-term
/// key or cert can't be silently clobbered or redirected through a planted path.
/// Only ever called on the fresh-generate path (both files absent), so `O_EXCL`
/// failing means a concurrent writer or a planted file, either of which we want
/// to surface loudly rather than write through.
fn write_new(path: &Path, bytes: &[u8], mode: u32) -> std::io::Result<()> {
    use std::io::Write;
    #[cfg(unix)]
    let mut f = {
        use std::os::unix::fs::OpenOptionsExt;
        std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(mode)
            .open(path)?
    };
    #[cfg(not(unix))]
    let mut f = {
        let _ = mode;
        std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)?
    };
    f.write_all(bytes)?;
    Ok(())
}

/// Read every enrolled client certificate (DER) from `dir`, returning their raw
/// bytes for [`mish_quic::config::stable_server_config`]'s allow-list. Only
/// `*.crt` files are read. A missing directory is created (`0700`) and treated as
/// an empty allow-list — a fresh daemon accepts no one until a client is enrolled,
/// which is the safe default (the verifier rejects every cert against an empty
/// set).
pub fn load_authorized_certs(dir: &Path) -> Result<Vec<Vec<u8>>> {
    if !dir.exists() {
        std::fs::create_dir_all(dir)
            .with_context(|| format!("creating authorized-certs dir {}", dir.display()))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700));
        }
        return Ok(Vec::new());
    }
    let mut certs = Vec::new();
    for entry in std::fs::read_dir(dir).with_context(|| format!("reading {}", dir.display()))? {
        let path = entry
            .with_context(|| format!("reading entry in {}", dir.display()))?
            .path();
        if path.extension().and_then(|e| e.to_str()) == Some(CLIENT_CERT_EXT) {
            certs
                .push(std::fs::read(&path).with_context(|| format!("reading {}", path.display()))?);
        }
    }
    Ok(certs)
}

/// Sanitize an untrusted path component (a peer-supplied client name or host) so
/// it is a safe single filename: keep `[A-Za-z0-9._-]`, map everything else to
/// `_`, and reject empty / dot-only names (which would escape or alias the dir).
/// The name flows into a filesystem path on the *other* end of an enrollment, so
/// this guards against traversal (`../`) and separators.
pub fn sanitize_component(name: &str) -> Result<String> {
    let clean: String = name
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect();
    if clean.is_empty() || clean.chars().all(|c| c == '.') {
        anyhow::bail!("invalid name {name:?}");
    }
    Ok(clean)
}

/// Enroll a client certificate into the server's allow-list `dir`: write its DER
/// bytes to `<dir>/<name>.crt` (the directory is created `0700` if missing).
/// Re-enrolling the same `name` overwrites its entry (a key rotation), so a
/// machine keeps a single slot. Returns the path written.
pub fn enroll_client_cert(dir: &Path, name: &str, cert_der: &[u8]) -> Result<PathBuf> {
    let file = format!("{}.{CLIENT_CERT_EXT}", sanitize_component(name)?);
    std::fs::create_dir_all(dir)
        .with_context(|| format!("creating authorized-certs dir {}", dir.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700));
    }
    let path = dir.join(file);
    std::fs::write(&path, cert_der).with_context(|| format!("writing {}", path.display()))?;
    Ok(path)
}

/// An enrolled client sends its [`StreamHello::Exec`] immediately at connect, so
/// waiting longer only keeps a broken peer's session task alive. Bounded so a
/// connected-but-silent connection cannot pin the accept task forever.
const EXEC_HELLO_TIMEOUT: Duration = Duration::from_secs(10);

/// Client side of the direct-connect exec handshake: open the connection's first
/// stream and send the [`StreamHello::Exec`] naming the command to run (empty
/// argv = login shell). The server waits for this before spawning the PTY.
pub async fn send_exec_hello(transport: &QuicTransport, argv: &[String]) -> Result<()> {
    let (mut send, _recv) = transport
        .open_side_channel()
        .await
        .context("opening the Exec hello stream")?;
    let hello = StreamHello::Exec {
        argv: argv.to_vec(),
    };
    write_message(&mut send, &hello.encode())
        .await
        .context("sending the Exec hello")?;
    let _ = send.finish();
    Ok(())
}

/// Server side of the exec handshake: the connection's first stream must carry
/// an [`StreamHello::Exec`]. Anything else is a protocol violation from an
/// authenticated-but-broken peer, refused loudly.
async fn read_exec_hello(transport: &QuicTransport) -> Result<Vec<String>> {
    let (_send, mut recv) = transport
        .accept_side_channel()
        .await
        .context("accepting the Exec hello stream")?;
    let bytes = read_message(&mut recv, MAX_MESSAGE_LEN)
        .await
        .context("reading the Exec hello frame")?
        .context("Exec hello stream closed without a frame")?;
    match StreamHello::decode(&bytes) {
        Some(StreamHello::Exec { argv }) => Ok(argv),
        Some(other) => anyhow::bail!("expected an Exec hello on the first stream, got {other:?}"),
        None => anyhow::bail!("malformed hello frame on the first stream"),
    }
}

/// Serve one accepted, already-authenticated connection to completion: wait for
/// the client's [`StreamHello::Exec`] naming this connection's command, spawn the
/// PTY (login shell on an empty argv), wire the side-channel server (scrollback;
/// forwarding stays off), and run the non-persistent session loop. When the loop
/// returns — client gone or shell exited — the [`PtyProcess`] drops, which closes
/// its control channel and reaps the child (`kill` + `wait`), so no process is
/// left behind.
///
/// A listener started with an explicit `--listen -- command` pins that command:
/// the hello is still required, but a non-empty argv in it is refused (the
/// operator's pin is the whole point of passing one).
pub async fn serve_connection(
    transport: QuicTransport,
    fixed_command: Vec<String>,
    network_timeout: Option<Duration>,
) -> Result<()> {
    let argv = tokio::time::timeout(EXEC_HELLO_TIMEOUT, read_exec_hello(&transport))
        .await
        .context("timed out waiting for the client's Exec hello")??;
    let command = if fixed_command.is_empty() {
        argv
    } else if argv.is_empty() {
        fixed_command
    } else {
        anyhow::bail!("client requested a command but the listener pins one");
    };

    let (cols, rows) = (80u16, 24u16);
    let pty = if command.is_empty() {
        PtyProcess::spawn_login_shell(cols, rows)
    } else {
        PtyProcess::spawn_argv(command, cols, rows)
    }
    .context("spawning PTY child")?;

    let clock = Arc::new(SystemClock::new());
    let emu = mish_terminal::emulator::Emulator::shared(cols, rows);
    let transport = Arc::new(transport);
    // Side-channels: scrollback history only. Port forwarding is disabled in
    // direct mode (`forward = false`), so `-L`/`-R` requests are denied.
    tokio::spawn(serve_side_channels(transport.clone(), emu.clone(), false));
    run_server(
        transport,
        emu,
        clock,
        network_timeout,
        pty.output,
        pty.control,
    )
    .await;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("mish-direct-{}-{}", tag, std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        d
    }

    /// First run generates and persists a stable identity; a second run loads the
    /// *same* bytes back (so enrolled clients keep trusting the server across
    /// restarts). The key file must be `0600`.
    #[test]
    fn identity_is_generated_then_loaded_stably() {
        let dir = tmp("identity");
        let key_path = dir.join("server.key");
        let (cert1, key1) = load_or_generate_identity(&key_path, SERVER_SUBJECT).expect("generate");
        assert!(!cert1.is_empty() && !key1.is_empty());

        let (cert2, key2) = load_or_generate_identity(&key_path, SERVER_SUBJECT).expect("load");
        assert_eq!(cert1, cert2, "cert must be stable across restarts");
        assert_eq!(&*key1, &*key2, "key must be stable across restarts");

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&key_path).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600, "server key must be 0600");
        }
        std::fs::remove_dir_all(&dir).ok();
    }

    /// A half-present identity (key without cert, or vice versa) is refused, not
    /// silently regenerated — regenerating would rotate the pin and clobber a key
    /// that may still be referenced.
    #[test]
    fn partial_identity_state_is_refused() {
        let dir = tmp("partial-identity");
        let key_path = dir.join("server.key");
        load_or_generate_identity(&key_path, SERVER_SUBJECT).expect("generate");

        // Delete the cert but keep the key: an incomplete identity.
        std::fs::remove_file(cert_path_for_key(&key_path)).unwrap();
        let before = std::fs::read(&key_path).unwrap();
        assert!(
            load_or_generate_identity(&key_path, SERVER_SUBJECT).is_err(),
            "a half-present identity must be refused, not regenerated"
        );
        assert_eq!(
            std::fs::read(&key_path).unwrap(),
            before,
            "the surviving key must be left untouched"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    /// A missing authorized-certs dir is created and yields an empty allow-list
    /// (accept no one). Enrolled `*.crt` files are read; other files are ignored.
    #[test]
    fn authorized_certs_reads_only_crt_files() {
        let dir = tmp("authorized");
        assert!(
            load_authorized_certs(&dir).expect("empty").is_empty(),
            "a fresh dir enrolls no clients"
        );
        assert!(dir.exists(), "the dir is created on first read");

        std::fs::write(dir.join("phone.crt"), b"DER-A").unwrap();
        std::fs::write(dir.join("laptop.crt"), b"DER-B").unwrap();
        std::fs::write(dir.join("README.txt"), b"ignore me").unwrap();
        std::fs::write(dir.join("notes"), b"no extension").unwrap();

        let mut certs = load_authorized_certs(&dir).expect("read");
        certs.sort();
        assert_eq!(
            certs,
            vec![b"DER-A".to_vec(), b"DER-B".to_vec()],
            "only *.crt files are enrolled"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    /// Enrolling writes `<name>.crt` and is picked up by the loader; a second
    /// enroll of the same name overwrites (rotation), keeping one slot.
    #[test]
    fn enroll_writes_and_rotates_a_named_slot() {
        let dir = tmp("enroll");
        enroll_client_cert(&dir, "phone", b"DER-1").expect("enroll");
        assert_eq!(
            load_authorized_certs(&dir).unwrap(),
            vec![b"DER-1".to_vec()]
        );
        // Same name, new key → overwrite, still one entry.
        enroll_client_cert(&dir, "phone", b"DER-2").expect("re-enroll");
        assert_eq!(
            load_authorized_certs(&dir).unwrap(),
            vec![b"DER-2".to_vec()]
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    /// A traversal-laden name is sanitized to a single safe filename, never
    /// escaping the allow-list dir.
    #[test]
    fn enroll_sanitizes_traversal_names() {
        let dir = tmp("enroll-evil");
        // Separators are mapped away, so the cert lands as one filename inside the
        // dir — no `../` escape. (A leftover `..` *substring* is harmless; only a
        // whole `.`/`..` component would traverse, and that's rejected below.)
        let path = enroll_client_cert(&dir, "../../etc/evil", b"DER").expect("enroll");
        assert_eq!(path.parent(), Some(dir.as_path()), "must stay inside dir");
        let fname = path.file_name().unwrap().to_string_lossy();
        assert!(!fname.contains('/'), "no separator survives: {fname}");
        assert_ne!(fname, "..");
        assert_ne!(fname, ".");
        // A name that is only dots (would alias the dir / its parent) is rejected.
        assert!(sanitize_component("..").is_err(), "`..` is rejected");
        assert!(sanitize_component(".").is_err(), "`.` is rejected");
        std::fs::remove_dir_all(&dir).ok();
    }
}
