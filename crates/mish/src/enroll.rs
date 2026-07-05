//! Client-side enrollment and credential storage for direct-connect mode.
//!
//! Direct mode (`mish-server --listen`) has no SSH handoff, so the client must
//! already hold two things before it can dial:
//!
//! 1. its own **persistent client identity** (`<config>/client.key` + `.crt`),
//!    whose certificate the server has enrolled in its allow-list; and
//! 2. the **pinned server certificate** for each host it connects to, stored at
//!    `<config>/known-servers/<host>.crt`.
//!
//! `mish enroll [user@]host` establishes both in one SSH round-trip: it ensures
//! the local client identity, ships the client cert to the server (which adds it
//! to its allow-list and materializes + returns its own cert), and pins that
//! server cert here. Afterwards `mish --connect host:port` needs no SSH at all.

use std::path::PathBuf;

use anyhow::{Context, Result};
use zeroize::Zeroizing;

use crate::direct::{config_dir, load_or_generate_identity, sanitize_component};

/// Subject of the persistent **client** identity. The direct-mode server pins
/// certificates by full DER equality, not by subject, so this is cosmetic — it
/// just labels the cert.
pub const CLIENT_SUBJECT: &str = "mish-client";

/// Directory under the config dir holding one pinned server cert per host.
const KNOWN_SERVERS_DIR: &str = "known-servers";

/// The persistent client identity: the cert the server enrolls, and the private
/// key the client presents on every direct connection (`--connect`).
pub struct ClientIdentity {
    pub cert: Vec<u8>,
    pub key: Zeroizing<Vec<u8>>,
}

/// Path of the persistent client-identity key (`<config>/client.key`; the cert
/// sits beside it as `client.crt`).
fn client_key_path() -> Result<PathBuf> {
    Ok(config_dir()?.join("client.key"))
}

/// Load the persistent client identity, generating and persisting it on first
/// use. Stable across runs so a single enrollment keeps working.
pub fn load_or_generate_client_identity() -> Result<ClientIdentity> {
    let (cert, key) = load_or_generate_identity(&client_key_path()?, CLIENT_SUBJECT)
        .context("loading client identity")?;
    Ok(ClientIdentity { cert, key })
}

/// Path of the pinned server certificate for `host` (`user@` stripped).
pub fn known_server_cert_path(host: &str) -> Result<PathBuf> {
    let name = sanitize_component(host_only(host))?;
    Ok(config_dir()?
        .join(KNOWN_SERVERS_DIR)
        .join(format!("{name}.crt")))
}

/// Pin `cert_der` as the trusted server certificate for `host`, overwriting any
/// previous pin (a server key rotation is re-established by re-enrolling).
pub fn store_server_cert(host: &str, cert_der: &[u8]) -> Result<PathBuf> {
    let path = known_server_cert_path(host)?;
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
    }
    std::fs::write(&path, cert_der).with_context(|| format!("writing {}", path.display()))?;
    Ok(path)
}

/// Load the pinned server certificate for `host`. A missing pin means the host
/// was never enrolled — fail loudly, pointing at `mish enroll`.
pub fn load_server_cert(host: &str) -> Result<Vec<u8>> {
    let path = known_server_cert_path(host)?;
    if !path.exists() {
        anyhow::bail!("no pinned server certificate for {host:?} — run `mish enroll {host}` first");
    }
    std::fs::read(&path).with_context(|| format!("reading {}", path.display()))
}

/// Strip a leading `user@` from a host spec, leaving the host.
pub fn host_only(host: &str) -> &str {
    host.rsplit_once('@').map(|(_, h)| h).unwrap_or(host)
}

/// A stable, human-readable label for this client machine, used as the filename
/// of its cert in the server's allow-list. `$MISH_CLIENT_NAME` overrides; else the
/// system hostname; else a fixed fallback. Sanitized by the server on receipt.
pub fn client_label() -> String {
    if let Ok(name) = std::env::var("MISH_CLIENT_NAME") {
        if !name.is_empty() {
            return name;
        }
    }
    hostname().unwrap_or_else(|| CLIENT_SUBJECT.to_string())
}

/// The system hostname via `gethostname(2)`, or `None` if it can't be read.
#[cfg(unix)]
fn hostname() -> Option<String> {
    let mut buf = [0u8; 256];
    // SAFETY: `buf` is a valid, writable buffer of `buf.len()` bytes for the
    // duration of the call; `gethostname` writes at most that many bytes.
    let rc = unsafe { libc::gethostname(buf.as_mut_ptr().cast(), buf.len()) };
    if rc != 0 {
        return None;
    }
    let end = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
    let name = String::from_utf8_lossy(&buf[..end]).into_owned();
    if name.is_empty() {
        None
    } else {
        Some(name)
    }
}

#[cfg(not(unix))]
fn hostname() -> Option<String> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_only_strips_user() {
        assert_eq!(host_only("me@nyx"), "nyx");
        assert_eq!(host_only("nyx"), "nyx");
        assert_eq!(host_only("me@10.99.1.10"), "10.99.1.10");
    }
}
