//! Connection bootstrap, mirroring how upstream mosh starts a session.
//!
//! The real `mosh` wrapper SSHes to the host, runs `mosh-server`, reads the
//! `MISH CONNECT <port> <key>` line it prints, then hands the port/key to
//! `mosh-client`, which opens the UDP session directly. We do the same: SSH (or,
//! in `--local` mode, a child process) starts `mish-server`, which prints
//!
//! ```text
//! MISH CONNECT <port> <hex-encoded-cert-DER>
//! ```
//!
//! over the (SSH-encrypted) channel. We parse it, then open a QUIC connection to
//! the host on that UDP port, trusting exactly that certificate.
//!
//! The bootstrap child (the local server process, or the `ssh` process) is held
//! for the lifetime of the [`Bootstrap`] and killed on drop. (Upstream mosh
//! daemonizes the server so SSH can fully close; keeping the channel open is
//! simpler and good enough for local/trusted use.)

use std::net::SocketAddr;
use std::process::Stdio;
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::{Child, Command};

/// A bootstrapped session target: where to connect, the cert to trust, and the
/// child process keeping the server reachable.
pub struct Bootstrap {
    pub addr: SocketAddr,
    pub cert_der: Vec<u8>,
    child: Child,
}

impl Drop for Bootstrap {
    fn drop(&mut self) {
        // Tear down the server / ssh channel when the session ends.
        let _ = self.child.start_kill();
    }
}

/// Build the `mish-server` argument list: optional `--detach`, an ephemeral
/// port, then an optional `-- command`.
fn server_args(detach: bool, port: &str, command: Option<&str>) -> Vec<String> {
    let mut args = Vec::new();
    if detach {
        args.push("--detach".to_string());
    }
    args.push(port.to_string());
    if let Some(cmd) = command {
        args.push("--".into());
        args.push(cmd.into());
    }
    args
}

/// Start `mish-server` locally as a child process (no SSH). Used for `--local`.
pub async fn local(server_cmd: &str, command: Option<&str>) -> Result<Bootstrap> {
    // Local mode: keep the server in the foreground as a managed child (no
    // detach — we kill it when the session ends).
    let mut child = Command::new(server_cmd)
        .args(server_args(false, "0", command))
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .kill_on_drop(true)
        .spawn()
        .with_context(|| format!("spawning local server `{server_cmd}`"))?;

    let (port, cert_der) = read_connect(&mut child).await?;
    Ok(Bootstrap {
        addr: SocketAddr::from(([127, 0, 0, 1], port)),
        cert_der,
        child,
    })
}

/// SSH to `host`, run `mish-server` there, and read its `MISH CONNECT` line.
pub async fn ssh(
    ssh_cmd: &str,
    host: &str,
    server_cmd: &str,
    command: Option<&str>,
) -> Result<Bootstrap> {
    // Over SSH: detach the server so it survives SSH closing (real mosh does
    // this). The `ssh` process exits once the server's parent returns; the
    // daemon keeps serving over UDP.
    let mut child = Command::new(ssh_cmd)
        .arg(host)
        .arg(server_cmd)
        .args(server_args(true, "0", command))
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .kill_on_drop(true)
        .spawn()
        .with_context(|| format!("spawning `{ssh_cmd} {host} {server_cmd}`"))?;

    let (port, cert_der) = read_connect(&mut child).await?;

    // The UDP session goes to the same host SSH reached; resolve its address.
    let hostname = host.rsplit('@').next().unwrap_or(host);
    let ip = tokio::net::lookup_host((hostname, port))
        .await
        .with_context(|| format!("resolving {hostname}"))?
        .next()
        .ok_or_else(|| anyhow!("no address for {hostname}"))?;

    Ok(Bootstrap {
        addr: ip,
        cert_der,
        child,
    })
}

/// Read the child's stdout until the `MISH CONNECT` line appears.
async fn read_connect(child: &mut Child) -> Result<(u16, Vec<u8>)> {
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
        Err(anyhow!(
            "server exited before printing a MISH CONNECT line"
        ))
    };

    tokio::time::timeout(Duration::from_secs(30), read)
        .await
        .context("timed out waiting for the server to start")?
}

/// Parse a `MISH CONNECT <port> <hex-cert>` line.
fn parse_connect(line: &str) -> Option<(u16, Vec<u8>)> {
    let mut it = line.split_whitespace();
    if it.next()? != "MOSH" || it.next()? != "CONNECT" {
        return None;
    }
    let port: u16 = it.next()?.parse().ok()?;
    let cert = from_hex(it.next()?)?;
    Some((port, cert))
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_roundtrip() {
        let data = vec![0x00, 0x01, 0xfe, 0xff, 0xa5, 0x5a];
        assert_eq!(from_hex(&to_hex(&data)), Some(data));
    }

    #[test]
    fn parse_connect_line() {
        let line = format!("MISH CONNECT 51234 {}", to_hex(&[0xde, 0xad, 0xbe, 0xef]));
        assert_eq!(parse_connect(&line), Some((51234, vec![0xde, 0xad, 0xbe, 0xef])));
        assert_eq!(parse_connect("garbage"), None);
        assert_eq!(parse_connect("MISH CONNECT notaport ff"), None);
    }
}
