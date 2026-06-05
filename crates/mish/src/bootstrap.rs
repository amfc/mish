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
    /// Server certificate (DER) the client pins to authenticate the server.
    pub server_cert_der: Vec<u8>,
    /// Client certificate (DER) the client presents for mutual auth.
    pub client_cert_der: Vec<u8>,
    /// Client private key (PKCS#8 DER) the client presents for mutual auth.
    pub client_key_der: Vec<u8>,
    child: Child,
}

impl Drop for Bootstrap {
    fn drop(&mut self) {
        // Tear down the server / ssh channel when the session ends.
        let _ = self.child.start_kill();
    }
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
        child,
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
        child,
    })
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
