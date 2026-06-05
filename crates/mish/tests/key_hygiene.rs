//! Key-hygiene regression (review §A.6): the per-session **client private key**
//! is delivered over the `MISH CONNECT` line on stdout (the intended, SSH-tunneled
//! channel) — but it must never leak into the server's *log* output (stderr,
//! where connection/diagnostic messages go). A stray `eprintln!` of the auth
//! struct, or logging the whole connect line to stderr, would expose it.

use std::process::Stdio;

use tokio::io::{AsyncBufReadExt, AsyncReadExt, BufReader};
use tokio::process::Command;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn client_key_never_appears_in_server_logs() {
    let server = env!("CARGO_BIN_EXE_mish-server");
    let mut child = Command::new(server)
        .args(["0", "--", "/bin/sh"])
        // Exit quickly if no client connects, so we can collect stderr to EOF.
        .env("MOSH_SERVER_SIGNAL_TMOUT", "2")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .expect("spawn mish-server");

    // Parse the client key (6th token) from the MISH CONNECT line on stdout.
    let stdout = child.stdout.take().unwrap();
    let mut lines = BufReader::new(stdout).lines();
    let mut client_key = None;
    while let Some(line) = lines.next_line().await.unwrap() {
        if let Some(rest) = line.strip_prefix("MISH CONNECT ") {
            // <port> <server-cert> <client-cert> <client-key>
            client_key = rest.split_whitespace().nth(3).map(str::to_string);
            break;
        }
    }
    let key = client_key.expect("server printed a MISH CONNECT line with a client key");
    assert!(key.len() >= 32, "client key hex looks real");

    // Collect all stderr (the server exits within the 2s signal timeout).
    let mut stderr = String::new();
    BufReader::new(child.stderr.take().unwrap())
        .read_to_string(&mut stderr)
        .await
        .unwrap();
    let _ = child.wait().await;

    assert!(
        !stderr.contains(&key),
        "the client private key must never appear in the server's log output (stderr)"
    );
}
