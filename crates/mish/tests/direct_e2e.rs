//! End-to-end test of direct-connect mode: enroll a client against the real
//! `mish-server` binary, run it as a long-lived `--listen` listener, and dial it
//! over QUIC with **no SSH** — the ssh-less fast path.
//!
//! Also covers the two invariants that make the mode safe and mosh-like:
//! * only an **enrolled** client cert is accepted (the allow-list is the whole
//!   security model); and
//! * each connection is its **own** shell (non-persistent) — a second dial is a
//!   fresh session multiplexed over the same listener port.

use std::sync::Arc;
use std::time::Duration;

use mish::bootstrap::{from_hex, to_hex};
use mish::client::{run_client, ClientInput};
use mish_quic::config::generate_identity;
use mish_quic::transport::{self, QuicTransport};
use mish_ssp::clock::{Clock, SystemClock};
use mish_terminal::predict::PredictMode;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::Command;
use tokio::sync::mpsc;

fn contains(hay: &[u8], needle: &[u8]) -> bool {
    hay.windows(needle.len()).any(|w| w == needle)
}

/// A throwaway config dir under the target dir, unique per test name (no
/// `Date`/`rand` in tests — the name is the discriminator).
fn config_dir(tag: &str) -> std::path::PathBuf {
    let dir = std::path::PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!("direct-{tag}"));
    let _ = std::fs::remove_dir_all(&dir);
    dir
}

/// Enroll `client_cert` against a server rooted at `config`, returning the
/// server certificate it hands back (as `mish enroll` would pin it). Drives the
/// real `--enroll-client` path.
fn enroll(server_bin: &str, config: &std::path::Path, client_cert: &[u8]) -> Vec<u8> {
    let out = std::process::Command::new(server_bin)
        .args(["--enroll-client", &to_hex(client_cert)])
        .env("MISH_CONFIG_DIR", config)
        .output()
        .expect("run --enroll-client");
    assert!(
        out.status.success(),
        "enroll failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    let hex = stdout
        .lines()
        .find_map(|l| l.strip_prefix("MISH IDENTITY "))
        .expect("MISH IDENTITY line");
    from_hex(hex.trim()).expect("server cert hex")
}

/// Read the `MISH LISTEN <addr>` line the listener prints on stdout.
async fn read_listen_addr(child: &mut tokio::process::Child) -> std::net::SocketAddr {
    let stdout = child.stdout.take().unwrap();
    let mut lines = BufReader::new(stdout).lines();
    while let Some(line) = lines.next_line().await.unwrap() {
        if let Some(addr) = line.strip_prefix("MISH LISTEN ") {
            return addr.trim().parse().expect("parse listen addr");
        }
    }
    panic!("no MISH LISTEN line");
}

/// Spawn `mish-server --listen 127.0.0.1:0` rooted at `config` and return the
/// child plus its bound address.
async fn spawn_listener(
    server_bin: &str,
    config: &std::path::Path,
) -> (tokio::process::Child, std::net::SocketAddr) {
    let mut child = Command::new(server_bin)
        .args(["--listen", "127.0.0.1:0"])
        .env("MISH_CONFIG_DIR", config)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .expect("spawn listener");
    let addr = read_listen_addr(&mut child).await;
    (child, addr)
}

/// Dial `addr`, presenting `client` creds and trusting `server_cert`.
async fn dial(
    addr: std::net::SocketAddr,
    server_cert: &[u8],
    client_cert: &[u8],
    client_key: &[u8],
) -> anyhow::Result<QuicTransport> {
    let endpoint = transport::authenticated_client_endpoint(
        "127.0.0.1:0".parse().unwrap(),
        server_cert,
        client_cert,
        client_key,
    )?;
    let t = transport::connect(&endpoint, addr, "localhost").await?;
    Ok(t)
}

/// Send the Exec hello for `argv`, then run the client and assert `marker`
/// resyncs back — typed at a shell when `keys` is non-empty, or straight from
/// the requested command's output when it is empty.
async fn run_and_expect_with(t: QuicTransport, argv: &[String], keys: &[u8], marker: &[u8]) {
    mish::direct::send_exec_hello(&t, argv)
        .await
        .expect("send Exec hello");
    let clock: Arc<dyn Clock> = Arc::new(SystemClock::new());
    let (cin_tx, cin_rx) = mpsc::channel::<ClientInput>(64);
    let (cout_tx, mut cout_rx) = mpsc::unbounded_channel::<Vec<u8>>();
    tokio::spawn(run_client(
        Arc::new(t),
        80,
        24,
        clock,
        PredictMode::Never,
        None,
        None,
        cin_rx,
        cout_tx,
    ));
    if !keys.is_empty() {
        cin_tx.send(ClientInput::Keys(keys.to_vec())).await.unwrap();
    }

    let marker = marker.to_vec();
    tokio::time::timeout(Duration::from_secs(20), async move {
        loop {
            let frame = cout_rx.recv().await.expect("client output");
            if contains(&frame, &marker) {
                return;
            }
        }
    })
    .await
    .expect("marker should traverse the direct session");
}

/// Login-shell session (empty Exec argv): type `keys`, expect `marker`.
async fn run_and_expect(t: QuicTransport, keys: &[u8], marker: &[u8]) {
    run_and_expect_with(t, &[], keys, marker).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn enrolled_client_connects_without_ssh_and_each_dial_is_fresh() {
    let server = env!("CARGO_BIN_EXE_mish-server");
    let config = config_dir("happy");

    // Enroll our client identity (materializes + returns the server cert).
    let (client_cert, client_key) = generate_identity("mish-client");
    let server_cert = enroll(server, &config, &client_cert);

    let (_child, addr) = spawn_listener(server, &config).await;

    // First dial: a working shell, ssh-less.
    let t1 = dial(addr, &server_cert, &client_cert, &client_key)
        .await
        .expect("enrolled client connects");
    run_and_expect(t1, b"echo DIRECT_OK_1\r", b"DIRECT_OK_1").await;

    // Second dial over the SAME listener port: a *separate* fresh shell,
    // multiplexed by QUIC connection id (non-persistent per-connection sessions).
    let t2 = dial(addr, &server_cert, &client_cert, &client_key)
        .await
        .expect("second connection is accepted on the same port");
    run_and_expect(t2, b"echo DIRECT_OK_2\r", b"DIRECT_OK_2").await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn enrollment_takes_effect_on_a_running_listener() {
    let server = env!("CARGO_BIN_EXE_mish-server");
    let config = config_dir("live-enroll");

    // Our client identity exists up front, but is NOT enrolled yet.
    let (client_cert, client_key) = generate_identity("mish-client");

    // Start the listener with an empty allow-list (this also materializes the
    // server identity the later enroll will load and hand back).
    let (_child, addr) = spawn_listener(server, &config).await;

    // Enroll AFTER the listener is already running.
    let server_cert = enroll(server, &config, &client_cert);

    // The listener re-reads the allow-list per handshake, so the freshly enrolled
    // client connects with no restart of the daemon.
    let t = dial(addr, &server_cert, &client_cert, &client_key)
        .await
        .expect("a client enrolled against a running listener connects without a restart");
    run_and_expect(t, b"echo LIVE_ENROLL_OK\r", b"LIVE_ENROLL_OK").await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unenrolled_client_is_rejected() {
    let server = env!("CARGO_BIN_EXE_mish-server");
    let config = config_dir("reject");

    // Enroll one client so the server has an identity + a non-empty allow-list.
    let (enrolled_cert, _enrolled_key) = generate_identity("mish-client");
    let server_cert = enroll(server, &config, &enrolled_cert);

    let (_child, addr) = spawn_listener(server, &config).await;

    // A different, *un-enrolled* identity: it trusts the (public) server cert but
    // its own cert isn't in the allow-list, so the mutual-TLS handshake must fail.
    let (stranger_cert, stranger_key) = generate_identity("stranger");
    let dialed = tokio::time::timeout(
        Duration::from_secs(10),
        dial(addr, &server_cert, &stranger_cert, &stranger_key),
    )
    .await;

    // With TLS 1.3, the client-side `connect` can complete before the server's
    // client-cert rejection arrives (the same subtlety `auth_e2e.rs` documents).
    // So "not admitted" means one of: the connect errored, it never completed in
    // the window, or it completed and the server then *closed* it. What must never
    // happen is a live connection that keeps running a shell.
    if let Ok(Ok(t)) = dialed {
        let closed = tokio::time::timeout(Duration::from_secs(8), t.connection().closed()).await;
        assert!(
            closed.is_ok(),
            "server must close (reject) an un-enrolled client's connection"
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn exec_hello_runs_the_requested_command() {
    let server = env!("CARGO_BIN_EXE_mish-server");
    let config = config_dir("exec");

    let (client_cert, client_key) = generate_identity("mish-client");
    let server_cert = enroll(server, &config, &client_cert);

    let (_child, addr) = spawn_listener(server, &config).await;

    // The Exec hello names this connection's command; its output arrives without
    // typing anything. The trailing sleep keeps the PTY alive while the marker
    // syncs (the session is torn down when the test drops the connection).
    let t = dial(addr, &server_cert, &client_cert, &client_key)
        .await
        .expect("enrolled client connects");
    let argv: Vec<String> = ["sh", "-c", "echo EXEC_HELLO_OK && sleep 30"]
        .iter()
        .map(|s| s.to_string())
        .collect();
    run_and_expect_with(t, &argv, b"", b"EXEC_HELLO_OK").await;
}
