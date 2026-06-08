//! Verifies `mish-server --detach` daemonizes: the spawned process (the fork
//! parent) exits after printing MISH CONNECT, yet the detached daemon keeps
//! serving on the UDP port — so we can still connect and run a session.

use std::sync::Arc;
use std::time::Duration;

use mish::bootstrap::from_hex;
use mish::client::{run_client, ClientInput};
use mish_quic::transport;
use mish_ssp::clock::{Clock, SystemClock};
use mish_terminal::predict::PredictMode;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::Command;
use tokio::sync::mpsc;

fn contains(hay: &[u8], needle: &[u8]) -> bool {
    hay.windows(needle.len()).any(|w| w == needle)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn detach_survives_parent_exit() {
    let server = env!("CARGO_BIN_EXE_mish-server");

    let mut child = Command::new(server)
        .args(["--detach", "0", "--", "/bin/sh"])
        // Backstop so a lingering daemon exits quickly if anything goes wrong.
        .env("MOSH_SERVER_NETWORK_TMOUT", "8")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .kill_on_drop(false)
        .spawn()
        .expect("spawn mish-server --detach");

    // Read MISH CONNECT from the (about-to-exit) parent.
    let stdout = child.stdout.take().unwrap();
    let mut lines = BufReader::new(stdout).lines();
    let mut conn = None;
    while let Some(line) = lines.next_line().await.unwrap() {
        let mut it = line.split_whitespace();
        if it.next() == Some("MOSH") && it.next() == Some("CONNECT") {
            let port: u16 = it.next().unwrap().parse().unwrap();
            let server_cert = from_hex(it.next().unwrap()).unwrap();
            let client_cert = from_hex(it.next().unwrap()).unwrap();
            let client_key = from_hex(it.next().unwrap()).unwrap();
            conn = Some((port, server_cert, client_cert, client_key));
            break;
        }
    }
    let (port, server_cert, client_cert, client_key) = conn.expect("server printed MISH CONNECT");

    // The fork parent must exit promptly (proving it detached the daemon).
    let status = tokio::time::timeout(Duration::from_secs(5), child.wait())
        .await
        .expect("parent should exit after forking the daemon")
        .expect("wait");
    assert!(status.success(), "detach parent exited cleanly");

    // The daemon is now an orphan — but still listening. Connect (mutual auth).
    let endpoint = transport::authenticated_client_endpoint(
        "0.0.0.0:0".parse().unwrap(),
        &server_cert,
        &client_cert,
        &client_key,
    )
    .expect("client endpoint");
    let t = transport::connect(&endpoint, ([127, 0, 0, 1], port).into(), "localhost")
        .await
        .expect("connect to the detached daemon");

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
        None, // session name (display-only)
        cin_rx,
        cout_tx,
    ));
    cin_tx
        .send(ClientInput::Keys(b"echo DAEMON_OK\r".to_vec()))
        .await
        .unwrap();

    tokio::time::timeout(Duration::from_secs(15), async {
        loop {
            let frame = cout_rx.recv().await.expect("client output");
            if contains(&frame, b"DAEMON_OK") {
                return;
            }
        }
    })
    .await
    .expect("detached daemon should still serve the session");
}
