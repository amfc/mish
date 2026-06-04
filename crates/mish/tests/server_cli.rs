//! mish-server CLI: `-p` port selection and the signal (connect) timeout.

use std::time::Duration;

use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::Command;

async fn read_connect_port(child: &mut tokio::process::Child) -> u16 {
    let stdout = child.stdout.take().unwrap();
    let mut lines = BufReader::new(stdout).lines();
    while let Some(line) = lines.next_line().await.unwrap() {
        let mut it = line.split_whitespace();
        if it.next() == Some("MOSH") && it.next() == Some("CONNECT") {
            return it.next().unwrap().parse().unwrap();
        }
    }
    panic!("no MISH CONNECT line");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn binds_port_in_requested_range() {
    let server = env!("CARGO_BIN_EXE_mish-server");
    let mut child = Command::new(server)
        .args(["-p", "51000:51010"])
        .env("MOSH_SERVER_SIGNAL_TMOUT", "1") // exit quickly (no client)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .unwrap();

    let port = read_connect_port(&mut child).await;
    assert!(
        (51000..=51010).contains(&port),
        "bound port {port} in range"
    );
    let _ = child.kill().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn exits_on_signal_timeout_without_client() {
    let server = env!("CARGO_BIN_EXE_mish-server");
    let mut child = Command::new(server)
        .args(["-p", "0"])
        .env("MOSH_SERVER_SIGNAL_TMOUT", "2") // no client ⇒ give up after 2s
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .unwrap();

    let _ = read_connect_port(&mut child).await;
    // With no client connecting, the server must exit on its own.
    let status = tokio::time::timeout(Duration::from_secs(6), child.wait())
        .await
        .expect("server should exit on the signal timeout")
        .expect("wait");
    assert!(status.success());
}
