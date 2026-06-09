//! Wiring test for the `--perf-log` keystroke-latency recorder: drive a headless
//! client/server session over the in-memory transport with the global recorder
//! installed, type a few keystrokes, and assert the JSON-lines log is produced
//! with one sane record per keystroke. This exercises the `run_client` hooks
//! (`perf::on_keystroke` / `on_ack` / `finish`) end-to-end without a real
//! network — the actual latency *values* need a real RTT (see `perf/`), but the
//! plumbing is verified here.
//!
//! The perf recorder is a process-global installed once; this is therefore the
//! file's *only* test (a second `perf::init` in the same binary is ignored).

use std::sync::Arc;
use std::time::Duration;

use mish::client::{run_client, ClientInput};
use mish::server::{run_server, PtyControl};
use mish_ssp::clock::{Clock, SystemClock};
use mish_ssp::memory;
use tokio::sync::mpsc;

/// Extract the raw value of a `"key":<value>` field from one JSON record line
/// (value runs until the next `,` or `}`). Good enough for our fixed, string-free
/// record shape — avoids pulling in a JSON parser dependency.
fn field<'a>(line: &'a str, key: &str) -> &'a str {
    let pat = format!("\"{key}\":");
    let start = line.find(&pat).expect("field present") + pat.len();
    let rest = &line[start..];
    let end = rest.find([',', '}']).expect("field terminated");
    &rest[..end]
}

#[tokio::test]
async fn perf_log_records_keystroke_latency() {
    // A unique temp path for this process so concurrent test binaries don't clash.
    let path = std::env::temp_dir().join(format!("mish-perf-{}.jsonl", std::process::id()));
    let _ = std::fs::remove_file(&path);
    mish::perf::init(&path).expect("install perf recorder");
    assert!(
        mish::perf::enabled(),
        "recorder should be active after init"
    );

    let (ta, tb) = memory::pair();
    let clock: Arc<dyn Clock> = Arc::new(SystemClock::new());

    // Server with a fake PTY.
    let (pty_out_tx, pty_out_rx) = mpsc::channel::<Vec<u8>>(64);
    let (pty_in_tx, _pty_in_rx) = mpsc::unbounded_channel::<PtyControl>();
    tokio::spawn(run_server(
        Arc::new(ta),
        mish_terminal::emulator::Emulator::shared(80, 24),
        clock.clone(),
        None,
        pty_out_rx,
        pty_in_tx,
    ));

    // Client with a fake TTY, prediction ALWAYS so every keystroke is echoed
    // locally (predicted = true, response ≈ 0).
    let (cin_tx, cin_rx) = mpsc::channel::<ClientInput>(64);
    let (cout_tx, mut cout_rx) = mpsc::unbounded_channel::<Vec<u8>>();
    let client = tokio::spawn(run_client(
        Arc::new(tb),
        80,
        24,
        clock.clone(),
        mish_terminal::predict::PredictMode::Always,
        None,
        None, // session name (display-only)
        cin_rx,
        cout_tx,
    ));

    // Bring the session live: the child writes, the client renders it.
    pty_out_tx.send(b"ready".to_vec()).await.unwrap();
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let frame = cout_rx.recv().await.expect("client output");
            if frame.windows(5).any(|w| w == b"ready") {
                return;
            }
        }
    })
    .await
    .expect("client renders initial output");

    // Type three keystrokes as separate events (→ three records).
    for ch in [b"a".to_vec(), b"b".to_vec(), b"c".to_vec()] {
        cin_tx.send(ClientInput::Keys(ch)).await.unwrap();
    }

    // Poll the log until the server has confirmed all three (the `on_ack` path
    // writes + flushes each record). This proves the round-trip wiring, not just
    // the local-echo half.
    let lines = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if let Ok(s) = std::fs::read_to_string(&path) {
                let n = s.lines().filter(|l| !l.is_empty()).count();
                if n >= 3 {
                    return s;
                }
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("three keystroke records should be written");

    // End the session cleanly so `run_client` runs `perf::finish()`.
    drop(cin_tx);
    let _ = tokio::time::timeout(Duration::from_secs(5), client).await;

    let records: Vec<&str> = lines.lines().filter(|l| !l.is_empty()).collect();
    assert!(
        records.len() >= 3,
        "one record per keystroke, got {}",
        records.len()
    );
    for line in &records {
        // Each was locally echoed under ALWAYS mode → predicted, response ≈ 0.
        assert_eq!(field(line, "predicted"), "true", "line: {line}");
        let press: u64 = field(line, "press_ms").parse().unwrap();
        let display: u64 = field(line, "display_ms").parse().unwrap();
        assert_eq!(
            display, press,
            "predicted key displays at press time: {line}"
        );
        // Confirmed keys carry a numeric confirm_ms >= press_ms.
        let confirm = field(line, "confirm_ms");
        if confirm != "null" {
            assert!(
                confirm.parse::<u64>().unwrap() >= press,
                "confirm after press: {line}"
            );
        }
        // nbytes is the single typed byte.
        assert_eq!(field(line, "nbytes"), "1", "line: {line}");
    }

    let _ = std::fs::remove_file(&path);
}
