//! Reproduction for "Ctrl-C can't interrupt a flooding program (`yes`)".
//!
//! Runs a real `/bin/sh` on a PTY over real QUIC, starts `yes` (an unbounded
//! output flood), then sends Ctrl-C (0x03) as a keystroke. If interrupt works,
//! SIGINT kills `yes`, the shell returns to a prompt, and a subsequent
//! `echo SENTINEL` runs and renders on the client. If Ctrl-C is swallowed, `yes`
//! stays in the foreground, the echo never executes, and the sentinel never
//! appears.

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use mish::client::{run_client, ClientInput};
use mish::pty::PtyProcess;
use mish::server::run_server;
use mish_quic::transport;
use mish_ssp::clock::{Clock, SystemClock};
use tokio::sync::mpsc;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn ctrl_c_interrupts_yes_flood() {
    let (server_ep, addr, _cert) = transport::loopback_server().unwrap();
    let clock: Arc<dyn Clock> = Arc::new(SystemClock::new());

    let sclock = clock.clone();
    tokio::spawn(async move {
        let t = transport::accept(&server_ep).await.expect("accept");
        let pty = PtyProcess::spawn("/bin/sh", 80, 24).expect("spawn shell");
        let emu = mish_terminal::emulator::Emulator::shared(80, 24);
        run_server(Arc::new(t), emu, sclock, None, pty.output, pty.control).await;
    });

    let client_ep = transport::loopback_client().unwrap();
    let t = transport::connect(&client_ep, addr, "localhost")
        .await
        .expect("connect");
    let (cin_tx, cin_rx) = mpsc::channel::<ClientInput>(64);
    let (cout_tx, mut cout_rx) = mpsc::unbounded_channel::<Vec<u8>>();
    tokio::spawn(run_client(
        Arc::new(t),
        80,
        24,
        clock.clone(),
        mish_terminal::predict::PredictMode::Never,
        None,
        None, // session name (display-only)
        String::new(),
        cin_rx,
        cout_tx,
    ));

    // Accumulate everything the client renders so we can search for the sentinel.
    let seen = Arc::new(Mutex::new(Vec::<u8>::new()));
    let seen2 = seen.clone();
    tokio::spawn(async move {
        while let Some(frame) = cout_rx.recv().await {
            seen2.lock().unwrap().extend_from_slice(&frame);
        }
    });

    // Start the flood.
    tokio::time::sleep(Duration::from_millis(300)).await;
    cin_tx
        .send(ClientInput::Keys(b"yes\r".to_vec()))
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(1000)).await;

    // Send Ctrl-C: SIGINT should kill `yes` and return to the shell prompt.
    cin_tx.send(ClientInput::Keys(vec![0x03])).await.unwrap();

    // Wait for the flood to actually stop before typing the next command. A fixed
    // sleep is too fragile on a slow/loaded CI runner: if SIGINT hasn't killed
    // `yes` yet, the echo keystrokes are typed into the still-running flood and
    // lost. Instead poll until the render output goes quiet (no new bytes for
    // ~250ms). If Ctrl-C failed to interrupt, `yes` keeps flooding, this never
    // settles, and the sentinel check below still fails as intended.
    {
        let mut last = 0usize;
        let mut quiet = 0;
        for _ in 0..120 {
            tokio::time::sleep(Duration::from_millis(50)).await;
            let len = seen.lock().unwrap().len();
            if len == last {
                quiet += 1;
                if quiet >= 5 {
                    break;
                }
            } else {
                quiet = 0;
                last = len;
            }
        }
    }

    // Now run a command only the *shell* (not `yes`) would execute, and look for
    // its output in the rendered diff stream. The client emits screen *diffs*, so
    // a contiguous "SENTINEL_DONE" only forms when the bytes are written to a
    // quiet screen — if residual flood is still draining over QUIC, the write gets
    // fragmented by interleaved cursor-move escapes and never matches as one run.
    //
    // The quiet-detection above can't fully guarantee that on a slow/loaded CI
    // runner: a transient scheduling lull reads as "quiet" while `yes` is merely
    // starved, and a large in-flight backlog can outlast its budget. So re-issue
    // the command periodically — if the first attempt races with draining output,
    // a later one lands on a settled screen and renders cleanly. If Ctrl-C truly
    // failed, `yes` keeps flooding, every echo stays scrambled, and this still
    // times out and fails as intended.
    let deadline = Instant::now() + Duration::from_secs(30);
    let mut ok = false;
    'wait: while Instant::now() < deadline {
        cin_tx
            .send(ClientInput::Keys(b"echo SENTINEL_DONE\r".to_vec()))
            .await
            .unwrap();
        for _ in 0..20 {
            tokio::time::sleep(Duration::from_millis(100)).await;
            if seen
                .lock()
                .unwrap()
                .windows(13)
                .any(|w| w == b"SENTINEL_DONE")
            {
                ok = true;
                break 'wait;
            }
        }
    }

    assert!(
        ok,
        "Ctrl-C did not interrupt `yes`: the shell never ran the follow-up echo"
    );

    drop(cin_tx);
}
