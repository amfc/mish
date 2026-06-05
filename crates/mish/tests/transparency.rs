//! Transparency invariant: the client's reconstructed `Screen` must equal the
//! server's emulator `Screen`. This is the "is the whole thing correct" test —
//! run a real program through the full server<->client SSP stack and compare the
//! two Screens directly (no tmux), plus a deterministic property test that any
//! fuzzed keystroke/resize stream arrives intact at the server.

use std::sync::Arc;
use std::time::Duration;

use mish::pty::PtyProcess;
use mish::server::PtyControl;
use mish_ssp::clock::{Clock, SystemClock};
use mish_ssp::core::SspConfig;
use mish_ssp::session::{Driver, Session};
use mish_ssp::sim::{NetworkSim, SimConfig};
use mish_terminal::emulator::Emulator;
use mish_terminal::screen::Screen;
use mish_terminal::user::{UserEvent, UserStream};
use tokio::sync::{mpsc, watch};

fn screen_eq(a: &Screen, b: &Screen) -> bool {
    a.cols == b.cols
        && a.rows == b.rows
        && a.cells == b.cells
        && a.cursor_row == b.cursor_row
        && a.cursor_col == b.cursor_col
        && a.cursor_visible == b.cursor_visible
        && a.title == b.title
        && a.bracketed_paste == b.bracketed_paste
        && a.mouse_mode == b.mouse_mode
        && a.cursor_shape == b.cursor_shape
        && a.cursor_blink == b.cursor_blink
}

fn cfg() -> SspConfig {
    SspConfig {
        rto: 60,
        ack_interval: 200,
        ack_delay: 10,
        send_interval_min: 5,
        ..Default::default()
    }
}

/// Full-stack transparency over a real PTY: the client types a script, the
/// server runs it, and the client's reconstructed Screen must equal the
/// server's emulator Screen once the dust settles.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn full_stack_client_screen_matches_server() {
    let (ta, tb) = mish_ssp::memory::pair();
    let clock: Arc<dyn Clock> = Arc::new(SystemClock::new());

    // Server: real PTY + emulator + SSP, publishing its current screen.
    let pty = PtyProcess::spawn("/bin/sh", 80, 24).expect("pty");
    let (screen_tx, screen_rx) = watch::channel(Screen::blank(80, 24));
    let sclock = clock.clone();
    tokio::spawn(server_loop(
        Arc::new(ta),
        sclock,
        pty.output,
        pty.control,
        screen_tx,
    ));

    // Client: SSP only; we read its reconstructed Screen directly.
    let (cdriver, chandle) = Driver::<_, UserStream, Screen>::with(Arc::new(tb), clock, cfg());
    cdriver.spawn();

    // The client "types" a script that produces varied terminal output.
    let mut stream = UserStream::new();
    stream.push_resize(80, 24);
    for line in [
        "printf '\\033[1;31mRED\\033[0m \\033[44mblue-bg\\033[0m\\n'\r",
        "printf '\\033[2J\\033[Hcleared\\n'\r",
        "seq 1 40 2>/dev/null | tail -20\r",
        "echo TRANSPARENCY_OK\r",
    ] {
        stream.push_keystroke(line.as_bytes().to_vec());
    }
    chandle.set_local(stream);

    // Wait until the client's screen shows the marker AND equals the server's.
    let ok = tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            let server_screen = screen_rx.borrow().clone();
            let client_screen = chandle.remote();
            if client_screen.to_text().contains("TRANSPARENCY_OK")
                && screen_eq(&client_screen, &server_screen)
            {
                return true;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .unwrap_or(false);

    assert!(
        ok,
        "client screen should exactly match the server's emulator screen"
    );
}

/// The server side of the session, exposing its current emulator screen.
async fn server_loop(
    transport: Arc<mish_ssp::memory::MemoryTransport>,
    clock: Arc<dyn Clock>,
    mut pty_output: mpsc::Receiver<Vec<u8>>,
    pty_input: mpsc::UnboundedSender<PtyControl>,
    screen_tx: watch::Sender<Screen>,
) {
    let (driver, handle) = Driver::<_, Screen, UserStream>::with(transport, clock, cfg());
    driver.spawn();
    let mut emu = Emulator::new(80, 24);
    let mut processed = 0u64;
    let publish = |emu: &Emulator, processed: u64| {
        let mut s = emu.snapshot();
        s.echo_ack = processed;
        s
    };
    handle.set_local(publish(&emu, processed));
    let _ = screen_tx.send(publish(&emu, processed));
    let mut remote = handle.subscribe_remote();
    loop {
        tokio::select! {
            out = pty_output.recv() => match out {
                Some(b) => {
                    emu.feed(&b);
                    let s = publish(&emu, processed);
                    handle.set_local(s.clone());
                    let _ = screen_tx.send(s);
                }
                None => break,
            },
            ch = remote.changed() => {
                if ch.is_err() { break; }
                let stream = remote.borrow_and_update().clone();
                for ev in stream.events_since(processed) {
                    match ev {
                        UserEvent::Keystroke(b) => { let _ = pty_input.send(PtyControl::Input(b.clone())); }
                        UserEvent::Resize { cols, rows } => {
                            let _ = pty_input.send(PtyControl::Resize { cols: *cols, rows: *rows });
                            emu.resize(*cols, *rows);
                        }
                    }
                }
                processed = stream.total();
                let s = publish(&emu, processed);
                handle.set_local(s.clone());
                let _ = screen_tx.send(s);
            }
        }
    }
}

// ---- Deterministic transparency for the input direction ----

fn arb_event() -> impl proptest::strategy::Strategy<Value = UserEvent> {
    use proptest::prelude::*;
    prop_oneof![
        prop::collection::vec(any::<u8>(), 0..8).prop_map(UserEvent::Keystroke),
        (1u16..200, 1u16..60).prop_map(|(cols, rows)| UserEvent::Resize { cols, rows }),
    ]
}

proptest::proptest! {
    #![proptest_config(proptest::test_runner::Config::with_cases(200))]

    /// Any fuzzed keystroke/resize stream the client sends arrives intact at the
    /// server (client->server transparency), over a lossy simulated link.
    #[test]
    fn fuzzed_input_arrives_intact(
        events in proptest::collection::vec(arb_event(), 0..24),
        loss in 0.0f64..0.4,
        seed in proptest::prelude::any::<u64>(),
    ) {
        let mut sim = NetworkSim::<UserStream, Screen>::new(SimConfig {
            loss, min_delay: 1, max_delay: 30, seed: seed | 1, ..Default::default()
        });
        let mut input = UserStream::new();
        for e in &events { input.push(e.clone()); }
        sim.set_a_local(input.clone());

        let want: Vec<UserEvent> = input.events_since(0).cloned().collect();
        let ok = sim.run_until(
            move |s| s.b_view_of_a().events_since(0).cloned().collect::<Vec<_>>() == want,
            600_000,
        );
        proptest::prop_assert!(ok, "fuzzed input did not arrive intact (t={})", sim.now());
    }
}
