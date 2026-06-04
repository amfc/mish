//! Property + simulation tests for the terminal `SyncState`s, reusing the
//! deterministic SSP simulator. Proves the row-granular screen diff and the
//! append-only user stream satisfy the `SyncState` contract and converge over a
//! lossy link.

use mish_ssp::sim::{NetworkSim, SimConfig};
use mish_ssp::state::SyncState;
use mish_terminal::emulator::Emulator;
use mish_terminal::screen::{Cell, Color, Screen};
use mish_terminal::user::{UserEvent, UserStream};
use proptest::prelude::*;

// ---------- Screen proptest strategies ----------

fn arb_color() -> impl Strategy<Value = Color> {
    prop_oneof![
        (0u16..300).prop_map(Color::Named),
        any::<u8>().prop_map(Color::Indexed),
        (any::<u8>(), any::<u8>(), any::<u8>()).prop_map(|(r, g, b)| Color::Rgb(r, g, b)),
    ]
}

fn arb_cell() -> impl Strategy<Value = Cell> {
    (prop::char::range(' ', '~'), arb_color(), arb_color(), 0u16..0x200)
        .prop_map(|(c, fg, bg, flags)| Cell { c, fg, bg, flags })
}

fn arb_screen() -> impl Strategy<Value = Screen> {
    (1u16..12, 1u16..6).prop_flat_map(|(cols, rows)| {
        let n = cols as usize * rows as usize;
        (
            Just(cols),
            Just(rows),
            prop::collection::vec(arb_cell(), n),
            0u16..rows,
            0u16..cols,
            any::<bool>(),
            "[a-z ]{0,8}",
            any::<u64>(),
        )
            .prop_map(|(cols, rows, cells, cr, cc, cv, title, echo_ack)| Screen {
                cols,
                rows,
                cells,
                cursor_row: cr,
                cursor_col: cc,
                cursor_visible: cv,
                title,
                echo_ack,
            })
    })
}

proptest! {
    #[test]
    fn screen_diff_roundtrip(a in arb_screen(), b in arb_screen()) {
        let diff = a.diff_from(&b);
        let mut x = b.clone();
        x.apply_diff(&diff);
        prop_assert!(x.equals(&a), "round-trip failed");
        // idempotent
        x.apply_diff(&diff);
        prop_assert!(x.equals(&a), "not idempotent");
    }

    #[test]
    fn screen_diff_from_initial(a in arb_screen()) {
        let mut x = Screen::new_initial();
        x.apply_diff(&a.diff_from(&x));
        prop_assert!(x.equals(&a));
    }

    #[test]
    fn screen_equal_states_empty_diff(a in arb_screen()) {
        prop_assert!(a.diff_from(&a).is_empty());
    }
}

// ---------- UserStream proptest ----------

fn arb_event() -> impl Strategy<Value = UserEvent> {
    prop_oneof![
        prop::collection::vec(any::<u8>(), 0..8).prop_map(UserEvent::Keystroke),
        (1u16..200, 1u16..60).prop_map(|(cols, rows)| UserEvent::Resize { cols, rows }),
    ]
}

proptest! {
    #[test]
    fn userstream_diff_roundtrip(events in prop::collection::vec(arb_event(), 0..20), k in 0usize..20) {
        let mut full = UserStream::new();
        for e in &events { full.push(e.clone()); }
        let k = k.min(events.len());
        let mut prev = UserStream::new();
        for e in events.iter().take(k) { prev.push(e.clone()); }

        let diff = full.diff_from(&prev);
        let mut x = prev.clone();
        x.apply_diff(&diff);
        prop_assert!(x.equals(&full), "round-trip failed");
        x.apply_diff(&diff);
        prop_assert!(x.equals(&full), "not idempotent");
    }
}

#[test]
fn userstream_subtract_preserves_logical_content() {
    let mut full = UserStream::new();
    for i in 0..5u8 {
        full.push_keystroke(vec![i]);
    }
    let mut prev = UserStream::new();
    prev.push_keystroke(vec![0]);
    prev.push_keystroke(vec![1]);
    assert_eq!(prev.total(), 2);

    full.subtract(&prev);
    // total() is unchanged; only the front is trimmed.
    assert_eq!(full.total(), 5);
    let tail: Vec<_> = full.events_since(2).cloned().collect();
    assert_eq!(
        tail,
        vec![
            UserEvent::Keystroke(vec![2]),
            UserEvent::Keystroke(vec![3]),
            UserEvent::Keystroke(vec![4]),
        ]
    );

    // Diffing after a trim still reconstructs the receiver correctly.
    let diff = full.diff_from(&prev);
    let mut x = prev.clone();
    x.apply_diff(&diff);
    assert_eq!(x.total(), 5);
}

// ---------- End-to-end client/server convergence over the simulator ----------

// Node A = client: sends UserStream, receives Screen.
// Node B = server: sends Screen, receives UserStream.
type Sim = NetworkSim<UserStream, Screen>;

fn make_screen() -> Screen {
    let mut emu = Emulator::new(20, 4);
    emu.feed(b"\x1b[1mhello\x1b[0m\r\nworld");
    emu.snapshot()
}

fn make_input() -> UserStream {
    let mut us = UserStream::new();
    us.push_keystroke(b"ls -la\r".to_vec());
    us.push_resize(120, 40);
    us
}

#[test]
fn client_server_states_converge_lossless() {
    let mut sim = Sim::new(SimConfig::default());
    let screen = make_screen();
    let input = make_input();
    sim.set_a_local(input.clone());
    sim.set_b_local(screen.clone());

    let want_input: Vec<UserEvent> = input.events_since(0).cloned().collect();
    let ok = sim.run_until(
        |s| {
            *s.a_view_of_b() == screen
                && s.b_view_of_a().events_since(0).cloned().collect::<Vec<_>>() == want_input
        },
        300_000,
    );
    assert!(ok, "states should converge (t={})", sim.now());
    let lines = sim.a_view_of_b().to_lines();
    assert_eq!(&lines[0..2], &["hello".to_string(), "world".to_string()]);
}

#[test]
fn client_server_states_converge_lossy() {
    let cfg = SimConfig {
        loss: 0.4,
        min_delay: 1,
        max_delay: 50,
        seed: 0x5EED_1234,
        ..Default::default()
    };
    let mut sim = Sim::new(cfg);
    let screen = make_screen();
    let input = make_input();
    sim.set_a_local(input.clone());
    sim.set_b_local(screen.clone());

    let want_input: Vec<UserEvent> = input.events_since(0).cloned().collect();
    let ok = sim.run_until(
        |s| {
            *s.a_view_of_b() == screen
                && s.b_view_of_a().events_since(0).cloned().collect::<Vec<_>>() == want_input
        },
        300_000,
    );
    assert!(
        ok,
        "should converge despite 40% loss (t={}, dropped={})",
        sim.now(),
        sim.dropped
    );
    assert!(sim.dropped > 0);
}
