//! Prediction-engine fuzzing: arbitrary keystroke bytes interleaved with
//! arbitrary server screens (any dims / cursor / echo_ack) must never panic,
//! must keep the predicted screen consistent with the server's geometry, and
//! must never get stuck — once the server confirms everything, the overlay
//! clears.

use mish_terminal::predict::{PredictMode, PredictionEngine};
use mish_terminal::screen::Screen;
use proptest::prelude::*;

#[derive(Clone, Debug)]
enum POp {
    Type(Vec<u8>),
    Server {
        cols: u16,
        rows: u16,
        cur_r: u16,
        cur_c: u16,
        echo_ack: u64,
    },
}

fn arb_pop() -> impl Strategy<Value = POp> {
    prop_oneof![
        proptest::collection::vec(any::<u8>(), 0..16).prop_map(POp::Type),
        (1u16..40, 1u16..12, any::<u16>(), any::<u16>(), any::<u64>()).prop_map(
            |(cols, rows, cur_r, cur_c, echo_ack)| POp::Server {
                cols,
                rows,
                cur_r,
                cur_c,
                echo_ack,
            }
        ),
    ]
}

fn mode(n: u8) -> PredictMode {
    match n % 3 {
        0 => PredictMode::Never,
        1 => PredictMode::Always,
        _ => PredictMode::Adaptive,
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(2000))]

    #[test]
    fn prediction_engine_robust(ops in proptest::collection::vec(arb_pop(), 0..60), m in any::<u8>()) {
        let mut eng = PredictionEngine::new(mode(m));
        eng.set_srtt(100.0); // above the adaptive trigger, so Adaptive shows
        let mut server = Screen::blank(24, 8);
        let mut idx = 0u64;
        // A monotonic clock that advances a bit each op, so the time-based glitch
        // aging is exercised (and asserted no-panic / bounded) too.
        let mut now = 0u64;

        for op in ops {
            now += 37;
            match op {
                POp::Type(bytes) => {
                    idx += 1;
                    eng.new_user_bytes(&bytes, &server, idx, now);
                }
                POp::Server { cols, rows, cur_r, cur_c, echo_ack } => {
                    let mut s = Screen::blank(cols, rows);
                    s.cursor_row = cur_r % rows;
                    s.cursor_col = cur_c % cols;
                    s.echo_ack = echo_ack;
                    eng.new_server_screen(&s, now);
                    server = s;
                }
            }
            eng.advance(now);
            // The displayed screen always matches the server's geometry.
            let shown = eng.predicted_screen(&server);
            prop_assert_eq!((shown.cols, shown.rows), (server.cols, server.rows));
            prop_assert_eq!(shown.cells.len(), server.cols as usize * server.rows as usize);
        }

        // No stuck state: confirming all input clears the overlay.
        let mut confirm = server.clone();
        confirm.echo_ack = u64::MAX;
        eng.new_server_screen(&confirm, now);
        prop_assert_eq!(eng.active_predictions(), 0, "overlay must clear once fully confirmed");
    }
}
