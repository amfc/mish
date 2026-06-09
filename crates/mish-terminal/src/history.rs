//! Scrollback history protocol: the request/response carried over a reliable
//! side-channel ([`mish_ssp::framing`]) so a client can scroll up into the
//! server-held terminal history.
//!
//! The live screen still rides unreliable datagrams as usual. When the user
//! scrolls up, the client sends a [`HistoryRequest`] for a window of rows; the
//! server answers from its emulator's scrollback with a [`HistoryResponse`].
//! This keeps history off the per-frame diff (it's fetched on demand, reliably)
//! — the design in `NEXT_FEATURES.md` #1.

use serde::{Deserialize, Serialize};

use crate::emulator::Emulator;
use crate::screen::Cell;

/// The most rows a single request may ask for, bounding the response size a
/// (authenticated) client can request. A client only ever needs its screen
/// height; this is a generous ceiling.
pub const MAX_HISTORY_ROWS: u16 = 512;

/// A request for a window of scrollback rows.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct HistoryRequest {
    /// Lines above the top visible row to start the window at (0 = the live top
    /// row; larger reaches further back into history).
    pub top_above: u32,
    /// Number of rows requested — normally the client's screen height.
    pub count: u16,
}

/// The server's answer: the requested rows plus how much history exists.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct HistoryResponse {
    /// Total scrollback lines available above the screen, so the client can
    /// clamp how far up it scrolls.
    pub history_size: u32,
    /// Screen width these rows were captured at (so the client renders them at
    /// the right geometry even if a resize raced the fetch).
    pub cols: u16,
    /// The cell rows of the requested window, top to bottom. May be shorter than
    /// `count` if the window ran past the ends of the retained range.
    pub rows: Vec<Vec<Cell>>,
}

impl HistoryRequest {
    pub fn encode(&self) -> Vec<u8> {
        bincode::serialize(self).expect("HistoryRequest serialization is infallible")
    }
    pub fn decode(bytes: &[u8]) -> Option<Self> {
        bincode::deserialize(bytes).ok()
    }
}

impl HistoryResponse {
    pub fn encode(&self) -> Vec<u8> {
        bincode::serialize(self).expect("HistoryResponse serialization is infallible")
    }
    pub fn decode(bytes: &[u8]) -> Option<Self> {
        bincode::deserialize(bytes).ok()
    }
}

/// Build the response for `req` from `emu`'s current scrollback. Pure given the
/// emulator state; the count is clamped to [`MAX_HISTORY_ROWS`] and the start is
/// clamped to the available history, so a malformed/hostile request is bounded.
pub fn answer_history(emu: &Emulator, req: &HistoryRequest) -> HistoryResponse {
    let history_size = emu.history_size();
    let top_above = req.top_above.min(history_size);
    let count = req.count.min(MAX_HISTORY_ROWS);
    HistoryResponse {
        history_size,
        cols: emu.cols(),
        rows: emu.history_lines(top_above, count),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_response_round_trip_codec() {
        let req = HistoryRequest {
            top_above: 42,
            count: 24,
        };
        assert_eq!(HistoryRequest::decode(&req.encode()), Some(req));

        let resp = HistoryResponse {
            history_size: 100,
            cols: 80,
            rows: vec![vec![Cell::default(); 80]; 3],
        };
        assert_eq!(HistoryResponse::decode(&resp.encode()), Some(resp));
        // A truncated buffer (fewer than the fixed 6 bytes) fails to decode.
        // (bincode will accept *any* sufficiently long buffer for a fixed-layout
        // struct; safety against hostile requests comes from the framing size
        // cap and `answer_history`'s clamping, not from decode rejecting bytes.)
        assert!(HistoryRequest::decode(b"\x00\x01").is_none());
    }

    #[test]
    fn answers_from_scrollback() {
        // Produce more lines than fit on screen so some land in history.
        let mut emu = Emulator::new(20, 4);
        for i in 0..20 {
            emu.feed(format!("line{i}\r\n").as_bytes());
        }
        assert!(emu.history_size() >= 16, "lines scrolled into history");

        // Ask for a window starting 8 lines above the top, 4 rows tall.
        let resp = answer_history(
            &emu,
            &HistoryRequest {
                top_above: 8,
                count: 4,
            },
        );
        assert_eq!(resp.cols, 20);
        assert_eq!(resp.rows.len(), 4);
        // Each returned row should contain its "lineN" text somewhere.
        let text: Vec<String> = resp
            .rows
            .iter()
            .map(|r| {
                r.iter()
                    .map(|c| c.c)
                    .collect::<String>()
                    .trim_end()
                    .to_string()
            })
            .collect();
        assert!(
            text.iter().any(|l| l.starts_with("line")),
            "history rows should carry the scrolled-off text, got {text:?}"
        );
    }

    #[test]
    fn hostile_request_is_bounded() {
        let emu = Emulator::new(20, 4);
        // Absurd count + offset: clamped, never panics, bounded response.
        let resp = answer_history(
            &emu,
            &HistoryRequest {
                top_above: u32::MAX,
                count: u16::MAX,
            },
        );
        assert!(resp.rows.len() <= MAX_HISTORY_ROWS as usize);
    }
}
