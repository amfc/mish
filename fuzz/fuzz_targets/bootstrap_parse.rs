//! Fuzz the session-bootstrap parsers — the code that runs *before* the QUIC
//! session exists and that consumes bytes from the (SSH-authenticated, but
//! possibly buggy or hostile) server's stdout and from user/script config:
//!
//! - the `MISH CONNECT` line parser + hex codec carrying the certs/keys,
//! - the `--ssh` shell-word splitter,
//! - the bounded line scanner ([`scan_connect`]), which must keep its buffer
//!   within the cap no matter how the bytes are chunked,
//! - the shell-quote ↔ shell-split round-trip (no injection / mangling).
//!
//! None may panic on arbitrary bytes, and the scanner must stay memory-bounded.
//!
//! Run with: `cargo +nightly fuzz run bootstrap_parse`.
#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    mish::bootstrap::fuzz_parse(data);
});
