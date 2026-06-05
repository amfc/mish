#!/usr/bin/env bash
# Run the tokio Driver's multi-threaded tests under ThreadSanitizer.
#
# TSan instruments memory accesses + synchronization and flags data races at
# runtime. We target mish-ssp's async tests: the Driver's shared-state channels
# (mpsc local queue, watch remote cell) plus the lossy link's relay tasks, driven
# from several worker threads by `concurrency.rs`. Needs nightly + rust-src
# (for the sanitizer-instrumented std via -Zbuild-std).
#
# The QUIC/PTY layer is intentionally excluded: it pulls C/asm crypto (ring) that
# TSan can't instrument and spawns external processes; it's covered by the e2e
# tests instead.
set -euo pipefail
exec env RUSTFLAGS="-Zsanitizer=thread" \
    cargo +nightly test -p mish-ssp \
    --test concurrency --test integration \
    -Zbuild-std --target x86_64-unknown-linux-gnu "$@"
