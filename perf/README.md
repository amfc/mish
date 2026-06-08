# Keystroke-latency measurement (`--perf-log`)

Reproduce the Mosh paper's keystroke-response-time graph for **mish**: the
CDF of *keypress → on-screen display* latency. The point is to measure it from a
**real interactive session** (the client instruments itself) and show that
predictive local echo puts the bulk of keystrokes at ~0 ms — the same result the
paper reports for Mosh (median < 5 ms vs 503 ms for SSH over a 3G link;
[Winstein & Balakrishnan, USENIX ATC 2012](https://mosh.org/mosh-paper.pdf)).

## 1. Record a session

Run a normal session with `--perf-log`, pointed at a host with real network
latency (a `--local` session has ~no RTT, so its graph is uninteresting):

```sh
mish-client --perf-log ~/mish-perf.jsonl --predict adaptive user@remote-host
```

Type as you normally would for a few minutes — shell editing, a `vim`/`less`
session, some `ls`/`git` — then detach (the escape prefix `Ctrl-^` then `.`). The
log is flushed on exit.

Each line is one keystroke (a JSON object, all monotonic ms from one client
clock):

| field        | meaning                                                              |
|--------------|---------------------------------------------------------------------|
| `idx`        | client input index (`UserStream::total()`)                          |
| `press_ms`   | the keystroke was received                                          |
| `display_ms` | it first appeared on screen (`== press_ms` when predicted locally)  |
| `confirm_ms` | the server confirmed it (true round-trip), or `null` if unconfirmed |
| `predicted`  | whether predictive local echo displayed it                          |
| `nbytes`     | input bytes in the batch (≈1 for normal typing)                     |

`response_ms = display_ms − press_ms` is the paper's "response time".

## 2. Set up matplotlib

```sh
python3 -m venv perf/.venv
perf/.venv/bin/pip install matplotlib
```

**NixOS note.** pip's numpy/matplotlib wheels need `libstdc++.so.6` at runtime,
which isn't on the default loader path. Point the loader at a `gcc-lib` from the
store before running the script:

```sh
export LD_LIBRARY_PATH="$(dirname "$(find /nix/store -maxdepth 3 -name libstdc++.so.6 -path '*gcc*-lib*' | head -1)")"
```

(Alternatively, if you have a flake-enabled nix, skip the venv entirely and run
the script under `nix shell nixpkgs#python3Packages.matplotlib`.)

## 3. Graph it

```sh
perf/.venv/bin/python perf/perf-latency-graph.py ~/mish-perf.jsonl \
    -o perf/latency-cdf.png
```

This prints the p50/p90/p99 response times and writes `latency-cdf.png`
(+ `.pdf`): the mish response-time CDF, with the paper's Mosh/SSH curves
overlaid as a labeled reference. Useful flags:

- `--show-confirm` — also draw the keypress→server-confirm (network round-trip)
  CDF, i.e. the floor predictive echo hides.
- `--linear` — linear x-axis to match the paper's Fig. 2 (default is log, which
  shows the near-zero cluster better).
- `--no-reference` — drop the paper overlay.
- multiple logs — pass several `*.jsonl` to compare sessions on one plot.

## Notes

- The Mosh/SSH overlay in `mosh-paper-reference.json` is **approximate** — it
  reproduces the paper's curve shape pinned to its quoted headline numbers, not a
  point-for-point digitization. Replace the points there for an exact overlay.
- A keystroke shown by prediction is recorded as response ≈ 0 even if a rare
  misprediction later corrects it (predictions are overwhelmingly right; this
  matches how the paper counts the predicted display).
- The recorder only instruments real typed keys (`ClientInput::Keys`), not
  mouse-wheel-as-arrows or scrollback keys.
