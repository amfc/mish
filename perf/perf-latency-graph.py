#!/usr/bin/env python3
"""Plot a keystroke-response-time CDF from one or more mish ``--perf-log`` files.

Reproduces the Mosh paper's keystroke-response-time graph (Winstein &
Balakrishnan, USENIX ATC 2012, Fig. 2) for *our* client: the empirical CDF of
``response_ms = display_ms - press_ms`` — the time from a keypress to the
character appearing on screen. With predictive local echo on, most keystrokes
display at ~0 ms (the curve hugs the left edge); unpredicted keys fall back to
the network round-trip.

The paper's Mosh/SSH curves are overlaid as a labeled, *approximate* reference
(see ``mosh-paper-reference.json``) so our curve can be read in the same frame.

Usage:
    python perf-latency-graph.py LOG.jsonl [MORE.jsonl ...] -o out.png

See ``perf/README.md`` for recording a log and setting up matplotlib.
"""

import argparse
import json
import os
import sys

# Floor for the log x-axis: a predicted keystroke has response_ms == 0, which has
# no place on a log scale, so it's drawn at this sub-millisecond position (and
# noted on the axis). Use --linear to plot true zeros instead.
LOG_ZERO_FLOOR_MS = 0.1


def load_responses(path):
    """Return (response_ms list, confirm_latency_ms list) from a perf JSONL log."""
    responses, confirms = [], []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue  # tolerate a partial trailing line
            responses.append(rec["display_ms"] - rec["press_ms"])
            if rec.get("confirm_ms") is not None:
                confirms.append(rec["confirm_ms"] - rec["press_ms"])
    return responses, confirms


def cdf_xy(samples, log_floor=None):
    """Sorted samples and their cumulative fractions (0..1], for a step CDF."""
    xs = sorted(samples)
    if log_floor is not None:
        xs = [max(x, log_floor) for x in xs]
    n = len(xs)
    ys = [(i + 1) / n for i in range(n)]
    return xs, ys


def pct(sorted_samples, p):
    """The p-th percentile (p in 0..100) of an already-sorted list."""
    if not sorted_samples:
        return float("nan")
    k = min(int(len(sorted_samples) * p / 100.0), len(sorted_samples) - 1)
    return sorted_samples[k]


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("logs", nargs="+", help="mish --perf-log JSONL file(s)")
    ap.add_argument("-o", "--output", default="latency-cdf.png",
                    help="output image path (.png/.pdf/.svg; default latency-cdf.png)")
    ap.add_argument("--reference",
                    default=os.path.join(os.path.dirname(__file__), "mosh-paper-reference.json"),
                    help="paper reference-curve JSON (default: alongside this script)")
    ap.add_argument("--no-reference", action="store_true", help="omit the paper overlay")
    ap.add_argument("--show-confirm", action="store_true",
                    help="also draw the keypress→server-confirm (network round-trip) CDF")
    ap.add_argument("--linear", action="store_true",
                    help="linear x-axis (matches the paper's Fig. 2) instead of log")
    ap.add_argument("--title", default="mish keystroke response time", help="plot title")
    args = ap.parse_args()

    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except ImportError:
        sys.exit("matplotlib is required — see perf/README.md (venv / nix-shell setup).")

    log_x = not args.linear
    floor = LOG_ZERO_FLOOR_MS if log_x else None

    fig, ax = plt.subplots(figsize=(8, 5))

    summary_lines = []
    for path in args.logs:
        responses, confirms = load_responses(path)
        if not responses:
            print(f"warning: no records in {path}", file=sys.stderr)
            continue
        label = os.path.splitext(os.path.basename(path))[0]
        xs, ys = cdf_xy(responses, floor)
        ax.step(xs, ys, where="post", linewidth=2, label=f"{label} (response)")

        s = sorted(responses)
        summary_lines.append(
            f"{label}: n={len(s)}  p50={pct(s,50):.1f}  p90={pct(s,90):.1f}  "
            f"p99={pct(s,99):.1f} ms")
        print(summary_lines[-1])

        if args.show_confirm and confirms:
            cx, cy = cdf_xy(confirms, floor)
            ax.step(cx, cy, where="post", linewidth=1, linestyle=":",
                    alpha=0.7, label=f"{label} (network round-trip)")

    # Paper reference overlay (approximate; see the JSON's _comment).
    if not args.no_reference:
        try:
            with open(args.reference) as f:
                ref = json.load(f)
            for name, points in ref.get("curves", {}).items():
                rx = [max(p[0], floor) if floor else p[0] for p in points]
                ry = [p[1] for p in points]
                ax.plot(rx, ry, linestyle="--", linewidth=1.5, alpha=0.8, label=name)
            if ref.get("approximate"):
                ax.text(0.99, 0.02, ref.get("citation", ""), transform=ax.transAxes,
                        ha="right", va="bottom", fontsize=7, style="italic", alpha=0.7)
        except FileNotFoundError:
            print(f"note: reference file {args.reference} not found; skipping overlay",
                  file=sys.stderr)

    if log_x:
        ax.set_xscale("log")
        ax.set_xlabel(f"keypress → display latency (ms, log; 0 shown at {LOG_ZERO_FLOOR_MS} ms)")
    else:
        ax.set_xlabel("keypress → display latency (ms)")
    ax.set_ylabel("cumulative fraction of keystrokes")
    ax.set_ylim(0, 1.0)
    ax.set_title(args.title)
    ax.grid(True, which="both", alpha=0.25)
    # Upper-left is the empty quadrant (the response curve plateaus low-left, the
    # references rise on the right), so the legend sits clear of both the data and
    # the bottom-right citation.
    ax.legend(loc="upper left", fontsize=8)

    fig.tight_layout()
    fig.savefig(args.output, dpi=150)
    print(f"wrote {args.output}")
    # Also emit a PDF sibling for crisp inclusion in docs.
    if args.output.lower().endswith(".png"):
        pdf = args.output[:-4] + ".pdf"
        fig.savefig(pdf)
        print(f"wrote {pdf}")


if __name__ == "__main__":
    main()
