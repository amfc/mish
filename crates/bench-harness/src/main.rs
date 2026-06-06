//! A/B latency harness: drive **mish** and **upstream mosh** through the
//! *same* fault-injecting loopback UDP relay and measure, identically:
//!
//! - **display latency** — one-way server→client: a child paints a wall-clock
//!   marker (`bench-child`); we read it off the client's reconstructed screen and
//!   subtract (both processes share the machine clock).
//! - **keyboard latency** — round-trip echo: we type a char into the client and
//!   time until it appears on the client's screen (child = `cat`, which the PTY
//!   line discipline echoes).
//!
//! The relay is L4-transparent, so QUIC (mish) and UDP/OCB (mosh) see the same
//! impairments. It's real wall-clock (not the deterministic sim), so we run many
//! trials and report medians/p90. Run:
//!
//! ```sh
//! cargo run -p bench-harness --release --bin bench-harness
//! ```

use std::io::{Read, Write};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::Stdio;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, bail, Context, Result};
use mish_terminal::emulator::Emulator;
use portable_pty::{native_pty_system, CommandBuilder, PtySize};
use tokio::net::UdpSocket;

const COLS: u16 = 80;
const ROWS: u16 = 24;
/// 1-based row the `bench-child` marker paints on; reconstructed at index `MARKER_ROW-1`.
const MARKER_ROW: usize = 10;

#[derive(Clone, Copy)]
struct Faults {
    /// One-way base delay added in each direction (ms).
    delay_ms: u64,
    /// Uniform random delay added on top, 0..=jitter_ms (ms). Because each packet
    /// is delayed independently, jitter already produces some reordering.
    jitter_ms: u64,
    loss: LossModel,
    /// Probability a forwarded packet is *held back* by `reorder_extra_ms`, so it
    /// arrives after packets sent later — explicit reordering on top of jitter.
    reorder_prob: f64,
    reorder_extra_ms: u64,
}

impl Faults {
    /// Independent (Bernoulli) per-packet loss — the classic, *easy* loss model.
    fn iid(loss: f64, delay_ms: u64, jitter_ms: u64) -> Self {
        Self {
            delay_ms,
            jitter_ms,
            loss: LossModel::Iid(loss),
            reorder_prob: 0.0,
            reorder_extra_ms: 0,
        }
    }
}

/// How packet loss is generated.
#[derive(Clone, Copy)]
enum LossModel {
    /// Independent per-packet loss probability.
    Iid(f64),
    /// Gilbert-Elliott burst loss: a two-state Markov chain (GOOD/BAD) with a
    /// per-state loss probability. Real links lose packets in *bursts* (fading,
    /// buffer overrun), which is far harder on a protocol than the same average
    /// loss spread out — it's where QUIC's cwnd collapse (vs mosh's blast-anyway)
    /// would actually bite.
    Gilbert {
        good_loss: f64,
        bad_loss: f64,
        /// P(GOOD→BAD) per packet.
        p_enter_bad: f64,
        /// P(BAD→GOOD) per packet (mean burst length ≈ 1 / p_leave_bad packets).
        p_leave_bad: f64,
    },
}

/// Per-direction loss state (the Gilbert-Elliott chain's current state).
struct LossState {
    in_bad: bool,
}

impl LossState {
    fn new() -> Self {
        Self { in_bad: false }
    }

    /// Advance the model one packet and decide whether to drop it.
    fn drops(&mut self, model: &LossModel, r: &mut Rng) -> bool {
        match *model {
            LossModel::Iid(p) => r.f64() < p,
            LossModel::Gilbert {
                good_loss,
                bad_loss,
                p_enter_bad,
                p_leave_bad,
            } => {
                if self.in_bad {
                    if r.f64() < p_leave_bad {
                        self.in_bad = false;
                    }
                } else if r.f64() < p_enter_bad {
                    self.in_bad = true;
                }
                let loss = if self.in_bad { bad_loss } else { good_loss };
                r.f64() < loss
            }
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Target {
    Mish,
    Mosh,
}

impl Target {
    fn label(self) -> &'static str {
        match self {
            Target::Mish => "mish",
            Target::Mosh => "mosh",
        }
    }
}

/// Predictive-echo mode passed to whichever client.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Predict {
    Never,
    Always,
}

fn now_ns() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos()
}

// ---------------------------------------------------------------------------
// Fault-injecting UDP relay
// ---------------------------------------------------------------------------

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x.wrapping_mul(0x2545F4914F6CDD1D)
    }
    fn f64(&mut self) -> f64 {
        (self.next() >> 11) as f64 / (1u64 << 53) as f64
    }
}

/// Bind a relay in front of `server`, returning the address the client should use.
/// Datagrams are dropped/delayed per `faults` (symmetric, seedable).
async fn spawn_relay(server: SocketAddr, faults: Faults, seed: u64) -> Result<SocketAddr> {
    let client_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await?);
    let listen = client_sock.local_addr()?;
    let server_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await?);
    let client_addr: Arc<Mutex<Option<SocketAddr>>> = Arc::new(Mutex::new(None));

    // Decide a forwarded packet's fate (drop, or a delay to send it after) using
    // this direction's own RNG + Gilbert-Elliott state.
    fn schedule(
        data: Vec<u8>,
        sock: Arc<UdpSocket>,
        to: SocketAddr,
        rng: &mut Rng,
        state: &mut LossState,
        faults: &Faults,
    ) {
        if state.drops(&faults.loss, rng) {
            return;
        }
        let jitter = if faults.jitter_ms > 0 {
            rng.next() % (faults.jitter_ms + 1)
        } else {
            0
        };
        let reorder = if faults.reorder_prob > 0.0 && rng.f64() < faults.reorder_prob {
            faults.reorder_extra_ms
        } else {
            0
        };
        let delay = faults.delay_ms + jitter + reorder;
        tokio::spawn(async move {
            if delay > 0 {
                tokio::time::sleep(Duration::from_millis(delay)).await;
            }
            let _ = sock.send_to(&data, to).await;
        });
    }

    // client → server: its own loss process (loss is not correlated between
    // directions on a real path, and each direction has its own GE state).
    {
        let (cs, ss, ca) = (
            client_sock.clone(),
            server_sock.clone(),
            client_addr.clone(),
        );
        tokio::spawn(async move {
            let mut rng = Rng(seed | 1);
            let mut state = LossState::new();
            let mut buf = [0u8; 2048];
            loop {
                if let Ok((n, from)) = cs.recv_from(&mut buf).await {
                    *ca.lock().unwrap() = Some(from);
                    schedule(
                        buf[..n].to_vec(),
                        ss.clone(),
                        server,
                        &mut rng,
                        &mut state,
                        &faults,
                    );
                }
            }
        });
    }
    // server → client
    {
        let (cs, ss, ca) = (client_sock, server_sock, client_addr);
        tokio::spawn(async move {
            let mut rng = Rng(seed ^ 0x9E37_79B9_7F4A_7C15);
            let mut state = LossState::new();
            let mut buf = [0u8; 2048];
            loop {
                if let Ok((n, _from)) = ss.recv_from(&mut buf).await {
                    let dest = *ca.lock().unwrap();
                    if let Some(dest) = dest {
                        schedule(
                            buf[..n].to_vec(),
                            cs.clone(),
                            dest,
                            &mut rng,
                            &mut state,
                            &faults,
                        );
                    }
                }
            }
        });
    }
    Ok(listen)
}

// ---------------------------------------------------------------------------
// Binaries
// ---------------------------------------------------------------------------

struct Bins {
    mish_server: PathBuf,
    mish_client: PathBuf,
    bench_child: PathBuf,
}

fn bins() -> Result<Bins> {
    let dir = std::env::current_exe()?
        .parent()
        .ok_or_else(|| anyhow!("no parent dir for current exe"))?
        .to_path_buf();
    Ok(Bins {
        mish_server: dir.join("mish-server"),
        mish_client: dir.join("mish-client"),
        bench_child: dir.join("bench-child"),
    })
}

/// Spawn the server (`target`) running `child_cmd`, returning (server UDP port,
/// client credential env, the child handle to kill at teardown).
async fn spawn_server(
    target: Target,
    bins: &Bins,
    child_cmd: &str,
) -> Result<(u16, Vec<(String, String)>, tokio::process::Child)> {
    use tokio::process::Command;
    let mut cmd = match target {
        Target::Mish => {
            let mut c = Command::new(&bins.mish_server);
            c.args(["-4", "-p", "0", "--", child_cmd]);
            c.env("MOSH_SERVER_SIGNAL_TMOUT", "30");
            c.env("MOSH_SERVER_NETWORK_TMOUT", "300");
            c
        }
        Target::Mosh => {
            let mut c = Command::new("mosh-server");
            c.args(["new", "-i", "127.0.0.1", "--", child_cmd]);
            // mosh exits if no client connects soon; 30s is plenty for a trial.
            c.env("MOSH_SERVER_SIGNAL_TMOUT", "30");
            c
        }
    };
    let mut child = cmd
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .stdin(Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .with_context(|| format!("spawning {} server", target.label()))?;

    // Read the MISH CONNECT line.
    let stdout = child.stdout.take().unwrap();
    let line = tokio::time::timeout(Duration::from_secs(10), async {
        use tokio::io::{AsyncBufReadExt, BufReader as TokioBufReader};
        let mut lines = TokioBufReader::new(stdout).lines();
        while let Some(l) = lines.next_line().await.ok().flatten() {
            if l.starts_with("MISH CONNECT ") {
                return Some(l);
            }
        }
        None
    })
    .await
    .context("timed out waiting for MISH CONNECT")?
    .ok_or_else(|| anyhow!("server exited before MISH CONNECT"))?;

    let mut it = line.split_whitespace();
    it.next(); // MOSH
    it.next(); // CONNECT
    let port: u16 = it.next().context("no port")?.parse().context("bad port")?;
    let env = match target {
        Target::Mish => {
            let rest: Vec<&str> = it.collect();
            if rest.len() != 3 {
                bail!("mish MISH CONNECT expected 3 creds, got {}", rest.len());
            }
            vec![("MISH_CONNECT".into(), rest.join(" "))]
        }
        Target::Mosh => {
            let key = it.next().context("no MOSH_KEY")?.to_string();
            vec![("MOSH_KEY".into(), key)]
        }
    };
    Ok((port, env, child))
}

/// Build the client command (in a PTY) for `target`, pointed at `relay`.
fn client_command(
    target: Target,
    bins: &Bins,
    relay: SocketAddr,
    predict: Predict,
) -> CommandBuilder {
    let pmode = match predict {
        Predict::Never => "never",
        Predict::Always => "always",
    };
    match target {
        Target::Mish => {
            let mut c = CommandBuilder::new(bins.mish_client.to_string_lossy().to_string());
            c.args([
                "--attach",
                "127.0.0.1",
                &relay.port().to_string(),
                "--predict",
                pmode,
                "--no-init",
            ]);
            c
        }
        Target::Mosh => {
            let mut c = CommandBuilder::new("mosh-client");
            c.args(["127.0.0.1", &relay.port().to_string()]);
            c.env("MOSH_PREDICTION_DISPLAY", pmode);
            c
        }
    }
}

// ---------------------------------------------------------------------------
// A client running in a PTY, with its screen reconstructed
// ---------------------------------------------------------------------------

struct ClientPty {
    emu: Arc<Mutex<Emulator>>,
    writer: Arc<Mutex<Box<dyn Write + Send>>>,
    child: Box<dyn portable_pty::Child + Send + Sync>,
    _alive: Arc<AtomicBool>,
}

impl ClientPty {
    fn spawn(cmd: CommandBuilder, env: &[(String, String)]) -> Result<Self> {
        let pty = native_pty_system().openpty(PtySize {
            rows: ROWS,
            cols: COLS,
            pixel_width: 0,
            pixel_height: 0,
        })?;
        let mut cmd = cmd;
        cmd.env("TERM", "xterm-256color");
        for (k, v) in env {
            cmd.env(k, v);
        }
        let child = pty.slave.spawn_command(cmd)?;
        drop(pty.slave);

        let emu = Arc::new(Mutex::new(Emulator::new(COLS, ROWS)));
        let alive = Arc::new(AtomicBool::new(true));
        let mut reader = pty.master.try_clone_reader()?;
        let writer = pty.master.take_writer()?;

        {
            let (emu, alive) = (emu.clone(), alive.clone());
            std::thread::spawn(move || {
                let mut buf = [0u8; 8192];
                while alive.load(Ordering::Relaxed) {
                    match reader.read(&mut buf) {
                        Ok(0) | Err(_) => break,
                        Ok(n) => emu.lock().unwrap().feed(&buf[..n]),
                    }
                }
            });
        }

        Ok(Self {
            emu,
            writer: Arc::new(Mutex::new(writer)),
            child,
            _alive: alive,
        })
    }

    /// The current reconstructed screen as one string per row.
    fn screen_lines(&self) -> Vec<String> {
        self.emu.lock().unwrap().snapshot().to_lines()
    }

    /// `(cursor_row, cursor_col, char-at-cursor)` from the reconstructed screen.
    /// Used to watch the exact cell a typed character will echo into.
    fn cursor_cell(&self) -> (u16, u16, char) {
        let s = self.emu.lock().unwrap().snapshot();
        let (r, c) = (s.cursor_row, s.cursor_col);
        let idx = r as usize * s.cols as usize + c as usize;
        let ch = s.cells.get(idx).map(|cell| cell.c).unwrap_or(' ');
        (r, c, ch)
    }

    /// The character at a specific cell of the reconstructed screen.
    fn char_at(&self, row: u16, col: u16) -> char {
        let s = self.emu.lock().unwrap().snapshot();
        let idx = row as usize * s.cols as usize + col as usize;
        s.cells.get(idx).map(|cell| cell.c).unwrap_or(' ')
    }

    fn type_bytes(&self, b: &[u8]) {
        let mut w = self.writer.lock().unwrap();
        let _ = w.write_all(b);
        let _ = w.flush();
    }
}

impl Drop for ClientPty {
    fn drop(&mut self) {
        self._alive.store(false, Ordering::Relaxed);
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

// ---------------------------------------------------------------------------
// Metrics
// ---------------------------------------------------------------------------

/// Parse the `[TS <ns>]` marker out of a reconstructed screen, if present.
fn parse_ts(lines: &[String]) -> Option<u128> {
    let row = lines.get(MARKER_ROW - 1)?;
    let start = row.find("[TS ")? + 4;
    let end = row[start..].find(']')? + start;
    row[start..end].trim().parse().ok()
}

/// Measure one-way display latency: time from the child emitting a wall-clock
/// marker to it appearing on the client screen. Samples each fresh marker.
async fn measure_display(client: &ClientPty, duration: Duration) -> Vec<f64> {
    let mut samples = Vec::new();
    let mut last_ts: Option<u128> = None;
    let deadline = Instant::now() + duration;
    while Instant::now() < deadline {
        if let Some(ts) = parse_ts(&client.screen_lines()) {
            if Some(ts) != last_ts {
                last_ts = Some(ts);
                let lag = now_ns().saturating_sub(ts) as f64 / 1e6; // ms
                if (0.0..60_000.0).contains(&lag) {
                    samples.push(lag);
                }
            }
        }
        tokio::time::sleep(Duration::from_millis(2)).await;
    }
    samples
}

/// Measure keyboard latency: type a character and time until **that exact glyph
/// appears at the cursor cell** on the reconstructed screen.
///
/// This is deliberately glyph-specific, not "any screen content changed": the
/// old version tripped on cursor moves / repaints / a prediction painted
/// elsewhere, which let a client register a "keyboard" sample faster than the
/// network could possibly deliver an echo. Watching the destination cell for the
/// typed character measures one well-defined event for both clients:
///
/// * prediction off → the glyph only appears once the server echo round-trips,
///   so the sample is a true round trip (≥ the link RTT);
/// * prediction on  → the client paints the predicted glyph locally first, so
///   the sample is the local prediction latency (well under the RTT).
///
/// The caller compares the medians against the known RTT floor to tell which is
/// which (see [`run_matrix`]'s annotation), so the two columns are interpreted
/// identically for mish and mosh instead of conflating different events.
///
/// `cat` is the server child: its PTY line discipline echoes input, so the
/// confirmed glyph lands at the cursor.
async fn measure_keyboard(client: &ClientPty, n: usize) -> Vec<f64> {
    let mut samples = Vec::new();
    for i in 0..n {
        // The cell the next echoed/predicted glyph will occupy, and what it
        // holds now — so we can pick a character that actually differs from it.
        let (row, col, present) = client.cursor_cell();
        if col >= COLS.saturating_sub(1) {
            // Near the right margin: go to a fresh line so the glyph lands in a
            // blank cell (cat echoes the CR, advancing to the next row).
            client.type_bytes(b"\r");
            tokio::time::sleep(Duration::from_millis(150)).await;
            continue;
        }
        // A printable char distinct from both the cell's current contents and a
        // blank, so the match is unambiguous.
        let ch = {
            let mut c = b'a' + (i % 26) as u8;
            if c as char == present {
                c = if c == b'z' { b'a' } else { c + 1 };
            }
            c
        };
        let t0 = Instant::now();
        client.type_bytes(&[ch]);
        let deadline = t0 + Duration::from_secs(3);
        loop {
            if client.char_at(row, col) == ch as char {
                samples.push(t0.elapsed().as_secs_f64() * 1000.0);
                break;
            }
            if Instant::now() > deadline {
                break; // never echoed within patience; skip this sample
            }
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
        tokio::time::sleep(Duration::from_millis(40)).await;
    }
    samples
}

fn pct(mut v: Vec<f64>, p: f64) -> f64 {
    if v.is_empty() {
        return f64::NAN;
    }
    v.sort_by(|a, b| a.partial_cmp(b).unwrap());
    v[((v.len() as f64 * p) as usize).min(v.len() - 1)]
}

// ---------------------------------------------------------------------------
// Driving one session
// ---------------------------------------------------------------------------

#[derive(Clone, Copy)]
enum Metric {
    Display,
    Keyboard,
}

async fn run_session(
    target: Target,
    bins: &Bins,
    faults: Faults,
    seed: u64,
    predict: Predict,
    metric: Metric,
) -> Result<Vec<f64>> {
    let child_cmd = match metric {
        Metric::Display => bins.bench_child.to_string_lossy().to_string(),
        // `cat` keeps the server PTY open so the line discipline echoes typed
        // chars; resolved via PATH by the server's spawner (don't hardcode a
        // path — e.g. NixOS has no /bin/cat).
        Metric::Keyboard => "cat".to_string(),
    };
    let (port, env, _server) = spawn_server(target, bins, &child_cmd).await?;
    let server_addr: SocketAddr = format!("127.0.0.1:{port}").parse()?;
    // `BENCH_DIRECT=1` bypasses the relay (connect straight to the server) — a
    // diagnostic to separate transport faults from harness/protocol behavior.
    let relay = if std::env::var_os("BENCH_DIRECT").is_some() {
        server_addr
    } else {
        spawn_relay(server_addr, faults, seed).await?
    };

    let cmd = client_command(target, bins, relay, predict);
    let client = ClientPty::spawn(cmd, &env)?;

    // Settle: let the handshake + initial sync complete.
    tokio::time::sleep(Duration::from_millis(2500)).await;

    let out = match metric {
        // Longer display window: under burst loss, fewer fresh markers get
        // through, so a wider window keeps the median statistically meaningful.
        Metric::Display => measure_display(&client, Duration::from_secs(6)).await,
        Metric::Keyboard => {
            let kn = std::env::var("BENCH_KSAMPLES")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(12);
            measure_keyboard(&client, kn).await
        }
    };
    drop(client); // kills the client; `_server` drops at fn end (kill_on_drop)
    Ok(out)
}

/// Run a metric across seeds and aggregate.
async fn matrix_cell(
    target: Target,
    bins: &Bins,
    faults: Faults,
    predict: Predict,
    metric: Metric,
    seeds: u64,
) -> (f64, f64, usize) {
    let mut all = Vec::new();
    let mut seed_medians = Vec::new();
    for s in 0..seeds {
        let seed = 0x9E3779B1u64.wrapping_mul(s + 1);
        match run_session(target, bins, faults, seed, predict, metric).await {
            Ok(v) => {
                if !v.is_empty() {
                    seed_medians.push(pct(v.clone(), 0.5));
                }
                all.extend(v);
            }
            Err(e) => eprintln!("  (session error: {e})"),
        }
    }
    let n = all.len();
    // Deep stats (MISH_STATS=1): pooled mean±stdev over every individual
    // sample, plus the spread of the per-seed medians (the run-to-run "noise").
    if std::env::var_os("MISH_STATS").is_some() && n > 0 {
        let mean = all.iter().sum::<f64>() / n as f64;
        let var = all.iter().map(|x| (x - mean).powi(2)).sum::<f64>() / n as f64;
        let sd = var.sqrt();
        let (mm, ms) = mean_sd(&seed_medians);
        let p = match predict {
            Predict::Never => "off",
            Predict::Always => "on",
        };
        let m = match metric {
            Metric::Display => "disp",
            Metric::Keyboard => "kbd",
        };
        eprintln!(
            "[stats {:>6} {m}-{p}] n={n}  mean={mean:.1}  sd={sd:.1}  median={:.1}  p90={:.1}  | per-seed medians: mean={mm:.1} sd={ms:.1} ({} seeds)",
            target.label(),
            pct(all.clone(), 0.5),
            pct(all.clone(), 0.9),
            seed_medians.len(),
        );
    }
    (pct(all.clone(), 0.5), pct(all, 0.9), n)
}

/// Mean and population standard deviation of a slice.
fn mean_sd(v: &[f64]) -> (f64, f64) {
    if v.is_empty() {
        return (f64::NAN, f64::NAN);
    }
    let mean = v.iter().sum::<f64>() / v.len() as f64;
    let var = v.iter().map(|x| (x - mean).powi(2)).sum::<f64>() / v.len() as f64;
    (mean, var.sqrt())
}

#[tokio::main]
async fn main() -> Result<()> {
    let bins = bins()?;
    for b in [&bins.mish_server, &bins.mish_client, &bins.bench_child] {
        if !b.exists() {
            bail!("missing binary {} — build the workspace first", b.display());
        }
    }
    let have_mosh = std::process::Command::new("mosh-server")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);

    let targets: &[Target] = if have_mosh {
        &[Target::Mish, Target::Mosh]
    } else {
        eprintln!("note: mosh-server not found — running mish only\n");
        &[Target::Mish]
    };

    println!("A/B latency harness — mish vs mosh over a fault-injecting relay\n");
    println!(
        "(real wall-clock; medians over a few trials; one-way display + round-trip keyboard)\n"
    );

    let conditions = [
        ("LAN     (rtt~2ms,  0% iid loss)", Faults::iid(0.0, 1, 0)),
        ("WAN     (rtt~80ms, 5% iid loss)", Faults::iid(0.05, 40, 5)),
        // Heavy loss, two ways: independent vs bursty at the *same ~15% average*.
        // This is the headline contrast — bursts are where QUIC's cwnd collapse
        // (vs mosh blasting through) should show, if it shows anywhere.
        (
            "LOSSY   (rtt~120ms, 15% iid loss)",
            Faults::iid(0.15, 60, 15),
        ),
        (
            "BURSTY  (rtt~80ms, ~14% BURST loss)",
            Faults {
                delay_ms: 40,
                jitter_ms: 10,
                loss: LossModel::Gilbert {
                    good_loss: 0.005,
                    bad_loss: 0.7,
                    p_enter_bad: 0.0625,
                    p_leave_bad: 0.25, // mean burst ~4 packets, P(bad)~20%
                },
                reorder_prob: 0.0,
                reorder_extra_ms: 0,
            },
        ),
        (
            "REORDER (rtt~60ms, 1% loss, 12% reorder)",
            Faults {
                delay_ms: 30,
                jitter_ms: 8,
                loss: LossModel::Iid(0.01),
                reorder_prob: 0.12,
                reorder_extra_ms: 60,
            },
        ),
        (
            "BRUTAL  (rtt~140ms, bursty + reorder)",
            Faults {
                delay_ms: 70,
                jitter_ms: 25,
                loss: LossModel::Gilbert {
                    good_loss: 0.01,
                    bad_loss: 0.6,
                    p_enter_bad: 0.04,
                    p_leave_bad: 0.2, // mean burst ~5 packets
                },
                reorder_prob: 0.10,
                reorder_extra_ms: 80,
            },
        ),
    ];
    // BENCH_SEEDS bumps the number of loss realizations per cell (more samples
    // for tighter mean/sd); BENCH_KBD_ONLY skips the display + predict-on cells
    // (just the keyboard-off round trip) for a fast, deep keyboard measurement.
    let seeds: u64 = std::env::var("BENCH_SEEDS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(1);
    let kbd_only = std::env::var_os("BENCH_KBD_ONLY").is_some();

    println!(
        "keyboard = time until the typed glyph paints at the cursor cell. Each keyboard\n\
         number is tagged against the round-trip floor (2×one-way delay): `rt` = a real\n\
         server echo (≥ floor), `loc` = painted locally before any echo could arrive\n\
         (i.e. predictive echo). A `loc` in the predict-off column, or an `rt` in the\n\
         predict-on column, means that client isn't behaving as the mode label claims.\n"
    );

    // `BENCH_ONLY=LOSSY,BRUTAL` restricts to conditions whose label contains any
    // of the comma-separated terms — handy for fast A/B iteration on a subset.
    let only = std::env::var("BENCH_ONLY").ok();
    for (name, faults) in conditions {
        if let Some(filter) = &only {
            if !filter.split(',').any(|t| name.contains(t.trim())) {
                continue;
            }
        }
        // Two different floors. Display is one-way (server→client), so it can't
        // beat a single relay delay. Keyboard is a round trip (type→server→echo→
        // client), so it can't beat 2× the delay. The `rt`/`loc` tag is against
        // the keyboard (round-trip) floor only.
        let one_way = faults.delay_ms as f64;
        let floor = 2.0 * one_way;
        println!(
            "=== {name} ===   [display 1-way floor ~{one_way:.0} ms · keyboard round-trip floor ~{floor:.0} ms]"
        );
        println!(
            "  DISPLAY 1-way (predict off)    KEYBOARD round-trip to-glyph (predict off / on)"
        );
        for &t in targets {
            if kbd_only {
                // Just the keyboard-off round trip — the deep-stats path prints
                // mean/sd via MISH_STATS; this line is the median summary.
                let (k_med, k_p90, kn) =
                    matrix_cell(t, &bins, faults, Predict::Never, Metric::Keyboard, seeds).await;
                println!(
                    "  {:>7}: KEYBOARD off  median {:>6.1} / p90 {:>6.1} ms {} (n={kn})",
                    t.label(),
                    k_med,
                    k_p90,
                    floor_tag(k_med, floor),
                );
                continue;
            }
            let (d_med, d_p90, dn) =
                matrix_cell(t, &bins, faults, Predict::Never, Metric::Display, seeds).await;
            let (k_med, _, kn) =
                matrix_cell(t, &bins, faults, Predict::Never, Metric::Keyboard, seeds).await;
            let (kp_med, _, kpn) =
                matrix_cell(t, &bins, faults, Predict::Always, Metric::Keyboard, seeds).await;
            println!(
                "  {:>7}: {:>6.1}/{:>6.1} ms (n={dn:>3})    {:>6.1} ms {} (n={kn:>2}) / {:>6.1} ms {} (n={kpn:>2})",
                t.label(),
                d_med,
                d_p90,
                k_med,
                floor_tag(k_med, floor),
                kp_med,
                floor_tag(kp_med, floor),
            );
        }
        println!();
    }
    Ok(())
}

/// Tag a keyboard median against the round-trip floor: `rt` if it's at least a
/// real echo round-trip, `loc` if it painted faster than the link could deliver
/// an echo (so it was a local prediction), `--` if there were no samples.
fn floor_tag(median_ms: f64, floor_ms: f64) -> &'static str {
    if median_ms.is_nan() {
        "-- "
    } else if median_ms + 1.0 < floor_ms {
        // 1 ms slack so a sample right at the floor isn't misclassified.
        "loc"
    } else {
        "rt "
    }
}
