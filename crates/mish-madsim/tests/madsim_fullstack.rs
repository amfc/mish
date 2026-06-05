//! Deterministic full-stack simulation under madsim: client, simulated network,
//! server, and a scripted (deterministic) shell — no real PTY or OS process.
//! Asserts the transparency invariant — the client's reconstructed screen equals
//! what the shell actually produced — reproducibly from `MADSIM_TEST_SEED`.
//!
//! Run with: `RUSTFLAGS="--cfg madsim" cargo test -p mish-madsim`
#![cfg(madsim)]

use std::net::SocketAddr;
use std::time::Duration;

use madsim::net::UdpSocket;
use madsim::runtime::Handle;
use madsim::time::{timeout, Instant};

use mish_ssp::core::{SspConfig, SspCore};
use mish_ssp::frag::{Defragmenter, Fragmenter};
use mish_ssp::instruction::Instruction;
use mish_terminal::emulator::Emulator;
use mish_terminal::screen::Screen;
use mish_terminal::user::{UserEvent, UserStream};

const PORT: u16 = 9100;
const MTU: usize = 1200;

fn cfg() -> SspConfig {
    SspConfig {
        rto: 300,
        ack_interval: 500,
        ack_delay: 20,
        send_interval_min: 20,
        ..Default::default()
    }
}

/// A deterministic "shell": echoes input, translating CR to CRLF (terminal echo).
fn shell_output(input: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    for &b in input {
        if b == b'\r' {
            out.extend_from_slice(b"\r\n");
        } else {
            out.push(b);
        }
    }
    out
}

async fn send_all(
    sock: &UdpSocket,
    peer: Option<SocketAddr>,
    frag: &mut Fragmenter,
    insts: Vec<Instruction>,
) {
    if let Some(p) = peer {
        for inst in insts {
            for f in frag.fragment(&inst.encode(), MTU) {
                let _ = sock.send_to(p, &f).await;
            }
        }
    }
}

fn screen_eq(a: &Screen, b: &Screen) -> bool {
    a.cols == b.cols
        && a.rows == b.rows
        && a.cells == b.cells
        && a.cursor_row == b.cursor_row
        && a.cursor_col == b.cursor_col
        && a.title == b.title
}

/// Server node: drives SspCore<Screen, UserStream> over madsim UDP, feeding the
/// scripted shell's output of received keystrokes into an emulator.
async fn server_node(addr: SocketAddr) {
    let sock = UdpSocket::bind(addr).await.unwrap();
    let mut core = SspCore::<Screen, UserStream>::with_config(0, cfg());
    let mut emu = Emulator::new(80, 24);
    let mut processed = 0u64;
    let mut frag = Fragmenter::new();
    let mut defrag = Defragmenter::new();
    let mut peer: Option<SocketAddr> = None;
    let mut buf = vec![0u8; 65536];
    core.set_current_state(emu.snapshot());
    let start = Instant::now();

    loop {
        let now = start.elapsed().as_millis() as u64;

        // Apply any newly-received keystrokes through the shell.
        let stream = core.remote_state().clone();
        if stream.total() > processed {
            for ev in stream.events_since(processed) {
                match ev {
                    UserEvent::Keystroke(b) => emu.feed(&shell_output(b)),
                    UserEvent::Resize { cols, rows } => emu.resize(*cols, *rows),
                }
            }
            processed = stream.total();
            let mut s = emu.snapshot();
            s.echo_ack = processed;
            core.set_current_state(s);
        }

        send_all(&sock, peer, &mut frag, core.tick(now)).await;

        let wait = core.wait_time(now).unwrap_or(3_600_000).max(1);
        if let Ok(Ok((n, from))) =
            timeout(Duration::from_millis(wait), sock.recv_from(&mut buf)).await
        {
            peer = Some(from);
            if let Some(payload) = defrag.push(&buf[..n]) {
                if let Some(inst) = Instruction::decode(&payload) {
                    let now2 = start.elapsed().as_millis() as u64;
                    core.recv(now2, &inst);
                }
            }
        }
    }
}

/// Client node: types `input`, waits until its reconstructed screen matches what
/// the shell produced, and returns whether transparency held.
async fn client_node(server: SocketAddr, input: Vec<u8>) -> bool {
    let sock = UdpSocket::bind((std::net::Ipv4Addr::UNSPECIFIED, 0))
        .await
        .unwrap();
    let mut core = SspCore::<UserStream, Screen>::with_config(0, cfg());
    let mut frag = Fragmenter::new();
    let mut defrag = Defragmenter::new();
    let mut buf = vec![0u8; 65536];

    // Independent reference: what the shell actually renders for this input.
    let mut ref_emu = Emulator::new(80, 24);
    ref_emu.feed(&shell_output(&input));
    let expected = ref_emu.snapshot();

    let mut stream = UserStream::new();
    stream.push_resize(80, 24);
    stream.push_keystroke(input);
    core.set_current_state(stream);

    let start = Instant::now();
    while start.elapsed() < Duration::from_secs(120) {
        let now = start.elapsed().as_millis() as u64;
        send_all(&sock, Some(server), &mut frag, core.tick(now)).await;

        if screen_eq(core.remote_state(), &expected) {
            return true;
        }

        let wait = core.wait_time(now).unwrap_or(3_600_000).max(1);
        if let Ok(Ok((n, _))) = timeout(Duration::from_millis(wait), sock.recv_from(&mut buf)).await
        {
            if let Some(payload) = defrag.push(&buf[..n]) {
                if let Some(inst) = Instruction::decode(&payload) {
                    let now2 = start.elapsed().as_millis() as u64;
                    core.recv(now2, &inst);
                }
            }
        }
    }
    screen_eq(core.remote_state(), &expected)
}

async fn run(loss: f64) -> bool {
    let handle = Handle::current();
    madsim::net::NetSim::current().update_config(|c| {
        c.packet_loss_rate = loss;
        c.send_latency = Duration::from_millis(5)..Duration::from_millis(60);
    });
    let server_ip = "10.0.0.1".parse().unwrap();
    let server = handle.create_node().ip(server_ip).build();
    let client = handle.create_node().ip("10.0.0.2".parse().unwrap()).build();
    let saddr = SocketAddr::new(server_ip, PORT);
    server.spawn(async move { server_node(saddr).await });

    // A multi-line script whose echoed output spans several rows (so the Screen
    // diff fragments across datagrams).
    let mut input = Vec::new();
    for i in 0..20 {
        input.extend_from_slice(format!("line {i} of the transparency check\r").as_bytes());
    }
    input.extend_from_slice(b"MADSIM_OK\r");

    client
        .spawn(async move { client_node(saddr, input).await })
        .await
        .unwrap()
}

#[madsim::test]
async fn full_stack_transparency_clean() {
    assert!(run(0.0).await, "client screen must match the shell output");
}

#[madsim::test]
async fn full_stack_transparency_under_loss() {
    assert!(run(0.2).await, "transparency must hold under 20% loss");
}
