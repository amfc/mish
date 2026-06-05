//! Reattach via the session registry (NEXT_FEATURES.md #2): a second
//! `mish-server --session NAME` finds the first one's live session and reprints
//! its `MISH CONNECT` line (so the client reattaches to the running daemon)
//! instead of starting a fresh server.

use std::io::{BufRead, BufReader};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

fn server_bin() -> &'static str {
    env!("CARGO_BIN_EXE_mish-server")
}

/// Read the first `MISH CONNECT …` line from a reader.
fn read_connect_line(reader: impl std::io::Read) -> String {
    let mut lines = BufReader::new(reader).lines();
    while let Some(Ok(line)) = lines.next() {
        if line.starts_with("MISH CONNECT ") {
            return line;
        }
    }
    panic!("no MISH CONNECT line");
}

#[test]
fn second_server_reattaches_to_existing_session() {
    // Isolated registry dir shared by both server processes.
    let xdg = std::env::temp_dir().join(format!("mish-reattach-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&xdg);
    std::fs::create_dir_all(&xdg).unwrap();

    // Server 1: a named, persistent session. Stays up (long signal timeout) so it
    // remains registered while server 2 looks it up. No --detach so we own it.
    let mut s1 = Command::new(server_bin())
        .args(["--session", "work"])
        .env("XDG_RUNTIME_DIR", &xdg)
        .env("MOSH_SERVER_SIGNAL_TMOUT", "30")
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn server 1");

    let line1 = read_connect_line(s1.stdout.take().unwrap());

    // Wait until server 1 has recorded its session file (written right after it
    // prints the connect line).
    let reg = xdg.join("mish").join("work.session");
    let deadline = Instant::now() + Duration::from_secs(5);
    while !reg.exists() {
        assert!(Instant::now() < deadline, "session never registered");
        std::thread::sleep(Duration::from_millis(20));
    }

    // Server 2: same session name. It must find the live session and reprint the
    // *same* connect line, then exit 0 — without starting a new server.
    let out2 = Command::new(server_bin())
        .args(["--session", "work"])
        .env("XDG_RUNTIME_DIR", &xdg)
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .output()
        .expect("run server 2");

    assert!(out2.status.success(), "reattach lookup should exit 0");
    let line2 = read_connect_line(&out2.stdout[..]);

    assert_eq!(
        line1, line2,
        "reattach must reprint the existing session's connect line (same port + creds)"
    );

    // Cleanup.
    let _ = s1.kill();
    let _ = s1.wait();
    let _ = std::fs::remove_dir_all(&xdg);
}
