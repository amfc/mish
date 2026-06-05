//! mish-client CLI surface: `--version`, `--help`, and `--predict` validation.
//! These exercise argument parsing only (no network / no server spawned).

use std::process::Command;

fn client() -> Command {
    Command::new(env!("CARGO_BIN_EXE_mish-client"))
}

#[test]
fn version_prints_and_exits_zero() {
    let out = client().arg("--version").output().unwrap();
    assert!(out.status.success(), "--version should exit 0");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("mish") && stdout.contains(env!("CARGO_PKG_VERSION")),
        "version line should name mish and the version, got: {stdout:?}"
    );
}

#[test]
fn help_exits_zero() {
    let out = client().arg("--help").output().unwrap();
    assert!(out.status.success(), "--help should exit 0");
    // Usage goes to stderr; it should mention the new flags.
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("--predict"), "help should list --predict");
    assert!(stderr.contains("--no-init"), "help should list --no-init");
}

#[test]
fn bad_predict_mode_is_rejected() {
    // A bogus predict mode must fail fast during parsing (before any bootstrap),
    // not silently default.
    let out = client()
        .args(["--predict", "bogus", "host"])
        .output()
        .unwrap();
    assert!(
        !out.status.success(),
        "an unknown --predict mode should be an error"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("bogus"),
        "the error should name the bad mode, got: {stderr:?}"
    );
}

#[test]
fn missing_host_is_rejected() {
    // No host and not --local → usage error.
    let out = client().output().unwrap();
    assert!(!out.status.success(), "no host should be an error");
}
