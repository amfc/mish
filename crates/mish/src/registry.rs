//! Session registry for **reattach** (NEXT_FEATURES.md #2): a per-user record of
//! live persistent sessions, so re-running `mish host --session NAME` finds an
//! existing detached session instead of starting a new one.
//!
//! Each session is a `0600` file `<dir>/<name>.session` holding the daemon's PID
//! and its verbatim `MISH CONNECT` line. Reattach just **reprints that line** and
//! exits; the already-running daemon keeps serving on the same UDP port, and the
//! reattaching client connects to it with the recorded (reused) session
//! credentials.
//!
//! Security: the file lives under the user's own runtime dir and is `0600`, so
//! only that user (and root) can read it — and that user already has shell access
//! on the host, so the credentials at rest are no new exposure (see SECURITY.md).
//! The trust anchor for *who may reattach* remains the SSH login that launches
//! the lookup.

use std::io::{self, Write};
use std::path::{Path, PathBuf};

/// A recorded live (or possibly stale) session.
pub struct SessionEntry {
    /// PID of the serving daemon (used to check liveness).
    pub pid: i32,
    /// The daemon's process start-time token (kernel jiffies since boot, from
    /// `/proc/<pid>/stat`), if it could be read when the entry was written. Pins
    /// the PID to a *specific* process so a recycled PID isn't mistaken for our
    /// still-live daemon. `None` when unavailable (non-Linux, or unreadable).
    pub start_time: Option<u64>,
    /// The verbatim `MISH CONNECT <port> <server> <client> <key>` line to reprint.
    pub connect_line: String,
}

impl SessionEntry {
    /// The UDP port from the connect line, if parseable.
    pub fn port(&self) -> Option<u16> {
        self.connect_line.split_whitespace().nth(2)?.parse().ok()
    }
}

/// Default per-user registry directory: `$XDG_RUNTIME_DIR/mish` if set, else
/// `$HOME/.mish` (created `0700` on write).
pub fn default_dir() -> PathBuf {
    if let Some(xdg) = std::env::var_os("XDG_RUNTIME_DIR") {
        PathBuf::from(xdg).join("mish")
    } else if let Some(home) = std::env::var_os("HOME") {
        PathBuf::from(home).join(".mish")
    } else {
        std::env::temp_dir().join("mish")
    }
}

/// Restrict a session name to a safe filename component (no path traversal).
fn sanitize(name: &str) -> String {
    name.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-') {
                c
            } else {
                '_'
            }
        })
        .collect()
}

fn entry_path(dir: &Path, name: &str) -> PathBuf {
    dir.join(format!("{}.session", sanitize(name)))
}

/// Whether process `pid` is alive *and signalable by us*. Unix: `kill(pid, 0)`
/// returning 0. An `EPERM` (the PID exists but is owned by another user) is
/// treated as **not** our session — our daemon always runs as the same user, so
/// a foreign-owned recycled PID can never be it; reporting it "alive" would let
/// a reattach lock onto an unrelated process.
pub fn is_alive(pid: i32) -> bool {
    #[cfg(unix)]
    {
        unsafe { libc::kill(pid, 0) == 0 }
    }
    #[cfg(not(unix))]
    {
        let _ = pid;
        false
    }
}

/// The start-time token for `pid`: field 22 (`starttime`, in clock ticks since
/// boot) of `/proc/<pid>/stat`. Together with the PID it uniquely identifies a
/// process instance, so PID reuse can be detected. `None` off Linux or if the
/// process is gone / unreadable.
pub fn process_start_time(pid: i32) -> Option<u64> {
    #[cfg(target_os = "linux")]
    {
        let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
        // The `comm` field (2nd) is wrapped in parens and may itself contain
        // spaces or ')', so parse after the *last* ')': the remaining
        // whitespace-separated fields begin at field 3 (`state`). `starttime` is
        // field 22, i.e. index 19 (0-based) of that remainder.
        let rest = &stat[stat.rfind(')')? + 1..];
        rest.split_whitespace().nth(19)?.parse().ok()
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = pid;
        None
    }
}

/// Write (or overwrite) the session entry as a `0600` file under `dir`.
pub fn store_in(dir: &Path, name: &str, pid: i32, connect_line: &str) -> io::Result<()> {
    std::fs::create_dir_all(dir)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700));
    }
    let path = entry_path(dir, name);
    // Line 1 is `<pid>` or `<pid> <start_time>` (start-time appended when
    // readable, so older/non-Linux readers still parse the PID).
    let contents = match process_start_time(pid) {
        Some(start) => format!("{pid} {start}\n{connect_line}\n"),
        None => format!("{pid}\n{connect_line}\n"),
    };

    #[cfg(unix)]
    let mut f = {
        use std::os::unix::fs::OpenOptionsExt;
        std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&path)?
    };
    #[cfg(not(unix))]
    let mut f = std::fs::File::create(&path)?;

    f.write_all(contents.as_bytes())?;
    Ok(())
}

/// Read a session entry by name (no liveness check), or `None` if absent/malformed.
pub fn load_in(dir: &Path, name: &str) -> Option<SessionEntry> {
    let s = std::fs::read_to_string(entry_path(dir, name)).ok()?;
    let mut lines = s.lines();
    let mut head = lines.next()?.split_whitespace();
    let pid: i32 = head.next()?.parse().ok()?;
    let start_time: Option<u64> = head.next().and_then(|t| t.parse().ok());
    let connect_line = lines.next()?.to_string();
    if !connect_line.starts_with("MISH CONNECT ") {
        return None;
    }
    Some(SessionEntry {
        pid,
        start_time,
        connect_line,
    })
}

/// Remove a session entry (best-effort).
pub fn remove_in(dir: &Path, name: &str) {
    let _ = std::fs::remove_file(entry_path(dir, name));
}

/// Find a *live* session by name: returns the entry only if its daemon PID is
/// still alive; otherwise cleans up the stale file and returns `None`.
pub fn find_live_in(dir: &Path, name: &str) -> Option<SessionEntry> {
    let entry = load_in(dir, name)?;
    if is_alive(entry.pid) && start_time_matches(&entry) {
        Some(entry)
    } else {
        remove_in(dir, name);
        None
    }
}

/// Confirm the live PID is still the *same process* we recorded, defeating PID
/// reuse. If we recorded a start-time it must match the running process's; if we
/// have none (non-Linux, or it was unreadable at store time) we can't verify and
/// fall back to trusting liveness alone.
fn start_time_matches(entry: &SessionEntry) -> bool {
    match entry.start_time {
        Some(recorded) => process_start_time(entry.pid) == Some(recorded),
        None => true,
    }
}

// --- Convenience wrappers over [`default_dir`] (used by the binary). ---

/// Store a session in the default registry dir.
pub fn store(name: &str, pid: i32, connect_line: &str) -> io::Result<()> {
    store_in(&default_dir(), name, pid, connect_line)
}

/// Find a live session in the default registry dir.
pub fn find_live(name: &str) -> Option<SessionEntry> {
    find_live_in(&default_dir(), name)
}

/// Remove a session from the default registry dir.
pub fn remove(name: &str) {
    remove_in(&default_dir(), name)
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        /// Security seam #4 — the session name (`--session NAME`) is
        /// attacker-influenceable (shared scripts, env). For *any* name, the
        /// registry path must stay a single component directly inside the dir:
        /// no `..`, no separators, no escape.
        #[test]
        fn entry_path_never_escapes_the_dir(name in ".*") {
            let dir = Path::new("/run/user/1000/mish");
            let p = entry_path(dir, &name);
            prop_assert_eq!(p.parent(), Some(dir));
            prop_assert!(
                !p.components().any(|c| c == std::path::Component::ParentDir),
                "path contains a parent-dir component: {:?}",
                p
            );
            let fname = p.file_name().and_then(|f| f.to_str()).unwrap();
            prop_assert!(!fname.contains('/') && fname.ends_with(".session"));
        }
    }

    /// Explicit hostile session names (the `.`/`..` edges the `.session` suffix
    /// has to neutralize) all stay inside the registry dir.
    #[test]
    fn hostile_session_names_stay_in_dir() {
        let dir = Path::new("/run/user/1000/mish");
        for name in [
            "..",
            ".",
            "../../etc/passwd",
            "/etc/passwd",
            "a/../../b",
            "....//....//",
            "\0evil",
            "",
        ] {
            let p = entry_path(dir, name);
            assert_eq!(p.parent(), Some(dir), "{name:?} escaped the dir: {p:?}");
        }
    }

    /// A unique temp dir for a test (no external tempdir crate).
    fn tmp(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("mish-reg-{}-{}", tag, std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        d
    }

    #[test]
    fn store_load_round_trip() {
        let dir = tmp("rt");
        let line = "MISH CONNECT 51234 deadbeef cafe babe";
        store_in(&dir, "work", 4242, line).unwrap();
        let e = load_in(&dir, "work").expect("entry");
        assert_eq!(e.pid, 4242);
        assert_eq!(e.connect_line, line);
        assert_eq!(e.port(), Some(51234));
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn stored_file_is_user_only() {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let dir = tmp("perms");
            store_in(&dir, "s", 1, "MISH CONNECT 1 a b c").unwrap();
            let mode = std::fs::metadata(entry_path(&dir, "s"))
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600, "session file must be 0600");
            std::fs::remove_dir_all(&dir).ok();
        }
    }

    #[test]
    fn find_live_self_is_alive() {
        let dir = tmp("alive");
        let pid = std::process::id() as i32; // ourselves — definitely alive
        store_in(&dir, "me", pid, "MISH CONNECT 5 a b c").unwrap();
        assert!(find_live_in(&dir, "me").is_some());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn find_live_reaps_dead_session() {
        let dir = tmp("dead");
        // A PID that is essentially never a live process.
        store_in(&dir, "ghost", i32::MAX, "MISH CONNECT 9 a b c").unwrap();
        assert!(
            find_live_in(&dir, "ghost").is_none(),
            "a dead session must be reported gone"
        );
        assert!(
            load_in(&dir, "ghost").is_none(),
            "the stale file must be cleaned up"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn pid_reuse_with_wrong_start_time_is_reaped() {
        // Our PID is alive, but a recorded start-time that doesn't match the
        // running process means the original daemon died and the PID was reused.
        // `find_live` must reject it (defeats PID-reuse misdirection) and clean up.
        let dir = tmp("reuse");
        let pid = std::process::id() as i32;
        // Hand-write an entry with a deliberately wrong start-time token.
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            entry_path(&dir, "s"),
            format!("{pid} 1\nMISH CONNECT 5 a b c\n"),
        )
        .unwrap();
        assert!(
            find_live_in(&dir, "s").is_none(),
            "a reused PID (start-time mismatch) must not be treated as live"
        );
        assert!(load_in(&dir, "s").is_none(), "stale entry must be reaped");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn store_records_and_matches_own_start_time() {
        // Storing our own live PID records our start-time, and find_live confirms
        // it matches — the legitimate-reattach path must still succeed.
        let dir = tmp("startmatch");
        let pid = std::process::id() as i32;
        store_in(&dir, "me", pid, "MISH CONNECT 5 a b c").unwrap();
        let e = load_in(&dir, "me").expect("entry");
        #[cfg(target_os = "linux")]
        assert!(
            e.start_time.is_some(),
            "start-time should be recorded on Linux"
        );
        assert!(
            find_live_in(&dir, "me").is_some(),
            "our own live session must verify"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn sanitize_blocks_path_traversal() {
        let dir = tmp("san");
        // A hostile name can't escape the registry dir.
        let p = entry_path(&dir, "../../etc/passwd");
        assert_eq!(p.parent(), Some(dir.as_path()));
        std::fs::remove_dir_all(&dir).ok();
    }
}
