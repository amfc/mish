//! Real PTY wiring (binary-only): spawn a child shell on a pseudo-terminal and
//! bridge it to the channel interface [`crate::server::run_server`] expects.
//!
//! `portable-pty` is blocking, so the read half and the control (write/resize)
//! half each run on a dedicated blocking thread feeding/draining tokio channels.

use std::io::{Read, Write};

use anyhow::Result;
use portable_pty::{native_pty_system, CommandBuilder, PtySize};
use tokio::sync::mpsc;

use crate::server::PtyControl;

/// Environment variables that may carry session credentials and must never be
/// inherited by the spawned login shell (where any same-user process could read
/// them via `/proc/<pid>/environ`). `MISH_CONNECT` holds the full connect line
/// including the client private key; `MOSH_KEY` is the mosh-style session key.
const SENSITIVE_ENV_VARS: &[&str] = &["MISH_CONNECT", "MOSH_KEY"];

/// A spawned child process on a PTY, exposed as channels.
pub struct PtyProcess {
    /// Child output bytes (stdout + stderr on the PTY).
    pub output: mpsc::Receiver<Vec<u8>>,
    /// Control messages (input bytes / resize) for the child.
    pub control: mpsc::UnboundedSender<PtyControl>,
}

impl PtyProcess {
    /// Spawn `command` (a single program) on a new PTY of the given size.
    pub fn spawn(command: &str, cols: u16, rows: u16) -> Result<Self> {
        Self::spawn_argv(vec![command.to_string()], cols, rows)
    }

    /// Spawn the user's `$SHELL` (or `/bin/sh`) as a **login shell** — invoked
    /// with `-l` so it reads the login profile (`.profile`/`.bash_profile`/…),
    /// matching how `mosh host` (and a real SSH login) starts a session.
    pub fn spawn_login_shell(cols: u16, rows: u16) -> Result<Self> {
        Self::spawn_argv(login_shell_argv(), cols, rows)
    }

    /// Spawn from an explicit argv (`argv[0]` is the program).
    pub fn spawn_argv(argv: Vec<String>, cols: u16, rows: u16) -> Result<Self> {
        let pty_system = native_pty_system();
        let pair = pty_system.openpty(PtySize {
            rows,
            cols,
            pixel_width: 0,
            pixel_height: 0,
        })?;

        // Tell the line discipline the child's input is UTF-8 so a cooked-mode
        // erase (backspace) deletes a whole multibyte character, not one byte
        // (mosh sets IUTF8 on the slave). On Linux the pty's termios is shared,
        // so setting it via the master fd reaches the slave. Best-effort.
        #[cfg(unix)]
        if let Some(fd) = pair.master.as_raw_fd() {
            enable_iutf8(fd);
        }

        let mut cmd = CommandBuilder::from_argv(argv.into_iter().map(Into::into).collect());
        cmd.env("TERM", "xterm-256color");
        // Scrub credential-bearing vars before the login shell inherits the
        // server's environment. The session key normally rides the SSH-encrypted
        // `MISH CONNECT` stdout line (never an env var), but if the server was
        // ever launched with one of these set (nested invocation, CI, the
        // `--attach` test harness), it would otherwise be readable by any
        // same-user process via /proc/<shell-pid>/environ or `ps -E`.
        for var in SENSITIVE_ENV_VARS {
            cmd.env_remove(var);
        }
        let mut child = pair.slave.spawn_command(cmd)?;
        drop(pair.slave); // child holds the slave now

        let mut reader = pair.master.try_clone_reader()?;
        let mut writer = pair.master.take_writer()?;
        let master = pair.master; // retained for resize; Send

        // Reader thread: child output → channel.
        let (out_tx, output) = mpsc::channel::<Vec<u8>>(256);
        std::thread::spawn(move || {
            let mut buf = [0u8; 8192];
            loop {
                match reader.read(&mut buf) {
                    // EOF / EIO on the master means every slave fd is closed — the
                    // child has exited. This is what should trigger the session's
                    // clean shutdown, so it's logged at info.
                    Ok(0) => {
                        tracing::info!(target: "mish::pty", "pty reader: EOF — child exited");
                        break;
                    }
                    Err(e) => {
                        tracing::info!(target: "mish::pty", error = %e, "pty reader: read error — child exited");
                        break;
                    }
                    Ok(n) => {
                        if out_tx.blocking_send(buf[..n].to_vec()).is_err() {
                            tracing::debug!(target: "mish::pty", "pty reader: output channel closed; stopping");
                            break;
                        }
                    }
                }
            }
            // Dropping `out_tx` here closes the server's pty_output channel.
            tracing::debug!(target: "mish::pty", "pty reader thread exiting (pty_output now closed)");
        });

        // Control thread: input writes + resizes (owns writer and master).
        let (control, mut ctrl_rx) = mpsc::unbounded_channel::<PtyControl>();
        std::thread::spawn(move || {
            while let Some(msg) = ctrl_rx.blocking_recv() {
                match msg {
                    PtyControl::Input(bytes) => {
                        if writer.write_all(&bytes).is_err() {
                            break;
                        }
                        let _ = writer.flush();
                    }
                    PtyControl::Resize { cols, rows } => {
                        let _ = master.resize(PtySize {
                            rows,
                            cols,
                            pixel_width: 0,
                            pixel_height: 0,
                        });
                    }
                }
            }
            // Session ended: reap the child.
            let _ = child.kill();
            let _ = child.wait();
        });

        Ok(Self { output, control })
    }
}

/// argv for a login shell: the user's `$SHELL` (or `/bin/sh`) invoked with `-l`.
/// (`portable-pty` execs `argv[0]`, so we can't use the `-bash` argv[0]
/// convention; `-l` gives the same login-profile behavior for bash/zsh/dash.)
pub fn login_shell_argv() -> Vec<String> {
    let shell = std::env::var("SHELL").unwrap_or_else(|_| "/bin/sh".to_string());
    login_argv_for(&shell)
}

fn login_argv_for(shell: &str) -> Vec<String> {
    vec![shell.to_string(), "-l".to_string()]
}

/// Set the `IUTF8` input flag on the terminal behind `fd`. Used so the kernel's
/// canonical-mode line editor erases whole UTF-8 characters. Best-effort: a
/// `tcgetattr`/`tcsetattr` failure (e.g. not a tty) is ignored.
#[cfg(unix)]
fn enable_iutf8(fd: std::os::unix::io::RawFd) {
    use std::mem::MaybeUninit;
    unsafe {
        let mut termios = MaybeUninit::<libc::termios>::uninit();
        if libc::tcgetattr(fd, termios.as_mut_ptr()) == 0 {
            let mut termios = termios.assume_init();
            termios.c_iflag |= libc::IUTF8;
            let _ = libc::tcsetattr(fd, libc::TCSANOW, &termios);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn login_argv_invokes_shell_with_dash_l() {
        assert_eq!(login_argv_for("/bin/bash"), vec!["/bin/bash", "-l"]);
        assert_eq!(login_argv_for("/usr/bin/zsh"), vec!["/usr/bin/zsh", "-l"]);
    }

    /// `enable_iutf8` on the pty master sets IUTF8 on the slave's line discipline
    /// (they share termios on Linux). Verifies our mosh-parity IUTF8 plumbing.
    #[cfg(unix)]
    #[test]
    fn iutf8_set_via_master_reaches_slave() {
        use std::mem::MaybeUninit;
        unsafe {
            let (mut master, mut slave) = (0, 0);
            let rc = libc::openpty(
                &mut master,
                &mut slave,
                std::ptr::null_mut(),
                std::ptr::null(),
                std::ptr::null(),
            );
            assert_eq!(rc, 0, "openpty failed");

            // Start from a known state: clear IUTF8 on the slave.
            let mut t = MaybeUninit::<libc::termios>::uninit();
            assert_eq!(libc::tcgetattr(slave, t.as_mut_ptr()), 0);
            let mut t = t.assume_init();
            t.c_iflag &= !libc::IUTF8;
            assert_eq!(libc::tcsetattr(slave, libc::TCSANOW, &t), 0);

            // Our helper, applied to the master fd.
            enable_iutf8(master);

            // The slave now sees IUTF8 set.
            let mut t2 = MaybeUninit::<libc::termios>::uninit();
            assert_eq!(libc::tcgetattr(slave, t2.as_mut_ptr()), 0);
            let t2 = t2.assume_init();
            let set = t2.c_iflag & libc::IUTF8 != 0;

            libc::close(master);
            libc::close(slave);
            assert!(set, "IUTF8 should be set on the slave via the master fd");
        }
    }
}
