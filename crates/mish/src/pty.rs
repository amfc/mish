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

/// A spawned child process on a PTY, exposed as channels.
pub struct PtyProcess {
    /// Child output bytes (stdout + stderr on the PTY).
    pub output: mpsc::Receiver<Vec<u8>>,
    /// Control messages (input bytes / resize) for the child.
    pub control: mpsc::UnboundedSender<PtyControl>,
}

impl PtyProcess {
    /// Spawn `command` on a new PTY of the given size.
    pub fn spawn(command: &str, cols: u16, rows: u16) -> Result<Self> {
        let pty_system = native_pty_system();
        let pair = pty_system.openpty(PtySize {
            rows,
            cols,
            pixel_width: 0,
            pixel_height: 0,
        })?;

        let mut cmd = CommandBuilder::new(command);
        cmd.env("TERM", "xterm-256color");
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
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        if out_tx.blocking_send(buf[..n].to_vec()).is_err() {
                            break;
                        }
                    }
                }
            }
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
