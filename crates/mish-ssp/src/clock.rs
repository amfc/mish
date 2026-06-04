//! Time abstraction.
//!
//! The SSP protocol core ([`crate::core::SspCore`]) is *sans-IO*: it never reads
//! a clock itself. Instead, every method that needs the current time takes a
//! `now` argument expressed in [`Millis`] (monotonic milliseconds). This makes
//! the core fully deterministic and lets simulation tests drive virtual time.
//!
//! The async driver ([`crate::session`]) is the only place that reads a real
//! clock, via the [`Clock`] trait, so it too can be swapped for a virtual clock.

/// Monotonic time in milliseconds. Mirrors mosh's `timestamp()`.
pub type Millis = u64;

/// Sentinel meaning "never" / "infinitely far in the future".
pub const NEVER: Millis = u64::MAX;

/// A source of monotonic time, injectable for simulation.
pub trait Clock: Send + Sync + 'static {
    /// Current monotonic time in milliseconds.
    fn now_ms(&self) -> Millis;
}

/// Real wall-clock-backed monotonic clock, anchored at construction.
pub struct SystemClock {
    origin: std::time::Instant,
}

impl SystemClock {
    pub fn new() -> Self {
        Self {
            origin: std::time::Instant::now(),
        }
    }
}

impl Default for SystemClock {
    fn default() -> Self {
        Self::new()
    }
}

impl Clock for SystemClock {
    fn now_ms(&self) -> Millis {
        self.origin.elapsed().as_millis() as Millis
    }
}
