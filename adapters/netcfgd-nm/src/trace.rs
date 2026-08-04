//! A ring of timestamped checkpoints, for a stall that disappears when watched.
//!
//! `ActivateConnection` occasionally returns no reply at all, nmcli gives up at
//! `GDBus`'s twenty-five-second default, and the secret agent is never asked --
//! its log stops at `registered` ([0106]). Instrumenting the handler with
//! `eprintln!` to find out where made it stop happening: eighteen consecutive
//! clean runs against a stall that had reproduced twice in four. A write
//! syscall per checkpoint is enough to move it.
//!
//! So this records into memory instead. A checkpoint is a monotonic timestamp
//! and a `&'static str`: no formatting, no allocation, no syscall, and an
//! uncontended mutex. The ring is dumped **after** the fact -- by a watchdog
//! thread that notices a handler has been in flight too long -- so nothing on
//! the path being measured ever writes to a file descriptor.
//!
//! Off unless `NCFG_NM_TRACE` is set, and then the cost is one relaxed atomic
//! load per checkpoint. This is a diagnostic for a specific open question, not
//! a logging framework, and it is meant to be removed when the question is
//! answered.
//!
//! [0106]: ../../../docs/decisions/0106-two-twenty-five-second-timers-racing.md

use std::collections::VecDeque;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

/// How many checkpoints to keep. One activation records a handful, so this
/// holds a long run's worth and still fits in a few tens of kilobytes.
const CAPACITY: usize = 4096;

/// How long a handler may be in flight before the watchdog decides it is stuck.
///
/// Under the twenty-five seconds nmcli waits, so the dump describes a stall
/// that is still happening rather than one that has already been given up on.
const STUCK_AFTER: Duration = Duration::from_secs(10);

/// How often the watchdog looks. Far coarser than the thing being measured,
/// because it must not itself be a source of scheduling noise.
const WATCH_EVERY: Duration = Duration::from_millis(250);

/// One checkpoint: when, and where.
type Entry = (u64, &'static str);

static RING: Mutex<VecDeque<Entry>> = Mutex::new(VecDeque::new());

/// The zero for every timestamp, so they are small and comparable.
fn origin() -> Instant {
	static ORIGIN: OnceLock<Instant> = OnceLock::new();
	*ORIGIN.get_or_init(Instant::now)
}

/// Microseconds since the first checkpoint.
///
/// `Instant::now` is a vDSO clock read on Linux -- no syscall, which is the
/// property that matters here.
fn stamp() -> u64 {
	u64::try_from(origin().elapsed().as_micros()).unwrap_or(u64::MAX)
}

/// Whether tracing was asked for, decided once.
pub(crate) fn enabled() -> bool {
	static ENABLED: OnceLock<bool> = OnceLock::new();
	*ENABLED.get_or_init(|| std::env::var_os("NCFG_NM_TRACE").is_some())
}

/// When the handler currently in flight started, or 0 for none.
static IN_FLIGHT_SINCE: AtomicU64 = AtomicU64::new(0);
/// The span the watchdog has already reported, so it says it once.
static REPORTED: AtomicU64 = AtomicU64::new(0);

/// Record reaching a point, by a name that is a compile-time constant.
///
/// `&'static str` rather than a `String` on purpose: the cost of a checkpoint
/// has to stay below the thing being measured, and formatting a message is the
/// part that would not.
pub(crate) fn mark(label: &'static str) {
	if !enabled() {
		return;
	}
	let at = stamp();
	if let Ok(mut ring) = RING.lock() {
		if ring.len() == CAPACITY {
			ring.pop_front();
		}
		ring.push_back((at, label));
	}
}

/// Record entering a handler that must not stall, and start its clock.
pub(crate) fn enter(label: &'static str) {
	if !enabled() {
		return;
	}
	mark(label);
	IN_FLIGHT_SINCE.store(stamp().max(1), Ordering::Relaxed);
}

/// Record leaving it, and stop the clock.
pub(crate) fn leave(label: &'static str) {
	if !enabled() {
		return;
	}
	IN_FLIGHT_SINCE.store(0, Ordering::Relaxed);
	mark(label);
}

/// The bus name of whatever the shim last asked for a secret.
///
/// A `String` and not a `&'static str`, so it cannot live in the ring -- but it
/// is written once per activation rather than per checkpoint, so the allocation
/// is nowhere near the path whose timing matters. Which agent was asked turns
/// out to be the whole question.
static LAST_ASKED: Mutex<String> = Mutex::new(String::new());

/// Record who is about to be asked for a secret.
pub(crate) fn asking(name: &str) {
	if !enabled() {
		return;
	}
	if let Ok(mut last) = LAST_ASKED.lock() {
		last.clear();
		last.push_str(name);
	}
}

/// Write the ring to stderr, newest last, with the gaps made obvious.
///
/// Called from the watchdog thread, never from a traced path: the point of the
/// ring is that the measured code does no I/O.
pub(crate) fn dump(reason: &str) {
	if !enabled() {
		return;
	}
	let Ok(ring) = RING.lock() else {
		return;
	};
	eprintln!("nm-trace: {reason}");
	if let Ok(last) = LAST_ASKED.lock() {
		if !last.is_empty() {
			eprintln!("nm-trace:   last agent asked for a secret: {last}");
		}
	}
	let mut previous: Option<u64> = None;
	for (at, label) in ring.iter() {
		let gap = previous.map_or(0, |last| at.saturating_sub(last));
		// The gap is what the reader is looking for: a checkpoint that is
		// seconds after the one before it is where the stall is.
		eprintln!("nm-trace:   +{gap:>9}us  @{at:>10}us  {label}");
		previous = Some(*at);
	}
	eprintln!("nm-trace: end");
}

/// Watch for a handler that went in and did not come out.
///
/// A thread rather than a timeout inside the handler, because a handler that is
/// stuck is precisely one that will not reach its own timeout check. Started
/// only when tracing is on, so a shim in ordinary use has neither the thread
/// nor the ring.
pub(crate) fn spawn_watchdog() {
	if !enabled() {
		return;
	}
	let _ = origin();
	let spawned = std::thread::Builder::new()
		.name("nm-trace".to_owned())
		.spawn(|| loop {
			std::thread::sleep(WATCH_EVERY);
			let since = IN_FLIGHT_SINCE.load(Ordering::Relaxed);
			if since == 0 {
				continue;
			}
			let stuck_for = stamp().saturating_sub(since);
			if u128::from(stuck_for) < STUCK_AFTER.as_micros() {
				continue;
			}
			if REPORTED.swap(since, Ordering::Relaxed) == since {
				continue;
			}
			dump(&format!(
				"a handler has been in flight for {stuck_for}us -- the ring follows"
			));
		});
	if spawned.is_err() {
		eprintln!("nm-trace: could not start the watchdog thread");
	}
}
