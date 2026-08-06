//! Commit-confirm's persistent half.
//!
//! The window has to outlive the process that opened it, or a daemon restart
//! at the wrong moment would leave a machine configured with something nobody
//! ever confirmed. So the armed state and the document to go back to are both
//! files, written before the change is applied rather than after.

use crate::state::write_atomic;
use netcfgd_model::Document;
use serde::{Deserialize, Serialize};
use std::fs;
use std::io;
use std::path::Path;
use std::time::{Duration, SystemTime};

/// An open commit-confirm window.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Window {
	/// When the window closes, as seconds since the epoch.
	///
	/// An absolute deadline rather than a duration, so that a daemon which
	/// restarts inside the window knows how much of it is left without having
	/// to trust its own uptime.
	pub deadline_epoch: u64,
	/// How long the window was, for reporting.
	pub window_seconds: u32,
	/// Hash of the document to revert to.
	pub last_good_hash: String,
}

impl Window {
	/// Whether the window has closed.
	#[must_use]
	pub fn expired(&self) -> bool {
		self.expired_at(now_epoch())
	}

	/// How long is left, saturating at zero.
	#[must_use]
	pub fn remaining(&self) -> Duration {
		self.remaining_at(now_epoch())
	}

	/// Whether the window has closed, against a clock the caller supplies.
	///
	/// Split out from [`Window::expired`] so the interesting cases can be
	/// tested at all: a machine that slept through the window, and a clock
	/// somebody moved. Reading `SystemTime::now()` inside the comparison made
	/// both of those unwritable, which is why neither had ever been checked.
	#[must_use]
	pub fn expired_at(&self, now: u64) -> bool {
		now >= self.deadline_epoch
	}

	/// How long is left against a supplied clock, saturating at zero.
	#[must_use]
	pub fn remaining_at(&self, now: u64) -> Duration {
		Duration::from_secs(self.deadline_epoch.saturating_sub(now))
	}
}

/// Seconds since the epoch, or zero if the clock is before it.
#[must_use]
pub fn now_epoch() -> u64 {
	SystemTime::now()
		.duration_since(SystemTime::UNIX_EPOCH)
		.map_or(0, |since| since.as_secs())
}

/// Open a window ending `window_seconds` from now.
#[must_use]
pub fn arm(window_seconds: u32, last_good_hash: String) -> Window {
	Window {
		deadline_epoch: now_epoch() + u64::from(window_seconds),
		window_seconds,
		last_good_hash,
	}
}

/// The open window, if there is one.
#[must_use]
pub fn read_window(run_dir: &Path) -> Option<Window> {
	fs::read_to_string(run_dir.join("confirm.json"))
		.ok()
		.and_then(|text| serde_json::from_str(&text).ok())
}

/// Record an open window.
///
/// # Errors
///
/// Returns an `io::Error` if the file cannot be written.
pub fn write_window(run_dir: &Path, window: &Window) -> io::Result<()> {
	let text = serde_json::to_string_pretty(window)
		.map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
	write_atomic(&run_dir.join("confirm.json"), &text)
}

/// Close the window.
///
/// # Errors
///
/// Returns an `io::Error` for anything but the file already being absent.
pub fn clear_window(run_dir: &Path) -> io::Result<()> {
	match fs::remove_file(run_dir.join("confirm.json")) {
		Ok(()) => Ok(()),
		Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
		Err(error) => Err(error),
	}
}

/// The last configuration that was applied and stood.
#[must_use]
pub fn read_last_good(run_dir: &Path) -> Option<Document> {
	let text = fs::read_to_string(run_dir.join("last-good.json")).ok()?;
	Document::from_json(&text).ok()
}

/// Record a configuration as the one to fall back to.
///
/// # Errors
///
/// Returns an `io::Error`, or the model's own error rendered as one.
pub fn write_last_good(run_dir: &Path, document: &Document) -> io::Result<()> {
	let text = document
		.to_json_canonical()
		.map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error.to_string()))?;
	write_atomic(&run_dir.join("last-good.json"), &text)
}

/// A document's identity, for naming which one a revert targets.
///
/// The canonical encoding is what makes this meaningful: two compiles of one
/// config produce the same bytes and therefore the same hash, so a hash
/// identifies a configuration rather than a compilation.
///
/// `generated_by` is cleared first, because the model excludes it from
/// equality -- section 2.1 calls it informational, and two documents differing
/// only there describe the same desired state. Hashing it would make a rebuild
/// under a new version look like a different configuration, which is exactly
/// the case the rejection guard must not be fooled by: the same broken config
/// from a newer binary is still the same broken config.
#[must_use]
pub fn document_hash(document: &Document) -> String {
	let mut bare = document.clone();
	bare.generated_by = None;
	bare.to_json_canonical().map_or_else(
		|_| "unhashable".to_owned(),
		|text| crate::hooks::sha256_hex(text.as_bytes()),
	)
}

#[cfg(test)]
mod tests {
	use super::*;

	fn document_with_confirm(seconds: u32) -> Document {
		Document {
			globals: netcfgd_model::Globals {
				confirm_default: Some(seconds),
				..netcfgd_model::Globals::default()
			},
			..Document::default()
		}
	}

	/// A scratch directory that removes itself when the test ends -- panic or
	/// no panic, which a tidy-up line at the end of a test cannot do.
	fn scratch(name: &str) -> netcfgd_testdir::TestDir {
		netcfgd_testdir::TestDir::new(&format!("confirm-{name}"))
	}

	#[test]
	fn a_window_round_trips_through_the_file() {
		let dir = scratch("roundtrip");
		let window = arm(120, "abc123".to_owned());
		write_window(&dir, &window).expect("writes");
		assert_eq!(read_window(&dir), Some(window));
		let _ = fs::remove_dir_all(&dir);
	}

	/// The deadline is absolute, so a daemon restarting inside the window
	/// knows how much is left without trusting its own uptime.
	#[test]
	fn a_window_that_has_passed_reports_expired() {
		let past = Window {
			deadline_epoch: now_epoch().saturating_sub(1),
			window_seconds: 60,
			last_good_hash: "x".to_owned(),
		};
		assert!(past.expired());
		assert_eq!(past.remaining(), Duration::from_secs(0));

		let future = arm(60, "x".to_owned());
		assert!(!future.expired());
		assert!(future.remaining().as_secs() > 55);
	}

	/// A window is wall-clock, so a machine that sleeps through it wakes with
	/// it already closed. That is the property suspend needs and the reason
	/// the deadline is an epoch rather than a monotonic instant: `Instant`
	/// does not advance across a suspend, so a window stored that way would
	/// come back with its whole duration still to run.
	///
	/// Pinned rather than argued about, because the consequence is a decision
	/// nobody has made: the first observation after the lid opens reverts a
	/// change the operator has been living with all night.
	#[test]
	fn a_window_does_not_survive_the_machine_sleeping_through_it() {
		let armed_at = 1_700_000_000;
		let window = Window {
			deadline_epoch: armed_at + 60,
			window_seconds: 60,
			last_good_hash: "x".to_owned(),
		};

		assert!(!window.expired_at(armed_at + 59));
		assert_eq!(window.remaining_at(armed_at + 59), Duration::from_secs(1));

		let eight_hours = armed_at + 8 * 60 * 60;
		assert!(window.expired_at(eight_hours));
		assert_eq!(window.remaining_at(eight_hours), Duration::from_secs(0));
	}

	/// The cost of wall-clock, stated where somebody deciding about it will
	/// look: the window is anchored to a clock other things move. A laptop
	/// usually takes an NTP correction shortly after resuming, and a step
	/// backwards lengthens an open window rather than leaving it alone.
	///
	/// Neither direction is asserted to be *right* here. The test exists so
	/// that changing it is a decision with a number attached rather than an
	/// accident.
	#[test]
	fn moving_the_clock_moves_an_open_window() {
		let armed_at = 1_700_000_000;
		let window = Window {
			deadline_epoch: armed_at + 60,
			window_seconds: 60,
			last_good_hash: "x".to_owned(),
		};

		// Stepped back an hour: the window that had 60s left now has an hour
		// and a minute, and nothing in netcfgd notices the jump.
		let back_an_hour = armed_at - 60 * 60;
		assert!(!window.expired_at(back_an_hour));
		assert_eq!(
			window.remaining_at(back_an_hour),
			Duration::from_secs(60 * 60 + 60)
		);

		// Stepped forward past the deadline: it closes early, and an operator
		// who was still deciding loses the change rather than the machine.
		assert!(window.expired_at(armed_at + 61));
	}

	/// Clearing is idempotent, because the expiry timer and an explicit revert
	/// can both reach it and neither should fail because the other won.
	#[test]
	fn clearing_an_absent_window_is_not_an_error() {
		let dir = scratch("clear");
		assert!(clear_window(&dir).is_ok());
		assert!(clear_window(&dir).is_ok());
		assert_eq!(read_window(&dir), None);
		let _ = fs::remove_dir_all(&dir);
	}

	/// A hash identifies a configuration rather than a compilation, which is
	/// what makes "the same config that was rejected" a decidable question.
	#[test]
	fn the_hash_follows_the_document_not_the_compile() {
		let one = document_with_confirm(30);
		let two = document_with_confirm(30);
		assert_eq!(document_hash(&one), document_hash(&two));
		assert_ne!(
			document_hash(&one),
			document_hash(&document_with_confirm(31))
		);
	}

	/// Provenance is excluded from the document's identity, so a rebuild does
	/// not look like a different configuration to the rejection check.
	#[test]
	fn generated_by_does_not_change_the_hash() {
		let one = Document {
			generated_by: Some("netcfgd 0.1".to_owned()),
			..Document::default()
		};
		let two = Document {
			generated_by: Some("netcfgd 0.2".to_owned()),
			..Document::default()
		};
		assert_eq!(one, two, "the model excludes provenance from equality");
		assert_eq!(
			document_hash(&one),
			document_hash(&two),
			"so the hash must exclude it too"
		);
	}

	#[test]
	fn a_last_good_document_round_trips() {
		let dir = scratch("lastgood");
		let document = document_with_confirm(90);
		write_last_good(&dir, &document).expect("writes");
		assert_eq!(read_last_good(&dir), Some(document));
		let _ = fs::remove_dir_all(&dir);
	}
}
