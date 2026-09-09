//! Messages with a severity, a subsystem, and a level that can turn them down.
//!
//! **Shaped after `flog`**, the C logging library two of the sibling projects
//! share as a submodule, because the holder asked for the same shape here and
//! because netcfgd had none of it. Every message this daemon emitted was
//! `eprintln!("netcfgd: ...")`: one stream, no severity, no subsystem, and no
//! way to ask for less. Measured on the reporting machine the same day this
//! was written, an adoption line printed every five seconds for twenty
//! minutes -- ordinary, correct, and indistinguishable at a glance from the
//! failure that was causing it.
//!
//! Three things come from flog and one does not.
//!
//! **The severity vocabulary is flog's**, name for name: critical, error,
//! warning, note, info, verbose info, debug. So is the rendering -- flog
//! prints `[subsystem] Error: text`, prints `!` for a note, and prints no
//! label at all for info, on the argument that the ordinary case should read
//! as a sentence rather than as a log line.
//!
//! **The accept mask is flog's** too. flog holds a bitmask of the types an
//! output takes; this holds the same idea as a threshold, because netcfgd's
//! severities are ordered and a mask that cannot express "warnings but not
//! errors" is a mask nobody wanted. `FLOG_ACCEPT_*` is the shape being
//! copied, not the bit pattern.
//!
//! **The subsystem is flog's fourth argument** and the thing netcfgd most
//! obviously lacked: `dhcp`, `supplicant`, `confirm`, `netlink`, `portal`.
//! With it, `journalctl -u netcfgd | grep '\[dhcp\]'` is a question somebody
//! can ask.
//!
//! **What is deliberately not copied: message ids and source location.**
//! flog carries both for embedded targets, where a numeric id saves the
//! string table and `__FILE__` is how a crash is placed. netcfgd runs under a
//! journal that timestamps and attributes every line, its messages are
//! sentences an operator reads rather than codes a receiver decodes, and
//! `file:line` in an operator-facing message is noise. Decision 0187.

use std::io::Write as _;
use std::sync::atomic::{AtomicU8, Ordering};

/// What a message is, in flog's vocabulary.
///
/// Ordered, most severe first, because the accept level is a threshold and
/// `PartialOrd` on the discriminant is what makes the comparison read the way
/// it does in `flog`'s `FLOG_ACCEPT_*` masks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
	/// The daemon cannot continue doing the thing it exists to do.
	Critical,
	/// Something asked for did not happen.
	Error,
	/// Something happened that the operator would want to have chosen.
	Warning,
	/// Worth noticing on an ordinary day.
	Note,
	/// The ordinary running commentary.
	Info,
	/// The commentary somebody debugging asked for.
	Verbose,
	/// For whoever is working on netcfgd itself.
	Debug,
}

impl Severity {
	/// The label flog prints, or `None` where it prints none.
	///
	/// Info and verbose carry no label on purpose: the ordinary line is a
	/// sentence, and `Info:` in front of every one of them is furniture.
	#[must_use]
	pub fn label(self) -> Option<&'static str> {
		match self {
			Self::Critical => Some("Critical"),
			Self::Error => Some("Error"),
			Self::Warning => Some("Warning"),
			Self::Note => Some("!"),
			Self::Info | Self::Verbose => None,
			Self::Debug => Some("Debug"),
		}
	}

	/// The name `NCFG_LOG` takes, and the one a diagnostic prints back.
	#[must_use]
	pub fn name(self) -> &'static str {
		match self {
			Self::Critical => "critical",
			Self::Error => "error",
			Self::Warning => "warning",
			Self::Note => "note",
			Self::Info => "info",
			Self::Verbose => "verbose",
			Self::Debug => "debug",
		}
	}

	/// The level a name asks for, or `None` for a word this does not know.
	#[must_use]
	pub fn from_name(text: &str) -> Option<Self> {
		[
			Self::Critical,
			Self::Error,
			Self::Warning,
			Self::Note,
			Self::Info,
			Self::Verbose,
			Self::Debug,
		]
		.into_iter()
		.find(|level| level.name() == text)
	}
}

/// The level accepted, as a discriminant so it can live in an atomic.
///
/// `Info` by default, which is what netcfgd printed before it had levels at
/// all: a change of shape must not also be a change of what an operator sees
/// on an ordinary machine.
static ACCEPTED: AtomicU8 = AtomicU8::new(Severity::Info as u8);

/// Take the level from the environment, once, at startup.
///
/// **`NCFG_LOG` and nothing cleverer.** A config key would mean a level that
/// only applies after the configuration has been read, which is exactly the
/// window somebody debugging a startup problem cares about.
pub fn accept_from_env() {
	if let Ok(text) = std::env::var("NCFG_LOG") {
		if let Some(level) = Severity::from_name(text.trim()) {
			accept(level);
		} else {
			// Said rather than ignored: a misspelt level that silently keeps
			// the default is the whole family of faults this tree spent a day
			// on.
			emit(
				"log",
				Severity::Warning,
				&format!(
					"NCFG_LOG=`{}` is not a level, so `{}` still applies. Levels: \
					 critical, error, warning, note, info, verbose, debug",
					text.trim(),
					accepted().name()
				),
			);
		}
	}
}

/// Set the level messages are taken at.
pub fn accept(level: Severity) {
	ACCEPTED.store(level as u8, Ordering::Relaxed);
}

/// The level in force.
#[must_use]
pub fn accepted() -> Severity {
	match ACCEPTED.load(Ordering::Relaxed) {
		0 => Severity::Critical,
		1 => Severity::Error,
		2 => Severity::Warning,
		3 => Severity::Note,
		5 => Severity::Verbose,
		6 => Severity::Debug,
		_ => Severity::Info,
	}
}

/// Emit one message, if the level takes it.
///
/// The rendering is flog's: `[subsystem] Label: text`, with no label for the
/// ordinary levels. The `netcfgd:` in front is netcfgd's own and predates
/// this -- a line read out of a terminal, a `journalctl -f` of several units,
/// or a bug report pasted into a mail says which program is speaking.
///
/// **One `write!` and not two.** Two would let another thread's line land
/// between the prefix and the text, which is how interleaved logs are made.
pub fn emit(subsystem: &str, severity: Severity, text: &str) {
	if severity > accepted() {
		return;
	}
	let line = match severity.label() {
		Some(label) => format!("netcfgd: [{subsystem}] {label}: {text}\n"),
		None => format!("netcfgd: [{subsystem}] {text}\n"),
	};
	let _ = std::io::stderr().write_all(line.as_bytes());
}

/// `netcfgd_sys::log_at!(subsystem, severity, "...", args)`.
///
/// The formatting is done by the caller's `format!`, so a message the level
/// refuses still costs its arguments. That is the trade flog makes too --
/// `flog_printf` formats before it filters -- and it is the right one here:
/// netcfgd's messages are rare enough that a saved `format!` is not worth a
/// macro that hides control flow.
#[macro_export]
macro_rules! log_at {
	($subsystem:expr, $severity:expr, $($arg:tt)*) => {
		$crate::log::emit($subsystem, $severity, &format!($($arg)*))
	};
}

/// A failure: something asked for did not happen.
#[macro_export]
macro_rules! log_error {
	($subsystem:expr, $($arg:tt)*) => {
		$crate::log_at!($subsystem, $crate::log::Severity::Error, $($arg)*)
	};
}

/// Something happened that the operator would want to have chosen.
#[macro_export]
macro_rules! log_warning {
	($subsystem:expr, $($arg:tt)*) => {
		$crate::log_at!($subsystem, $crate::log::Severity::Warning, $($arg)*)
	};
}

/// Worth noticing on an ordinary day.
#[macro_export]
macro_rules! log_note {
	($subsystem:expr, $($arg:tt)*) => {
		$crate::log_at!($subsystem, $crate::log::Severity::Note, $($arg)*)
	};
}

/// The ordinary running commentary.
#[macro_export]
macro_rules! log_info {
	($subsystem:expr, $($arg:tt)*) => {
		$crate::log_at!($subsystem, $crate::log::Severity::Info, $($arg)*)
	};
}

#[cfg(test)]
mod tests {
	use super::{accept, accepted, Severity};

	/// The order is the whole mechanism: a threshold only works if a more
	/// severe message compares as smaller.
	#[test]
	fn severities_are_ordered_from_most_severe() {
		assert!(Severity::Critical < Severity::Error);
		assert!(Severity::Error < Severity::Warning);
		assert!(Severity::Warning < Severity::Note);
		assert!(Severity::Note < Severity::Info);
		assert!(Severity::Info < Severity::Verbose);
		assert!(Severity::Verbose < Severity::Debug);
	}

	/// **Info by default**, because a change of shape must not be a change of
	/// what an ordinary machine prints.
	#[test]
	fn the_default_level_is_what_netcfgd_printed_before_it_had_levels() {
		assert_eq!(accepted(), Severity::Info);
		assert!(Severity::Error <= accepted(), "an error is taken");
		assert!(Severity::Note <= accepted(), "a note is taken");
		assert!(Severity::Debug > accepted(), "debug is not");
	}

	/// Every level round-trips through the name `NCFG_LOG` takes, or the
	/// environment variable can name a level nothing can select.
	#[test]
	fn every_level_is_reachable_by_name() {
		for level in [
			Severity::Critical,
			Severity::Error,
			Severity::Warning,
			Severity::Note,
			Severity::Info,
			Severity::Verbose,
			Severity::Debug,
		] {
			assert_eq!(Severity::from_name(level.name()), Some(level), "{level:?}");
			// And the discriminant survives the atomic, which is the other
			// half of the round trip and the one a wrong `accepted()` arm
			// would break silently.
			accept(level);
			assert_eq!(accepted(), level, "{level:?} through the atomic");
		}
		accept(Severity::Info);
		assert_eq!(Severity::from_name("shouting"), None);
	}

	/// flog prints no label for the ordinary levels and a word for the rest,
	/// and this is the one place that could drift from it.
	#[test]
	fn the_labels_are_flogs() {
		assert_eq!(Severity::Critical.label(), Some("Critical"));
		assert_eq!(Severity::Error.label(), Some("Error"));
		assert_eq!(Severity::Warning.label(), Some("Warning"));
		assert_eq!(Severity::Note.label(), Some("!"));
		assert_eq!(Severity::Info.label(), None);
		assert_eq!(Severity::Verbose.label(), None);
		assert_eq!(Severity::Debug.label(), Some("Debug"));
	}
}
