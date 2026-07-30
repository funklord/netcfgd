//! Watching the config directory, whichever way the system allows.
//!
//! inotify where it works, mtime polling where it does not. The fallback is
//! not defensive programming for its own sake: `inotify_init1` fails with
//! `EMFILE` when `fs.inotify.max_user_instances` is exhausted, which happens
//! on real machines running enough watchers, and some container runtimes and
//! hardened kernels restrict it outright. A config daemon that stops noticing
//! config changes because a limit somewhere else was reached is a worse
//! outcome than one that polls.
//!
//! Both paths answer the same question -- "did anything change?" -- and both
//! answer it the same way netlink does: by saying that something moved, not by
//! saying what. The caller re-reads and recompiles, so a missed detail costs
//! nothing and a missed *event* is what matters.

use crate::inotify::{mask, Inotify};
use std::io;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

/// Which mechanism a watcher ended up with.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mechanism {
	/// The kernel tells us.
	Inotify,
	/// We ask, repeatedly.
	Polling,
}

impl Mechanism {
	/// A name for logs and for `ncfg status`, because an operator debugging a
	/// reload that did not happen needs to know which one is in play.
	#[must_use]
	pub fn name(self) -> &'static str {
		match self {
			Self::Inotify => "inotify",
			Self::Polling => "mtime polling",
		}
	}
}

/// Watches a set of directories for any change.
pub struct Watcher {
	inotify: Option<Inotify>,
	paths: Vec<PathBuf>,
	fingerprint: Vec<(PathBuf, Option<SystemTime>)>,
	mechanism: Mechanism,
}

impl Watcher {
	/// Watch these directories, preferring inotify.
	///
	/// Never fails: a directory that does not exist yet is still watched by
	/// the polling path, and its appearance counts as a change. That matters
	/// because `conf.d/` is created the first time somebody writes a drop-in.
	#[must_use]
	pub fn new(paths: &[PathBuf]) -> Self {
		let inotify = Inotify::new().ok().filter(|inotify| {
			// A descriptor with no successful watch is worse than none: it
			// would block forever reporting nothing. Insist on at least one.
			paths
				.iter()
				.filter(|path| path.is_dir())
				.filter_map(|path| inotify.watch(path, mask::CONFIG).ok())
				.count() > 0
		});

		let mechanism = if inotify.is_some() {
			Mechanism::Inotify
		} else {
			Mechanism::Polling
		};

		let mut watcher = Self {
			inotify,
			paths: paths.to_vec(),
			fingerprint: Vec::new(),
			mechanism,
		};
		watcher.fingerprint = watcher.take_fingerprint();
		watcher
	}

	/// Watch these directories without inotify.
	///
	/// Public rather than test-only for two reasons: an operator debugging a
	/// reload that is not happening wants to take inotify out of the picture,
	/// and a fallback that only runs when something else has already gone
	/// wrong is a fallback nobody has ever seen work. The tests use it to
	/// exercise both paths against the same assertions.
	#[must_use]
	pub fn polling(paths: &[PathBuf]) -> Self {
		let mut watcher = Self {
			inotify: None,
			paths: paths.to_vec(),
			fingerprint: Vec::new(),
			mechanism: Mechanism::Polling,
		};
		watcher.fingerprint = watcher.take_fingerprint();
		watcher
	}

	/// Which mechanism is in use.
	#[must_use]
	pub fn mechanism(&self) -> Mechanism {
		self.mechanism
	}

	/// Wait up to `timeout_ms` for a change.
	///
	/// Returns false on timeout, so a caller can use this as its own tick.
	///
	/// # Errors
	///
	/// Returns the underlying `io::Error` only where the watch itself failed
	/// in a way that is not recoverable by looking again.
	pub fn wait(&mut self, timeout_ms: i32) -> io::Result<bool> {
		if let Some(inotify) = &self.inotify {
			let events = inotify.wait(timeout_ms)?;
			if events.is_empty() {
				return Ok(false);
			}
			// The fingerprint is kept current even on the inotify path, so
			// that a later fall back to polling does not immediately report a
			// change that was already handled.
			self.fingerprint = self.take_fingerprint();
			return Ok(true);
		}

		std::thread::sleep(std::time::Duration::from_millis(
			u64::try_from(timeout_ms.max(0)).unwrap_or(0),
		));
		let current = self.take_fingerprint();
		if current == self.fingerprint {
			return Ok(false);
		}
		self.fingerprint = current;
		Ok(true)
	}

	/// Every watched path and every `.conf` beneath it, with its mtime.
	///
	/// A file that does not exist contributes `None` rather than being
	/// omitted, so its appearance and its disappearance both change the
	/// fingerprint. Omitting it would make a deleted drop-in invisible.
	fn take_fingerprint(&self) -> Vec<(PathBuf, Option<SystemTime>)> {
		let mut out = Vec::new();
		for path in &self.paths {
			out.push((path.clone(), mtime(path)));
			let Ok(entries) = std::fs::read_dir(path) else {
				continue;
			};
			let mut children: Vec<PathBuf> = entries
				.filter_map(Result::ok)
				.map(|entry| entry.path())
				.collect();
			// Sorted, or the fingerprint would differ run to run on directory
			// order alone and every tick would look like a change.
			children.sort();
			for child in children {
				let stamp = mtime(&child);
				out.push((child, stamp));
			}
		}
		out
	}
}

fn mtime(path: &Path) -> Option<SystemTime> {
	std::fs::metadata(path)
		.ok()
		.and_then(|metadata| metadata.modified().ok())
}
