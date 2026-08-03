#![forbid(unsafe_code)]
//! A temporary directory that takes itself away again.
//!
//! Every crate here has tests that build a directory of files, and every one of
//! them wrote `let _ = std::fs::remove_dir_all(&dir);` as the last line -- which
//! a panicking test never reaches. So a failing test leaked a directory into
//! `/tmp`, silently: nothing here is red for a leaked directory, and the only
//! reason anybody looked was habit. One tree of them had reached 1252.
//!
//! The answer is a value whose `Drop` does it, because `Drop` runs while the
//! stack unwinds and a trailing line does not. This crate exists so that answer
//! is written once rather than in fourteen test modules -- two copies of a rule
//! is how two of them come to disagree about it, which this project has paid to
//! learn more than once.
//!
//! **A dev dependency only.** Nothing links it into a binary, so it costs
//! nothing to install and nothing to the size budget.
//!
//! ```
//! let dir = netcfgd_testdir::TestDir::new("example");
//! std::fs::write(dir.join("netcfgd.conf"), "interface eth0 { }\n").expect("written");
//! assert!(dir.join("netcfgd.conf").is_file());
//! // and it is gone when `dir` goes, panic or no panic
//! ```

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};

/// How many have been made in this process, so two in one test do not collide.
///
/// The process id alone is not enough -- tests in one binary share it, and they
/// run in parallel by default -- and a fixed name is worse still: two tests
/// racing on one directory is a failure that only appears under load.
static SERIAL: AtomicUsize = AtomicUsize::new(0);

/// A directory under the system temporary directory, removed when this is
/// dropped.
///
/// Dereferences to [`Path`], so `dir.join("x")` and `&dir` work wherever a path
/// is wanted and the call sites read as they did before.
#[derive(Debug)]
pub struct TestDir {
	path: PathBuf,
}

impl TestDir {
	/// Make one, named after the test that wanted it.
	///
	/// The tag is for the human who finds one that survived -- a crash, a
	/// `SIGKILL`, a machine that lost power -- so it should say which test.
	///
	/// # Panics
	///
	/// If the directory cannot be created, which is a broken machine rather than
	/// a test failure and is worth saying so immediately.
	#[must_use]
	pub fn new(tag: &str) -> Self {
		let serial = SERIAL.fetch_add(1, Ordering::Relaxed);
		let path = std::env::temp_dir().join(format!("ncfg-{tag}-{}-{serial}", std::process::id()));
		// Removed first: a previous run that was killed rather than dropped
		// leaves one behind, and a test that finds stale files in it fails for a
		// reason that has nothing to do with what it is testing.
		let _ = std::fs::remove_dir_all(&path);
		std::fs::create_dir_all(&path)
			.unwrap_or_else(|error| panic!("cannot make {}: {error}", path.display()));
		Self { path }
	}

	/// The path itself, where a `&Path` is wanted explicitly.
	#[must_use]
	pub fn path(&self) -> &Path {
		&self.path
	}
}

impl std::ops::Deref for TestDir {
	type Target = Path;

	fn deref(&self) -> &Path {
		&self.path
	}
}

impl AsRef<Path> for TestDir {
	fn as_ref(&self) -> &Path {
		&self.path
	}
}

/// So that a `TestDir` goes wherever a path-shaped argument is taken, including
/// the `impl Into<PathBuf>` signatures that are common here. Without it every
/// call site would need a `.path()`, which is the kind of churn that stops a
/// change like this being made at all.
impl AsRef<std::ffi::OsStr> for TestDir {
	fn as_ref(&self) -> &std::ffi::OsStr {
		self.path.as_os_str()
	}
}

impl Drop for TestDir {
	fn drop(&mut self) {
		// Failure is ignored on purpose: this runs while a test may already be
		// panicking, and a second panic while unwinding aborts the process --
		// which would turn "one test failed" into "the suite died", hiding the
		// failure that mattered.
		let _ = std::fs::remove_dir_all(&self.path);
	}
}

#[cfg(test)]
mod tests {
	use super::TestDir;

	/// The whole point: the directory is gone after the value is.
	#[test]
	fn it_removes_itself() {
		let path;
		{
			let dir = TestDir::new("selftest");
			path = dir.to_path_buf();
			std::fs::write(dir.join("file"), "x").expect("written");
			assert!(path.is_dir());
		}
		assert!(!path.exists(), "{} survived its guard", path.display());
	}

	/// And it survives the case it exists for: a panic, where a tidy-up line at
	/// the end of a test is never reached.
	#[test]
	fn it_removes_itself_when_a_test_panics() {
		let path = std::panic::catch_unwind(|| {
			let dir = TestDir::new("panicking");
			let path = dir.to_path_buf();
			std::fs::write(dir.join("file"), "x").expect("written");
			// What a failing assertion does, with the directory still live.
			std::panic::panic_any(path);
		})
		.expect_err("the closure panics");
		let path = path
			.downcast::<std::path::PathBuf>()
			.expect("the panic carries the path");
		assert!(!path.exists(), "{} survived a panic", path.display());
	}

	/// Two in one process do not collide, which a fixed name or the pid alone
	/// would not give.
	#[test]
	fn two_do_not_collide() {
		let first = TestDir::new("same");
		let second = TestDir::new("same");
		assert_ne!(first.path(), second.path());
	}
}
