//! An exclusive advisory lock, held for as long as the guard is alive.
//!
//! Here rather than beside the code that wants it, for the reason [`crate::term`]
//! gives about echo: constraint 4 confines `unsafe` to one audited crate, and
//! this is it -- not because it is the netlink crate, but because it is where
//! the libc boundary lives.
//!
//! **Why not `std::fs::File::lock`.** It exists and does exactly this, and it
//! is unstable: `file_lock` is not in 1.85, which is this workspace's
//! `rust-version` and also the rustc this machine has. Taking it would raise
//! the floor for everybody who builds netcfgd from a distribution toolchain,
//! which is a decision about who can compile this rather than a way of writing
//! four lines. Worth revisiting when the floor moves for a reason of its own.
//!
//! **Why `flock` and not a lock file created with `O_EXCL`.** The lock has to
//! survive whatever the holder does, including being killed: an `O_EXCL` file
//! outlives the process that made it, so every user of one needs a staleness
//! rule, and every staleness rule is a guess about how long the work takes. A
//! `flock` is held by the open file description and the kernel drops it when
//! the last descriptor closes, which a dying process does for free.

use std::fs::OpenOptions;
use std::io;
use std::os::fd::AsRawFd;
use std::path::Path;

/// An exclusive lock on a file, released when this is dropped.
///
/// The file's *contents* are not the point and are never read or written; what
/// is being locked is the name, so that two processes agree on who is midway
/// through a read-modify-write of something else.
#[derive(Debug)]
pub struct FileLock {
	/// Held because closing the descriptor is what releases the lock. Never
	/// read from or written to.
	file: std::fs::File,
}

impl FileLock {
	/// Take the exclusive lock, creating the file if it is not there.
	///
	/// **Blocks** until the lock is available, which is the behaviour that makes
	/// this useful: the caller wants the update to happen, not to be told that
	/// somebody else is updating. The critical sections it guards are a read, a
	/// serialisation and a rename.
	///
	/// # Errors
	///
	/// Returns an `io::Error` if the directory cannot be created, the file
	/// cannot be opened, or the lock cannot be taken. A caller that treats a
	/// failure as "carry on without the lock" is choosing the old behaviour
	/// deliberately and should say so.
	pub fn exclusive(path: &Path) -> io::Result<Self> {
		if let Some(parent) = path.parent() {
			std::fs::create_dir_all(parent)?;
		}
		// Opened for writing because a lock is a claim to change something, and
		// a descriptor opened read-only can still take `LOCK_EX` -- which would
		// make the mode say the opposite of what the caller means.
		let file = OpenOptions::new()
			.write(true)
			.create(true)
			.truncate(false)
			.open(path)?;

		// SAFETY: `flock` takes a descriptor and an integer and returns an
		// integer. No pointers. The descriptor is owned by `file`, which is
		// live for the rest of this function and is moved into the value
		// returned, so it cannot be closed while the lock is meant to be held.
		let rc = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) };
		if rc < 0 {
			return Err(io::Error::last_os_error());
		}
		Ok(Self { file })
	}
}

impl Drop for FileLock {
	fn drop(&mut self) {
		// `LOCK_UN` rather than leaving it to the close that follows
		// immediately after. Both release it, and the explicit call is what
		// makes the release visible at the point the guard ends -- a reader
		// should not have to know that `File`'s own `Drop` is what unlocks
		// this. A failure here is not actionable and is not reported: the
		// close on the next line releases the lock regardless.
		// SAFETY: as in `exclusive`. The descriptor is still owned by
		// `self.file`, which is dropped after this.
		unsafe {
			libc::flock(self.file.as_raw_fd(), libc::LOCK_UN);
		}
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	/// The lock is mutual between two descriptors of one file.
	///
	/// This is the property the whole module rests on and it is not the one
	/// POSIX record locks have: `fcntl` locks are owned by the *process*, so a
	/// second thread taking one would be handed it immediately and the guard
	/// would guard nothing. `flock` is owned by the open file description, so
	/// two `open` calls conflict whether or not they are in the same process --
	/// which is what makes a thread test meaningful evidence about two daemons.
	#[test]
	fn a_second_descriptor_waits_for_the_first() {
		let dir = netcfgd_testdir::TestDir::new("sys-lock");
		let path = dir.join("owned.lock");

		let held = FileLock::exclusive(&path).expect("the first lock");

		// Non-blocking, because the point is that it is *not* available. The
		// blocking call is what the daemon makes and is not what a test can
		// assert on without a deadline.
		let second = OpenOptions::new()
			.write(true)
			.create(true)
			.truncate(false)
			.open(&path)
			.expect("opened");
		// SAFETY: as in `exclusive`.
		let rc = unsafe { libc::flock(second.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
		assert_eq!(rc, -1, "a second exclusive lock must not be granted");
		assert_eq!(
			io::Error::last_os_error().raw_os_error(),
			Some(libc::EWOULDBLOCK),
			"refused for the wrong reason"
		);

		drop(held);

		// SAFETY: as above.
		let rc = unsafe { libc::flock(second.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
		assert_eq!(rc, 0, "the lock must be free once the guard is dropped");
	}
}
