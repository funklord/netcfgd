//! inotify, for noticing that the config directory changed.
//!
//! Not netlink, and in this crate anyway. Section 1 constraint 4 names
//! `netcfgd-netlink` as the single crate permitted `unsafe`, so what defines
//! it is the audit, not the protocol -- a second crate making raw syscalls
//! would mean a second thing to review to the same bar, which is exactly what
//! the constraint exists to prevent. See `docs/decisions/0012`.
//!
//! The split is the same as for netlink: the syscalls are here with SAFETY
//! comments, and the parsing of what comes back is entirely safe code in
//! [`Events`], with the same termination hazard and the same treatment.

use std::ffi::CString;
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;

/// Length of `struct inotify_event` before its trailing name.
pub const EVENT_HDR_LEN: usize = 16;

/// Event masks, from `linux/inotify.h`.
pub mod mask {
	/// A file was written to.
	pub const MODIFY: u32 = 0x0000_0002;
	/// A file open for writing was closed. The usual signal for "an editor
	/// finished saving".
	pub const CLOSE_WRITE: u32 = 0x0000_0008;
	/// Something was moved out of the directory.
	pub const MOVED_FROM: u32 = 0x0000_0040;
	/// Something was moved into it. The other usual editor signal, since a
	/// careful writer renames into place rather than truncating.
	pub const MOVED_TO: u32 = 0x0000_0080;
	/// Something was created in it.
	pub const CREATE: u32 = 0x0000_0100;
	/// Something was deleted from it.
	pub const DELETE: u32 = 0x0000_0200;
	/// The watched directory itself went away.
	pub const DELETE_SELF: u32 = 0x0000_0400;
	/// The watched directory itself was moved.
	pub const MOVE_SELF: u32 = 0x0000_0800;
	/// The kernel's event queue overflowed and events were lost.
	pub const Q_OVERFLOW: u32 = 0x0000_4000;

	/// Everything that means "the config directory changed".
	///
	/// `MODIFY` is included as well as `CLOSE_WRITE` because a writer that
	/// keeps the file open -- `>>` from a script, say -- never produces a
	/// close, and a config that changed without netcfgd noticing is the whole
	/// failure this watch exists to prevent.
	pub const CONFIG: u32 =
		MODIFY | CLOSE_WRITE | MOVED_FROM | MOVED_TO | CREATE | DELETE | DELETE_SELF | MOVE_SELF;
}

/// One event, as read from the descriptor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Event {
	/// Which watch produced it.
	pub wd: i32,
	/// What happened.
	pub mask: u32,
	/// The name within the watched directory, where there is one.
	pub name: Option<String>,
}

impl Event {
	/// Whether the kernel dropped events before this one.
	///
	/// Handled the same way as netlink's `ENOBUFS`: it means "you missed
	/// something", which for a watcher that re-reads everything is
	/// indistinguishable from an ordinary change.
	#[must_use]
	pub fn overflowed(&self) -> bool {
		self.mask & mask::Q_OVERFLOW != 0
	}
}

/// Walk the events in one read from an inotify descriptor.
///
/// Safe code over bytes the kernel wrote, with the same two obligations as the
/// netlink iterators: it must terminate, and it must not panic. A `len` field
/// large enough to run past the buffer ends iteration rather than indexing out
/// of bounds.
#[derive(Debug, Clone)]
pub struct Events<'a> {
	rest: &'a [u8],
}

impl<'a> Events<'a> {
	/// Start walking `bytes`.
	#[must_use]
	pub fn new(bytes: &'a [u8]) -> Self {
		Self { rest: bytes }
	}
}

impl Iterator for Events<'_> {
	type Item = Event;

	fn next(&mut self) -> Option<Self::Item> {
		if self.rest.len() < EVENT_HDR_LEN {
			return None;
		}
		let wd = i32::from_ne_bytes(self.rest[0..4].try_into().ok()?);
		let mask = u32::from_ne_bytes(self.rest[4..8].try_into().ok()?);
		let len = u32::from_ne_bytes(self.rest[12..16].try_into().ok()?) as usize;

		let total = EVENT_HDR_LEN.checked_add(len)?;
		if total > self.rest.len() {
			self.rest = &[];
			return None;
		}

		let name = if len == 0 {
			None
		} else {
			let raw = &self.rest[EVENT_HDR_LEN..total];
			// The name is NUL-padded to an alignment boundary, so trim at the
			// first NUL rather than trusting `len` to be the string length.
			let end = raw.iter().position(|byte| *byte == 0).unwrap_or(raw.len());
			std::str::from_utf8(&raw[..end]).ok().map(ToOwned::to_owned)
		};

		self.rest = &self.rest[total..];
		Some(Event { wd, mask, name })
	}
}

/// An inotify descriptor.
#[derive(Debug)]
pub struct Inotify {
	fd: libc::c_int,
}

impl Inotify {
	/// Open a descriptor.
	///
	/// # Errors
	///
	/// Returns the underlying `io::Error`. `EMFILE` here means the system's
	/// `fs.inotify.max_user_instances` is exhausted, which is a real and
	/// ordinary condition on a busy machine -- the caller is expected to fall
	/// back rather than fail.
	pub fn new() -> io::Result<Self> {
		// SAFETY: `inotify_init1` takes one integer flag and returns a file
		// descriptor or -1. No pointers are involved, so there is nothing to
		// get wrong about lifetimes or provenance, and -1 is checked.
		let fd = unsafe { libc::inotify_init1(libc::IN_CLOEXEC | libc::IN_NONBLOCK) };
		if fd < 0 {
			return Err(io::Error::last_os_error());
		}
		Ok(Self { fd })
	}

	/// Watch a directory.
	///
	/// # Errors
	///
	/// Returns the underlying `io::Error`, including for a path that does not
	/// exist -- which is not fatal, since a config directory may be created
	/// later.
	pub fn watch(&self, path: &Path, mask: u32) -> io::Result<i32> {
		let raw = CString::new(path.as_os_str().as_bytes())
			.map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "path contains a NUL"))?;
		// SAFETY: `raw` is a live NUL-terminated C string that outlives the
		// call, which is exactly what `inotify_add_watch` requires of its
		// second argument. `self.fd` is valid for as long as `self`.
		let wd = unsafe { libc::inotify_add_watch(self.fd, raw.as_ptr(), mask) };
		if wd < 0 {
			return Err(io::Error::last_os_error());
		}
		Ok(wd)
	}

	/// Wait up to `timeout_ms` for events, and return them.
	///
	/// An empty vector means the wait timed out, which a caller can use as its
	/// own tick.
	///
	/// # Errors
	///
	/// Returns the underlying `io::Error` for anything but a timeout or an
	/// interrupted syscall.
	pub fn wait(&self, timeout_ms: i32) -> io::Result<Vec<Event>> {
		let mut poll = libc::pollfd {
			fd: self.fd,
			events: libc::POLLIN,
			revents: 0,
		};
		// SAFETY: the pointer is to one live, fully initialised `pollfd` that
		// outlives the call, and the count passed is exactly one, so the
		// kernel reads and writes only that struct.
		let ready = unsafe { libc::poll(std::ptr::addr_of_mut!(poll), 1, timeout_ms) };
		if ready < 0 {
			let error = io::Error::last_os_error();
			// A signal during poll is not a failure to watch.
			if error.kind() == io::ErrorKind::Interrupted {
				return Ok(Vec::new());
			}
			return Err(error);
		}
		if ready == 0 {
			return Ok(Vec::new());
		}

		let mut buffer = vec![0_u8; 8192];
		// SAFETY: `buffer` is a live, uniquely borrowed allocation of the
		// length passed, so the kernel writes only within memory we own and
		// may mutate. The descriptor is non-blocking, so this cannot park.
		let read = unsafe {
			libc::read(
				self.fd,
				buffer.as_mut_ptr().cast::<libc::c_void>(),
				buffer.len(),
			)
		};
		if read < 0 {
			let error = io::Error::last_os_error();
			return match error.kind() {
				io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted => Ok(Vec::new()),
				_ => Err(error),
			};
		}
		let read = usize::try_from(read).unwrap_or(0).min(buffer.len());
		Ok(Events::new(&buffer[..read]).collect())
	}
}

impl Drop for Inotify {
	fn drop(&mut self) {
		// SAFETY: `self.fd` was opened by `new`, has not been closed, and is
		// not reachable elsewhere -- `Inotify` is not `Clone` and does not
		// hand the descriptor out. Dropping is therefore the only close.
		unsafe { libc::close(self.fd) };
	}
}
