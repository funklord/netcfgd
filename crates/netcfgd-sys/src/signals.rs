//! Termination signals as a readable descriptor.
//!
//! A full-screen client has to leave by one path. `SIGTERM` and `SIGHUP` on
//! their default disposition kill the process outright, so nothing runs on the
//! way out -- no destructor, no restore -- and the operator's shell is handed
//! back with echo off, the cursor hidden and the alternate screen still up.
//! Measured before this existed: `kill` on `ncfg tui` left `ECHO` and `ICANON`
//! both off.
//!
//! `signalfd` turns them into a descriptor that can be waited on beside the
//! keyboard, so a `SIGTERM` leaves by exactly the same path as pressing `q`.
//! No self-pipe, no async-signal-safe flag, and no race between testing a flag
//! and blocking on the next read.
//!
//! This does not save a crash. `SIGSEGV` and an abort still bypass everything,
//! and the release profile's `panic = "abort"` means a panic does too. What it
//! covers is deliberate termination, which is the case that actually happens.

use std::io;
use std::os::fd::RawFd;

/// The signals this blocks and reports.
///
/// `SIGINT` is included even though raw mode turns `ISIG` off and `^C` arrives
/// as a byte: an interrupt can also be sent from elsewhere, and a client that
/// handled the keystroke but not the signal would be inconsistent about the
/// same request.
///
/// **`SIGQUIT` is the same argument and was missing.** `cbreak` leaves `ISIG`
/// on, so `^\` reaches the process as a signal whose default is to dump core
/// and die -- nothing runs, and measured against a real pty it left `ECHO`,
/// `ICANON`, `ICRNL` and `ONLCR` all off with the alternate screen still up.
/// It is a key a person can press, next to the two that were already handled,
/// and it was the one that broke the terminal.
const BLOCKED: [libc::c_int; 4] = [libc::SIGTERM, libc::SIGHUP, libc::SIGINT, libc::SIGQUIT];

/// A descriptor that becomes readable when a termination signal arrives.
///
/// The signals are blocked for as long as this is alive, and unblocked when it
/// is dropped, so a caller that stops watching does not silently become
/// unkillable.
#[derive(Debug)]
pub struct Signals {
	fd: RawFd,
	previous: libc::sigset_t,
}

impl Signals {
	/// Block the termination signals and open a descriptor reporting them.
	///
	/// # Errors
	///
	/// Returns the underlying `io::Error`.
	pub fn new() -> io::Result<Self> {
		// SAFETY: `sigset_t` is an opaque bitmask with no invalid patterns, so
		// all-zero is a valid instance; `sigemptyset` initialises it properly
		// and is called before any use.
		let mut mask: libc::sigset_t = unsafe { std::mem::zeroed() };
		// SAFETY: the pointer is to one live, uniquely borrowed `sigset_t`
		// that outlives the call.
		unsafe { libc::sigemptyset(std::ptr::addr_of_mut!(mask)) };
		for signal in BLOCKED {
			// SAFETY: same live `sigset_t`, and `signal` is one of three
			// constants from libc.
			unsafe { libc::sigaddset(std::ptr::addr_of_mut!(mask), signal) };
		}

		// SAFETY: `sigset_t` is an opaque bitmask with no invalid patterns, so
		// all-zero is a valid instance; `sigprocmask` overwrites it.
		let mut previous: libc::sigset_t = unsafe { std::mem::zeroed() };

		// SAFETY: `previous` is a live `sigset_t` the kernel fills in, and
		// `mask` is the live set built above. Blocking is what makes
		// `signalfd` the only consumer -- without it the default disposition
		// kills the process before the descriptor is ever read.
		let rc = unsafe {
			libc::sigprocmask(
				libc::SIG_BLOCK,
				std::ptr::addr_of!(mask),
				std::ptr::addr_of_mut!(previous),
			)
		};
		if rc < 0 {
			return Err(io::Error::last_os_error());
		}

		// SAFETY: -1 asks for a new descriptor, and `mask` is the live set
		// just blocked. The flags are the two libc constants.
		let fd = unsafe {
			libc::signalfd(
				-1,
				std::ptr::addr_of!(mask),
				libc::SFD_CLOEXEC | libc::SFD_NONBLOCK,
			)
		};
		if fd < 0 {
			let error = io::Error::last_os_error();
			// SAFETY: `previous` is the live mask the kernel filled in above,
			// so this restores exactly what was there before.
			unsafe {
				libc::sigprocmask(
					libc::SIG_SETMASK,
					std::ptr::addr_of!(previous),
					std::ptr::null_mut(),
				);
			}
			return Err(error);
		}

		Ok(Self { fd, previous })
	}

	/// The descriptor, for waiting on.
	#[must_use]
	pub fn fd(&self) -> RawFd {
		self.fd
	}
}

impl Drop for Signals {
	fn drop(&mut self) {
		// SAFETY: `self.fd` was opened by `new` and has not been closed or
		// handed out.
		unsafe { libc::close(self.fd) };
		// SAFETY: `self.previous` is the live mask `new` saved. Restoring it
		// is what stops a caller that dropped this from staying unkillable.
		unsafe {
			libc::sigprocmask(
				libc::SIG_SETMASK,
				std::ptr::addr_of!(self.previous),
				std::ptr::null_mut(),
			);
		}
	}
}

/// What a [`wait`] returned.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ready {
	/// The first descriptor has something to read.
	Input,
	/// A termination signal arrived.
	Signal,
	/// The timeout expired with nothing ready.
	Timeout,
}

/// Wait for input, a signal, or the timeout, whichever comes first.
///
/// # Errors
///
/// Returns the underlying `io::Error`. An interrupted wait is reported as
/// [`Ready::Timeout`], because the caller's response to both is the same: go
/// round again.
pub fn wait(input: RawFd, signals: &Signals, timeout_ms: i32) -> io::Result<Ready> {
	let mut fds = [
		libc::pollfd {
			fd: input,
			events: libc::POLLIN,
			revents: 0,
		},
		libc::pollfd {
			fd: signals.fd(),
			events: libc::POLLIN,
			revents: 0,
		},
	];

	// SAFETY: the pointer is to a live array of exactly the two `pollfd`s
	// declared above, and the count matches its length. `poll` writes only
	// `revents` in each.
	let ready = unsafe { libc::poll(fds.as_mut_ptr(), 2, timeout_ms) };
	if ready < 0 {
		let error = io::Error::last_os_error();
		if error.kind() == io::ErrorKind::Interrupted {
			return Ok(Ready::Timeout);
		}
		return Err(error);
	}
	if ready == 0 {
		return Ok(Ready::Timeout);
	}
	// The signal is checked first. If both are ready the caller is leaving,
	// and processing a keystroke on the way out could apply something.
	if fds[1].revents & libc::POLLIN != 0 {
		return Ok(Ready::Signal);
	}
	Ok(Ready::Input)
}
