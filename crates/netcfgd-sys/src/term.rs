//! Is this a terminal, and how big is it.
//!
//! Raw mode, key decoding and drawing used to live here and are now ncurses'
//! (see [`crate::curses`]). What is left is what ncurses cannot answer for
//! you: whether there is a terminal at all -- `initscr` exits the process
//! rather than returning when there is not -- and, for anything that wants it
//! without starting a screen, how big it is and how to stop it echoing.
//!
//! Here rather than in the client for the reason everything else in this crate
//! is here. Constraint 4 confines `unsafe` to one audited crate, and this is
//! it -- not because it is the netlink crate, but because it is where the libc
//! boundary lives. `inotify` and `SO_PEERCRED` were already in it and neither
//! is netlink either.

use std::io;
use std::os::fd::RawFd;

/// How many rows and columns the terminal has.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Size {
	/// Rows.
	pub rows: u16,
	/// Columns.
	pub columns: u16,
}

impl Default for Size {
	/// The size design section 7.2 requires the TUI to work in.
	///
	/// Used when the ioctl fails, which is what happens on a pipe. A client
	/// that guessed larger would draw off the edge of a real 80x24 terminal;
	/// one that guessed smaller would waste a big one.
	fn default() -> Self {
		Self {
			rows: 24,
			columns: 80,
		}
	}
}

/// The terminal's current size, or [`Size::default`] if it has none.
#[must_use]
pub fn size(fd: RawFd) -> Size {
	// SAFETY: `winsize` is four `u16`s with no padding requirements and no
	// invalid bit patterns, so all-zero is a valid instance. The ioctl
	// overwrites it entirely on success and leaves it alone on failure, which
	// is why the return code is checked before the value is read.
	let mut window: libc::winsize = unsafe { std::mem::zeroed() };

	// SAFETY: `TIOCGWINSZ` takes exactly one out-pointer to a `winsize`, which
	// is what is passed, and it is live for the duration of the call. A
	// descriptor that is not a terminal returns -1 rather than writing
	// anything.
	let rc = unsafe { libc::ioctl(fd, libc::TIOCGWINSZ, std::ptr::addr_of_mut!(window)) };
	if rc < 0 || window.ws_row == 0 || window.ws_col == 0 {
		return Size::default();
	}
	Size {
		rows: window.ws_row,
		columns: window.ws_col,
	}
}

/// Whether a descriptor is a terminal.
///
/// The TUI refuses to start without one rather than emitting escape sequences
/// into a pipe, which is how a redirected run fills a file with cursor
/// movements instead of output.
#[must_use]
pub fn is_terminal(fd: RawFd) -> bool {
	// SAFETY: `isatty` takes one integer and returns one. No pointers.
	unsafe { libc::isatty(fd) == 1 }
}

/// Echo turned off for as long as this is alive, and restored when it is not.
///
/// For reading a passphrase. `netcfgd-secret` goes to some length to keep secret
/// material out of `Debug`, out of diagnostics and out of `/run`; printing one
/// into the operator's scrollback on the way in would undo all of it.
///
/// Only `ECHO` is cleared. The line discipline keeps `ICANON`, so the read is
/// still a line read with the erase key working, and it keeps `ISIG`, so `^C`
/// still interrupts -- which is the one hazard here, since a process killed
/// between the two calls leaves a terminal with echo off. A caller that reads a
/// passphrase should block the termination signals for the duration
/// ([`crate::signals::Signals`] does exactly that, and its own doc comment is
/// about this same failure) so the pending signal is delivered after the
/// restore rather than instead of it.
#[derive(Debug)]
pub struct EchoOff {
	fd: RawFd,
	previous: libc::termios,
}

impl EchoOff {
	/// Turn echo off, or answer `None` if the descriptor is not a terminal.
	///
	/// Not a terminal is not an error: a passphrase arriving on a pipe is the
	/// scripted case, and there is nothing to turn off.
	///
	/// # Errors
	///
	/// Returns the underlying `io::Error` when the descriptor is a terminal
	/// whose attributes cannot be read or set.
	pub fn new(fd: RawFd) -> io::Result<Option<Self>> {
		if !is_terminal(fd) {
			return Ok(None);
		}

		// SAFETY: `termios` is a struct of integers and arrays of integers with
		// no invalid bit patterns, so all-zero is a valid instance;
		// `tcgetattr` overwrites it entirely on success, which is why the
		// return code is checked before the value is used.
		let mut previous: libc::termios = unsafe { std::mem::zeroed() };
		// SAFETY: the pointer is to one live, uniquely borrowed `termios` that
		// outlives the call.
		let rc = unsafe { libc::tcgetattr(fd, std::ptr::addr_of_mut!(previous)) };
		if rc < 0 {
			return Err(io::Error::last_os_error());
		}

		let mut quiet = previous;
		quiet.c_lflag &= !libc::ECHO;
		// `TCSAFLUSH` rather than `TCSANOW`: it discards input that has already
		// been typed but not read, so a keystroke that arrived between the
		// prompt being printed and this taking effect is not echoed and does
		// not become part of the passphrase.
		// SAFETY: `quiet` is a live copy of the attributes the kernel just
		// filled in, with one flag cleared.
		let rc = unsafe { libc::tcsetattr(fd, libc::TCSAFLUSH, std::ptr::addr_of!(quiet)) };
		if rc < 0 {
			return Err(io::Error::last_os_error());
		}

		Ok(Some(Self { fd, previous }))
	}
}

impl Drop for EchoOff {
	fn drop(&mut self) {
		// SAFETY: `self.previous` is the live attribute set `new` saved, so
		// this restores exactly what was there before -- including the case
		// where echo was already off, which is then left off.
		unsafe {
			libc::tcsetattr(self.fd, libc::TCSAFLUSH, std::ptr::addr_of!(self.previous));
		}
	}
}
