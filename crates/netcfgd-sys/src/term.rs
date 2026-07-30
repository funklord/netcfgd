//! Is this a terminal, and how big is it.
//!
//! Raw mode, key decoding and drawing used to live here and are now ncurses'
//! (see [`crate::curses`]). What is left is the pair of questions ncurses
//! cannot answer for you: whether there is a terminal at all -- `initscr`
//! exits the process rather than returning when there is not -- and, for
//! anything that wants it without starting a screen, how big it is.
//!
//! Here rather than in the client for the reason everything else in this crate
//! is here. Constraint 4 confines `unsafe` to one audited crate, and this is
//! it -- not because it is the netlink crate, but because it is where the libc
//! boundary lives. `inotify` and `SO_PEERCRED` were already in it and neither
//! is netlink either.

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
