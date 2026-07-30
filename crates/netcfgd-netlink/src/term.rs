//! The controlling terminal: raw mode, and how big it is.
//!
//! Here rather than in the client for the reason everything else in this crate
//! is here. Constraint 4 confines `unsafe` to one audited crate, and this is
//! it -- not because it is the netlink crate, but because it is where the libc
//! boundary lives. `inotify` and `SO_PEERCRED` are already in it and neither
//! is netlink either.
//!
//! There is no safe route. Terminal attributes are an ioctl, std has no API
//! for them, and no escape sequence turns off canonical mode. So it is three
//! FFI calls of the same shape as the fourteen already in this crate -- a
//! zeroed struct that is simpler than the `sockaddr_nl` next door, and two
//! calls that take a descriptor and a pointer to it.
//!
//! **A panic leaves the terminal in raw mode.** The release profile is
//! `panic = "abort"`, so [`RawMode`]'s destructor does not run on the way out.
//! The mitigation is that the restore also happens on every ordinary exit path
//! and that `q` and `^C` are both ordinary exits -- in raw mode `ISIG` is off,
//! so `^C` arrives as a byte the caller reads rather than as a signal that
//! bypasses cleanup.

use std::io;
use std::os::fd::{AsRawFd, RawFd};

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

/// Raw mode for as long as this is alive.
///
/// Restores the previous attributes on drop. Held by value rather than set and
/// forgotten so that the restore cannot be skipped by an early return, which
/// is the usual way a program leaves somebody's shell without an echo.
#[derive(Debug)]
pub struct RawMode {
	fd: RawFd,
	saved: libc::termios,
}

impl RawMode {
	/// Put the terminal into raw mode.
	///
	/// Canonical input, echo, signal generation and output post-processing all
	/// go off, which is what lets the caller see each keystroke as it happens
	/// and draw the screen itself.
	///
	/// # Errors
	///
	/// Returns the underlying `io::Error`. `ENOTTY` means the descriptor is
	/// not a terminal.
	pub fn new(fd: RawFd) -> io::Result<Self> {
		// SAFETY: `termios` is a plain-old-data struct of integers and a byte
		// array, with no invalid bit patterns, so all-zero is a valid
		// instance. `tcgetattr` overwrites it on success.
		let mut saved: libc::termios = unsafe { std::mem::zeroed() };

		// SAFETY: the out-pointer is to one live, fully initialised `termios`
		// that outlives the call, which is exactly what `tcgetattr` writes to.
		let rc = unsafe { libc::tcgetattr(fd, std::ptr::addr_of_mut!(saved)) };
		if rc < 0 {
			return Err(io::Error::last_os_error());
		}

		let mut raw = saved;
		// ICANON: deliver each byte rather than each line. ECHO: do not print
		// what was typed, because the screen is drawn here. ISIG: let ^C and
		// ^Z arrive as bytes -- this is the half that keeps cleanup reachable,
		// since a signal would otherwise abort past the destructor. IEXTEN:
		// no literal-next processing.
		raw.c_lflag &= !(libc::ICANON | libc::ECHO | libc::ISIG | libc::IEXTEN);
		// IXON: no flow control, so ^S does not freeze the display. ICRNL: do
		// not rewrite carriage return as newline, so Enter is distinguishable.
		raw.c_iflag &= !(libc::IXON | libc::ICRNL | libc::BRKINT | libc::INPCK | libc::ISTRIP);
		// OPOST: no output post-processing, so a newline is not silently a
		// carriage return as well and the cursor goes where it is put.
		raw.c_oflag &= !libc::OPOST;
		// A read returns as soon as one byte is there, and blocks until then.
		raw.c_cc[libc::VMIN] = 1;
		raw.c_cc[libc::VTIME] = 0;

		// SAFETY: `raw` is a live, fully initialised `termios` that outlives
		// the call; `TCSAFLUSH` discards input typed before the switch, which
		// is what stops a stray keystroke being interpreted under the new
		// rules.
		let rc = unsafe { libc::tcsetattr(fd, libc::TCSAFLUSH, std::ptr::addr_of!(raw)) };
		if rc < 0 {
			return Err(io::Error::last_os_error());
		}

		Ok(Self { fd, saved })
	}

	/// Make reads return after `deciseconds` even with nothing typed.
	///
	/// What lets a full-screen client redraw on a timer without a second
	/// thread or a poll loop: `VMIN = 0` with `VTIME` set means "return what
	/// there is, or nothing, after this long".
	///
	/// # Errors
	///
	/// Returns the underlying `io::Error`.
	pub fn set_read_timeout(&self, deciseconds: u8) -> io::Result<()> {
		// SAFETY: `termios` is plain-old-data with no invalid bit patterns, so
		// all-zero is a valid instance; `tcgetattr` overwrites it on success.
		let mut current: libc::termios = unsafe { std::mem::zeroed() };

		// SAFETY: the out-pointer is to one live, fully initialised `termios`
		// that outlives the call, which is what `tcgetattr` writes to.
		let rc = unsafe { libc::tcgetattr(self.fd, std::ptr::addr_of_mut!(current)) };
		if rc < 0 {
			return Err(io::Error::last_os_error());
		}
		current.c_cc[libc::VMIN] = 0;
		current.c_cc[libc::VTIME] = deciseconds;

		// SAFETY: `current` is a live, fully initialised `termios` that
		// outlives the call. `TCSANOW` rather than `TCSAFLUSH` because this
		// runs mid-session and discarding pending input would eat a keystroke.
		let rc = unsafe { libc::tcsetattr(self.fd, libc::TCSANOW, std::ptr::addr_of!(current)) };
		if rc < 0 {
			return Err(io::Error::last_os_error());
		}
		Ok(())
	}

	/// The descriptor this was taken on.
	#[must_use]
	pub fn fd(&self) -> RawFd {
		self.fd
	}
}

impl Drop for RawMode {
	fn drop(&mut self) {
		// SAFETY: `self.saved` is the fully initialised `termios` read in
		// `new`, live for the duration of the call, and `self.fd` is the same
		// descriptor it was read from. The result is deliberately ignored:
		// this runs on the way out, there is nothing useful to do about a
		// failure, and returning early would skip nothing else.
		unsafe {
			libc::tcsetattr(self.fd, libc::TCSAFLUSH, std::ptr::addr_of!(self.saved));
		}
	}
}

/// Read whatever is available, straight from the descriptor.
///
/// Not `std::io::Stdin`, and the difference is a bug rather than a
/// preference. `Stdin` is `BufReader`-backed: a one-byte read pulls the whole
/// kernel buffer into userspace and hands back one byte, so a caller waiting
/// on the descriptor with `poll` is then told there is nothing to read while
/// holding the next keystroke in a buffer it cannot see.
///
/// Measured: two bytes written together -- which is what an arrow key, a
/// paste, or fast typing looks like -- left the second one stranded until the
/// next poll timeout expired, a full second later.
///
/// # Errors
///
/// Returns the underlying `io::Error`.
pub fn read(fd: RawFd, buffer: &mut [u8]) -> io::Result<usize> {
	// SAFETY: the pointer and length come from one live, uniquely borrowed
	// slice, so the kernel writes only within it. A negative return is the
	// error case and is checked before the count is used.
	let count = unsafe { libc::read(fd, buffer.as_mut_ptr().cast::<libc::c_void>(), buffer.len()) };
	if count < 0 {
		return Err(io::Error::last_os_error());
	}
	Ok(usize::try_from(count).unwrap_or(0))
}

/// Raw mode on standard input, with its size.
///
/// # Errors
///
/// Returns `NotConnected` where standard input is not a terminal, and the
/// underlying `io::Error` if the attributes cannot be changed.
pub fn enter() -> io::Result<(RawMode, Size)> {
	let fd = io::stdin().as_raw_fd();
	if !is_terminal(fd) {
		return Err(io::Error::new(
			io::ErrorKind::NotConnected,
			"standard input is not a terminal",
		));
	}
	let size = size(fd);
	Ok((RawMode::new(fd)?, size))
}
