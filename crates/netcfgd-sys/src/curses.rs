//! ncurses, thinly.
//!
//! Bindings, not a reimplementation. netcfgd hand-writes netlink because there
//! is no library that speaks it the way this project needs; there is no such
//! excuse for terminal handling, and the first version of `ncfg tui` proved
//! it -- hand-rolled ANSI shipped with no escape-sequence decoding at all
//! (arrow keys did nothing), a buffered-read bug that stranded the second byte
//! of every burst for a full second, and no signal handling. All three are
//! things ncurses has had right for thirty years.
//!
//! What is used, and why it is worth the link:
//!
//! **Key decoding from terminfo.** `keypad()` turns escape sequences into
//! `KEY_*` values using the terminal's own capabilities, so arrows and
//! function keys work on terminals nobody here has heard of. The alternative
//! is a hand-maintained table that is wrong for everything not tested.
//!
//! **Dirty-region rendering.** Each `WINDOW` is a back buffer with per-line
//! dirty ranges; `doupdate` diffs against what the terminal is believed to be
//! showing and emits the minimum, including hardware scroll where the terminal
//! supports it. The hand-rolled version rewrote the whole frame.
//!
//! **Wide characters.** `ncursesw`, so an SSID that is not ASCII occupies the
//! columns it actually occupies. The hand-rolled version counted `char`s and
//! would misalign every row below a CJK network name.
//!
//! Attributes are set with `wstandout`/`wstandend` rather than `wattron` with
//! `A_REVERSE`, deliberately: `A_REVERSE` is a macro over `chtype`, whose width
//! varies with how ncurses was configured, and getting it wrong is a constant
//! that silently means something else. The standout pair are ordinary
//! functions with no such ambiguity.

use std::ffi::{c_char, c_int, CString};

/// An opaque ncurses `WINDOW`.
#[repr(C)]
pub struct Window {
	_private: [u8; 0],
}

/// `ERR`, returned by `wgetch` when there is nothing to read.
pub const ERR: c_int = -1;

/// How long to wait for the rest of an escape sequence before deciding a bare
/// `0x1b` was the Escape key.
///
/// ncurses defaults to 1000ms, which is what makes Escape feel broken. This is
/// the conventional replacement and is long enough for a sequence that has
/// already begun arriving to finish, even over ssh.
const ESCDELAY_MS: c_int = 25;

/// `KEY_DOWN`. Fixed in the ncurses header as an octal constant, so it is
/// stable across versions; only the handful actually bound are declared, and
/// an unrecognised key is ignored rather than mapped to the wrong action.
pub const KEY_DOWN: c_int = 0o402;
/// `KEY_UP`.
pub const KEY_UP: c_int = 0o403;
/// `KEY_RESIZE`, which ncurses synthesises from its own `SIGWINCH` handler.
pub const KEY_RESIZE: c_int = 0o632;

extern "C" {
	fn initscr() -> *mut Window;
	fn endwin() -> c_int;
	fn cbreak() -> c_int;
	fn noecho() -> c_int;
	fn nonl() -> c_int;
	fn curs_set(visibility: c_int) -> c_int;
	fn keypad(window: *mut Window, enable: bool) -> c_int;
	fn set_escdelay(milliseconds: c_int) -> c_int;
	fn wtimeout(window: *mut Window, milliseconds: c_int);
	fn newwin(lines: c_int, columns: c_int, y: c_int, x: c_int) -> *mut Window;
	fn delwin(window: *mut Window) -> c_int;
	fn mvwaddnstr(window: *mut Window, y: c_int, x: c_int, text: *const c_char, n: c_int) -> c_int;
	fn wclrtoeol(window: *mut Window) -> c_int;
	fn wmove(window: *mut Window, y: c_int, x: c_int) -> c_int;
	fn wstandout(window: *mut Window) -> c_int;
	fn wstandend(window: *mut Window) -> c_int;
	fn wnoutrefresh(window: *mut Window) -> c_int;
	fn doupdate() -> c_int;
	fn wgetch(window: *mut Window) -> c_int;
	fn getmaxy(window: *mut Window) -> c_int;
	fn getmaxx(window: *mut Window) -> c_int;
	fn resizeterm(lines: c_int, columns: c_int) -> c_int;
	fn use_env(flag: bool);
}

/// The screen, for as long as this is alive.
///
/// `endwin` runs on drop, which restores the terminal. It is held by value
/// rather than set and forgotten so an early return cannot skip it -- and
/// because a signal would skip it anyway, the caller is expected to route
/// termination through [`crate::signals`] rather than let the default
/// disposition kill the process.
#[derive(Debug)]
pub struct Screen {
	stdscr: *mut Window,
}

impl Screen {
	/// Start ncurses on the controlling terminal.
	///
	/// # Errors
	///
	/// Returns `NotConnected` where the terminal could not be initialised,
	/// which is what happens without a `TERM` ncurses recognises.
	pub fn open() -> std::io::Result<Self> {
		// Ask the terminal its size rather than trusting `$LINES`/`$COLUMNS`,
		// which are frequently stale in a resized window.
		// SAFETY: takes one bool and returns nothing.
		unsafe { use_env(false) };

		// SAFETY: `initscr` takes nothing and returns the standard screen, or
		// exits the process if the terminal cannot be set up. The pointer is
		// owned by ncurses and lives until `endwin`.
		let stdscr = unsafe { initscr() };
		if stdscr.is_null() {
			return Err(std::io::Error::new(
				std::io::ErrorKind::NotConnected,
				"the terminal could not be initialised",
			));
		}

		// SAFETY: each takes no arguments or the live `stdscr` above, and
		// returns a status this code does not need to branch on -- every one
		// of them fails only if ncurses was never initialised, which the null
		// check above has already excluded.
		unsafe {
			cbreak(); // a key at a time, not a line
			noecho(); // the screen is drawn here
			nonl(); // do not rewrite Enter, so it stays distinguishable
			curs_set(0); // no cursor to chase around the panes
			keypad(stdscr, true); // decode escape sequences from terminfo
			set_escdelay(ESCDELAY_MS);
			// Blocking, deliberately, even though `poll` drives the caller's
			// loop. ncurses only assembles escape sequences reliably in
			// blocking mode: given a timed or non-blocking read it sees the
			// `ESC`, cannot wait out `ESCDELAY` for the rest, and hands back
			// the raw bytes. Measured -- with a 50ms timeout, Down arrived as
			// 27, 91, 66 and every arrow key did nothing.
			//
			// It is safe to block here because the caller only calls after
			// `poll` says the descriptor is readable, and because ncurses
			// reads the descriptor a byte at a time rather than slurping it
			// into a buffer of its own. So nothing is ever stranded where
			// `poll` cannot see it -- which is the trap the hand-rolled
			// version fell into with Rust's buffered stdin.
			wtimeout(stdscr, -1);
		}

		Ok(Self { stdscr })
	}

	/// The standard screen, for reading keys.
	#[must_use]
	pub fn stdscr(&self) -> *mut Window {
		self.stdscr
	}

	/// How many rows and columns the screen has.
	#[must_use]
	pub fn size(&self) -> (u16, u16) {
		// SAFETY: `self.stdscr` is the live standard screen, valid until this
		// value is dropped.
		let rows = unsafe { getmaxy(self.stdscr) };
		// SAFETY: same live standard screen.
		let columns = unsafe { getmaxx(self.stdscr) };
		(
			u16::try_from(rows).unwrap_or(24),
			u16::try_from(columns).unwrap_or(80),
		)
	}

	/// Take the next key, or `None` if there is nothing waiting.
	///
	/// **Blocks**, so it must only be called once the descriptor is known to
	/// be readable. See `Screen::open` for why blocking is the only mode in
	/// which ncurses decodes escape sequences, and why it strands nothing.
	///
	/// `None` means `ERR`, which after a successful `poll` means the terminal
	/// went away.
	#[must_use]
	pub fn key(&self) -> Option<c_int> {
		// SAFETY: `self.stdscr` is the live standard screen.
		let key = unsafe { wgetch(self.stdscr) };
		(key != ERR).then_some(key)
	}

	/// Tell ncurses the terminal changed size.
	pub fn resized(&self, rows: u16, columns: u16) {
		// SAFETY: takes two integers. It reallocates ncurses' internal
		// buffers, which invalidates nothing this type hands out -- `stdscr`
		// is stable across a resize.
		unsafe { resizeterm(c_int::from(rows), c_int::from(columns)) };
	}

	/// Push everything staged by the panes to the terminal, in one update.
	pub fn flush(&self) {
		// SAFETY: takes nothing; emits the difference between the virtual
		// screen and what the terminal is believed to show.
		unsafe { doupdate() };
	}
}

impl Drop for Screen {
	fn drop(&mut self) {
		// SAFETY: ncurses is initialised, since this value exists. The result
		// is ignored because this runs on the way out and there is nothing
		// useful to do about a failure.
		unsafe { endwin() };
	}
}

/// One pane: a window, and whether its contents have changed.
///
/// The flag is the dirty rectangle at pane granularity; ncurses narrows it
/// further to the changed cells within the window. Nothing is drawn unless the
/// flag is set, and nothing reaches the terminal until [`Screen::flush`].
#[derive(Debug)]
pub struct Pane {
	window: *mut Window,
	dirty: bool,
}

impl Pane {
	/// A window of this size at this position.
	///
	/// # Errors
	///
	/// Returns `OutOfMemory` if ncurses could not allocate it.
	pub fn new(rows: u16, columns: u16, y: u16, x: u16) -> std::io::Result<Self> {
		// SAFETY: four integers in, a fresh window out or null. The window is
		// owned by this value and freed in `Drop`.
		let window = unsafe {
			newwin(
				c_int::from(rows.max(1)),
				c_int::from(columns.max(1)),
				c_int::from(y),
				c_int::from(x),
			)
		};
		if window.is_null() {
			return Err(std::io::Error::new(
				std::io::ErrorKind::OutOfMemory,
				"ncurses could not allocate a window",
			));
		}
		Ok(Self {
			window,
			dirty: true,
		})
	}

	/// Mark it as needing a redraw.
	pub fn touch(&mut self) {
		self.dirty = true;
	}

	/// Whether it needs redrawing.
	#[must_use]
	pub fn is_dirty(&self) -> bool {
		self.dirty
	}

	/// Draw these lines, one per row, clearing the rest of each.
	///
	/// `highlight` is the index of the row to show in standout, if any. Rows
	/// past the end of `lines` are cleared, so a pane that shrinks does not
	/// leave the tail of its previous contents behind.
	pub fn draw(&mut self, lines: &[String], highlight: Option<usize>) {
		// SAFETY: `self.window` is live for the lifetime of this value.
		let rows = unsafe { getmaxy(self.window) };
		for row in 0..rows {
			let index = usize::try_from(row).unwrap_or(usize::MAX);
			// SAFETY: `self.window` is live; `wmove` and `wclrtoeol` take it
			// and integers within the window's own bounds.
			unsafe {
				wmove(self.window, row, 0);
				wclrtoeol(self.window);
			}
			let Some(line) = lines.get(index) else {
				continue;
			};
			// A NUL in the text would truncate the C string, so it is dropped
			// rather than allowed to silently shorten a row. Interface names
			// and SSIDs are the sources here and neither should contain one.
			let Ok(text) = CString::new(line.replace('\0', "")) else {
				continue;
			};
			let standout = highlight == Some(index);
			// SAFETY: `self.window` is live, `text` outlives the call, and
			// the length is that string's own byte count.
			unsafe {
				if standout {
					wstandout(self.window);
				}
				mvwaddnstr(
					self.window,
					row,
					0,
					text.as_ptr(),
					c_int::try_from(text.as_bytes().len()).unwrap_or(0),
				);
				if standout {
					wstandend(self.window);
				}
			}
		}
		// SAFETY: stages into the virtual screen only; the terminal is not
		// touched until `doupdate`.
		unsafe { wnoutrefresh(self.window) };
		self.dirty = false;
	}
}

impl Drop for Pane {
	fn drop(&mut self) {
		// SAFETY: `self.window` was allocated by `new` and has not been freed
		// or handed out.
		unsafe { delwin(self.window) };
	}
}
