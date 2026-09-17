//! Printing that ends quietly when the reader goes away.
//!
//! **`ncfg status | head -1` aborted with a Rust panic.** Exit status 134, and
//! four lines on stderr about `library/std/src/io/stdio.rs`. Every program
//! here did it: `println!` unwraps the write, Rust ignores `SIGPIPE` so the
//! write returns `EPIPE` rather than killing the process, and the unwrap turns
//! that into a panic. So the ordinary shapes -- `| head`, `| less` quit early,
//! `ncfg show | jq .interfaces[0]` -- printed a crash report at somebody who
//! had done nothing wrong.
//!
//! **The one-line fix is the wrong one.** Restoring `SIGPIPE` to its default
//! would make stdout behave like every other Unix tool, and it would also
//! apply to the socket this client writes its requests into: a daemon
//! restarted mid-request would kill `ncfg` where today it prints *"cannot send
//! to netcfgd"*. The C client reached the same junction from the other side
//! and answered it the same way -- `send` with `MSG_NOSIGNAL` per call, and a
//! comment refusing to change a process-wide disposition on a program's behalf
//! (`client/ncfg_client.c`). A dead reader on **stdout** is this program's own
//! business; a dead peer on a **socket** is a diagnostic somebody needs.
//!
//! So printing is what changes, and it ends the process where `println!` would
//! have panicked. [`crate::log::emit`] has always done the same for stderr: it
//! writes with `let _ =`, because a log line nobody can receive is not a reason
//! to take a daemon down.

use std::io::Write as _;

/// What a shell reports for a program killed by `SIGPIPE`.
///
/// 128 + 13, which is what this would have exited with if Rust left the signal
/// on its default disposition -- so `ncfg status | head -1` now reports what
/// `cat /dev/urandom | head -1` reports.
const BROKEN_PIPE: i32 = 141;

/// Write to stdout, or leave.
///
/// **No error is returned and none could be acted on.** The only write that
/// fails here is one whose reader has gone, and there is nowhere to report
/// that to: stdout is the thing that broke, and stderr is likely the same pipe.
///
/// Exiting here skips destructors, exactly as the signal would have. That is
/// safe for what prints through it -- a report, a list, a usage message -- and
/// is worth knowing before anything that has a terminal to restore starts
/// using it. `ncfg tui` does not: it draws through `curses` and leaves by one
/// path on purpose.
pub fn emit(arguments: std::fmt::Arguments<'_>) {
	let stdout = std::io::stdout();
	let mut handle = stdout.lock();
	// `write_fmt` rather than `write_all(&format!(...))`: the same thing
	// `println!` does, without materialising each line as a `String` first.
	// It also reports a formatting implementation that returned an error,
	// which `println!` panics about separately and which nothing here has.
	if handle.write_fmt(arguments).is_err() {
		std::process::exit(BROKEN_PIPE);
	}
}

/// `print!`, for a program that may be at the sharp end of a pipe.
#[macro_export]
macro_rules! say {
	($($arg:tt)*) => {
		$crate::out::emit(format_args!($($arg)*))
	};
}

/// `println!`, for a program that may be at the sharp end of a pipe.
///
/// The empty form is `sayln!()`, which writes the newline and nothing else --
/// `println!()` spells a blank line that way, and the rewrite that introduced
/// this macro had to keep every one of them.
#[macro_export]
macro_rules! sayln {
	() => {
		$crate::out::emit(format_args!("\n"))
	};
	($($arg:tt)*) => {
		$crate::out::emit(format_args!("{}\n", format_args!($($arg)*)))
	};
}
