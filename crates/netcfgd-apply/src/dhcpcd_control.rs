//! Asking a running dhcpcd which configuration file it was started with.
//!
//! **The one backend whose mark cannot be read from the process.** netcfgd
//! recovers its supplicant, and now its udhcpc, by finding a path it chose as a
//! whole `argv` element (decision 0140). dhcpcd calls `setproctitle` and
//! destroys both: measured, `/proc/<pid>/cmdline` reads `dhcpcd: wlp0s20f3
//! [ip4]`, and the environment block comes back 4494 bytes of NUL against a
//! control process that kept its variables. Nothing netcfgd passed survives in
//! the process image.
//!
//! What does survive is dhcpcd's own memory of its `-f` argument, which it
//! recites verbatim -- symlink and all, with no `realpath` -- to anyone who
//! asks `--getconfigfile` on its control socket. So netcfgd starts dhcpcd with
//! a `-f` under its own run directory and asks for it back. Decision 0143.
//!
//! **Three things measured that the obvious implementation gets wrong**, each
//! of which breaks a platform this exists to serve:
//!
//! - **The privileged socket, not the unprivileged one.** dhcpcd 10.5.0
//!   removed `<iface>-4.unpriv.sock` outright -- "a breaking ABI change" in its
//!   own commit message -- and Debian sid ships 10.5.2 today. netcfgd is root,
//!   so the privileged socket is available on every version that has a socket
//!   at all, and answers this command identically.
//! - **The length prefix is a native `size_t`.** dhcpcd's `control.c` writes
//!   `iov[0].iov_len = sizeof(size_t)`: eight bytes on amd64, **four** on
//!   32-bit ARM, and big-endian on a big-endian MIPS. Parsing it as a `u64`
//!   little-endian works on the developer's machine and on nothing else this
//!   targets, so the reply is read to its first NUL under a byte cap instead.
//! - **An unknown command does not fail, it hangs.** `--getinterfaces`,
//!   `--isprivileged` and a bare `-q` were each measured to produce no reply
//!   *and no close*, past a four-second wait, on both sockets. A probe without
//!   a deadline is a daemon that stops reconciling.

use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::time::Duration;

/// How long to wait for a reply.
///
/// Generous rather than tuned. The command is answered by dhcpcd's separate
/// `[control proxy]` process, which replied in 0.00s even with the main dhcpcd
/// stopped with `SIGSTOP` -- only stopping *every* dhcpcd process silenced it.
/// So the deadline exists for the wedged case, not the ordinary one, and
/// waiting longer buys nothing but a slower refusal.
const DEADLINE: Duration = Duration::from_millis(250);

/// The longest reply worth reading.
///
/// A path, so `PATH_MAX` and a little. This is the cap that stands in for the
/// length prefix netcfgd deliberately does not parse.
const REPLY_MAX: usize = 4200;

/// Where dhcpcd puts its control socket for one interface and family.
///
/// Privileged first. The unprivileged one is a fallback for nothing in
/// particular -- netcfgd is root -- and is tried only because a machine may
/// have tightened the privileged socket's mode.
fn socket_paths(run_dir: &str, iface: &str, family: &str) -> Vec<PathBuf> {
	let base = PathBuf::from(run_dir);
	vec![
		base.join(format!("{iface}-{family}.sock")),
		base.join(format!("{iface}-{family}.unpriv.sock")),
	]
}

/// The configuration file a running dhcpcd was started with.
///
/// `None` covers every way of not knowing: no socket, nothing listening, a
/// version that does not answer, a reply that does not parse, or the deadline.
/// **`None` is not "somebody else's"** -- it is "netcfgd could not tell", and
/// the caller must treat the two differently, which is 0074's rule and 0141's
/// default.
#[must_use]
pub fn config_file_of(run_dir: &str, iface: &str, family: &str) -> Option<String> {
	for path in socket_paths(run_dir, iface, family) {
		let Ok(mut stream) = UnixStream::connect(&path) else {
			continue;
		};
		if stream.set_read_timeout(Some(DEADLINE)).is_err()
			|| stream.set_write_timeout(Some(DEADLINE)).is_err()
		{
			continue;
		}
		// Arguments are NUL-separated with a newline before the final NUL.
		if stream.write_all(b"--getconfigfile\n\0").is_err() {
			continue;
		}
		// Read what arrives within the deadline, then parse. Not "read to the
		// first NUL": the length prefix's low byte is printable for any
		// ordinary path -- measured, a 33-byte path gives `22 00 00 00 00 00
		// 00 00` -- so a scan stopping at the first NUL stops after one
		// character. dhcpcd does not close the connection either, so this
		// reads once under the timeout rather than to EOF.
		let mut buffer = vec![0_u8; REPLY_MAX];
		let read = match stream.read(&mut buffer) {
			Ok(0) | Err(_) => continue,
			Ok(count) => count,
		};
		buffer.truncate(read);
		let Some(reply) = payload(&buffer) else {
			continue;
		};
		if !reply.is_empty() {
			return Some(reply);
		}
	}
	None
}

/// The path out of one control-socket reply.
///
/// The frame is a native-width length then a NUL-terminated string, and netcfgd
/// parses only the second half. The width is the platform's -- eight bytes on
/// amd64, **four** on 32-bit ARM, big-endian on a big-endian MIPS -- so a
/// reader that decodes it works on the machine it was written on and on none of
/// the others this project targets.
///
/// Instead: the last run of printable bytes. A filesystem path holds no NUL and
/// no control character, dhcpcd sends exactly one string, and the prefix is
/// binary -- so the tail is the answer whatever width the prefix had.
fn payload(bytes: &[u8]) -> Option<String> {
	let end = bytes.iter().rposition(|byte| *byte >= 0x20)? + 1;
	let start = bytes[..end]
		.iter()
		.rposition(|byte| *byte < 0x20)
		.map_or(0, |at| at + 1);
	let text = String::from_utf8_lossy(&bytes[start..end])
		.trim()
		.to_owned();
	(!text.is_empty()).then_some(text)
}

#[cfg(test)]
mod tests {
	use super::payload;

	/// The exact bytes dhcpcd 10.1.0 sent, measured in a namespace.
	#[test]
	fn the_measured_reply_parses() {
		let mut wire = vec![0x22, 0, 0, 0, 0, 0, 0, 0];
		wire.extend_from_slice(b"/run/netcfgd/dhcpcd/probe0-4.conf\0");
		assert_eq!(
			payload(&wire).as_deref(),
			Some("/run/netcfgd/dhcpcd/probe0-4.conf")
		);
	}

	/// **The bug this replaced.** Reading to the first NUL stops after the
	/// length prefix's low byte, which is printable for any ordinary path.
	#[test]
	fn the_printable_length_byte_is_not_the_answer() {
		let mut wire = vec![0x11, 0, 0, 0, 0, 0, 0, 0];
		wire.extend_from_slice(b"/etc/dhcpcd.conf\0");
		assert_eq!(payload(&wire).as_deref(), Some("/etc/dhcpcd.conf"));
	}

	/// A four-byte prefix, which is what a 32-bit platform sends.
	#[test]
	fn a_narrower_prefix_parses_the_same() {
		let mut wire = vec![0x11, 0, 0, 0];
		wire.extend_from_slice(b"/etc/dhcpcd.conf\0");
		assert_eq!(payload(&wire).as_deref(), Some("/etc/dhcpcd.conf"));
	}

	#[test]
	fn nothing_printable_is_no_answer() {
		assert_eq!(payload(&[0, 0, 0, 0]), None);
		assert_eq!(payload(&[]), None);
	}
}
