//! Asking a process netcfgd started to stop.
//!
//! Every other daemon netcfgd runs has a control socket to be stopped through
//! -- `wpa_supplicant`, `hostapd` and `OpenVPN` all do, and decision 0014's
//! reason for preferring one holds for each: an operator's own daemons are
//! common, and a process found by name would be reached along with netcfgd's.
//!
//! `pppd` has no socket. What it has is a pid file it writes itself, named for
//! the interface, which is a record of *this* session rather than a search for
//! something that looks like one. That is what makes signalling it defensible
//! -- and the caller checks the process is the one netcfgd started before this
//! is called at all, because a pid file outlives the process it names and pids
//! are recycled.

use std::io;
use std::path::Path;

/// The pid in a file, if the process it names is alive and is the one expected.
///
/// **A pid file outlives the process it names, and pids are recycled.** So the
/// pid is only half an answer: the other half is `/proc/<pid>/cmdline`, read
/// NUL-separated so that `marker` has to be a *whole argument* rather than a
/// substring of one. `None` covers every way of not knowing -- no file, no
/// number in it, no such process, or a process that is somebody else's.
///
/// The marker should be as specific as the caller can make it. A path netcfgd
/// chose -- an options file, a management socket, a generated configuration --
/// is unique to one daemon on one machine; an interface name is a short string
/// an unrelated command line could contain, and is what to use only when there
/// is nothing better.
///
/// One function because this rule was written four times: `pppd`'s pid, radvd's,
/// the `DHCP` clients' and a tunnel's. Four copies of a rule is how two of them
/// come to disagree about what counts as ownership -- and this one is a security
/// property, not a convenience: it is what stands between netcfgd and signalling
/// a process somebody else started.
#[must_use]
pub fn pid_of(path: &Path, marker: &str) -> Option<i32> {
	let text = std::fs::read_to_string(path).ok()?;
	let pid: i32 = text.trim().lines().next()?.trim().parse().ok()?;
	if pid <= 0 {
		return None;
	}
	let cmdline = std::fs::read(format!("/proc/{pid}/cmdline")).ok()?;
	cmdline
		.split(|byte| *byte == 0)
		.any(|argument| argument == marker.as_bytes())
		.then_some(pid)
}

/// Ask a process to terminate.
///
/// `SIGTERM` rather than `SIGKILL`, always: `pppd` on a `SIGTERM` hangs up the
/// link, runs its `ip-down` script and takes the interface away. A `SIGKILL`
/// leaves the session up at the far end and the report on disk, which is the
/// state this exists to avoid.
///
/// # Errors
///
/// Returns the errno. `ESRCH` -- no such process -- is the state the caller
/// asked for, so it is reported as success.
pub fn terminate(pid: i32) -> io::Result<()> {
	// SAFETY: `kill` takes a pid and a signal number and touches no memory this
	// crate owns. A pid of 0 or -1 would signal a process group or every
	// process the caller may signal, which is refused above rather than passed
	// through.
	if pid <= 0 {
		return Err(io::Error::new(
			io::ErrorKind::InvalidInput,
			"a pid must be positive: 0 and -1 mean process groups",
		));
	}
	// SAFETY: as above; `pid` is positive and `SIGTERM` is a valid signal.
	let result = unsafe { libc::kill(pid, libc::SIGTERM) };
	if result == 0 {
		return Ok(());
	}
	let error = io::Error::last_os_error();
	if error.raw_os_error() == Some(libc::ESRCH) {
		// Nothing there to stop, which is what was asked for.
		return Ok(());
	}
	Err(error)
}

/// Ask a process to re-read its configuration.
///
/// `SIGHUP` is the convention and radvd honours it -- `radvd.c` handles it by
/// calling `reload_config`, which re-reads the file it was started with. That
/// is what makes a changed prefix free: the daemon keeps running and nothing on
/// the wire is disturbed.
///
/// # Errors
///
/// Returns the errno. Unlike [`terminate`], `ESRCH` is *not* success: a reload
/// asked of a process that is gone did not happen, and the caller has a
/// document that no longer matches anything.
pub fn hangup(pid: i32) -> io::Result<()> {
	if pid <= 0 {
		return Err(io::Error::new(
			io::ErrorKind::InvalidInput,
			"a pid must be positive: 0 and -1 mean process groups",
		));
	}
	// SAFETY: `kill` takes a pid and a signal number and touches no memory this
	// crate owns. The pid is positive, checked above, so this cannot address a
	// process group.
	let result = unsafe { libc::kill(pid, libc::SIGHUP) };
	if result == 0 {
		Ok(())
	} else {
		Err(io::Error::last_os_error())
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn a_pid_that_is_not_a_pid_is_refused() {
		// 0 and -1 are process groups, and "stop every process I may signal" is
		// not a thing this should be able to express by accident.
		for pid in [0, -1] {
			assert!(terminate(pid).is_err(), "{pid} should be refused");
		}
	}

	#[test]
	fn a_process_that_is_already_gone_is_success() {
		// The state the caller asked for. A pid that cannot exist stands in for
		// one that has exited: the kernel answers ESRCH either way.
		assert!(terminate(0x0040_0000).is_ok());
	}
}
