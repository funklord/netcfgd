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

/// The pid of a process carrying `marker` as a whole argument, if any.
///
/// **[`pid_of`]'s recovery path, and it exists because the pid file is an
/// index into a fact rather than the fact itself.** netcfgd starts its
/// supplicant with `-P <run>/supplicant/<iface>.pid`, so the process carries
/// netcfgd's mark in its own `argv` for as long as it lives. The file that
/// holds the pid does not: `RuntimeDirectory=netcfgd` means systemd deletes
/// `/run/netcfgd` on a real stop, while the supplicant -- which netcfgd
/// deliberately does not stop (0134) -- keeps running. netcfgd then cannot
/// recognise its own child, and the guard against taking another manager's
/// radio refuses it for ever, naming `NetworkManager` for a process netcfgd
/// started itself. Decision 0140.
///
/// **This is a scan of `/proc`, which the module header above forbids -- and
/// the exception is the marker, not the need.** That header rules out finding
/// a process *by name*, because an operator's own `wpa_supplicant` would be
/// reached along with netcfgd's. This matches an absolute path netcfgd
/// composed from its own run directory and one interface, as a **whole**
/// `argv` element, by exactly the test [`pid_of`] applies. No other manager's
/// command line can carry it. Loosen this to a substring or to a program name
/// and the rule really is broken -- which is what the negative tests below are
/// for.
///
/// The lowest matching pid, so that the answer is stable across calls when a
/// caller has somehow produced two.
#[must_use]
pub fn pid_by_marker(marker: &str) -> Option<i32> {
	let mut found: Option<i32> = None;
	let entries = std::fs::read_dir("/proc").ok()?;
	for entry in entries.flatten() {
		let Ok(name) = entry.file_name().into_string() else {
			continue;
		};
		let Ok(pid) = name.parse::<i32>() else {
			continue;
		};
		if pid <= 0 {
			continue;
		}
		let Ok(cmdline) = std::fs::read(format!("/proc/{pid}/cmdline")) else {
			continue;
		};
		if cmdline
			.split(|byte| *byte == 0)
			.any(|argument| argument == marker.as_bytes())
		{
			found = Some(found.map_or(pid, |seen: i32| seen.min(pid)));
		}
	}
	found
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

/// Make a command run as somebody else, giving up everything on the way.
///
/// Three calls in one order, and the order is the whole of it:
///
/// 1. `setgroups` -- **first, because it needs the privilege being dropped**.
///    After `setuid` it fails, so a version that did it last would leave the
///    process in root's supplementary groups while looking like it had
///    dropped. That is the classic incomplete drop: no longer uid 0, still in
///    every group root belongs to.
/// 2. `setgid` -- before `setuid`, for the same reason.
/// 3. `setuid` -- last, because it is the door that only opens outward.
///
/// **Any failure fails the exec.** The closure returns the errno, `Command`
/// turns that into a failed spawn, and the caller reports it -- so a hook that
/// asked to be unprivileged never runs privileged instead. That is the whole
/// security property, and it is why this returns nothing to check: there is no
/// path where the drop is skipped and the program continues.
///
/// An empty `groups` is meaningful rather than a no-op: `setgroups(0, ...)`
/// clears the inherited set, which is what a user in no supplementary groups
/// must get.
///
/// # Safety and ordering with the rest of `Command`
///
/// The closure runs in the child between `fork` and `exec`, where only
/// async-signal-safe work is allowed. It makes three syscalls and allocates
/// nothing; `groups` is moved in and its buffer is already allocated by the
/// time the fork happens.
pub fn run_as(command: &mut std::process::Command, ids: &crate::peer::UserIds) {
	use std::os::unix::process::CommandExt;

	let uid = ids.uid;
	let gid = ids.gid;
	let groups = ids.groups.clone();

	// SAFETY: the closure calls three libc functions and allocates nothing, so
	// it is safe to run between fork and exec. `groups` is moved in and its
	// allocation predates the fork. Each result is checked, and an error stops
	// the exec rather than continuing with privilege half given up.
	unsafe {
		command.pre_exec(move || {
			let count = libc::size_t::try_from(groups.len()).unwrap_or(libc::size_t::MAX);
			if libc::setgroups(count, groups.as_ptr()) != 0 {
				return Err(io::Error::last_os_error());
			}
			if libc::setgid(gid) != 0 {
				return Err(io::Error::last_os_error());
			}
			if libc::setuid(uid) != 0 {
				return Err(io::Error::last_os_error());
			}
			Ok(())
		});
	}
}

/// Ask a whole process group to terminate.
///
/// A hook is a script, and a script that runs `sleep 300` has *forked* it:
/// the shell is the child netcfgd spawned, and the work is a grandchild.
/// Signalling the child kills the shell and leaves the grandchild running,
/// reparented to init -- so the daemon stops waiting and the thing it was
/// waiting for carries on. Measured, not supposed: two `sleep 300` processes
/// outlived a run that believed it had killed them.
///
/// The caller must have put the child in its own group -- `Command::
/// process_group(0)` -- or this signals netcfgd's own group, which includes
/// the daemon.
///
/// # Errors
///
/// Returns the errno. `ESRCH` means the group is already gone, which is the
/// outcome that was wanted.
pub fn terminate_group(pgid: i32) -> io::Result<()> {
	if pgid <= 0 {
		return Err(io::Error::new(
			io::ErrorKind::InvalidInput,
			"a process group id must be positive; negating it is this function's job",
		));
	}
	// SAFETY: two integers in, one out, no pointers. The negation is what
	// makes this a group signal, and the guard above is what stops a stray
	// zero reaching it -- `kill(0, ...)` signals the caller's own group.
	let result = unsafe { libc::kill(-pgid, libc::SIGTERM) };
	if result < 0 {
		return Err(io::Error::last_os_error());
	}
	Ok(())
}

/// Kill a whole process group outright.
///
/// The group counterpart of [`kill`], with [`terminate_group`]'s reasoning
/// about why a group and not a process, and the same guard against zero.
///
/// # Errors
///
/// Returns the errno. `ESRCH` means the group is already gone.
pub fn kill_group(pgid: i32) -> io::Result<()> {
	if pgid <= 0 {
		return Err(io::Error::new(
			io::ErrorKind::InvalidInput,
			"a process group id must be positive; negating it is this function's job",
		));
	}
	// SAFETY: as in `terminate_group`.
	let result = unsafe { libc::kill(-pgid, libc::SIGKILL) };
	if result < 0 {
		return Err(io::Error::last_os_error());
	}
	Ok(())
}

/// Kill a process outright, when asking has not worked.
///
/// The last resort and never the first: [`terminate`] says why `SIGTERM` is
/// the right signal for anything netcfgd starts, and a `SIGKILL` that arrives
/// before a process has had its chance to clean up is the state that rule
/// exists to avoid. This is here for the one case where the chance has been
/// given and refused -- a hook that has ignored a `SIGTERM` through its grace
/// period, which cannot be waited on for ever because the reconcile loop is
/// behind it.
///
/// # Errors
///
/// Returns the errno. `ESRCH` -- no such process -- means it exited between
/// the check and the signal, which is the outcome that was wanted.
pub fn kill(pid: i32) -> io::Result<()> {
	// SAFETY: `kill` takes two integers and returns one. No pointers. `pid` is
	// positive, so this signals one process rather than a group.
	let result = unsafe { libc::kill(pid, libc::SIGKILL) };
	if result < 0 {
		return Err(io::Error::last_os_error());
	}
	Ok(())
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
	/// A whole-argument match finds netcfgd's own process.
	#[test]
	fn a_marker_in_argv_is_found() {
		// The suffix is per test, not per process: tests in one binary share a
		// pid, so two of them using the same marker race for each other's
		// child and `pid_by_marker`'s lowest-pid rule picks the wrong one.
		let marker = format!(
			"/run/netcfgd-test-{}-found/supplicant/x.pid",
			std::process::id()
		);
		// `sh -c CMD NAME` puts NAME in the shell's own argv and keeps it
		// there while it waits. `sleep 30 <path>` would not: sleep rejects a
		// non-numeric argument and the child would be gone before /proc could
		// be asked, which is a test that proves nothing rather than a fix.
		let mut child = std::process::Command::new("sh")
			.arg("-c")
			.arg("sleep 30")
			.arg(&marker)
			.spawn()
			.expect("spawn");
		// The child may not have exec'd yet; /proc is authoritative only once
		// it has, so retry rather than sleep once and hope.
		let mut found = None;
		for _ in 0..100 {
			found = pid_by_marker(&marker);
			if found.is_some() {
				break;
			}
			std::thread::sleep(std::time::Duration::from_millis(20));
		}
		let seen = found;
		let _ = child.kill();
		let _ = child.wait();
		assert_eq!(seen, i32::try_from(child.id()).ok());
	}

	/// **A substring must not match.** This is the whole defensibility of
	/// scanning `/proc` at all: the module header forbids finding a process by
	/// name, and what makes this exception narrow is that the marker is an
	/// absolute path tested as a whole argument. Loosen it and netcfgd would
	/// adopt another manager's supplicant.
	#[test]
	fn a_substring_of_an_argument_does_not_match() {
		let marker = format!(
			"/run/netcfgd-test-{}-substr/supplicant/x.pid",
			std::process::id()
		);
		// `sh -c CMD NAME` puts NAME in the shell's own argv and keeps it
		// there while it waits. `sleep 30 <path>` would not: sleep rejects a
		// non-numeric argument and the child would be gone before /proc could
		// be asked, which is a test that proves nothing rather than a fix.
		let mut child = std::process::Command::new("sh")
			.arg("-c")
			.arg("sleep 30")
			.arg(&marker)
			.spawn()
			.expect("spawn");
		let mut ready = false;
		for _ in 0..100 {
			if pid_by_marker(&marker).is_some() {
				ready = true;
				break;
			}
			std::thread::sleep(std::time::Duration::from_millis(20));
		}
		let prefix = pid_by_marker(&marker[..marker.len() - 4]);
		let longer = pid_by_marker(&format!("{marker}.more"));
		let _ = child.kill();
		let _ = child.wait();
		assert!(ready, "the child never appeared, so this proved nothing");
		assert_eq!(prefix, None, "a proper prefix must not match");
		assert_eq!(longer, None, "a longer string must not match");
	}

	/// A marker nothing carries returns nothing, rather than a stray pid.
	#[test]
	fn an_absent_marker_finds_nothing() {
		assert_eq!(
			pid_by_marker("/run/netcfgd-nothing-carries-this-9c1f2e/x.pid"),
			None
		);
	}

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
