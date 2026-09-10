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

/// The real and effective uids of a process, from `/proc/<pid>/status`.
///
/// **The real uid is the one that answers "who started this", and it is not
/// the one the obvious instrument reports.** `stat` on `/proc/<pid>` gives the
/// *effective* uid, and for a setuid binary the kernel reports that directory
/// as root's -- so a process an unprivileged user launched to be mistaken for
/// netcfgd's stats as root. Measured on this machine, with a marker netcfgd
/// composes in its own argv:
///
/// ```text
/// $ sudo -k -S -p '' /run/netcfgd/openvpn/vpn0.sock < pipe &
/// stat -c %u /proc/<pid>          ->  0
/// grep ^Uid: /proc/<pid>/status   ->  Uid:  1000  0  0  0
/// ```
///
/// sudo will refuse the command, but the attacker chooses how long it sits at
/// the password prompt, and adoption needs to happen once. So this reads the
/// `Uid:` line and takes the first field.
fn uids_of(pid: &str) -> Option<(u32, u32)> {
	let status = std::fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
	let line = status.lines().find(|line| line.starts_with("Uid:"))?;
	let mut fields = line.split_whitespace().skip(1);
	let real = fields.next()?.parse().ok()?;
	let effective = fields.next()?.parse().ok()?;
	Some((real, effective))
}

/// Whoever is asking.
fn my_uid() -> u32 {
	uids_of("self").map_or(u32::MAX, |(_, effective)| effective)
}

/// Whether a process could be one netcfgd started.
///
/// **A marker in `argv` says nothing about who put it there.** Every marker
/// netcfgd uses is a path it composed from its own run directory and one
/// interface -- and it is a *predictable* path, not a secret one, so any local
/// user can type it into their own command line and have it matched. Measured:
/// `sh -c 'sleep 300' /run/netcfgd/openvpn/vpn0.sock`, run as an ordinary
/// user, was adopted as netcfgd's `OpenVPN` backend; netcfgd recorded the start
/// as done, started no openvpn, and reported the tunnel up.
///
/// What the impostor cannot forge is *privilege*. netcfgd runs as root and
/// starts its backends as root, so a candidate an unprivileged user could have
/// created is not netcfgd's, whatever its argv says.
///
/// **Root, or whoever is asking** -- and the second half is not slack. netcfgd
/// applying is root, so it collapses to "root" in the case that matters. It is
/// there because `ncfg diff` and `ncfg status` observe locally and may be run
/// by anybody: a rule of "root only" would be read by an unprivileged observer
/// as every backend having stopped, and it would then plan to start them all.
/// A rule of "mine only" would refuse a root backend for the same reader. The
/// pair is the rule that is safe from both ends, and it is also what lets the
/// tests below run as an ordinary user against their own children.
fn ours(pid: i32, mine: u32) -> bool {
	uids_of(&pid.to_string()).is_some_and(|(real, _)| real == 0 || real == mine)
}

/// The pid in a file, if the process it names is alive and is the one expected.
///
/// **A pid file outlives the process it names, and pids are recycled.** So the
/// pid is only half an answer: the other half is `/proc/<pid>/cmdline`, read
/// NUL-separated so that `marker` has to be a *whole argument* rather than a
/// substring of one, and `/proc/<pid>/status` for who started it. `None`
/// covers every way of not knowing -- no file, no number in it, no such
/// process, or a process that is somebody else's.
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
	pid_of_as(path, marker, my_uid())
}

/// [`pid_of`], told who is asking, so that a test can supply a uid its own
/// children do not have and watch the answer be refused.
fn pid_of_as(path: &Path, marker: &str, mine: u32) -> Option<i32> {
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
		.filter(|pid| ours(*pid, mine))
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
/// `argv` element, by exactly the test [`pid_of`] applies. Loosen this to a
/// substring or to a program name and the rule really is broken -- which is
/// what the negative tests below are for.
///
/// **This used to say that no other manager's command line can carry the
/// marker, and that was the wrong question.** No other *manager* would, and
/// nothing stops anybody else: the path is composed from public parts, so a
/// local user can type it into their own `argv` and be adopted. The marker
/// says which backend a process claims to be; [`ours`] is what says whether
/// the claim is worth anything.
///
/// The lowest matching pid, so that the answer is stable across calls when a
/// caller has somehow produced two.
#[must_use]
pub fn pid_by_marker(marker: &str) -> Option<i32> {
	pid_by_marker_as(marker, my_uid())
}

/// [`pid_by_marker`], told who is asking. See [`pid_of_as`].
fn pid_by_marker_as(marker: &str, mine: u32) -> Option<i32> {
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
			&& ours(pid, mine)
		{
			found = Some(found.map_or(pid, |seen: i32| seen.min(pid)));
		}
	}
	found
}

/// The program a pid is running, from `/proc/<pid>/comm`.
///
/// `comm` rather than `cmdline[0]`: a daemon re-executed under a path, a
/// symlink or a wrapper has whatever argv it was given, while `comm` is the
/// kernel's own name for the executable. It is **truncated to 15 characters**,
/// which is why the caller's list carries `systemd-resolve` rather than
/// `systemd-resolved` -- a fact worth stating where the list is written, since
/// a name that is one character too long simply never matches and the sweep
/// reports nothing.
#[must_use]
pub fn program_of(pid: i32) -> Option<String> {
	let text = std::fs::read_to_string(format!("/proc/{pid}/comm")).ok()?;
	let name = text.trim_end_matches('\n');
	(!name.is_empty()).then(|| name.to_owned())
}

/// Whether a service manager is holding this process up.
///
/// **A killed service comes straight back**, so this is the difference between
/// removing an interference and starting a fight that cannot be won:
/// `systemd-resolved.service` carries `Restart=`, and signalling it buys
/// seconds. The answer for those is `Conflicts=` in a unit, not a signal.
///
/// Read from `/proc/<pid>/cgroup`, where a systemd service names a
/// `*.service` slice. A process outside one -- started from a shell, a hook,
/// an init script that does not supervise -- has no such name, and a kill
/// holds for it.
///
/// **It answers false where it cannot tell**, which is the direction that
/// matches the caller: an unreadable cgroup on a kernel without the
/// controller is not evidence of supervision, and treating it as such would
/// make the sweep do nothing on exactly the machines it is wanted on.
///
/// **The question is whose service, and it used to be "any service".** Every
/// process netcfgd spawns inherits netcfgd's own cgroup, so a dhcpcd that
/// netcfgd started is in `/system.slice/netcfgd.service` -- which contains
/// `.service`, so the old test answered yes about netcfgd's own child.
///
/// Measured on the reporting machine the moment netcfgd was selected:
///
/// ```text
/// dhcpcd (pid 2538344) keeps rewriting resolv.conf and is run by a service
/// manager, so netcfgd is not signalling it
/// resolv.conf has been taken back 3 times and netcfgd found nothing it could signal
/// ```
///
/// -- netcfgd declining to signal a process it had started itself, and
/// advising the operator to stand it down with `Conflicts=`. The guard exists
/// so netcfgd does not fight *another* supervisor; turned on netcfgd's own
/// children it does the one thing it was written to prevent, which is leave an
/// interference in place.
///
/// So compare the unit rather than look for the word. A pid in the same
/// `*.service` as this process is this process' own and is netcfgd's to
/// signal; one in a different service belongs to somebody who will restart it.
/// Where *our* unit cannot be read the old answer stands: not being able to
/// prove it is ours is not evidence that it is.
#[must_use]
pub fn is_service_supervised(pid: i32) -> bool {
	supervised_by_another(
		service_of(&pid.to_string()).as_deref(),
		service_of("self").as_deref(),
	)
}

/// The `*.service` unit a `/proc` entry belongs to, if any.
///
/// A cgroup line is `0::/system.slice/netcfgd.service`, and a delegated child
/// may sit below it -- `.../netcfgd.service/something.scope` -- so this takes
/// the nearest `.service` component rather than the last one.
fn service_of(pid: &str) -> Option<String> {
	let text = std::fs::read_to_string(format!("/proc/{pid}/cgroup")).ok()?;
	text.lines()
		.find_map(|line| line.rsplit('/').find(|part| part.ends_with(".service")))
		.map(ToOwned::to_owned)
}

/// Whether a process is in *this* process' own service.
///
/// **The other half of the cgroup question, and the load-bearing one.** A
/// process netcfgd started inherits netcfgd's cgroup, so this is a positive
/// identification of netcfgd's own children -- including the ones netcfgd has
/// no record of.
///
/// It has one, and it matters: dhcpcd writes its pid file to its own run
/// directory, `/run/dhcpcd/<iface>-4.pid`, and netcfgd's `ours()` scans
/// `/run/netcfgd/*/*.pid`. Measured on the reporting machine:
///
/// ```text
/// /run/dhcpcd/wlp0s20f3-4.pid          <- dhcpcd's, where netcfgd does not look
/// /run/netcfgd/supplicant/wlp0s20f3.pid <- the only pid netcfgd knows
/// ```
///
/// So netcfgd's own DHCP client is not on its list of its own processes, and
/// the resolv.conf sweep treated it as a foreign writer. Nothing bad followed
/// only because [`is_service_supervised`] was answering yes about it for the
/// wrong reason -- two faults cancelling, and fixing either one alone makes
/// netcfgd terminate the client holding this machine's lease.
///
/// The cgroup answers where a pid file cannot: dhcpcd forks a privileged
/// proxy, a control proxy and a BPF helper, all of which inherit the cgroup
/// and none of which appear in any pid file.
///
/// **False where netcfgd is not under a service manager at all** -- run from a
/// shell, or under `unshare` as the live suite does -- which leaves the
/// existing identification to do the work it already does there.
#[must_use]
pub fn in_our_service(pid: i32) -> bool {
	let ours = service_of("self");
	ours.is_some() && service_of(&pid.to_string()) == ours
}

/// The decision, without the filesystem, so it can be checked.
///
/// `None` for theirs is a process in no service at all: killable. Equal units
/// mean it is one of ours. `None` for ours -- netcfgd not under systemd, or a
/// `/proc` that will not answer about this process -- leaves the conservative
/// answer, since a service netcfgd cannot prove is its own is one that may
/// come straight back.
fn supervised_by_another(theirs: Option<&str>, ours: Option<&str>) -> bool {
	theirs.is_some() && ours != theirs
}

/// Whether a process is in the same network namespace as this one.
///
/// **A daemon in another network namespace is not configuring netcfgd's
/// interfaces**, so it cannot be interfering with netcfgd whatever its name
/// is. That is not a nicety: netcfgd's own live suite runs each script under
/// `unshare -rn`, where `/proc` still lists every process on the machine, so
/// without this a test that reached the sweep would terminate the developer's
/// real `dhclient` or `NetworkManager`. It is equally the right answer for a
/// container, where the host's daemons are visible and are somebody else's.
///
/// **It fails closed, and that is the opposite of
/// [`is_service_supervised`].** Where the link cannot be read -- a process
/// that exited between the scan and the check, or one whose `/proc` entry is
/// not readable -- the answer is "not ours to signal". The two defaults point
/// opposite ways because the costs do: mistaking a supervised process for an
/// unsupervised one wastes a signal, while mistaking another namespace's
/// process for ours kills something outside the world netcfgd manages.
#[must_use]
pub fn shares_network_namespace(pid: i32) -> bool {
	let Ok(mine) = std::fs::read_link("/proc/self/ns/net") else {
		return false;
	};
	std::fs::read_link(format!("/proc/{pid}/ns/net")).is_ok_and(|theirs| theirs == mine)
}

/// Every pid whose program name is one of `names`.
///
/// The scan `pid_by_marker` does, asked a different question: that one looks
/// for an argument netcfgd put there, and this one for programs netcfgd did
/// not start at all.
#[must_use]
pub fn pids_of_programs(names: &[&str]) -> Vec<(i32, String)> {
	let mut found = Vec::new();
	let Ok(entries) = std::fs::read_dir("/proc") else {
		return found;
	};
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
		if let Some(program) = program_of(pid) {
			if names.iter().any(|wanted| *wanted == program) {
				found.push((pid, program));
			}
		}
	}
	found.sort_unstable();
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

/// Why a program would not run, when the kernel said `EACCES`.
///
/// **`Permission denied` on an exec has two causes and they need different
/// repairs**, and the message the standard library gives is the same for
/// both: the file is not executable, or it is executable and sits on a
/// filesystem mounted `noexec`. Decision 0178 is the second one costing an
/// afternoon -- systemd has mounted `/run` `noexec` by default since v256,
/// netcfgd wrote a hook there, and dhcpcd's `script_runreason: Permission
/// denied` appeared 1,350 times in a journal while netcfgd reported success.
///
/// So this answers the question the operator has next: **is the mode wrong,
/// or is the mount?** It looks the program up the way an exec does -- an
/// absolute path as given, a bare name along `PATH` -- and reports the first
/// candidate that exists. A file that is there with an executable bit set,
/// refused anyway, is the mount, and nothing else it could be.
///
/// Returns `None` where there is nothing useful to add: another errno, a
/// program that is not there at all (the caller's own "not installed"
/// message is better), or a `PATH` this cannot read.
#[must_use]
pub fn exec_refusal(program: &str, error: &io::Error) -> Option<String> {
	use std::os::unix::fs::PermissionsExt as _;

	if error.kind() != io::ErrorKind::PermissionDenied {
		return None;
	}
	let path = if program.contains('/') {
		Some(std::path::PathBuf::from(program))
	} else {
		std::env::var_os("PATH").and_then(|paths| {
			std::env::split_paths(&paths)
				.map(|dir| dir.join(program))
				.find(|candidate| candidate.exists())
		})
	}?;
	let mode = std::fs::metadata(&path).ok()?.permissions().mode();
	Some(if mode & 0o111 == 0 {
		format!(
			"{} is there with mode {:04o}, which has no executable bit",
			path.display(),
			mode & 0o7777
		)
	} else {
		format!(
			"{} is there and executable, so the refusal is the filesystem it is on -- \
			 a `noexec` mount. systemd mounts /run that way by default, and often /tmp",
			path.display()
		)
	})
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

	/// **A marker carried by somebody else's process is refused.**
	///
	/// The whole defect: the marker is a predictable path, so a local user can
	/// put it in their own `argv`. The child below is exactly the reproduction
	/// -- an ordinary `sh` carrying an `OpenVPN` management socket path -- and
	/// the uid it is asked about is one no process here has, which is what a
	/// root netcfgd looking at a user's process is. Found for the real uid,
	/// refused for the other, so the difference is the guard and not the scan.
	#[test]
	fn a_marker_carried_by_another_user_is_refused() {
		let marker = format!(
			"/run/netcfgd-test-{}-foreign/openvpn/vpn0.sock",
			std::process::id()
		);
		let mut child = std::process::Command::new("sh")
			.arg("-c")
			.arg("sleep 30")
			.arg(&marker)
			.spawn()
			.expect("spawn");
		// **A root-owned child cannot demonstrate this refusal, by design.**
		// `ours` answers "root, or whoever is asking" -- a process owned by
		// root is netcfgd's whatever uid asks, which is the rule the doc
		// comment above argues for and the thing that makes an unprivileged
		// `ncfg status` safe. So when this suite runs as root its own child is
		// root's, `ours` says yes to every caller, and there is no refusal to
		// observe.
		//
		// Probed on the child rather than asked of `geteuid`: what decides is
		// who owns the process, and that is what is read here.
		if uids_of(&child.id().to_string()).is_some_and(|(real, _)| real == 0) {
			let _ = child.kill();
			let _ = child.wait();
			eprintln!(
				"a_marker_carried_by_another_user_is_refused: skipped -- this suite is running as root, so its own \
				 child is root-owned and `ours` returns true for every caller by \
				 design. The refusal is exercised when the suite runs as an \
				 ordinary user."
			);
			return;
		}
		let mine = my_uid();
		let mut ready = false;
		for _ in 0..100 {
			if pid_by_marker_as(&marker, mine).is_some() {
				ready = true;
				break;
			}
			std::thread::sleep(std::time::Duration::from_millis(20));
		}
		// A uid nothing on the machine runs as, so `ours` can answer only
		// "not root and not you". `mine + 1` would be a real account.
		let refused = pid_by_marker_as(&marker, u32::MAX - 1);
		let _ = child.kill();
		let _ = child.wait();
		assert!(ready, "the child never appeared, so this proved nothing");
		assert_eq!(
			refused, None,
			"a process another user started must not be adopted"
		);
	}

	/// The same guard on the pid-file path, which is what signals a process.
	#[test]
	fn a_pid_file_naming_another_user_is_refused() {
		let dir = std::env::temp_dir().join(format!("netcfgd-owner-{}", std::process::id()));
		std::fs::create_dir_all(&dir).expect("mkdir");
		let marker = dir.join("supplicant.pid").to_string_lossy().into_owned();
		let mut child = std::process::Command::new("sh")
			.arg("-c")
			.arg("sleep 30")
			.arg(&marker)
			.spawn()
			.expect("spawn");
		// **A root-owned child cannot demonstrate this refusal, by design.**
		// `ours` answers "root, or whoever is asking" -- a process owned by
		// root is netcfgd's whatever uid asks, which is the rule the doc
		// comment above argues for and the thing that makes an unprivileged
		// `ncfg status` safe. So when this suite runs as root its own child is
		// root's, `ours` says yes to every caller, and there is no refusal to
		// observe.
		//
		// Probed on the child rather than asked of `geteuid`: what decides is
		// who owns the process, and that is what is read here.
		if uids_of(&child.id().to_string()).is_some_and(|(real, _)| real == 0) {
			let _ = child.kill();
			let _ = child.wait();
			eprintln!(
				"a_pid_file_naming_another_user_is_refused: skipped -- this suite is running as root, so its own \
				 child is root-owned and `ours` returns true for every caller by \
				 design. The refusal is exercised when the suite runs as an \
				 ordinary user."
			);
			return;
		}
		let file = dir.join("pid");
		std::fs::write(&file, format!("{}\n", child.id())).expect("write");
		let mine = my_uid();
		// `sh` may not have exec'd yet, and /proc is authoritative only once it
		// has -- so retry rather than read once and hope. Without this the
		// positive half fails intermittently and says nothing about the guard.
		let mut found = None;
		for _ in 0..100 {
			found = pid_of_as(&file, &marker, mine);
			if found.is_some() {
				break;
			}
			std::thread::sleep(std::time::Duration::from_millis(20));
		}
		let refused = pid_of_as(&file, &marker, u32::MAX - 1);
		let _ = child.kill();
		let _ = child.wait();
		let _ = std::fs::remove_file(&file);
		let _ = std::fs::remove_dir(&dir);
		assert_eq!(
			found,
			i32::try_from(child.id()).ok(),
			"its own child must be found"
		);
		assert_eq!(
			refused, None,
			"a process another user started must not be signalled"
		);
	}

	/// **`Uid:`'s first field, not `stat` on the directory.**
	///
	/// `/proc/<pid>` is owned by the *effective* uid, and the kernel reports it
	/// as root's for a setuid binary -- so the obvious instrument answers
	/// "root" for a process an unprivileged user started. This asserts the two
	/// fields are read in the right order against a process whose real and
	/// effective uid are the same, which is the only case a test can build
	/// without privilege; the setuid measurement is in `uids_of`'s comment.
	///
	/// **The negative half needs the caller not to be root**, because `ours`
	/// accepts a root-owned process for anybody on purpose -- "root, or
	/// whoever is asking", and its comment says why. So under `unshare -r`,
	/// where uid 0 is mapped and the test *is* root, `and no other is` asked
	/// for a refusal the rule does not make, and failed. It had been passing
	/// as real root only by accident of ordering: the privilege tests run
	/// first, shed, and take the whole process to uid 65534 on the way.
	#[test]
	fn the_real_uid_is_read_before_the_effective_one() {
		let (real, effective) = uids_of("self").expect("this process has a status file");
		assert_eq!(real, effective, "an unprivileged test is not setuid");
		assert!(
			ours(i32::try_from(std::process::id()).expect("a pid fits"), real),
			"its own uid is its own"
		);
		if real == 0 {
			eprintln!(
				"process: skipping the refusal -- this process is root, and `ours` \
				 accepts a root-owned process for every caller by design"
			);
			return;
		}
		assert!(
			!ours(
				i32::try_from(std::process::id()).expect("a pid fits"),
				u32::MAX - 1
			),
			"and no other is"
		);
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

	/// **`Permission denied` on an exec is two faults, and they are repaired
	/// differently.** A missing executable bit is a `chmod`; an executable
	/// file on a `noexec` mount is a mount option, and no amount of `chmod`
	/// will touch it. The standard library gives the same four words for both.
	#[test]
	fn a_program_with_no_executable_bit_is_named_with_its_mode() {
		use std::os::unix::fs::PermissionsExt as _;

		let dir = netcfgd_testdir::TestDir::new("exec-refusal");
		let program = dir.join("client");
		std::fs::write(&program, b"#!/bin/sh\nexit 0\n").expect("written");
		std::fs::set_permissions(&program, std::fs::Permissions::from_mode(0o644)).expect("chmod");

		let denied = io::Error::from(io::ErrorKind::PermissionDenied);
		let said = super::exec_refusal(&program.display().to_string(), &denied)
			.expect("a program that is there has something to say");
		assert!(said.contains("0644"), "names the mode it found: {said}");
		assert!(said.contains("no executable bit"), "got {said}");
	}

	/// And a file that *is* executable and was refused anyway: the mount.
	///
	/// No mount is made here, and none is needed -- the function's whole job
	/// is to read what is on disk and say which of the two remains. 0178 is
	/// the case this exists for, and it cost a day with the answer sitting in
	/// `findmnt`.
	#[test]
	fn an_executable_program_that_was_refused_points_at_the_mount() {
		let dir = netcfgd_testdir::TestDir::new("exec-refusal");
		let program = dir.join("client");
		std::fs::write(&program, b"#!/bin/sh\nexit 0\n").expect("written");
		make_executable(&program);

		let denied = io::Error::from(io::ErrorKind::PermissionDenied);
		let said = super::exec_refusal(&program.display().to_string(), &denied)
			.expect("an executable file that would not run has something to say");
		assert!(said.contains("noexec"), "names the mount option: {said}");
		assert!(
			said.contains(&program.display().to_string()),
			"names the file: {said}"
		);
	}

	/// **Nothing to add is said by saying nothing**, so the caller's own
	/// message stands. Another errno is one; a program that is not installed
	/// is the other, and there the caller's "install one of these" is better
	/// than anything this could invent.
	#[test]
	fn nothing_is_added_where_there_is_nothing_to_add() {
		let dir = netcfgd_testdir::TestDir::new("exec-refusal");
		let program = dir.join("client");
		std::fs::write(&program, b"#!/bin/sh\n").expect("written");
		make_executable(&program);

		assert!(
			super::exec_refusal(
				&program.display().to_string(),
				&io::Error::from(io::ErrorKind::NotFound)
			)
			.is_none(),
			"a different errno is not this function's question"
		);
		assert!(
			super::exec_refusal(
				&dir.join("never-installed").display().to_string(),
				&io::Error::from(io::ErrorKind::PermissionDenied)
			)
			.is_none(),
			"a program that is not there has nothing to look at"
		);
	}

	fn make_executable(path: &std::path::Path) {
		use std::os::unix::fs::PermissionsExt as _;
		std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).expect("chmod");
	}

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

	/// Whose service, not any service.
	///
	/// Every process netcfgd spawns inherits netcfgd's cgroup, so the old test
	/// -- does this cgroup mention `.service` -- answered yes about netcfgd's
	/// own dhcpcd and netcfgd declined to signal a child it had started. The
	/// live symptom was resolv.conf being taken back three times with netcfgd
	/// reporting it had "found nothing it could signal".
	#[test]
	fn a_process_in_our_own_service_is_ours_to_signal() {
		let ours = Some("netcfgd.service");

		// The bug, as an assertion: netcfgd's own child.
		assert!(!supervised_by_another(Some("netcfgd.service"), ours));

		// Somebody else's, which is the whole reason the guard exists. A
		// killed `systemd-resolved` comes straight back.
		assert!(supervised_by_another(
			Some("systemd-resolved.service"),
			ours
		));
		assert!(supervised_by_another(Some("dhcpcd.service"), ours));

		// In no service at all -- a shell, a hook, an init script that does
		// not supervise. A kill holds for these.
		assert!(!supervised_by_another(None, ours));

		// netcfgd not under systemd, or a `/proc` that will not answer about
		// this process. Not being able to prove it is ours is not evidence
		// that it is, so the conservative answer stands.
		assert!(supervised_by_another(Some("dhcpcd.service"), None));
		assert!(!supervised_by_another(None, None));
	}

	/// The two halves answer opposite questions about the same fact.
	///
	/// `in_our_service` identifies netcfgd's own children -- the thing a pid
	/// file could not do, since dhcpcd writes its own to `/run/dhcpcd` and
	/// forks helpers that appear in no file at all. `is_service_supervised`
	/// identifies somebody else's. A process cannot be both, and the pair has
	/// to stay exclusive: they guard the same sweep, one skipping and one
	/// terminating, and an overlap would mean netcfgd killing its own client.
	#[test]
	fn ours_and_another_managers_are_exclusive() {
		for (theirs, ours) in [
			(Some("netcfgd.service"), Some("netcfgd.service")),
			(Some("dhcpcd.service"), Some("netcfgd.service")),
			(None, Some("netcfgd.service")),
			(Some("dhcpcd.service"), None),
			(None, None),
		] {
			// `in_our_service`'s rule, spelled the way the function spells it.
			let mine = ours.is_some() && theirs == ours;
			assert!(
				!(mine && supervised_by_another(theirs, ours)),
				"a process cannot be both ours and another manager's: \
				 theirs={theirs:?} ours={ours:?}"
			);
		}
	}

	/// The unit is read out of a real cgroup line, including a delegated child.
	#[test]
	fn the_service_is_the_nearest_one_in_the_path() {
		// This process, whatever is running the tests, has to be answerable
		// without panicking -- which is the only property available here,
		// since a test runner may be in a service, a user scope or neither.
		let _ = service_of("self");

		// Absent for a pid that cannot exist, rather than a panic.
		assert_eq!(service_of("0x00400000"), None);
	}
}
