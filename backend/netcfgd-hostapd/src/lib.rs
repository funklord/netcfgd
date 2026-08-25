#![forbid(unsafe_code)]

//! Running an access point through `hostapd`.
//!
//! An `access_point` block is the last of the four features the M4 freeze put
//! in the document with nothing behind them. Decision 0026 says why it is
//! hostapd: it is what a wireless router actually runs, and it is the only
//! thing that can grow the parts of an access point the schema does not yet
//! describe.
//!
//! The shape differs from [`netcfgd_supplicant`] in one way that drives
//! everything here. A supplicant is filled over its control socket, so
//! decision 0015 can say it holds no state; hostapd reads a file once at
//! startup and offers no way to hand it a network afterwards. So netcfgd
//! writes that file, into `/run` where derived state belongs (constraint 1),
//! and regenerates it on every apply. Nothing is read back out of it -- the
//! document remains the only authority, and the file is a rendering of the
//! document rather than a second place a network can be defined.
//!
//! The control socket is still used, for stopping. hostapd speaks the same
//! `wpa_ctrl` protocol as `wpa_supplicant`, so the client from that crate
//! reaches it unchanged.

pub mod acl;
pub mod render;
pub mod station;

pub use acl::Live;
pub use render::{band_of_hw_mode, config, to_file, to_redacted, Line, Unsupported};
pub use station::{stations, Station};

use netcfgd_model::{AccessPoint, ObservedPolicy};
use netcfgd_secret::Resolver;
use std::path::{Path, PathBuf};
use std::process::Command;

/// Where the control sockets and generated configurations live.
///
/// Under netcfgd's own `/run` directory rather than `/run/hostapd`, because a
/// socket in the distribution's location would be found by that
/// distribution's `hostapd_cli` and its init script, which would then be
/// talking to an access point netcfgd owns.
#[must_use]
pub fn ctrl_dir(run_dir: &Path) -> PathBuf {
	run_dir.join("hostapd")
}

/// The generated configuration for one device.
#[must_use]
pub fn config_path(run_dir: &Path, device: &str) -> PathBuf {
	ctrl_dir(run_dir).join(format!("{device}.conf"))
}

/// Where hostapd's startup diagnostics go.
#[must_use]
pub fn log_path(run_dir: &Path, device: &str) -> PathBuf {
	ctrl_dir(run_dir).join(format!("{device}.log"))
}

/// Where the access point on this device records its pid.
///
/// netcfgd chooses the path and passes it as `-P`, which is what makes it a
/// usable marker: it names the interface and it lands in hostapd's command
/// line, so `/proc/<pid>/cmdline` can confirm that the pid belongs to *this*
/// access point rather than to whatever recycled the number. The supplicant's
/// pid file is the same shape for the same reason (0080).
#[must_use]
pub fn pid_path(run_dir: &Path, device: &str) -> PathBuf {
	ctrl_dir(run_dir).join(format!("{device}.pid"))
}

/// Find `hostapd`.
///
/// The same search as the supplicant's, and for the same reason: it lives in
/// `/usr/sbin`, which is not on a non-root `PATH` on Debian and several
/// others, so `Command::new("hostapd")` finds nothing on a machine that has
/// it.
#[must_use]
pub fn binary() -> Option<PathBuf> {
	for dir in ["/usr/sbin", "/sbin", "/usr/local/sbin", "/usr/bin"] {
		let path = Path::new(dir).join("hostapd");
		if path.is_file() {
			return Some(path);
		}
	}
	std::env::var_os("PATH").and_then(|paths| {
		std::env::split_paths(&paths)
			.map(|dir| dir.join("hostapd"))
			.find(|path| path.is_file())
	})
}

/// Write the configuration for one access point, and say where it went.
///
/// Mode 0600 before anything is written to it, because a `psk` access point's
/// file holds the passphrase in the clear -- hostapd has no indirection for
/// it. That is the same trade the `PPPoE` options file already makes, and the
/// same mitigations apply: the file is under `/run`, so it is tmpfs and does
/// not survive a reboot, and the document itself still carries only a
/// `SecretRef` (constraint 5).
///
/// # Errors
///
/// Returns a message naming the access point if the document cannot be
/// rendered, or the file cannot be written.
pub fn write_config(
	run_dir: &Path,
	access_point: &AccessPoint,
	resolver: &Resolver,
) -> Result<PathBuf, String> {
	use std::io::Write;
	use std::os::unix::fs::OpenOptionsExt;

	let dir = ctrl_dir(run_dir);
	std::fs::create_dir_all(&dir).map_err(|error| format!("{}: {error}", dir.display()))?;

	let passphrase = match &access_point.security {
		netcfgd_model::Security::Psk(psk) => Some(
			resolver
				.resolve(&psk.passphrase)
				.map_err(|error| format!("`{}`: {error}", access_point.id))?,
		),
		_ => None,
	};

	let lines = config(
		access_point,
		&dir,
		passphrase.as_ref().map(netcfgd_secret::Secret::expose),
	)
	.map_err(|error| format!("`{}`: {error}", access_point.id))?;

	// Before the configuration that names it: hostapd refuses to start when
	// `deny_mac_file` points at nothing, so a run where this failed silently
	// would take the access point down rather than leave the list unenforced.
	// Written even when the list is empty, for the same reason -- an empty file
	// is the statement "nobody is denied", and a missing one is a failure.
	write_acl(run_dir, access_point)?;

	let path = config_path(run_dir, &access_point.device);
	// Truncate through `OpenOptions` rather than `fs::write` plus a chmod: the
	// window between the two is a window in which the passphrase is readable by
	// everybody, and a mode set afterwards is a mode that was wrong once.
	let mut file = std::fs::OpenOptions::new()
		.write(true)
		.create(true)
		.truncate(true)
		.mode(0o600)
		.open(&path)
		.map_err(|error| format!("cannot write {}: {error}", path.display()))?;
	file.write_all(to_file(&access_point.id, &lines).as_bytes())
		.map_err(|error| format!("cannot write {}: {error}", path.display()))?;

	Ok(path)
}

/// Where the station list for one device is written.
#[must_use]
pub fn acl_path(run_dir: &Path, device: &str) -> PathBuf {
	ctrl_dir(run_dir).join(format!("{device}.acl"))
}

/// Write the station list, or remove it when the document asks for none.
///
/// Mode 0644 rather than the configuration's 0600: this holds no secret, and a
/// list of MAC addresses that only root can read is a list nobody debugging an
/// access point can read either.
///
/// # Errors
///
/// Returns a message naming the file that could not be written.
pub fn write_acl(run_dir: &Path, access_point: &AccessPoint) -> Result<(), String> {
	use std::io::Write;
	use std::os::unix::fs::OpenOptionsExt;

	let path = acl_path(run_dir, &access_point.device);
	let Some(acl) = &access_point.access_control else {
		// A block that was there and is not any more. Leaving the file would
		// leave a list that nothing reads, which is worse than no file: the
		// next person to look would find an ACL and believe it.
		match std::fs::remove_file(&path) {
			Ok(()) => return Ok(()),
			Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
			Err(error) => return Err(format!("cannot remove {}: {error}", path.display())),
		}
	};
	// Mode at open rather than left to the umask, so that the comment above is
	// a fact about the file and not about whoever started the daemon.
	let mut file = std::fs::OpenOptions::new()
		.write(true)
		.create(true)
		.truncate(true)
		.mode(0o644)
		.open(&path)
		.map_err(|error| format!("cannot write {}: {error}", path.display()))?;
	file.write_all(render::acl_contents(acl).as_bytes())
		.map_err(|error| format!("cannot write {}: {error}", path.display()))
}

/// Which policy the access point on this device was started with.
///
/// Read out of the station list netcfgd generated, where [`render::acl_contents`]
/// records it as a comment hostapd ignores. Three answers, because the two ways
/// of finding no policy mean opposite things:
///
/// - **No file.** [`write_acl`] removes it when the document carries no
///   `access_control` block, so its absence says hostapd was started without
///   one and has no `macaddr_acl` at all -- [`ObservedPolicy::Unset`].
/// - **A file with no record**, written by a netcfgd from before this existed:
///   [`ObservedPolicy::Unknown`], and nothing may be converged from there.
/// - **A file with a record**: that policy.
///
/// This is only the truth about a *running* hostapd. The file is written by
/// [`start`] and by nothing else, so while the process is alive it says what
/// the process read; once it has exited the file is a leftover and the caller
/// must not treat it as an observation. That is why the observer asks only
/// about backends it believes are running.
#[must_use]
pub fn recorded_policy(run_dir: &Path, device: &str) -> ObservedPolicy {
	match std::fs::read_to_string(acl_path(run_dir, device)) {
		Ok(contents) => render::policy_in(&contents).map_or(ObservedPolicy::Unknown, |policy| {
			ObservedPolicy::Set(policy)
		}),
		Err(error) if error.kind() == std::io::ErrorKind::NotFound => ObservedPolicy::Unset,
		// Present and unreadable is not the same as absent. A file netcfgd
		// cannot open says nothing about what hostapd read out of it, and
		// reporting `Unset` would have the planner restart an access point over
		// a permissions problem.
		Err(_) => ObservedPolicy::Unknown,
	}
}

/// Open the control socket of the access point on one device.
///
/// The phrasing is the point of having this in one place. "Connection refused
/// on a unix socket" sends an operator to look at permissions; what is almost
/// always true is that no access point is running, which is the ordinary state
/// for a radio whose block was never applied.
///
/// The deadline is a parameter because one caller runs in the reconcile loop
/// and the rest do not -- see [`acl::read`], which is the one that cannot
/// afford to wait.
///
/// # Errors
///
/// Returns that message, naming the device.
pub fn connect(
	run_dir: &Path,
	device: &str,
	timeout: std::time::Duration,
) -> Result<netcfgd_supplicant::Client, String> {
	netcfgd_supplicant::Client::connect_within(&ctrl_dir(run_dir), device, timeout).map_err(
		|error| {
			format!(
				"no access point is running on {device}, or its control socket is \
				 unreachable: {error}"
			)
		},
	)
}

/// How long an ordinary command may take.
///
/// The client's own default, named here so the callers that want it read the
/// same as the one that does not.
pub const PATIENT: std::time::Duration = std::time::Duration::from_secs(10);

/// How hostapd is invoked, as a list something can assert against.
///
/// A function rather than four chained `arg` calls for the reason
/// `udhcpc_start_args` is one (0108): an argument list nothing can read back is
/// an argument list a rewrite can quietly drop a flag from, and both flags here
/// are load-bearing in ways no compiler notices.
///
/// `-B` daemonizes, which is what makes the exit status mean "hostapd started"
/// rather than "hostapd was launched" -- it forks only after the interface is
/// up, so a configuration it will not parse and a driver it cannot attach to
/// both come back as a failure here rather than as a daemon that dies later.
///
/// `-P` names the pid file, and without it an access point is the one backend
/// netcfgd can never tell has died: the liveness pass (0078) needs a handle,
/// and the recorded `running: true` would otherwise be the only account of a
/// daemon that crashed an hour ago -- so 0079's restart could not fire for it
/// either. Decision 0110.
///
/// The order is hostapd's own usage, which puts the flags before the
/// configuration file: `hostapd [-hdBKtv] [-P <PID file>] ...
/// <configuration file(s)>`.
///
/// One thing this deliberately does not fix. hostapd writes the pid file
/// *after* it daemonizes -- `os_daemonize` calls `daemon(0, 0)` and only then
/// `fopen` -- so the parent whose exit status is read above is gone before the
/// file appears. That window is harmless, and only because of 0078's rule: a
/// pid file that is not there means netcfgd cannot tell, which is not the same
/// as "it is not running". Do not turn a missing file into a stop.
#[must_use]
pub fn start_args(pid: &Path, config: &Path) -> Vec<std::ffi::OsString> {
	vec![
		"-B".into(),
		"-P".into(),
		pid.as_os_str().to_owned(),
		config.as_os_str().to_owned(),
	]
}

/// Start an access point.
///
/// # Errors
///
/// Returns a message naming what failed: no hostapd installed, a document this
/// build cannot render, or hostapd refusing to start.
pub fn start(
	run_dir: &Path,
	access_point: &AccessPoint,
	resolver: &Resolver,
) -> Result<(), String> {
	let device = &access_point.device;
	let path = write_config(run_dir, access_point, resolver)?;

	let program = binary().ok_or_else(|| {
		format!(
			"no hostapd found for {device}; an access point needs the hostapd package. \
			 netcfgd does not implement one itself (doc/decision/0026)"
		)
	})?;

	// Startup diagnostics go to a file rather than through a pipe. hostapd
	// daemonizes on success and closes its standard streams when it does, so a
	// pipe would be fine -- but a file is fine either way, and it leaves the
	// reason an access point failed somewhere the operator can read it after
	// the fact rather than only in whatever captured netcfgd's stderr.
	let log = log_path(run_dir, device);
	let capture = std::fs::File::create(&log)
		.map_err(|error| format!("cannot write {}: {error}", log.display()))?;
	let errors = capture
		.try_clone()
		.map_err(|error| format!("cannot write {}: {error}", log.display()))?;

	let status = Command::new(&program)
		.args(start_args(&pid_path(run_dir, device), &path))
		.stdout(capture)
		.stderr(errors)
		.status()
		.map_err(|error| format!("could not run {}: {error}", program.display()))?;

	if !status.success() {
		// hostapd exits nonzero for a configuration it will not parse *and* for
		// a driver it cannot initialise -- it daemonizes only after the
		// interface is up, which is what makes this check worth making at all.
		// The last lines it wrote say which, and they are far more use than the
		// exit status: "unknown configuration item" and "nl80211 driver
		// initialization failed" send the operator to different places.
		return Err(format!(
			"hostapd would not start on {device}: {}. Its output is in {}",
			complaints(&log, 2).unwrap_or_else(|| format!("it exited with {status}")),
			log.display()
		));
	}
	Ok(())
}

/// Stop an access point.
///
/// Through the control socket rather than by signal, for the reason the
/// supplicant's teardown gives: killing by name would reach an access point
/// netcfgd did not start.
///
/// # Errors
///
/// Returns a message if hostapd is listening and refuses to stop. Nothing
/// listening is the state this was asked to produce, so that is success.
pub fn stop(run_dir: &Path, device: &str) -> Result<(), String> {
	// Nothing listening is taken as nothing running, and that is safe *here*
	// because hostapd's `-B` returns only after the control interface is up --
	// measured against a real hostapd 2.10, where the socket is already there
	// the moment the parent exits. openvpn's `--daemon` is the opposite and
	// needed a pid file for it (0074); do not make these symmetrical without
	// measuring the daemon in question.
	//
	// But *only* nothing listening. This swallowed every error at all until
	// decision 0109, and the one it was most wrong about is a hostapd that has
	// bound its socket and gone silent: `connect` opens with a `PING`, so that
	// daemon fails here rather than at `TERMINATE`, and the stop reported
	// success without a byte having been sent. Measured, not reasoned about --
	// a stopped fake answers nothing, `ncfg apply` said `ok backend.stop`, the
	// access point was still on the air, and the run state came back with no
	// backend in it at all, so nothing would ever try again.
	let dir = ctrl_dir(run_dir);
	let outcome = match netcfgd_supplicant::Client::connect_within(
		&dir,
		device,
		netcfgd_supplicant::IMPATIENT,
	) {
		Ok(client) => client
			.command("TERMINATE")
			.map_err(|error| format!("could not stop the access point on {device}: {error}")),
		Err(error) if netcfgd_supplicant::nothing_is_listening(&error) => Ok(()),
		Err(error) => Err(format!(
			"could not stop the access point on {device}: it is running and did \
			 not answer its control socket: {error}"
		)),
	};

	// The generated configuration holds the passphrase in the clear, because
	// hostapd has no indirection for one -- and an access point that is not
	// running has nothing to authenticate. `/run` is tmpfs so it would go at
	// the next reboot regardless, but a passphrase sitting beside a stopped
	// access point is one nobody is watching.
	//
	// Removed whether or not the daemon answered, and that is the case that
	// matters most: a hostapd that died leaves the file behind and is exactly
	// the situation where nobody is going to come back and tidy it.
	//
	// Nothing reads it after startup. `write_config` is its only writer and
	// `start` its only caller, so a start after this regenerates it -- and the
	// policy record the observer reads lives in the `.acl` beside it, which
	// holds no secret and keeps the lifecycle decision 0039 gave it.
	let _ = std::fs::remove_file(config_path(run_dir, device));

	// And the pid file, for the reason the supplicant's teardown gives (0080):
	// hostapd removes its own on a clean exit, one that was killed leaves it,
	// and a stale file would have the next observation asking about a pid that
	// belongs to somebody else by then.
	//
	// After the `TERMINATE` above rather than before, and unconditionally: if
	// the stop failed, `outcome` carries that and the backend stays in the run
	// state, so the next run asks again. Removing the file cannot make that
	// worse -- a missing pid file is "cannot tell", which is where an access
	// point that will not answer already is.
	let _ = std::fs::remove_file(pid_path(run_dir, device));
	outcome
}

/// The lines of a log that say what went wrong, for an error message.
///
/// The tail is the wrong answer, which is what running this against a real
/// hostapd showed. hostapd announces the problem and then narrates its
/// shutdown, so the last three lines of a failed start are `AP-DISABLED`,
/// `CTRL-EVENT-TERMINATING` and `Interface ap0 wasn't started` -- all true,
/// none of them the reason, and the operator is sent to look at the interface
/// when the answer was "this driver is not a wireless driver" four lines
/// earlier.
///
/// So the diagnosis is picked out by what it looks like instead. The two
/// failures that matter both announce themselves in the first line that
/// matches: a configuration hostapd will not parse says `Line 6: ...`, and a
/// driver it cannot attach to says `nl80211 driver initialization failed`.
///
/// Joined with `; ` rather than kept as lines: this ends up in a single-line
/// journal record and in `ncfg apply` output, where an embedded newline breaks
/// the alignment of everything after it.
fn complaints(path: &Path, count: usize) -> Option<String> {
	let text = std::fs::read_to_string(path).ok()?;
	let lines: Vec<&str> = text
		.lines()
		.map(str::trim)
		.filter(|line| !line.is_empty())
		.collect();
	if lines.is_empty() {
		return None;
	}

	let telling: Vec<&str> = lines
		.iter()
		.filter(|line| {
			let lowered = line.to_lowercase();
			line.starts_with("Line ")
				|| [
					"fail",
					"error",
					"not support",
					"cannot",
					"could not",
					"invalid",
				]
				.iter()
				.any(|marker| lowered.contains(marker))
		})
		.take(count)
		.copied()
		.collect();

	// Nothing recognisable: the tail, which is at least the most recent thing
	// hostapd had to say. Better than reporting only the exit status.
	let chosen = if telling.is_empty() {
		lines[lines.len().saturating_sub(count)..].to_vec()
	} else {
		telling
	};
	// hostapd's lines end in a full stop about half the time, and the caller
	// puts this in the middle of a sentence. Trimming here rather than there,
	// because here is where it is known that the text came from somebody else.
	Some(chosen.join("; ").trim_end_matches('.').to_owned())
}

#[cfg(test)]
mod tests {
	use super::{pid_path, start_args};
	use std::path::Path;

	/// Both flags, in hostapd's order, with the pid file netcfgd chose.
	///
	/// The pid path is asserted as a whole string rather than "contains -P",
	/// because the path is not decoration: it is the marker the liveness check
	/// looks for in `/proc/<pid>/cmdline`, so a `-P` pointing somewhere netcfgd
	/// does not read would satisfy a looser test and tell netcfgd nothing.
	#[test]
	fn the_access_point_is_told_where_to_record_its_pid() {
		let run = Path::new("/run/netcfgd");
		let args = start_args(
			&pid_path(run, "ap0"),
			Path::new("/run/netcfgd/hostapd/ap0.conf"),
		);
		let args: Vec<String> = args
			.iter()
			.map(|arg| arg.to_string_lossy().into_owned())
			.collect();
		assert_eq!(
			args,
			vec![
				"-B",
				"-P",
				"/run/netcfgd/hostapd/ap0.pid",
				"/run/netcfgd/hostapd/ap0.conf",
			]
		);
	}

	/// The pid file sits beside the socket and the configuration, and names the
	/// device -- one access point per device, so two never collide.
	#[test]
	fn the_pid_file_is_named_for_the_device() {
		let run = Path::new("/run/netcfgd");
		assert_eq!(
			pid_path(run, "wlan1"),
			Path::new("/run/netcfgd/hostapd/wlan1.pid")
		);
		assert_ne!(pid_path(run, "ap0"), pid_path(run, "ap1"));
	}
}
