#![forbid(unsafe_code)]

//! Running an `OpenVPN` tunnel whose configuration netcfgd does not own.
//!
//! The shape differs from every other backend here in one way that decides
//! everything else. netcfgd generates hostapd's configuration and `pppd`'s
//! options file; it generates none of `OpenVPN`'s. `openvpn --help` lists **253
//! top-level options**, against a couple of dozen expressible keys for hostapd,
//! and a `.ovpn` is something an operator is *given* rather than a rendering of
//! an intent netcfgd holds. Decision 0046 has the argument; the consequence for
//! this crate is that it never opens the file.
//!
//! What it owns is the lifecycle: start the daemon, stop the one it started,
//! and say what the daemon said when it will not run.
//!
//! ## Stopped through the management socket
//!
//! `--management <path> unix` gives `OpenVPN` a line-oriented text protocol on a
//! unix **stream** socket, and `signal SIGTERM` over it stops the daemon. That
//! is the third daemon of this shape after `wpa_supplicant` and `hostapd`, and
//! decision 0014's reason for preferring it holds unchanged: an operator's own
//! `OpenVPN` tunnels are common, and killing a process found by name would reach
//! one netcfgd did not start.
//!
//! The socket is a stream where `wpa_ctrl` is a datagram, so this is a separate
//! client rather than a reuse of [`netcfgd_supplicant`]'s.

use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

/// Where the management sockets and logs live.
///
/// Under netcfgd's own `/run` rather than `/run/openvpn`, for the reason
/// [`netcfgd_hostapd::ctrl_dir`](https://docs.rs/) gives about hostapd: a
/// socket in the distribution's location would be found by that distribution's
/// tooling, which would then be managing a tunnel netcfgd owns.
#[must_use]
pub fn run_dir(run_dir: &Path) -> PathBuf {
	run_dir.join("openvpn")
}

/// The management socket for one tunnel.
#[must_use]
pub fn socket_path(run: &Path, iface: &str) -> PathBuf {
	run_dir(run).join(format!("{iface}.sock"))
}

/// Where the daemon's startup diagnostics go.
#[must_use]
pub fn log_path(run: &Path, iface: &str) -> PathBuf {
	run_dir(run).join(format!("{iface}.log"))
}

/// Where the credentials for one tunnel go, when the server wants any.
///
/// Mode 0600 and under `/run`, which is the same trade the generated hostapd
/// configuration and the `pppd` options file already make and comes with the
/// same mitigations: `/run` is tmpfs so it does not survive a reboot, and the
/// document itself still carries only a `SecretRef` (constraint 5). `OpenVPN` has
/// no indirection for a password either -- `--auth-user-pass` takes a file with
/// the username on the first line and the password on the second, and there is
/// no other way in.
#[must_use]
pub fn auth_path(run: &Path, iface: &str) -> PathBuf {
	run_dir(run).join(format!("{iface}.auth"))
}

/// Write the credentials file, or remove it when the document carries none.
///
/// # Errors
///
/// Returns a message naming the file that could not be written.
fn write_auth(run: &Path, iface: &str, username: &str, password: &str) -> Result<PathBuf, String> {
	use std::os::unix::fs::OpenOptionsExt;

	let path = auth_path(run, iface);
	// The mode is set at open rather than afterwards. A chmod after the write
	// leaves a window in which the password is world-readable, and a mode that
	// was wrong once is a mode that was wrong.
	let mut file = std::fs::OpenOptions::new()
		.write(true)
		.create(true)
		.truncate(true)
		.mode(0o600)
		.open(&path)
		.map_err(|error| format!("cannot write {}: {error}", path.display()))?;
	// Exactly two lines, which is what `--auth-user-pass` reads. A username
	// containing a newline would become a password line; nothing in the model
	// stops one, so it is stopped here.
	if username.contains('\n') || password.contains('\n') {
		return Err(format!(
			"the openvpn credentials for {iface} contain a newline, which would be read 			 as a different field"
		));
	}
	file.write_all(format!("{username}\n{password}\n").as_bytes())
		.map_err(|error| format!("cannot write {}: {error}", path.display()))?;
	Ok(path)
}

/// Find `openvpn`.
///
/// The same search as hostapd's and for the same reason: it lives in
/// `/usr/sbin`, which is not on a non-root `PATH` on Debian and several others.
#[must_use]
pub fn binary() -> Option<PathBuf> {
	for dir in ["/usr/sbin", "/sbin", "/usr/local/sbin", "/usr/bin"] {
		let path = Path::new(dir).join("openvpn");
		if path.is_file() {
			return Some(path);
		}
	}
	std::env::var_os("PATH").and_then(|paths| {
		std::env::split_paths(&paths)
			.map(|dir| dir.join("openvpn"))
			.find(|path| path.is_file())
	})
}

/// Start the tunnel described by `config`, which is a path netcfgd hands over
/// unread.
///
/// # Errors
///
/// Returns a message naming what failed: no openvpn installed, a configuration
/// file that is not there, or the daemon refusing to start -- quoting what it
/// said rather than its exit status.
pub fn start(
	run: &Path,
	iface: &str,
	config: &str,
	credentials: Option<(&str, &str)>,
) -> Result<(), String> {
	let dir = run_dir(run);
	std::fs::create_dir_all(&dir).map_err(|error| format!("{}: {error}", dir.display()))?;

	// Checked here rather than left to openvpn, only because the error is so
	// much better: netcfgd knows the path came from a document and can say so,
	// where openvpn says "Options error" against a file the operator may not
	// realise netcfgd chose.
	if !Path::new(config).is_file() {
		return Err(format!(
			"the openvpn configuration for {iface} is `{config}`, and there is no file there"
		));
	}

	let program = binary().ok_or_else(|| {
		format!("no openvpn found for {iface}; a tunnel needs the openvpn package")
	})?;

	let socket = socket_path(run, iface);
	// A socket left by a daemon that died takes the bind, and openvpn does not
	// clear it. Removing it here is safe because `stop` has already been asked
	// of anything netcfgd started.
	let _ = std::fs::remove_file(&socket);

	let log = log_path(run, iface);
	let capture = std::fs::File::create(&log)
		.map_err(|error| format!("cannot write {}: {error}", log.display()))?;
	let errors = capture
		.try_clone()
		.map_err(|error| format!("cannot write {}: {error}", log.display()))?;

	let auth = match credentials {
		Some((username, password)) => Some(write_auth(run, iface, username, password)?),
		// No credentials in the document. Left to the `.ovpn`, which for a file
		// with inline certificates authenticates without any -- and removed if
		// an earlier configuration had some, so a password does not outlive the
		// document that asked for it.
		None => {
			let _ = std::fs::remove_file(auth_path(run, iface));
			None
		}
	};

	let mut command = Command::new(&program);
	command
		.arg("--config")
		.arg(config)
		// The interface name is netcfgd's to choose, not the file's: the
		// document says `interface vpn0`, and a `.ovpn` that named something
		// else would produce a tunnel no plan could find.
		.arg("--dev")
		.arg(iface)
		.arg("--management")
		.arg(&socket)
		.arg("unix")
		// So the apply does not block. A tunnel can take seconds to negotiate,
		// and the interface arriving later is already how a PPPoE session
		// behaves -- the planner gets there on the next reconcile.
		.arg("--daemon")
		.arg(format!("netcfgd-{iface}"))
		.arg("--log")
		.arg(&log)
		.stdout(capture)
		.stderr(errors);
	if let Some(auth) = &auth {
		// The path, never the values. A password on a command line is readable
		// by every process on the machine through /proc.
		command.arg("--auth-user-pass").arg(auth);
	}
	let status = command
		.status()
		.map_err(|error| format!("could not run {}: {error}", program.display()))?;

	if !status.success() {
		return Err(format!(
			"openvpn would not start on {iface}: {}. Its output is in {}",
			complaints(&log, 2).unwrap_or_else(|| format!("it exited with {status}")),
			log.display()
		));
	}
	Ok(())
}

/// Stop the tunnel on one interface.
///
/// # Errors
///
/// Returns a message if the daemon is listening and will not stop. Nothing
/// listening is the state this was asked to produce, so that is success.
pub fn stop(run: &Path, iface: &str) -> Result<(), String> {
	let socket = socket_path(run, iface);
	let Ok(mut client) = Management::connect(&socket) else {
		return Ok(());
	};
	client
		.command("signal SIGTERM")
		.map_err(|error| format!("could not stop the openvpn tunnel on {iface}: {error}"))?;
	// The daemon removes its own socket on the way out, but only if it got far
	// enough to install the handler. Left behind, it would take the bind on the
	// next start.
	let _ = std::fs::remove_file(&socket);
	// And the credentials, which have nothing left to authenticate. `/run` is
	// tmpfs so they would go at the next reboot regardless, but a password
	// sitting beside a tunnel that is not running is one nobody is watching.
	let _ = std::fs::remove_file(auth_path(run, iface));
	Ok(())
}

/// A connection to one tunnel's management socket.
pub struct Management {
	stream: UnixStream,
}

impl Management {
	/// How long to wait for the daemon to answer.
	///
	/// Short, and for the reason `netcfgd_hostapd::acl::read`'s is: this runs
	/// where an apply is waiting, and the daemon is answering from memory. A
	/// tunnel that has wedged should not hold the executor.
	const TIMEOUT: Duration = Duration::from_secs(2);

	/// Open the management socket.
	///
	/// # Errors
	///
	/// Returns an error when nothing is listening, which is the ordinary case
	/// for a tunnel that is not running.
	pub fn connect(path: &Path) -> std::io::Result<Self> {
		let stream = UnixStream::connect(path)?;
		stream.set_read_timeout(Some(Self::TIMEOUT))?;
		stream.set_write_timeout(Some(Self::TIMEOUT))?;
		Ok(Self { stream })
	}

	/// Send one command and read until the daemon answers it.
	///
	/// `OpenVPN` greets a new client with `>INFO:` before it is asked anything,
	/// and emits further `>`-prefixed notifications whenever it likes,
	/// interleaved with replies. Reading the first line as the answer is the
	/// classic bug in a management client and produces a stop that silently did
	/// nothing -- the same failure `netcfgd_supplicant`'s client documents for
	/// `wpa_ctrl` events, arrived at independently because both protocols made
	/// the same choice.
	///
	/// Skipping them needs no test for `>`: reading until a line *is* an answer
	/// passes over anything that is not one, and a `>` branch on top would be a
	/// guard clause no input could make fire. The guarantee is pinned by
	/// `tests/live/openvpn.sh`, whose fake sends the greeting first, rather
	/// than by a line of code that looks like it is doing the work.
	///
	/// # Errors
	///
	/// Returns an error on a socket failure, a timeout, or an `ERROR:` reply.
	pub fn command(&mut self, command: &str) -> std::io::Result<String> {
		writeln!(self.stream, "{command}")?;
		self.stream.flush()?;

		let reader = BufReader::new(self.stream.try_clone()?);
		for line in reader.lines() {
			let line = line?;
			let line = line.trim_end();
			if let Some(rest) = line.strip_prefix("SUCCESS: ") {
				return Ok(rest.to_owned());
			}
			if let Some(rest) = line.strip_prefix("ERROR: ") {
				return Err(std::io::Error::new(
					std::io::ErrorKind::InvalidData,
					format!("openvpn refused `{command}`: {rest}"),
				));
			}
		}
		Err(std::io::Error::new(
			std::io::ErrorKind::UnexpectedEof,
			format!("no answer to `{command}`"),
		))
	}
}

/// The lines of a log that say what went wrong, for an error message.
///
/// The same problem and the same answer as hostapd's: a daemon that fails
/// announces the reason and then narrates its shutdown, so the tail is the
/// wrong lines. `OpenVPN`'s own vocabulary for the two failures that matter is
/// `Options error:` for a configuration it will not take and `Cannot` or
/// `Could not` for a file or a socket it cannot have.
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
			["options error", "error:", "cannot", "could not", "fatal"]
				.iter()
				.any(|marker| lowered.contains(marker))
		})
		.take(count)
		.copied()
		.collect();
	let chosen = if telling.is_empty() {
		lines[lines.len().saturating_sub(count)..].to_vec()
	} else {
		telling
	};
	Some(chosen.join("; ").trim_end_matches('.').to_owned())
}
