//! The control socket itself.
//!
//! `wpa_supplicant` listens on a unix *datagram* socket, which has a consequence
//! worth stating up front: the client must bind an address of its own, because
//! a datagram socket has nowhere to send the reply otherwise. That bound path
//! is a file in the filesystem, so it has to be created somewhere writable and
//! removed afterwards -- and both of those are this module's problem rather
//! than the caller's.
//!
//! No `unsafe` here. `UnixDatagram` covers bind, connect, send and receive,
//! and the timeout is a `set_read_timeout` rather than a `setsockopt` -- so
//! constraint 4 holds without an exception.

use crate::protocol::{is_event, Reply};
use std::io;
use std::os::unix::net::UnixDatagram;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant};

/// Distinguishes concurrent connections from one process.
static NEXT_SERIAL: AtomicU32 = AtomicU32::new(0);

/// Where `wpa_supplicant` puts its per-interface sockets by default.
pub const DEFAULT_CTRL_DIR: &str = "/run/wpa_supplicant";

/// How long to wait for a reply.
///
/// Generous, because `SCAN_RESULTS` on a busy band is not instant, and a
/// timeout here is reported to the operator as the supplicant being
/// unresponsive -- a false one of those is worse than a slow command.
const REPLY_TIMEOUT: Duration = Duration::from_secs(10);

/// A connection to one interface's control socket.
#[derive(Debug)]
pub struct Client {
	socket: UnixDatagram,
	/// Our own bound path, removed on drop.
	local: PathBuf,
	/// The interface this socket belongs to, for diagnostics.
	interface: String,
}

impl Client {
	/// Connect to the control socket for `interface` under `dir`.
	///
	/// # Errors
	///
	/// Returns an error if the socket does not exist, cannot be bound to, or
	/// does not answer `PING`.
	pub fn connect(dir: &Path, interface: &str) -> io::Result<Self> {
		let remote = dir.join(interface);
		if !remote.exists() {
			return Err(io::Error::new(
				io::ErrorKind::NotFound,
				format!(
					"no control socket at {}: is wpa_supplicant running on {interface}?",
					remote.display()
				),
			));
		}

		// The local path must be unique per process *and* per connection: two
		// clients in one process binding the same name is an error, and a
		// stale file from a crashed run would be too. A counter rather than a
		// clock, because two connections can be opened inside one clock tick.
		let serial = NEXT_SERIAL.fetch_add(1, Ordering::Relaxed);
		let local = dir.join(format!("netcfgd-{}-{serial}", std::process::id()));
		let _ = std::fs::remove_file(&local);

		let socket = UnixDatagram::bind(&local).map_err(|error| {
			io::Error::new(
				error.kind(),
				format!(
					"cannot create a reply socket at {}: {error}",
					local.display()
				),
			)
		})?;
		socket.set_read_timeout(Some(REPLY_TIMEOUT))?;
		socket.connect(&remote).map_err(|error| {
			let _ = std::fs::remove_file(&local);
			io::Error::new(
				error.kind(),
				format!("cannot reach {}: {error}", remote.display()),
			)
		})?;

		let client = Self {
			socket,
			local,
			interface: interface.to_owned(),
		};
		client.ping()?;
		Ok(client)
	}

	/// Which interface this client talks to.
	#[must_use]
	pub fn interface(&self) -> &str {
		&self.interface
	}

	/// Send a command and read its reply.
	///
	/// # Errors
	///
	/// Returns an error on a socket failure or a timeout. A `FAIL` reply is
	/// not an error here -- it is a [`Reply::Fail`], because several callers
	/// treat it as information rather than a fault.
	pub fn request(&self, command: &str) -> io::Result<Reply> {
		// A command containing a newline would be read as two, and the second
		// would run without ever having been reviewed by whatever built the
		// first. Everything reaching here is built by this crate, so this is a
		// backstop rather than the control -- but it is the kind of backstop
		// that turns a future mistake into an error instead of an incident.
		if command.contains(['\n', '\r', '\0']) {
			return Err(io::Error::new(
				io::ErrorKind::InvalidInput,
				"a control command cannot contain a newline",
			));
		}

		self.socket.send(command.as_bytes())?;

		// Events share this socket once anything has attached, and they arrive
		// interleaved with replies. Reading one as the answer to a command is
		// the classic bug in a `wpa_supplicant` client -- it produces a status
		// display that occasionally reports the previous command's outcome.
		let deadline = Instant::now() + REPLY_TIMEOUT;
		let mut buffer = vec![0_u8; 8192];
		loop {
			let read = self.socket.recv(&mut buffer)?;
			let text = String::from_utf8_lossy(&buffer[..read]).into_owned();
			if !is_event(&text) {
				return Ok(Reply::parse(&text));
			}
			if Instant::now() >= deadline {
				return Err(io::Error::new(
					io::ErrorKind::TimedOut,
					format!("no reply to `{command}`, only events"),
				));
			}
		}
	}

	/// Send a command, requiring a body rather than a failure.
	///
	/// # Errors
	///
	/// Returns an error on a socket failure, or if the supplicant answered
	/// `FAIL`.
	pub fn ask(&self, command: &str) -> io::Result<String> {
		self.request(command)?
			.body(command)
			.map_err(|message| io::Error::new(io::ErrorKind::InvalidData, message))
	}

	/// Send a command that must answer `OK`.
	///
	/// # Errors
	///
	/// Returns an error if the reply was anything else.
	pub fn command(&self, command: &str) -> io::Result<()> {
		match self.request(command)? {
			Reply::Ok => Ok(()),
			other => Err(io::Error::new(
				io::ErrorKind::InvalidData,
				format!("`{command}` answered {other:?} rather than OK"),
			)),
		}
	}

	/// Check the supplicant is alive.
	///
	/// # Errors
	///
	/// Returns an error if it does not answer `PONG`.
	pub fn ping(&self) -> io::Result<()> {
		match self.request("PING")? {
			Reply::Data(body) if body == "PONG" => Ok(()),
			other => Err(io::Error::new(
				io::ErrorKind::InvalidData,
				format!("PING answered {other:?} rather than PONG"),
			)),
		}
	}
}

impl Drop for Client {
	fn drop(&mut self) {
		// The bound path is a real file. Leaving it behind fills
		// `/run/wpa_supplicant` with dead sockets, and the next reader of that
		// directory cannot tell which are live.
		let _ = std::fs::remove_file(&self.local);
	}
}
