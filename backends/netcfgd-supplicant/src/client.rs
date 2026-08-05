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

use crate::protocol::{is_event, Event, Reply};
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

/// How long a *stop* waits, which is not the same question.
///
/// The default above is sized for `SCAN_RESULTS` on a busy band. A `TERMINATE`
/// is a local datagram to a daemon that either answers at once or is not going
/// to, and the difference is not academic: `stop` runs inside the reconcile
/// loop, so the wait is a wait the whole machine takes.
///
/// Measured rather than reasoned about, on the laptop feature that has no
/// operator in it. Pull the cable with a wedged access point recorded, and the
/// switch to wifi took **12.2 seconds** on the ten-second default against
/// **106ms** with nothing wedged -- the reconcile loop blocked in the `PING`
/// inside `connect`, with a carrier event waiting behind it. That is the same
/// stall decision 0085 measured on the ACL read at 10.2 seconds and cured with
/// a deadline; the read got one and the stop kept the default.
///
/// One second, matching that read deliberately. It is enormous for a unix
/// datagram round trip and the symmetry is worth more than a tighter number.
///
/// **What this costs**: a healthy hostapd that is merely slow now fails its
/// stop rather than being waited for -- `acl.sh` has seen a healthy fake miss a
/// one-second deadline on a saturated machine. That failure is loud, fail-stop
/// and re-runnable, and it leaves the backend recorded (0109). Stalling every
/// other interface on the machine for ten seconds is neither loud nor
/// recoverable, and it happens on a working machine rather than a busy one.
pub const STOP_TIMEOUT: Duration = Duration::from_secs(1);

/// A connection to one interface's control socket.
#[derive(Debug)]
pub struct Client {
	socket: UnixDatagram,
	/// Our own bound path, removed on drop.
	local: PathBuf,
	/// The interface this socket belongs to, for diagnostics.
	interface: String,
	/// How long to wait for a reply on this connection.
	timeout: Duration,
}

impl Client {
	/// Connect to the control socket for `interface` under `dir`.
	///
	/// # Errors
	///
	/// Returns an error if the socket does not exist, cannot be bound to, or
	/// does not answer `PING`.
	pub fn connect(dir: &Path, interface: &str) -> io::Result<Self> {
		Self::connect_within(dir, interface, REPLY_TIMEOUT)
	}

	/// The same, waiting less than the default for every reply including the
	/// opening `PING`.
	///
	/// The `PING` is why this is a parameter rather than something set on a
	/// connection afterwards. It happens inside the connect, so a deadline
	/// applied to the returned client is a deadline that never covers the one
	/// round trip a wedged daemon is most likely to eat -- which is exactly what
	/// it did here, measured at ten seconds against a process that had bound its
	/// socket and stopped answering.
	///
	/// Shortening only: a longer value than the default is clamped, so this
	/// cannot be used to make a scan time out.
	///
	/// # Errors
	///
	/// The same as [`Client::connect`].
	pub fn connect_within(dir: &Path, interface: &str, timeout: Duration) -> io::Result<Self> {
		let timeout = timeout.min(REPLY_TIMEOUT);
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
		socket.set_read_timeout(Some(timeout))?;
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
			timeout,
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
		let deadline = Instant::now() + self.timeout;
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

	/// Ask to be sent unsolicited events on this connection.
	///
	/// `ATTACH` is per connection, not per supplicant: a client that has not
	/// asked gets replies only. So this is the whole difference between a
	/// connection that can watch a radio and one that can only interrogate it,
	/// and it is deliberately a separate call -- the request path drops events
	/// while waiting for a reply, and a connection doing both would throw away
	/// the ones that arrived at the wrong moment.
	///
	/// # Errors
	///
	/// Returns an error if the supplicant refuses or does not answer.
	pub fn attach(&self) -> io::Result<()> {
		self.command("ATTACH")
	}

	/// The next unsolicited event, or `None` if none arrived in time.
	///
	/// `None` is the ordinary answer on a quiet radio and is not an error --
	/// which is why the timeout is an argument: a caller polling several
	/// interfaces wants a short one, and one waiting on a single radio wants a
	/// long one rather than a spin.
	///
	/// Replies are skipped rather than returned. Nothing should be issuing
	/// commands on an attached connection, and if something does, its answer is
	/// not an event and must not be handed back as one.
	///
	/// # Errors
	///
	/// Returns an error if the socket fails. A timeout is `Ok(None)`.
	pub fn next_event(&self, timeout: Duration) -> io::Result<Option<Event>> {
		self.socket.set_read_timeout(Some(timeout))?;
		let mut buffer = vec![0_u8; 8192];
		match self.socket.recv(&mut buffer) {
			Ok(read) => {
				let text = String::from_utf8_lossy(&buffer[..read]).into_owned();
				Ok(Event::parse(&text))
			}
			// The two a timeout arrives as, which differ by platform and by
			// whether the socket was interrupted first.
			Err(error)
				if matches!(
					error.kind(),
					io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
				) =>
			{
				Ok(None)
			}
			Err(error) => Err(error),
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

/// Whether a failed [`Client::connect`] means there is nothing to talk to.
///
/// Every caller that stops a daemon through its control socket has to answer
/// this, and until it existed they all answered it the same wrong way: any
/// error at all was taken as "nothing is running", so the stop reported
/// success. That is right for a socket that is not there and wrong for every
/// other failure -- and the failure it is most wrong about is the one that
/// matters, because [`Client::connect`] sends a `PING` and a daemon that has
/// bound its socket and stopped answering fails here rather than at the
/// command. Reading that as absence tells the operator an access point was
/// stopped while it is still on the air with its passphrase in memory, and
/// drops it out of the run state so nothing ever tries again.
///
/// Two kinds mean absence and no others. `NotFound` is the socket not
/// existing, which `connect` raises by name. `ConnectionRefused` is a socket
/// file left behind by a process that is gone -- the kernel's answer for a
/// unix datagram address nobody has open. A timeout is not in the list, and
/// that is the whole point of the list.
#[must_use]
pub fn nothing_is_listening(error: &io::Error) -> bool {
	matches!(
		error.kind(),
		io::ErrorKind::NotFound | io::ErrorKind::ConnectionRefused
	)
}

impl Drop for Client {
	fn drop(&mut self) {
		// The bound path is a real file. Leaving it behind fills
		// `/run/wpa_supplicant` with dead sockets, and the next reader of that
		// directory cannot tell which are live.
		let _ = std::fs::remove_file(&self.local);
	}
}

#[cfg(test)]
mod tests {
	use super::nothing_is_listening;
	use std::io;

	/// The two that mean nothing is there, and the one that does not.
	///
	/// `WouldBlock` is what a `set_read_timeout` produces on Linux and is
	/// therefore the shape of a daemon that is running and silent. It is
	/// listed here so that a rewrite widening the match has to delete an
	/// assertion rather than merely relax a condition.
	#[test]
	fn a_silent_daemon_is_not_an_absent_one() {
		assert!(nothing_is_listening(&io::Error::from(
			io::ErrorKind::NotFound
		)));
		assert!(nothing_is_listening(&io::Error::from(
			io::ErrorKind::ConnectionRefused
		)));
		assert!(!nothing_is_listening(&io::Error::from(
			io::ErrorKind::WouldBlock
		)));
		assert!(!nothing_is_listening(&io::Error::from(
			io::ErrorKind::TimedOut
		)));
		assert!(!nothing_is_listening(&io::Error::from(
			io::ErrorKind::InvalidData
		)));
	}
}
