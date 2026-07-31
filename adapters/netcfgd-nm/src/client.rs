//! Talking to netcfgd.
//!
//! The adapter is an ordinary unprivileged socket client (design section 9.2):
//! it holds no capability, has no privileged path into the daemon, and can do
//! exactly what the control tiers let any other client do. Nothing here is
//! special-cased for being an adapter, which is the property that makes
//! "deletable without trace" true rather than aspirational.
//!
//! Blocking, like every other client in this tree. The shim serves D-Bus from
//! a thread and refreshes from this one, and a socket round trip on a local
//! unix socket is not a thing worth an async runtime.

use netcfgd_model::Observed;
use netcfgd_proto::{read_message, write_message, Request, Response};
use std::io::{BufReader, BufWriter};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};

/// Where the daemon's socket is.
///
/// `NCFG_RUN_DIR` for the same reason every other component honours it: a test
/// needs somewhere that is not the real one, and a network namespace does not
/// give it a separate mount namespace.
#[must_use]
pub(crate) fn socket_path() -> PathBuf {
	std::env::var_os("NCFG_RUN_DIR")
		.map_or_else(|| PathBuf::from("/run/netcfgd"), PathBuf::from)
		.join("netcfgd.sock")
}

/// One request, one response.
///
/// # Errors
///
/// Returns a message naming what could not be reached. "Connection refused"
/// alone sends the reader looking for a network problem, when the answer is
/// that a daemon is not running.
pub(crate) fn ask(socket: &Path, request: &Request) -> Result<Response, String> {
	let stream = UnixStream::connect(socket).map_err(|error| {
		format!(
			"cannot reach netcfgd at {}: {error}. The shim serves NetworkManager's \
			 interface from netcfgd's state, so it needs netcfgd running",
			socket.display()
		)
	})?;
	let write_half = stream
		.try_clone()
		.map_err(|error| format!("cannot use the socket: {error}"))?;

	let mut reader = BufReader::new(stream);
	let mut writer = BufWriter::new(write_half);

	write_message(&mut writer, request).map_err(|error| format!("cannot send: {error}"))?;
	match read_message::<Response, _>(&mut reader) {
		Ok(Some(Response::Error { message })) => Err(message),
		Ok(Some(response)) => Ok(response),
		Ok(None) => Err("netcfgd closed the connection without answering".to_owned()),
		Err(error) => Err(format!("cannot read the answer: {error}")),
	}
}

/// The observed state of the machine.
///
/// # Errors
///
/// Returns a message if the daemon cannot be reached or answers with something
/// other than a status.
pub(crate) fn observed(socket: &Path) -> Result<Observed, String> {
	match ask(socket, &Request::Status)? {
		Response::Status(observed) => Ok(*observed),
		other => Err(format!(
			"asked netcfgd for status and got {}",
			describe(&other)
		)),
	}
}

/// The compiled desired-state document.
///
/// # Errors
///
/// Returns a message if the daemon cannot be reached or answers with something
/// other than a document.
pub(crate) fn document(socket: &Path) -> Result<netcfgd_model::Document, String> {
	match ask(socket, &Request::Show)? {
		Response::Document(document) => Ok(*document),
		other => Err(format!(
			"asked netcfgd for the document and got {}",
			describe(&other)
		)),
	}
}

/// Scan for access points on a radio.
///
/// This is the one request here that makes the hardware do something, so it is
/// only sent when a client asks -- `RequestScan`, or the first time a radio is
/// published. NM clients call it when a menu opens, which is exactly when a
/// scan is wanted; scanning on a timer would keep a radio busy for nobody.
///
/// # Errors
///
/// Returns netcfgd's own message. A radio with no supplicant running says so,
/// and passing that through unchanged is more use than "scan failed".
pub(crate) fn scan(
	socket: &Path,
	interface: &str,
) -> Result<Vec<netcfgd_proto::ScanEntry>, String> {
	let request = Request::WifiScan {
		interface: interface.to_owned(),
	};
	match ask(socket, &request)? {
		Response::WifiScan(report) => Ok(report.access_points),
		other => Err(format!(
			"asked netcfgd to scan and got {}",
			describe(&other)
		)),
	}
}

/// Which access point a radio is associated with, if any.
///
/// # Errors
///
/// Returns netcfgd's own message.
pub(crate) fn associated(socket: &Path, interface: &str) -> Result<Option<String>, String> {
	let request = Request::WifiStatus {
		interface: interface.to_owned(),
	};
	match ask(socket, &request)? {
		// An unassociated radio reports a state and no BSSID. The supplicant
		// also spells "not associated" as an all-zero address, which is not a
		// BSSID any scan will match, so it is read as absence.
		Response::WifiStatus(status) => Ok(status
			.bssid
			.filter(|bssid| bssid != "00:00:00:00:00:00" && !bssid.is_empty())),
		other => Err(format!(
			"asked netcfgd for radio status and got {}",
			describe(&other)
		)),
	}
}

/// Re-read the configuration directory.
///
/// # Errors
///
/// Returns netcfgd's own message, which for a config that does not compile is
/// the diagnostics -- exactly what a client should show.
pub(crate) fn reload(socket: &Path) -> Result<(), String> {
	match ask(socket, &Request::Reload)? {
		Response::Ok => Ok(()),
		other => Err(format!(
			"asked netcfgd to reload and got {}",
			describe(&other)
		)),
	}
}

/// Join a network the configuration already describes.
///
/// Decision 0013's boundary, unchanged by being reached over D-Bus: this can
/// join what somebody with the admin tier wrote down, and nothing else. The
/// shim holds no privilege the CLI does not.
///
/// # Errors
///
/// Returns netcfgd's own message, including its refusal when the network is
/// not in the configuration.
pub(crate) fn connect(socket: &Path, interface: &str, network: &str) -> Result<(), String> {
	let request = Request::WifiConnect {
		interface: interface.to_owned(),
		network: network.to_owned(),
	};
	match ask(socket, &request)? {
		Response::Ok => Ok(()),
		other => Err(format!(
			"asked netcfgd to connect and got {}",
			describe(&other)
		)),
	}
}

/// Leave the current network without forgetting it.
///
/// # Errors
///
/// Returns netcfgd's own message.
pub(crate) fn disconnect(socket: &Path, interface: &str) -> Result<(), String> {
	let request = Request::WifiDisconnect {
		interface: interface.to_owned(),
	};
	match ask(socket, &request)? {
		Response::Ok => Ok(()),
		other => Err(format!(
			"asked netcfgd to disconnect and got {}",
			describe(&other)
		)),
	}
}

/// What a response is, for an error message.
///
/// Named rather than silently ignored: a client that treats an unexpected
/// answer as success is the bug this project keeps refusing to write.
fn describe(response: &Response) -> &'static str {
	match response {
		Response::Hello { .. } => "a hello",
		Response::Status(_) => "a status",
		Response::Plan(_) => "a plan",
		Response::Document(_) => "a document",
		Response::Journal(_) => "a journal",
		Response::Explanation(_) => "an explanation",
		Response::Event(_) => "an event",
		Response::WifiScan(_) => "a scan",
		Response::WifiStatus(_) => "a radio status",
		Response::ApStations(_) => "a station list",
		Response::Ok => "ok",
		Response::Error { .. } => "an error",
	}
}

/// A monitor stream, for noticing that the machine changed.
///
/// Design section 9.3 needs `PropertiesChanged` to be emitted rather than
/// merely answered, because libnm builds a client-side cache and an applet
/// that never hears about a change draws stale state forever. netcfgd already
/// streams events for exactly this, so the shim subscribes rather than polls.
pub(crate) struct Monitor {
	reader: BufReader<UnixStream>,
}

impl Monitor {
	/// Open a monitor stream.
	///
	/// # Errors
	///
	/// Returns a message if the daemon cannot be reached.
	pub(crate) fn open(socket: &Path) -> Result<Self, String> {
		let stream = UnixStream::connect(socket)
			.map_err(|error| format!("cannot reach netcfgd at {}: {error}", socket.display()))?;
		let write_half = stream
			.try_clone()
			.map_err(|error| format!("cannot use the socket: {error}"))?;
		let mut writer = BufWriter::new(write_half);
		write_message(&mut writer, &Request::Monitor)
			.map_err(|error| format!("cannot subscribe: {error}"))?;
		Ok(Self {
			reader: BufReader::new(stream),
		})
	}

	/// Block until the machine changes, or the stream ends.
	///
	/// Returns `None` when netcfgd goes away, which the caller treats as a
	/// reason to reconnect rather than as an error -- a daemon restart is an
	/// ordinary event, and an applet should not have to be restarted with it.
	pub(crate) fn next_change(&mut self) -> Option<()> {
		loop {
			match read_message::<Response, _>(&mut self.reader) {
				Ok(Some(Response::Event(_))) => return Some(()),
				// Anything else on this stream is not an event and not a
				// reason to redraw the world.
				Ok(Some(_)) => {}
				Ok(None) | Err(_) => return None,
			}
		}
	}
}
