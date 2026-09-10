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
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::time::{Duration, Instant};

/// Distinguishes concurrent connections from one process.
static NEXT_SERIAL: AtomicU32 = AtomicU32::new(0);

/// Where `wpa_supplicant` puts its per-interface sockets by default.
pub const DEFAULT_CTRL_DIR: &str = "/run/wpa_supplicant";

/// What a client's own reply socket is called.
///
/// A datagram client must bind an address to be replied to, and it binds it in
/// the control directory beside the sockets it talks to -- that being the
/// directory both ends are known to be able to write. The consequence is that
/// **the control directory contains entries that are not interfaces**, and
/// anything reading it has to know which.
const REPLY_PREFIX: &str = "netcfgd-";

/// Is this directory entry one of netcfgd's own reply sockets?
///
/// For readers of the control directory, and it exists because one of them was
/// not doing this. The roam watcher took every entry as an interface name and
/// connected to it, which against a reply socket has two effects and both are
/// bad: the connect waits out its whole timeout, because the far end is a live
/// process that is not a server and will never answer a `PING` -- measured at
/// three `PING`s in twenty-five seconds, so once per timeout, forever -- and
/// the `PING` lands **in another client's reply queue**, where it is not an
/// event, so that client can return it as the answer to whatever command it had
/// just sent. Decision 0112.
///
/// A prefix rather than a parse: the serial and the pid are this module's
/// business, and a reader only needs to know the entry is ours.
#[must_use]
pub fn is_reply_socket(name: &str) -> bool {
	name.starts_with(REPLY_PREFIX)
}

/// How long a scan gets to finish before its results are read anyway.
///
/// A scan is not a round trip. The radio leaves the channel it is on and
/// visits every other one it is allowed to use, in both bands and in 6 GHz
/// where the hardware has it, dwelling on each long enough to hear a beacon.
/// Seconds, not milliseconds -- and the number is a property of the band plan
/// and the regulatory domain rather than of anything netcfgd controls.
///
/// Ten, which is `REPLY_TIMEOUT`'s reasoning applied to the thing it was
/// written about. Being wrong in the impatient direction here returns the
/// previous results and says so; being wrong in the other direction makes a
/// person wait for a radio that is not going to answer.
pub const SCAN_PATIENCE: Duration = Duration::from_secs(10);

/// Wait for a scan to finish.
///
/// **`SCAN` does not answer with results and `SCAN_RESULTS` does not scan.**
/// The first queues a scan and returns at once; the second reads the cache the
/// last completed scan filled. Sending one and immediately reading the other
/// therefore returns *the previous scan's* results, always -- and the scan
/// just asked for lands in whatever reads the cache next.
///
/// Measured on the reporting machine before this existed: `ncfg wifi scan`
/// returned in **7 milliseconds**, which is four orders of magnitude short of
/// a real scan, and three consecutive calls returned 15, then 20, then 20
/// access points. The first call's list was five networks out of date and the
/// scan it had just asked for is what made the second call's list right.
///
/// So wait for the supplicant to say it finished. `CTRL-EVENT-SCAN-RESULTS`
/// is that statement; `CTRL-EVENT-SCAN-FAILED` is the other outcome and is
/// worth returning early for, since nothing further is coming.
///
/// The caller must have sent `ATTACH` -- without it no event reaches this
/// connection and every scan waits out the full patience. It is not done here
/// because attaching has to happen *before* `SCAN` is sent, and this is called
/// after.
///
/// # Errors
///
/// Returns a description when the scan failed or did not finish in time. The
/// caller can still read `SCAN_RESULTS`; what it gets is stale, and the point
/// of the error is that it now knows that.
pub fn wait_for_scan(client: &Client, patience: Duration) -> Result<(), String> {
	let deadline = Instant::now() + patience;
	loop {
		let left = deadline.saturating_duration_since(Instant::now());
		if left.is_zero() {
			return Err(format!(
				"the scan did not finish within {}s",
				patience.as_secs()
			));
		}
		// Capped so a supplicant that goes quiet is noticed at the deadline
		// rather than one poll interval after it.
		match client.next_event(left.min(Duration::from_millis(250))) {
			Ok(Some(event)) => match event.name() {
				"CTRL-EVENT-SCAN-RESULTS" => return Ok(()),
				// `ret=` is the driver's own errno, negated: -16 is EBUSY, a
				// radio doing something else, and -100 is ENETDOWN. Passed
				// through rather than translated, because the set is the
				// kernel's and any translation here would be a partial one.
				"CTRL-EVENT-SCAN-FAILED" => {
					return Err(match event.field("ret") {
						Some(code) => format!("the supplicant could not scan (ret={code})"),
						None => "the supplicant could not scan".to_owned(),
					})
				}
				_ => {}
			},
			Ok(None) => {}
			Err(error) => return Err(format!("the supplicant stopped answering: {error}")),
		}
	}
}

/// Remove reply sockets left behind by processes that are gone.
///
/// **`Drop` removes the socket and cannot be relied on to.** netcfgd installs
/// no `SIGTERM` handler, so the default disposition kills the process outright
/// and nothing unwinds -- and a `SIGKILL` would skip `Drop` even if a handler
/// existed. Measured on the reporting machine: an ordinary
/// `systemctl restart netcfgd` took the directory from 18 entries to 20, two
/// per daemon lifetime, for ever. Sixteen of the eighteen belonged to processes
/// that no longer existed. Nothing had noticed because 0112 taught every reader
/// to skip these entries, so the litter was invisible to exactly the code that
/// was walking past it.
///
/// It is not a correctness fault and it is not nothing: the directory belongs
/// to `wpa_supplicant`, the roam watcher lists all of it on every pass, and a
/// runtime directory that only ever grows is one somebody eventually has to
/// explain.
///
/// **This deletes files, so it parses rather than prefix-matches.**
/// [`is_reply_socket`] is a prefix test and that is right for a reader deciding
/// what to skip; it is not enough for something removing what it finds. Five
/// things must hold, and a candidate failing any of them is left alone:
///
/// 1. the name is exactly `netcfgd-<pid>-<serial>`, both of them digits;
/// 2. it is a socket, by `symlink_metadata` so a symlink is never followed to
///    whatever it points at;
/// 3. the pid is not this process;
/// 4. `/proc/<pid>` does not exist, which is how the rest of this tree asks
///    whether a pid is alive -- and it needs no `unsafe`, so the promise at the
///    top of this file still holds;
/// 5. `/proc/self` *does* exist.
///
/// The last is the one that matters. Without `/proc` mounted, step 4 answers
/// "dead" for every pid on the machine, including the live ones -- so the
/// reaper would delete the reply sockets of running clients, which is the
/// failure it exists to prevent, committed wholesale. Where it cannot tell, it
/// removes nothing.
///
/// A pid that has been reused by an unrelated process leaves its socket in
/// place. Wrong in the direction that costs one stale entry rather than one
/// live connection.
///
/// Returns how many were removed, for the caller to say so. Decision 0193.
pub fn reap_reply_sockets(dir: &Path) -> usize {
	if !Path::new("/proc/self").exists() {
		return 0;
	}
	let Ok(entries) = std::fs::read_dir(dir) else {
		return 0;
	};
	let mine = std::process::id().to_string();
	let mut removed = 0;
	for entry in entries.flatten() {
		let Some(name) = entry.file_name().to_str().map(ToOwned::to_owned) else {
			continue;
		};
		let Some(rest) = name.strip_prefix(REPLY_PREFIX) else {
			continue;
		};
		let Some((pid, serial)) = rest.split_once('-') else {
			continue;
		};
		let shaped = !pid.is_empty()
			&& !serial.is_empty()
			&& pid.bytes().all(|byte| byte.is_ascii_digit())
			&& serial.bytes().all(|byte| byte.is_ascii_digit());
		if !shaped || pid == mine {
			continue;
		}
		let path = dir.join(&name);
		let Ok(metadata) = std::fs::symlink_metadata(&path) else {
			continue;
		};
		if !std::os::unix::fs::FileTypeExt::is_socket(&metadata.file_type()) {
			continue;
		}
		if Path::new(&format!("/proc/{pid}")).exists() {
			continue;
		}
		if std::fs::remove_file(&path).is_ok() {
			removed += 1;
		}
	}
	removed
}

/// How long to wait for a reply.
///
/// Generous, because `SCAN_RESULTS` on a busy band is not instant, and a
/// timeout here is reported to the operator as the supplicant being
/// unresponsive -- a false one of those is worse than a slow command.
const REPLY_TIMEOUT: Duration = Duration::from_secs(10);

/// How long anything with something waiting behind it gives a control socket.
///
/// The default above is sized for `SCAN_RESULTS` on a busy band. Nothing else
/// netcfgd sends is a scan: a `TERMINATE`, an ACL read, a `SET_NETWORK` are
/// local datagrams to a daemon that either answers at once or is not going to,
/// and every one of them happens somewhere a wait is a wait the machine takes.
///
/// One second, and it is the number every caller arrived at independently
/// before this constant existed -- the ACL read (0085), the observation, then
/// the stop (0111) -- which is why the consolidation is a rename rather than a
/// decision. Three private copies of `Duration::from_secs(1)` in two crates is
/// the same value with three chances to drift.
///
/// Measured rather than reasoned about, twice and from both ends:
///
/// - **What it saves.** With a wedged access point recorded, pulling the cable
///   took **12.2 seconds** to switch to wifi on the ten-second default, against
///   **106ms** with nothing wedged -- the reconcile loop blocked in a `PING`
///   for an unrelated interface (0111).
/// - **What it costs.** Against a real `wpa_supplicant`, every command
///   `populate_supplicant` sends answers in **0.07-0.13ms**. A second is some
///   four orders of magnitude beyond the worst of them, so the shortened
///   deadline cannot fail a supplicant that is merely busy.
///
/// Being wrong in the impatient direction costs an apply that fails, says which
/// daemon did not answer, and can be re-run -- the record is left behind for it
/// (0109). Being wrong in the other direction stalls a machine that is working.
pub const IMPATIENT: Duration = Duration::from_secs(1);

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
	/// Whether `ATTACH` succeeded, so `Drop` knows to undo it.
	attached: AtomicBool,
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
		// **Before anything touches the filesystem.** `interface` arrives from
		// a request at the `observe` tier, `dir.join` with an absolute path
		// replaces the base rather than extending it, and the two errors below
		// say different things about what is there -- so without this the
		// pair is an existence oracle over the whole filesystem, answered as
		// root. Refusing here rather than at the four call sites because this
		// is where the name becomes a path. Decision 0160.
		netcfgd_model::interface::usable_name(interface).map_err(|why| {
			io::Error::new(
				io::ErrorKind::InvalidInput,
				format!("`{interface}` is not an interface name: {why}"),
			)
		})?;
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
		let local = dir.join(format!("{REPLY_PREFIX}{}-{serial}", std::process::id()));
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
			attached: AtomicBool::new(false),
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
		let outcome = self.command("ATTACH");
		if outcome.is_ok() {
			self.attached.store(true, Ordering::Relaxed);
		}
		outcome
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
		// **An attached connection is registered inside `wpa_supplicant`**,
		// and removing the socket underneath it does not unregister anything.
		// The supplicant finds out on the next event it tries to deliver, logs
		//
		//     CTRL_IFACE: Detach monitor that cannot receive messages: ...
		//
		// and drops it then. Harmless once; this connection is now made and
		// dropped for every `ncfg wifi scan` (0194), so without this each scan
		// leaves a monitor for the supplicant to trip over, and every event it
		// emits walks a list of dead ones first.
		//
		// **Sent, not asked.** `command("DETACH")` would wait for OK, up to
		// this connection's timeout -- ten seconds against a supplicant that
		// has stopped answering, on a code path whose whole job is to let go.
		// Cleanup that can block is worse than cleanup that can be missed, and
		// the supplicant's own sweep is the backstop either way.
		if self.attached.load(Ordering::Relaxed) {
			let _ = self.socket.send(b"DETACH");
		}
		// The bound path is a real file. Leaving it behind fills
		// `/run/wpa_supplicant` with dead sockets, and the next reader of that
		// directory cannot tell which are live.
		let _ = std::fs::remove_file(&self.local);
	}
}

#[cfg(test)]
mod tests {
	use super::{is_reply_socket, nothing_is_listening, reap_reply_sockets, Client};
	use std::io;
	use std::os::unix::net::UnixDatagram;

	/// **A name that is a path is refused before the filesystem is touched.**
	///
	/// The defect: `dir.join(interface)` with an absolute path replaces the
	/// base, and the two failure messages below the join distinguish "not
	/// there" from "there and not connectable" -- so the pair answered, at the
	/// `observe` tier, whether an arbitrary path exists. Measured against the
	/// daemon: `/etc/shadow` gave "Permission denied", `/etc/nonexistent` gave
	/// "no control socket at ...".
	///
	/// The assertion is on the *kind* rather than only on the failure. Every
	/// one of these would have failed anyway with the guard removed -- there
	/// is no supplicant at any of them -- so a test that only asked "does this
	/// error" would pass against the oracle it was written to close. What
	/// changes is that the answer no longer depends on what is on disk, and
	/// `InvalidInput` is how the code says so.
	#[test]
	fn a_name_that_is_a_path_is_refused_without_looking() {
		let dir = netcfgd_testdir::TestDir::new("supplicant-name");
		for name in [
			"/etc/shadow",
			"/etc/definitely-not-here",
			"../../etc/passwd",
			"..",
			"",
			"a name with spaces",
			"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		] {
			let error = Client::connect(dir.path(), name).expect_err("refused");
			assert_eq!(
				error.kind(),
				io::ErrorKind::InvalidInput,
				"`{name}` must be refused as a name, not reported on as a path: {error}"
			);
		}
	}

	/// And an ordinary name still reaches the filesystem to say what is wrong.
	///
	/// The other half: a guard that refused everything would pass the test
	/// above and take the diagnostic with it.
	#[test]
	fn an_ordinary_name_still_gets_the_ordinary_answer() {
		let dir = netcfgd_testdir::TestDir::new("supplicant-ordinary");
		let error = Client::connect(dir.path(), "wlan0").expect_err("nothing is listening");
		assert_eq!(
			error.kind(),
			io::ErrorKind::NotFound,
			"a real name gets the real diagnosis: {error}"
		);
	}

	/// A shortened deadline governs the commands, not just the opening `PING`.
	///
	/// This is the half `populate_supplicant` depends on and the half that is
	/// easy to lose: a daemon can answer the `PING` and wedge before the first
	/// real command, so a deadline that covered only the connect would leave
	/// every command after it on the ten-second default. Measured against a
	/// fake that answered `PING` and then nothing: ten seconds flat, per
	/// command, on the reconcile loop. Decision 0114.
	///
	/// Timed rather than merely checked for an error, because the wrong
	/// behaviour here *also* returns an error -- just far too late to matter.
	#[test]
	fn the_deadline_outlives_the_connect() {
		use std::time::{Duration, Instant};

		let dir = std::env::temp_dir().join(format!("ncfg-deadline-{}", std::process::id()));
		let _ = std::fs::remove_dir_all(&dir);
		std::fs::create_dir_all(&dir).expect("a directory to bind in");
		let server = UnixDatagram::bind(dir.join("wlan0")).expect("a server socket");

		// Answers the opening PING and nothing after it.
		let answering = std::thread::spawn(move || {
			let mut buffer = vec![0_u8; 4096];
			if let Ok((read, sender)) = server.recv_from(&mut buffer) {
				// The reply goes to the address the client bound, which is a
				// path: a datagram socket has nowhere else to send it.
				if &buffer[..read] == b"PING" {
					if let Some(path) = sender.as_pathname() {
						let _ = server.send_to(b"PONG\n", path);
					}
				}
			}
			// Held open, so the socket stays bound while the command below
			// waits: a closed one would fail fast for the wrong reason.
			std::thread::sleep(Duration::from_secs(3));
		});

		let client = Client::connect_within(&dir, "wlan0", Duration::from_millis(250))
			.expect("the PING is answered, so the connect succeeds");
		let start = Instant::now();
		let outcome = client.command("SET update_config 0");
		let waited = start.elapsed();
		drop(client);
		let _ = answering.join();
		let _ = std::fs::remove_dir_all(&dir);

		assert!(outcome.is_err(), "nothing answered, so this cannot succeed");
		assert!(
			waited < Duration::from_secs(2),
			"a command after the connect waited {waited:?}, so it took the \
			 default rather than the deadline the connect was given"
		);
	}

	/// The reply socket a client binds is recognised as netcfgd's own.
	///
	/// Observed while a connect is in flight rather than asserted as a literal,
	/// because the coupling this pins spans two places: what the client *names*
	/// its socket and what a directory reader *skips*. A test asserting the
	/// prefix alone would keep passing if the naming moved.
	///
	/// It has to be watched from another thread. The name exists only for the
	/// duration of the attempt -- `Drop` removes it, including on the failure
	/// path this takes -- so reading the directory afterwards finds nothing,
	/// which is exactly how the first version of this test asserted nothing at
	/// all while passing.
	#[test]
	fn a_clients_own_reply_socket_is_not_an_interface() {
		use std::time::{Duration, Instant};

		let dir = std::env::temp_dir().join(format!("ncfg-reply-{}", std::process::id()));
		let _ = std::fs::remove_dir_all(&dir);
		std::fs::create_dir_all(&dir).expect("a directory to bind in");

		// A socket that exists and answers nothing, so the connect gets past
		// its existence check, binds its reply socket, and then waits.
		let server = UnixDatagram::bind(dir.join("wlan0")).expect("a server socket");

		let scanned = dir.clone();
		let listing = std::thread::spawn(move || {
			let deadline = Instant::now() + Duration::from_secs(2);
			let mut seen: Vec<String> = Vec::new();
			while Instant::now() < deadline {
				if let Ok(entries) = std::fs::read_dir(&scanned) {
					for entry in entries.flatten() {
						if let Some(name) = entry.file_name().to_str() {
							if name != "wlan0" && !seen.iter().any(|held| held == name) {
								seen.push(name.to_owned());
							}
						}
					}
				}
				if !seen.is_empty() {
					break;
				}
				std::thread::sleep(Duration::from_millis(1));
			}
			seen
		});

		let outcome = Client::connect_within(&dir, "wlan0", Duration::from_millis(500));
		let seen = listing.join().expect("the directory-listing thread");
		drop(server);
		let _ = std::fs::remove_dir_all(&dir);

		assert!(outcome.is_err(), "nothing answers, so this cannot succeed");
		assert!(
			!seen.is_empty(),
			"the connect bound no reply socket, so this test checked nothing"
		);
		for name in &seen {
			assert!(
				is_reply_socket(name),
				"{name} was bound in the control directory and would be taken for an interface"
			);
		}

		assert!(!is_reply_socket("wlan0"));
		assert!(!is_reply_socket("p2p-dev-wlan0"));
	}

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

	/// The reaper takes the dead and leaves everything else.
	///
	/// Written as one directory holding every case at once, because what this
	/// function has to get right is not "does it delete" but "does it delete
	/// *only* that" -- and a test with one candidate per run cannot fail in the
	/// way that matters. Six entries go in; exactly one comes out.
	#[test]
	fn only_sockets_of_dead_processes_are_reaped() {
		use std::os::unix::net::UnixDatagram;

		let dir = std::env::temp_dir().join(format!("ncfg-reap-{}", std::process::id()));
		let _ = std::fs::remove_dir_all(&dir);
		std::fs::create_dir_all(&dir).expect("a directory to sweep");

		// A pid that cannot be alive. Pid 0 is the scheduler from userspace's
		// point of view and never appears in /proc, so `/proc/0` is absent on
		// every Linux -- which is the whole condition being tested, arranged
		// without having to kill something and race its reaping.
		let dead = dir.join("netcfgd-0-7");
		let _dead_socket = UnixDatagram::bind(&dead).expect("a socket to leave behind");

		// Ours, and the process holding it is this one.
		let mine = dir.join(format!("netcfgd-{}-0", std::process::id()));
		let _mine_socket = UnixDatagram::bind(&mine).expect("a live socket");

		// **Another process' socket, and that process is alive.** This is the
		// case the whole function turns on, and the first version of this test
		// did not have it: every other entry here is excluded by its name, its
		// type, or by being ours, so removing the liveness check entirely left
		// the test passing. Pid 1 is alive on any machine this runs on and is
		// never us.
		let live = dir.join("netcfgd-1-3");
		let _live_socket = UnixDatagram::bind(&live).expect("another client's socket");

		// A real interface socket, which is what the directory is *for*.
		let interface = dir.join("wlan0");
		let _interface_socket = UnixDatagram::bind(&interface).expect("an interface socket");

		// Shaped like ours and not a socket. A regular file with this name is
		// not something netcfgd made, and a reaper that removes it is removing
		// somebody else's file on the strength of its name alone.
		let regular = dir.join("netcfgd-0-8");
		std::fs::write(&regular, b"not a socket").expect("a regular file");

		// Nearly ours: the serial is not a number, so the name did not come
		// from `connect_within` and the pid in it means nothing.
		let malformed = dir.join("netcfgd-0-x");
		let _malformed_socket = UnixDatagram::bind(&malformed).expect("a socket");

		// Ours in prefix only, with no serial at all.
		let truncated = dir.join("netcfgd-0");
		let _truncated_socket = UnixDatagram::bind(&truncated).expect("a socket");

		let removed = reap_reply_sockets(&dir);

		assert_eq!(removed, 1, "exactly the one dead socket");
		assert!(!dead.exists(), "the dead process' socket is gone");
		assert!(mine.exists(), "this process' own socket is untouched");
		assert!(
			live.exists(),
			"a living process' socket is not the reaper's to take"
		);
		assert!(
			interface.exists(),
			"an interface socket is not ours to remove"
		);
		assert!(regular.exists(), "a regular file is not a reply socket");
		assert!(
			malformed.exists(),
			"a name that did not come from here is left"
		);
		assert!(truncated.exists(), "a prefix match alone is not enough");

		let _ = std::fs::remove_dir_all(&dir);
	}
}
