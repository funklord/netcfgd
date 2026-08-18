//! The control socket: one thread per connection, one channel to the loop.
//!
//! No epoll, no async runtime. A blocking accept and a blocking read per
//! connection, with `mpsc` carrying the work to a single-threaded state
//! machine. That keeps every crate but `netcfgd-sys` free of `unsafe`
//! (constraint 4), keeps the daemon's state free of locks, and costs a thread
//! per client on a socket that will normally have one or two.

use netcfgd_model::Control;
use netcfgd_proto::{read_request, write_message, Event, Request, Response};
use netcfgd_sys::peer::{group_id, Peer};
use std::io::{BufReader, BufWriter};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc::{Receiver, Sender, SyncSender};
use std::sync::Arc;
use std::thread;

/// What reaches the event loop.
pub(crate) enum Command {
	/// A client asked something and is waiting for one answer.
	Request {
		/// What was asked.
		request: Request,
		/// Who asked.
		peer: Peer,
		/// Where to send the answer.
		reply: SyncSender<Response>,
	},
	/// A client wants to be sent events until it goes away.
	Subscribe {
		/// Where to send them.
		events: SyncSender<Event>,
	},
	/// The kernel reported a change.
	KernelChanged,
	/// The config directory changed.
	ConfigChanged,
	/// Nothing happened, but it has been a while.
	Tick,
	/// A commit-confirm window reached its deadline.
	ConfirmExpired,
	/// A radio associated with a different access point than it was on.
	Roamed {
		/// Which interface moved.
		interface: String,
		/// The access point it is on now.
		bssid: String,
	},
}

/// Bind the control socket and serve it until the process exits.
///
/// # Errors
///
/// Returns the underlying `io::Error` if the socket cannot be bound.
pub(crate) fn serve(
	path: &Path,
	control: &Control,
	commands: Sender<Command>,
) -> std::io::Result<()> {
	if let Some(parent) = path.parent() {
		std::fs::create_dir_all(parent)?;
	}
	// A stale socket from a previous run refuses to bind, and leaving the
	// daemon unable to start because it did not shut down cleanly last time is
	// a worse failure than removing a file nothing is listening on.
	let _ = std::fs::remove_file(path);

	let listener = UnixListener::bind(path)?;
	apply_policy_permissions(path, control);

	let connections = Connections::new();
	thread::Builder::new()
		.name("control".to_owned())
		.spawn(move || {
			for stream in listener.incoming() {
				let Ok(mut stream) = stream else {
					continue;
				};
				// Refused with an answer rather than a dropped connection: the
				// protocol has an error response and section 7 says to return
				// one, so a client that hits the cap is told which wall it met
				// instead of seeing an end of stream it has to guess about.
				let Some(slot) = connections.take() else {
					let _ = write_message(
						&mut stream,
						&Response::error(format!(
							"too many connections, {MAX_CONNECTIONS} are open"
						)),
					);
					continue;
				};
				let commands = commands.clone();
				// One thread per connection. A client that stops reading
				// blocks only itself, and `slot` moves into the thread so the
				// count falls when that thread ends however it ends.
				if thread::Builder::new()
					.name("client".to_owned())
					.spawn(move || {
						let _slot = slot;
						handle(stream, &commands);
					})
					.is_err()
				{
					// The slot went with the closure and died with it, so the
					// count is already correct. Nothing useful is left to do
					// for this client, and the loop must keep accepting.
					continue;
				}
			}
		})?;
	Ok(())
}

/// How many connections may be open at once.
///
/// Generous for what actually connects: a tray, a window, a TUI, a monitor
/// stream and whatever `ncfg` invocations are in flight is under ten on a busy
/// desktop. The number exists to bound the damage, not to ration ordinary use,
/// and a machine that legitimately needs more than this has something else
/// going on.
const MAX_CONNECTIONS: usize = 64;

/// How many connections are open, with a slot released when its guard drops.
///
/// The socket already bounds one connection: `MAX_LINE` refuses a client that
/// sends a gigabyte without a newline, and `docs/socket-protocol.md` says why
/// in as many words -- the daemon holds `CAP_NET_ADMIN`, so making it allocate
/// its way to being killed is a denial of service with extra steps. Nothing
/// bounded the *number* of connections, and the same sentence applies to ten
/// thousand of them: each one is an OS thread, and the accept loop spawned
/// without counting.
///
/// This tree bounds everything else it reads or allocates -- line length,
/// nesting depth, the event channel at 64, include recursion -- so the absent
/// bound was conspicuous rather than deliberate. Nothing in the tree recorded
/// a decision either way.
#[derive(Debug, Clone)]
struct Connections(Arc<AtomicUsize>);

/// One open connection. Releases its slot when dropped.
///
/// A guard rather than a decrement at the end of `handle`, because the failure
/// mode of getting this wrong is worse than the defect it fixes: a count that
/// rises on every accept and falls on only some paths stops the daemon
/// accepting anything at all once it has served `MAX_CONNECTIONS` in total.
/// `Drop` runs on the ordinary return and on an unwind, so there is no exit
/// path left to forget.
#[derive(Debug)]
struct Slot(Arc<AtomicUsize>);

impl Connections {
	fn new() -> Self {
		Self(Arc::new(AtomicUsize::new(0)))
	}

	/// Take a slot, or `None` if the cap is reached.
	///
	/// `fetch_update` rather than an add followed by a check-and-undo: two
	/// accepts racing on the latter both see a count under the cap, both add,
	/// and the cap is briefly exceeded by however many threads were in that
	/// window. The compare-and-swap has no such window.
	fn take(&self) -> Option<Slot> {
		self.0
			.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |open| {
				(open < MAX_CONNECTIONS).then_some(open + 1)
			})
			.ok()
			.map(|_| Slot(Arc::clone(&self.0)))
	}

	/// How many are open.
	///
	/// Test-only: nothing in the daemon asks, and an unused method is a
	/// warning, which CI turns into a failure with `-D warnings`.
	#[cfg(test)]
	fn open(&self) -> usize {
		self.0.load(Ordering::Relaxed)
	}
}

impl Drop for Slot {
	fn drop(&mut self) {
		self.0.fetch_sub(1, Ordering::Relaxed);
	}
}

/// Give the socket permissions that match what the policy promises.
///
/// A policy naming a group is a lie if the socket stays root-only, because the
/// caller cannot connect to be told yes. So the mode follows the most
/// permissive tier, and where a tier names a group the socket is given to it.
///
/// Where that cannot be done -- no such group, or the daemon is not root --
/// this says so loudly rather than leaving a root-only socket under a config
/// that claims otherwise. That combination produces a bug report about wifi
/// not working which takes an afternoon to trace.
fn apply_policy_permissions(path: &Path, control: &Control) {
	use std::os::unix::fs::PermissionsExt;

	let groups = control.named_groups();
	let mode = if control.observe == netcfgd_model::Principal::Any
		|| control.wifi == netcfgd_model::Principal::Any
		|| control.admin == netcfgd_model::Principal::Any
	{
		0o666
	} else if control.opens_beyond_root() {
		0o660
	} else {
		0o600
	};

	if let Err(error) = std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)) {
		eprintln!("netcfgd: could not set socket mode {mode:o}: {error}");
	}

	// One group can own the socket. Where the policy names several, the first
	// is used and the rest are reported -- a machine wanting two groups to
	// reach the socket wants one shared group, and saying so beats silently
	// serving whichever the code happened to pick.
	let Some(name) = groups.first() else {
		return;
	};
	if groups.len() > 1 {
		eprintln!(
			"netcfgd: the control policy names {} groups ({}); the socket can belong to one, \
			 so it is given to `{name}`. Members of the others will not be able to connect.",
			groups.len(),
			groups.join(", ")
		);
	}
	match group_id(name) {
		Some(gid) => {
			if let Err(error) = chown_group(path, gid) {
				eprintln!(
					"netcfgd: the control policy opens access to group `{name}`, but the socket \
					 could not be given to it: {error}. Nobody outside root will be able to \
					 connect."
				);
			}
		}
		None => eprintln!(
			"netcfgd: the control policy names group `{name}`, which does not exist in \
			 /etc/group. Nobody outside root will be able to connect."
		),
	}
}

/// `chown` the socket to a group, leaving the owner alone.
fn chown_group(path: &Path, gid: u32) -> std::io::Result<()> {
	std::os::unix::fs::chown(path, None, Some(gid))
}

fn handle(stream: UnixStream, commands: &Sender<Command>) {
	// Read once, at accept time, rather than per request: the credentials
	// belong to the connection, and re-reading them would only widen the
	// window in which the peer's pid could be recycled.
	let Ok(peer) = netcfgd_sys::credentials(&stream) else {
		return;
	};
	let Ok(write_half) = stream.try_clone() else {
		return;
	};
	let mut reader = BufReader::new(stream);
	let mut writer = BufWriter::new(write_half);

	loop {
		// `read_request` and not `read_message`: this is the surface that reads
		// untrusted bytes, and it refuses a member the protocol does not define.
		// The client half deliberately stays lenient, so an older client is not
		// broken by a newer daemon's response.
		let request = match read_request(&mut reader) {
			Ok(Some(request)) => request,
			// A clean disconnect. Not an error, and not worth logging.
			Ok(None) => return,
			Err(error) => {
				let _ = write_message(&mut writer, &Response::error(error));
				return;
			}
		};

		if matches!(request, Request::Monitor) {
			// Streaming is still a request and still gets checked. The loop
			// does the checking, so ask it first and only subscribe if the
			// answer is yes.
			let (probe, verdict) = std::sync::mpsc::sync_channel(1);
			if commands
				.send(Command::Request {
					request: Request::Monitor,
					peer: peer.clone(),
					reply: probe,
				})
				.is_err()
			{
				return;
			}
			match verdict.recv() {
				Ok(Response::Ok) => {}
				Ok(other) => {
					let _ = write_message(&mut writer, &other);
					return;
				}
				Err(_) => return,
			}
			// Streaming: the connection hands the loop a sender and then does
			// nothing but forward. Keeping socket writes on this thread means
			// a slow client cannot stall the event loop -- the bounded channel
			// fills, and the loop drops the subscriber rather than blocking.
			let (events, incoming) = std::sync::mpsc::sync_channel(64);
			if commands.send(Command::Subscribe { events }).is_err() {
				return;
			}
			for event in incoming {
				if write_message(&mut writer, &Response::Event(Box::new(event))).is_err() {
					return;
				}
			}
			return;
		}

		let (reply, answer) = std::sync::mpsc::sync_channel(1);
		if commands
			.send(Command::Request {
				request,
				peer: peer.clone(),
				reply,
			})
			.is_err()
		{
			return;
		}
		let Ok(response) = answer.recv() else {
			return;
		};
		if let Err(error) = write_message(&mut writer, &response) {
			// A client that hung up mid-answer is ordinary and silent. A
			// response that will not serialise is a bug in the daemon, and one
			// that presents to the operator as "the daemon closed the
			// connection without answering" -- indistinguishable from a crash,
			// with nothing anywhere saying otherwise. It cost a probe to find
			// once; it will not again.
			if error.kind() == std::io::ErrorKind::InvalidData {
				eprintln!(
					"netcfgd: could not serialise a response, which is a bug: {error}. \
					 The client was told nothing."
				);
			}
			return;
		}
	}
}

/// Fan an event out to every subscriber, dropping the ones that have gone.
///
/// A subscriber whose channel is full is dropped rather than waited for. The
/// alternative is letting a client that stopped reading stall the reconcile
/// loop, and a monitoring client is never worth that.
pub(crate) fn broadcast(subscribers: &mut Vec<SyncSender<Event>>, event: &Event) {
	subscribers.retain(|subscriber| subscriber.try_send(event.clone()).is_ok());
}

/// Drain everything currently queued without blocking.
///
/// Used to collapse a burst -- bringing an interface up produces a run of
/// netlink messages -- into a single re-read.
pub(crate) fn drain(commands: &Receiver<Command>) -> Vec<Command> {
	commands.try_iter().collect()
}

#[cfg(test)]
mod tests {
	use super::*;

	/// The cap holds, and a released slot is reusable.
	///
	/// The second half is the one worth having. A counter that only ever rises
	/// would pass the first assertion and then refuse every connection after
	/// the daemon had served `MAX_CONNECTIONS` in total -- a worse failure than
	/// the unbounded accept it replaced, and one no burst test would show.
	#[test]
	fn the_cap_holds_and_a_released_slot_comes_back() {
		let connections = Connections::new();
		let held: Vec<Slot> = (0..MAX_CONNECTIONS)
			.map(|_| connections.take().expect("under the cap"))
			.collect();
		assert_eq!(connections.open(), MAX_CONNECTIONS);
		assert!(connections.take().is_none(), "the cap must refuse");

		drop(held);
		assert_eq!(connections.open(), 0, "every slot releases on drop");
		assert!(
			connections.take().is_some(),
			"the daemon must accept again once connections close"
		);
	}

	/// Racing accepts never exceed the cap.
	///
	/// This is what `fetch_update` buys over an add followed by a
	/// check-and-undo: with the latter, every thread in the window sees a count
	/// under the cap, all of them add, and the daemon holds more threads than
	/// it agreed to. Asserted rather than reasoned about, because a race that
	/// is only argued for is one nobody has run.
	#[test]
	fn concurrent_takes_never_exceed_the_cap() {
		let connections = Connections::new();
		let mut workers = Vec::new();
		for _ in 0..8 {
			let connections = connections.clone();
			workers.push(thread::spawn(move || {
				let mut mine = Vec::new();
				for _ in 0..MAX_CONNECTIONS {
					if let Some(slot) = connections.take() {
						mine.push(slot);
					}
				}
				mine
			}));
		}

		let held: Vec<Slot> = workers
			.into_iter()
			.flat_map(|worker| worker.join().expect("a worker finished"))
			.collect();

		assert_eq!(
			held.len(),
			MAX_CONNECTIONS,
			"eight threads asking for more than the cap must be handed exactly the cap"
		);
		assert_eq!(connections.open(), MAX_CONNECTIONS);
	}
}
