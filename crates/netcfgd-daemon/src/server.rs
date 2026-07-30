//! The control socket: one thread per connection, one channel to the loop.
//!
//! No epoll, no async runtime. A blocking accept and a blocking read per
//! connection, with `mpsc` carrying the work to a single-threaded state
//! machine. That keeps every crate but `netcfgd-sys` free of `unsafe`
//! (constraint 4), keeps the daemon's state free of locks, and costs a thread
//! per client on a socket that will normally have one or two.

use netcfgd_model::Control;
use netcfgd_proto::{read_message, write_message, Event, Request, Response};
use netcfgd_sys::peer::{group_id, Peer};
use std::io::{BufReader, BufWriter};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use std::sync::mpsc::{Receiver, Sender, SyncSender};
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

	thread::Builder::new()
		.name("control".to_owned())
		.spawn(move || {
			for stream in listener.incoming() {
				let Ok(stream) = stream else {
					continue;
				};
				let commands = commands.clone();
				// One thread per connection. A client that stops reading
				// blocks only itself.
				let _ = thread::Builder::new()
					.name("client".to_owned())
					.spawn(move || handle(stream, &commands));
			}
		})?;
	Ok(())
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
		let request = match read_message::<Request, _>(&mut reader) {
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
