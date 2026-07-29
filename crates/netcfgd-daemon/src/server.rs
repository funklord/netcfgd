//! The control socket: one thread per connection, one channel to the loop.
//!
//! No epoll, no async runtime. A blocking accept and a blocking read per
//! connection, with `mpsc` carrying the work to a single-threaded state
//! machine. That keeps every crate but `netcfgd-netlink` free of `unsafe`
//! (constraint 4), keeps the daemon's state free of locks, and costs a thread
//! per client on a socket that will normally have one or two.

use netcfgd_proto::{read_message, write_message, Event, Request, Response};
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
}

/// Bind the control socket and serve it until the process exits.
///
/// # Errors
///
/// Returns the underlying `io::Error` if the socket cannot be bound.
pub(crate) fn serve(path: &Path, commands: Sender<Command>) -> std::io::Result<()> {
	if let Some(parent) = path.parent() {
		std::fs::create_dir_all(parent)?;
	}
	// A stale socket from a previous run refuses to bind, and leaving the
	// daemon unable to start because it did not shut down cleanly last time is
	// a worse failure than removing a file nothing is listening on.
	let _ = std::fs::remove_file(path);

	let listener = UnixListener::bind(path)?;
	restrict_permissions(path)?;

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

/// Mode 0600 on the socket.
///
/// The socket can arm a commit-confirm window, tear down an interface and run
/// hooks as root, so it is exactly as privileged as the daemon. Section 13's
/// tiering -- a read-only group that can ask but not change -- needs the
/// request to carry a peer credential check, which is M3 work; until then the
/// honest thing is to let nobody but root open it at all rather than to offer
/// a distinction that is not enforced.
fn restrict_permissions(path: &Path) -> std::io::Result<()> {
	use std::os::unix::fs::PermissionsExt;
	std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
}

fn handle(stream: UnixStream, commands: &Sender<Command>) {
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
		if commands.send(Command::Request { request, reply }).is_err() {
			return;
		}
		let Ok(response) = answer.recv() else {
			return;
		};
		if write_message(&mut writer, &response).is_err() {
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
