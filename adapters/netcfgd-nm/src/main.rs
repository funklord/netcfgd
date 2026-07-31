#![forbid(unsafe_code)]

//! `netcfgd-nm`: `NetworkManager`'s D-Bus interface, served from netcfgd.
//!
//! Design section 9.1: there is a large installed base of good NM *clients*
//! -- `nmcli`, `nm-applet`, `plasma-nm`, every desktop's network panel -- and
//! they all converge on one thing, the D-Bus API. Serving that API means those
//! clients keep working against a daemon that has none of NM's config model.
//!
//! Three properties hold, and they are the whole discipline (section 9.2):
//!
//! - **It defines nothing.** Every answer is derived from netcfgd's observed
//!   state or its document. Nothing is stored here that is not in `/etc` or
//!   `/run`, so deleting this program loses nothing.
//! - **It is unprivileged.** An ordinary socket client, subject to the same
//!   control tiers as `ncfg`.
//! - **Its dependencies are its own.** A separate workspace with a separate
//!   lockfile; `make nm-containment` proves the core links none of it.
//!
//! Mutual exclusion with a real `NetworkManager` is free: only one process can
//! own a well-known bus name, so if NM is running this exits saying so.

mod accesspoint;
mod client;
mod device;
mod enums;
mod manager;
mod state;

use state::State;
use std::sync::Arc;
use zbus::blocking::connection;

/// The name every NM client looks for.
const BUS_NAME: &str = "org.freedesktop.NetworkManager";
/// The root object.
const MANAGER_PATH: &str = "/org/freedesktop/NetworkManager";

fn main() -> std::process::ExitCode {
	match run() {
		Ok(()) => std::process::ExitCode::SUCCESS,
		Err(message) => {
			eprintln!("netcfgd-nm: {message}");
			std::process::ExitCode::FAILURE
		}
	}
}

fn run() -> Result<(), String> {
	let arguments: Vec<String> = std::env::args().skip(1).collect();
	let flags: Vec<&str> = arguments.iter().map(String::as_str).collect();
	match flags.as_slice() {
		[] => serve(false),
		// The session bus, for testing. A real deployment uses the system bus,
		// because that is where clients look; a test cannot, because claiming
		// NM's name there would take it from the daemon actually running the
		// machine this is being developed on.
		["--session"] => serve(true),
		["--help" | "-h"] => {
			print_usage();
			Ok(())
		}
		["--version"] => {
			println!("netcfgd-nm {}", env!("CARGO_PKG_VERSION"));
			Ok(())
		}
		other => Err(format!(
			"unrecognised arguments: {}. Try --help",
			other.join(" ")
		)),
	}
}

fn print_usage() {
	println!(
		"netcfgd-nm -- NetworkManager's D-Bus interface, served from netcfgd

Serves org.freedesktop.NetworkManager on the system bus, answering from
netcfgd's state. Existing NM clients -- nmcli, nm-applet, plasma-nm -- keep
working; netcfgd's configuration files stay the only authority.

  --session   claim the name on the session bus instead (for testing)
  --version   print the version
  --help      this

It needs netcfgd running, and it cannot run alongside NetworkManager: only one
process owns a bus name, which is the mutual exclusion doing its job."
	);
}

fn serve(session: bool) -> Result<(), String> {
	let socket = client::socket_path();
	let state = Arc::new(State::new(socket.clone()));

	// Ask netcfgd before claiming the name. A shim that owns
	// org.freedesktop.NetworkManager while unable to answer anything is worse
	// than one that is not running: clients would find a daemon and get
	// errors, rather than finding none and saying so.
	let changes = state
		.refresh()
		.map_err(|error| format!("{error}\nrefusing to claim {BUS_NAME} without it"))?;

	// The document, for the two questions an observation cannot answer: which
	// devices netcfgd treats as radios, and what security a configured network
	// uses. Not fatal if it fails -- a machine whose config does not compile
	// still has interfaces worth showing, and the shim degrades to sysfs for
	// the first question and to a guess for the second.
	match client::document(&socket) {
		Ok(document) => state.adopt_document(Some(document)),
		Err(error) => eprintln!("netcfgd-nm: cannot read the configuration: {error}"),
	}

	let builder = if session {
		connection::Builder::session()
	} else {
		connection::Builder::system()
	}
	.map_err(|error| format!("cannot reach the message bus: {error}"))?;

	// The name is deliberately *not* requested here. The objects go up first,
	// and the name is asked for below with flags this cares about -- a client
	// that sees the name appear is entitled to find a device tree behind it.
	let connection = builder
		.serve_at(MANAGER_PATH, manager::Manager::new(Arc::clone(&state)))
		.map_err(|error| format!("cannot serve the manager object: {error}"))?
		.serve_at(MANAGER_PATH, manager::Compat)
		.map_err(|error| format!("cannot serve the compat object: {error}"))?
		.build()
		.map_err(|error| format!("cannot reach the message bus: {error}"))?;

	// zbus serves ObjectManager itself, at the path asked for. NM puts it at
	// /org/freedesktop rather than under its own object, which libnm depends
	// on -- it calls GetManagedObjects there to build its whole cache in one
	// round trip. Confirmed against a running NetworkManager 1.52 rather than
	// taken from the specification, because the design doc had it down as an
	// open question.
	connection
		.object_server()
		.at("/org/freedesktop", zbus::fdo::ObjectManager)
		.map_err(|error| format!("cannot serve the object manager: {error}"))?;

	publish(&connection, &state, &changes)?;
	state.refresh_associations();
	claim_name(&connection)?;

	// One job queue, and every change to the object tree goes through it. That
	// is not tidiness: registering an object and emitting a signal are the two
	// things a D-Bus method handler cannot do from zbus's blocking API, so a
	// `RequestScan` arriving on zbus's own thread posts a job here instead of
	// doing the work where it was asked.
	let (sender, jobs) = std::sync::mpsc::channel::<state::Job>();
	state.set_jobs(sender.clone());

	// netcfgd streams events, so the shim subscribes rather than polling. In
	// its own thread, because the main loop now has two things to wait for and
	// a blocking read of the monitor socket can only be one of them. A daemon
	// that goes away is a reconnect rather than an exit: an applet should not
	// have to be restarted when netcfgd is.
	{
		let socket = socket.clone();
		std::thread::Builder::new()
			.name("monitor".to_owned())
			.spawn(move || loop {
				match client::Monitor::open(&socket) {
					Ok(mut monitor) => {
						while monitor.next_change().is_some() {
							if sender.send(state::Job::Refresh).is_err() {
								return;
							}
						}
					}
					Err(error) => eprintln!("netcfgd-nm: {error}; retrying"),
				}
				if sender.send(state::Job::Refresh).is_err() {
					return;
				}
				// Wait rather than spin: netcfgd may be restarting, and a
				// client that reconnects in a tight loop makes that slower.
				std::thread::sleep(std::time::Duration::from_secs(2));
			})
			.map_err(|error| format!("cannot start the monitor thread: {error}"))?;
	}

	// A first scan on every radio, so a client that connects and immediately
	// reads AccessPoints has something rather than an empty list it would show
	// as "no networks found".
	for radio in state.radios() {
		let _ = sender_of(&state, &radio);
	}

	for job in jobs {
		match job {
			state::Job::Refresh => {
				match state.refresh() {
					Ok(changes) => publish(&connection, &state, &changes)?,
					Err(error) => {
						eprintln!("netcfgd-nm: cannot refresh: {error}");
						continue;
					}
				}
				// The configuration may have changed with it -- a reload is one
				// of the events netcfgd streams.
				if let Ok(document) = client::document(&socket) {
					state.adopt_document(Some(document));
				}
				state.refresh_associations();
				republish_wireless(&connection, &state)?;
			}
			state::Job::Scan(interface) => match state.rescan(&interface) {
				Ok(changes) => {
					publish_access_points(&connection, &state, &changes)?;
					republish_wireless(&connection, &state)?;
				}
				// By now the caller is gone -- `RequestScan` returned when the
				// job was posted, which is what NM's semantics ask for. So this
				// is logged rather than returned, and the client sees it as no
				// new access points.
				Err(error) => eprintln!("netcfgd-nm: scan on {interface} failed: {error}"),
			},
		}
	}

	Ok(())
}

/// Ask for the first scan on a radio, ignoring a refusal.
///
/// Split out only so the startup path reads as one line. A radio that refuses
/// here is one with no supplicant yet, which is ordinary at startup and
/// resolves itself when the next client asks.
fn sender_of(state: &Arc<State>, radio: &str) -> Result<(), String> {
	state.request_scan(radio)
}

/// Take `org.freedesktop.NetworkManager`, or say why not and stop.
///
/// Design section 9.3 says mutual exclusion with a real `NetworkManager` is free,
/// because only one process can own a well-known name. That is true of the bus
/// and was not true of this program: asking for a name through zbus's
/// connection builder *queues* for it, so a second shim started while the first
/// held the name reported success, served nothing, and would have silently
/// become the machine's `NetworkManager` the moment the first one exited. The
/// live test found it by hanging.
///
/// `DoNotQueue` is what makes the claim mean what it says. `ReplaceExisting` is
/// deliberately absent: taking the name away from a running `NetworkManager`
/// would leave two daemons configuring one machine, which is the outcome the
/// exclusion exists to prevent.
fn claim_name(connection: &zbus::blocking::Connection) -> Result<(), String> {
	use zbus::fdo::{RequestNameFlags, RequestNameReply};

	// Both outcomes below mean the same thing to an operator, and they are
	// reached differently: with `DoNotQueue`, zbus turns the bus's refusal into
	// an `Err` rather than returning `Exists`. Writing only the match arm left
	// the useful half of the message unreachable, which the live test caught by
	// looking for it.
	let taken = |detail: &str| {
		format!(
			"cannot claim {BUS_NAME}: {detail}.\n\
			 If NetworkManager is running, this is the exclusion working as intended: \
			 two daemons cannot own the name, and they must not both configure the \
			 network. Stop NetworkManager first."
		)
	};

	match connection.request_name_with_flags(BUS_NAME, RequestNameFlags::DoNotQueue.into()) {
		Ok(RequestNameReply::PrimaryOwner | RequestNameReply::AlreadyOwner) => Ok(()),
		Ok(RequestNameReply::Exists | RequestNameReply::InQueue) => {
			Err(taken("something else owns it"))
		}
		Err(error) => Err(taken(&error.to_string())),
	}
}

/// Make the object tree match the state.
///
/// Adding and removing objects is what emits `InterfacesAdded` and
/// `InterfacesRemoved`, which is how a libnm client learns a device appeared
/// without asking. zbus emits those from the object server, so registering the
/// object *is* the notification -- there is deliberately no second code path
/// that could get out of step with what is actually being served.
fn publish(
	connection: &zbus::blocking::Connection,
	state: &Arc<State>,
	changes: &state::Changes,
) -> Result<(), String> {
	let server = connection.object_server();

	// Removals first. A device that went away and a device that arrived can
	// share a refresh -- unplugging one USB adapter and plugging in another is
	// one netlink burst -- and a client that hears "added" before "removed"
	// briefly believes in both.
	for (name, number) in &changes.removed {
		let path = device::path_for(*number);
		// Each interface separately, because the object carries two: removing
		// the last one is what takes the node out of the tree and emits
		// InterfacesRemoved. Only one of the four per-kind interfaces is on any
		// given object, so three of these find nothing and that is not an
		// error.
		let _ = server.remove::<device::Wireless, _>(&path);
		let _ = server.remove::<device::Wired, _>(&path);
		let _ = server.remove::<device::Generic, _>(&path);
		let _ = server.remove::<device::Loopback, _>(&path);
		server
			.remove::<device::Device, _>(&path)
			.map_err(|error| format!("cannot stop serving {name} at {path}: {error}"))?;
	}

	for (name, number) in state.devices() {
		let path = device::path_for(number);
		let added = server
			.at(&path, device::Device::new(Arc::clone(state), name.clone()))
			.map_err(|error| format!("cannot serve {path}: {error}"))?;
		if !added {
			continue;
		}

		// Exactly one per-kind interface goes on the same object, and "exactly"
		// is load-bearing in both directions. Two would make libnm build the
		// wrong device class; none makes it ignore the device entirely, which
		// is how the first version of this served six devices and `nmcli`
		// listed one.
		let Some(link) = state.link(&name) else {
			continue;
		};
		let kind_interface = match device::flavour_of(&link, state.is_radio(&name)) {
			device::Flavour::Loopback => server.at(&path, device::Loopback),
			device::Flavour::Wireless => server.at(
				&path,
				device::Wireless::new(Arc::clone(state), name.clone()),
			),
			device::Flavour::Wired => {
				server.at(&path, device::Wired::new(Arc::clone(state), name.clone()))
			}
			device::Flavour::Generic => {
				server.at(&path, device::Generic::new(Arc::clone(state), name.clone()))
			}
		};
		kind_interface
			.map_err(|error| format!("cannot serve the kind interface of {path}: {error}"))?;
	}

	Ok(())
}

/// Make the access point objects match the last scan.
///
/// Registering the object emits `InterfacesAdded`, but a libnm client does not
/// learn about an access point that way -- it listens for
/// `AccessPointAdded` on the radio. Both are emitted, because both are part of
/// the contract and a client is entitled to use either.
fn publish_access_points(
	connection: &zbus::blocking::Connection,
	state: &Arc<State>,
	changes: &state::ApChanges,
) -> Result<(), String> {
	let server = connection.object_server();

	for (interface, bssid, number) in &changes.added {
		let path = accesspoint::path_for(*number);
		server
			.at(
				&path,
				accesspoint::AccessPoint::new(Arc::clone(state), interface.clone(), bssid.clone()),
			)
			.map_err(|error| format!("cannot serve {path}: {error}"))?;
		signal_access_point(connection, state, interface, *number, true)?;
	}

	for (interface, _, number) in &changes.removed {
		// Signalled before the object goes, so a client that reacts by reading
		// the path finds it rather than an error. NM does the same.
		signal_access_point(connection, state, interface, *number, false)?;
		let path = accesspoint::path_for(*number);
		server
			.remove::<accesspoint::AccessPoint, _>(&path)
			.map_err(|error| format!("cannot stop serving {path}: {error}"))?;
	}

	Ok(())
}

/// Tell a radio's clients that its access point list moved.
fn signal_access_point(
	connection: &zbus::blocking::Connection,
	state: &Arc<State>,
	interface: &str,
	number: u32,
	added: bool,
) -> Result<(), String> {
	let Some(device_number) = state
		.devices()
		.into_iter()
		.find(|(name, _)| name == interface)
		.map(|(_, number)| number)
	else {
		return Ok(());
	};
	let device_path = device::path_for(device_number);
	let Ok(wireless) = connection
		.object_server()
		.interface::<_, device::Wireless>(&device_path)
	else {
		// The radio has no wireless interface on its object, which means it is
		// not being served as a radio. Nothing to tell anybody.
		return Ok(());
	};
	let emitter = wireless.signal_emitter();
	let path = accesspoint::path_for(number);
	let result = if added {
		async_io::block_on(device::Wireless::access_point_added(emitter, path.as_ref()))
	} else {
		async_io::block_on(device::Wireless::access_point_removed(
			emitter,
			path.as_ref(),
		))
	};
	result.map_err(|error| format!("cannot announce {path}: {error}"))
}

/// Tell clients that a radio's own properties moved.
///
/// `AccessPoints`, `ActiveAccessPoint` and `LastScan` are computed from the
/// state rather than stored in the interface, so zbus has no way to know when
/// they change and emits nothing by itself. Saying so explicitly is what keeps
/// a libnm cache -- and therefore an open applet menu -- from showing the
/// results of the scan before last.
fn republish_wireless(
	connection: &zbus::blocking::Connection,
	state: &Arc<State>,
) -> Result<(), String> {
	let server = connection.object_server();
	for (name, number) in state.devices() {
		if !state.is_radio(&name) {
			continue;
		}
		let path = device::path_for(number);
		let Ok(wireless) = server.interface::<_, device::Wireless>(&path) else {
			continue;
		};
		let emitter = wireless.signal_emitter();
		let interface = wireless.get();
		for changed in [
			async_io::block_on(interface.access_points_changed(emitter)),
			async_io::block_on(interface.active_access_point_changed(emitter)),
			async_io::block_on(interface.last_scan_changed(emitter)),
		] {
			changed.map_err(|error| format!("cannot announce {path}: {error}"))?;
		}
	}
	Ok(())
}
