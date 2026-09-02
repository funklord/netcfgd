//! The wireless requests, and the supplicant behind them.
//!
//! Every handler here opens a control socket, uses it and drops it. That is
//! deliberate rather than lazy: decision 0015 says the supplicant holds no
//! state, and a daemon holding a long-lived connection to it would start
//! caching what it last saw. A datagram socket and a `PING` cost a round trip
//! on a local socket, which is nothing next to the scan they precede.
//!
//! The one rule that shapes all of this: a caller in the `wifi` tier can join
//! a network the configuration already describes, and nothing else. Nothing in
//! this module can create a network, so the tier cannot be talked into writing
//! config (decision 0013).

use netcfgd_host::wifi_profile;
use netcfgd_model::device::WifiBackend;
use netcfgd_model::{Document, Ssid, WifiNetwork};
use netcfgd_proto::{Response, ScanEntry, ScanReport, StationEntry, StationReport, WifiState};
use netcfgd_secret::Resolver;
use netcfgd_supplicant::protocol::{
	parse_mobility_domain, parse_network_list, parse_scan_results, parse_status, status_field,
};
use netcfgd_supplicant::{add_network, Client};
use std::path::Path;

/// Open a control socket, or explain why not in terms of what to do.
fn connect(interface: &str) -> Result<Client, String> {
	let dir = netcfgd_supplicant::ctrl_dir();
	Client::connect(&dir, interface).map_err(|error| {
		format!(
			"cannot reach the supplicant for `{interface}`: {error}. netcfgd starts \
			 wpa_supplicant for a managed wireless device; if this device is not managed, \
			 or the last apply failed, there is nothing listening."
		)
	})
}

/// Refuse a device the configuration points at a supplicant netcfgd cannot
/// drive.
///
/// Decision 0014: asking for `iwd` is refused by name rather than quietly
/// served by `wpa_supplicant`. Substituting a different supplicant would produce
/// different roaming behaviour than the config asked for, which is exactly the
/// sort of thing nobody thinks to check.
pub(crate) fn check_backend(document: Option<&Document>, interface: &str) -> Result<(), String> {
	let Some(document) = document else {
		return Ok(());
	};
	let Some(device) = document
		.devices
		.iter()
		.find(|device| device.name == interface)
	else {
		return Ok(());
	};
	let Some(policy) = &device.wifi else {
		return Ok(());
	};
	match policy.backend {
		WifiBackend::Auto | WifiBackend::WpaSupplicant => Ok(()),
		WifiBackend::Iwd => Err(format!(
			"`{interface}` asks for the iwd backend, which this build does not have. iwd keeps \
			 its own network database and writes to it, which conflicts with netcfgd's \
			 configuration being the only authority, so supporting it needs iwd to grow a \
			 stateless mode (doc/decision/0014). Use `backend = \"wpa_supplicant\"`."
		)),
	}
}

/// The radios this machine has, and what netcfgd is doing about each.
///
/// **From the kernel, not from the document.** A list built out of `device`
/// blocks would show only the radios already taken on, and this list exists so
/// that somebody can take one on -- it has to name the ones netcfgd is not
/// managing, because those are the interesting ones.
///
/// `supplicant` is asked separately from `activated` because the gap between
/// them is what a person needs to see. Activated with nothing answering is a
/// fault. Not activated with something answering is another manager holding
/// this radio, which netcfgd declines to take rather than fighting over -- so
/// a client can say that activating it will change nothing until that stops.
pub(crate) fn radios(document: Option<&Document>, observed: &netcfgd_model::Observed) -> Response {
	let dir = netcfgd_supplicant::ctrl_dir();
	let radios = observed
		.links
		.iter()
		.filter(|link| link.wireless)
		.map(|link| netcfgd_proto::Radio {
			activated: document.is_some_and(|document| {
				document.devices.iter().any(|device| {
					device.name == link.name && device.managed && device.wifi.is_some()
				})
			}),
			supplicant: netcfgd_supplicant::answers(&dir, &link.name),
			interface: link.name.clone(),
		})
		.collect();
	Response::Radios { radios }
}

/// Take a radio on, or hand it back.
///
/// # Errors
///
/// Named rather than silent for an interface that is not a radio: activating
/// `eth0` is a mistake worth a sentence, and the alternative is a `device`
/// block that quietly does nothing.
pub(crate) fn set_radio(
	state: &mut crate::State,
	observed: &netcfgd_model::Observed,
	interface: &str,
	activate: bool,
) -> Response {
	if !observed
		.links
		.iter()
		.any(|link| link.name == interface && link.wireless)
	{
		return Response::error(format!(
			"`{interface}` is not a radio on this machine. `ncfg wifi radios` lists the \
			 ones there are"
		));
	}

	// One drop-in per radio, named for it. So activating a second radio does
	// not rewrite the first one's file, and so `ncfg config rm` can undo this
	// by a name somebody can guess.
	let name = netcfgd_host::config::radio_drop_in(interface);
	let result = if activate {
		netcfgd_host::config::install_drop_in(
			&state.paths.config,
			&state.paths.factory,
			&name,
			&netcfgd_host::config::radio_blocks(interface),
			// Replacing is right here and is not the general case: this is a
			// switch, so turning on something already on is the state being
			// asked for rather than a collision.
			true,
		)
		.map(|_| ())
	} else {
		netcfgd_host::config::remove_drop_in(&state.paths.config, &state.paths.factory, &name)
	};

	if let Err(message) = result {
		return Response::error(message);
	}
	state.reload();

	// **Written is not running.** netcfgd applies nothing on a configuration
	// change by itself -- `on_drift` defaults to `report`, and `ncfg apply` is
	// the explicit step -- so activation used to leave a correct plan that
	// nothing had run, and the operator got "cannot reach the supplicant" from
	// the very next scan. Reported as "the buttons don't work properly", which
	// is what a switch that changes a file and nothing else looks like.
	//
	// So this applies the radio's own plan before answering, and applies all
	// of it. netcfgd configures a machine's networking; a switch that changes
	// a file and leaves the machine alone is not doing that. The daemon would
	// reach the same state within a tick either way -- what the synchronous
	// apply buys is a truthful answer, and a client that scans the moment it
	// is told the radio is netcfgd's does not scan a radio with no supplicant.
	if activate {
		if let Err(message) = apply_interface(state, interface) {
			return Response::error(message);
		}
	}
	Response::Ok
}

/// Start the backends one interface now wants, before answering.
///
/// Restricted twice: to the interface that was asked about, and to *starting a
/// backend*. The first is `state::restrict`'s job; the second is done here
/// because no other caller wants it.
///
/// **Not the whole interface plan, and the reason is a failure.** It was the
/// whole plan for a day, on the reasoning that netcfgd applies its
/// configuration and a switch that half-applies is the fault this milestone
/// was full of. But addressing is in that plan, and `wifi_journey.sh` found
/// what it costs: activating a radio ran `dhcpcd`, which cannot get a lease on
/// a link with nothing behind it, and the activation *failed* -- so handing
/// netcfgd a radio was refused because DHCP had not finished on it.
///
/// The rest is not skipped, only deferred: the reconcile loop applies it on
/// the next pass, where a DHCP client that will not settle is a report rather
/// than a refusal. What the synchronous half buys is the property a client
/// depends on -- told the radio is netcfgd's, it can scan at once.
///
/// # Errors
///
/// A netlink socket that will not open, or an action that failed. The journal
/// is written either way, so `ncfg status` explains what this only names.
fn apply_interface(state: &mut crate::State, interface: &str) -> Result<(), String> {
	let full = state.plan(&netcfgd_plan::PlanOptions::default());
	let (restricted, _dropped) = crate::state::restrict(&full, &[interface.to_owned()]);
	let mut plan = netcfgd_plan::Plan {
		warnings: restricted.warnings.clone(),
		refusals: restricted.refusals.clone(),
		stranded: restricted.stranded.clone(),
		..netcfgd_plan::Plan::default()
	};
	plan.actions = restricted
		.actions
		.into_iter()
		.filter(|action| {
			// The *supplicant*, not "a backend". `BackendStart` covers the
			// DHCP client too, and filtering on the op alone still ran
			// `dhcpcd` -- which cannot get a lease on a radio that has not
			// associated with anything yet, so activating a radio failed
			// because addressing had not finished on it. Found by
			// `wifi_journey.sh` under `make live` and not standalone, because
			// the suite puts /sbin on PATH and a plain shell does not: the
			// same code, and whether it broke depended on whether `dhcpcd`
			// could be found.
			matches!(
				action.op,
				netcfgd_plan::Op::BackendStart {
					kind: netcfgd_model::BackendKind::Supplicant,
					..
				}
			)
		})
		.collect();
	if plan.actions.is_empty() {
		// Nothing to do is success: the radio may already be up from a
		// previous activation, and reporting that as a failure would make a
		// switch complain about being already on.
		return Ok(());
	}

	let mut executor = state.executor()?;
	let journal = netcfgd_apply::apply(&plan, &mut executor);
	let _ = crate::run_state::update_owned(&state.paths.run, |owned| {
		owned.absorb(&executor.effects);
	});
	let _ = crate::run_state::write_journal(&state.paths.run, &journal);
	state.reobserve();

	if !journal.succeeded() {
		// The executor's own sentence, because it names the action and the
		// reason -- including the one an operator most needs here, which is
		// that another manager is still holding the radio.
		let why = journal
			.failure()
			.and_then(|record| record.error.clone())
			.unwrap_or_else(|| "no reason was recorded".to_owned());
		return Err(format!(
			"`{interface}` is netcfgd's in the configuration, and starting its \
			 supplicant failed: {why}"
		));
	}
	Ok(())
}

/// Why there is no supplicant on an interface, in words that say what to do.
///
/// **The control socket's own message cannot answer this and should not try.**
/// It says "no control socket at ...: is `wpa_supplicant` running?", which is
/// true, unhelpful, and points at the wrong program: the question is not
/// whether somebody started a supplicant, it is why *netcfgd* did not. Only
/// the document knows, and the document is here.
///
/// The case this was written for: a machine with no `device` block at all,
/// where scanning worked until `NetworkManager` was stopped. NM adds the
/// interface to the system `wpa_supplicant`, which creates the socket, so
/// netcfgd was scanning through a supplicant it had not started and had no
/// opinion about. Stop NM and the socket goes. Nothing in the old message
/// suggested the fix was three lines of configuration.
fn why_no_supplicant(document: Option<&Document>, interface: &str) -> Option<String> {
	// Not a radio at all: the socket's own message is the right one, because
	// the answer is not about configuration.
	// The shared predicate, not a fourth copy of the path. This function had
	// its own `Path::new("/sys/class/net")` -- written before
	// `netcfgd_sys::radio` collected the other three -- so it asked the real
	// machine while everything around it asked wherever `NCFG_SYS_CLASS_NET`
	// pointed. On a test radio it therefore answered "not a radio at all" and
	// declined to explain anything, which is how `wifi_journey.sh` found it on
	// the day it was written.
	if !netcfgd_sys::radio::is_wireless(&netcfgd_sys::radio::class_net(), interface) {
		return None;
	}

	let device = document?
		.devices
		.iter()
		.find(|device| device.name == interface);
	match device {
		Some(device) if !device.managed => Some(format!(
			"`{interface}` is a radio, and its `device` block says `managed = false` -- \
			 so netcfgd does not touch it and has started no supplicant. That is the \
			 documented way to hand an interface to another daemon; remove the line to \
			 take it back."
		)),
		// **Configured correctly, and still no supplicant.** This arm returned
		// `None` -- no diagnosis at all -- for the case an operator is most
		// likely to be in: radio managed, `wifi` policy present, network written
		// down, and another daemon holding the control socket. The caller then
		// fell back to a message listing what the cause *might* be, when netcfgd
		// could say which it was.
		//
		// **The question is who bound the socket, not whether it answers.** The
		// first version of this asked `answers()` and so said nothing in exactly
		// the reported case: NetworkManager's supplicant is driven over D-Bus and
		// does not reply on the control interface, so the socket exists, stays
		// mute, and `answers()` is false. Measured against the real message.
		Some(device) if device.wifi.is_some() => {
			let dir = netcfgd_supplicant::ctrl_dir();
			let socket = dir.join(interface);
			if !socket.exists() {
				// Nothing has bound it. That is the ordinary "netcfgd has not
				// applied yet, or the apply failed" case, and the caller's own
				// message already says so.
				return None;
			}
			let pidfile = netcfgd_host::state::resolve_dir(None)
				.join("supplicant")
				.join(format!("{interface}.pid"));
			if netcfgd_sys::process::pid_of(&pidfile, &pidfile.to_string_lossy()).is_some() {
				// netcfgd's own, and not answering: that is the wedged case, which
				// the planner reports with its own warning and 0141's refusal.
				return Some(format!(
					"`{interface}` has a supplicant netcfgd started, and it is not \
					 answering its control socket at {}. netcfgd does not kill it by \
					 default, because a busy machine misses the deadline the same \
					 way. `ncfg apply --restart-wedged {interface}` restarts it.",
					socket.display()
				));
			}
			// Bound by something netcfgd did not start.
			Some(format!(
				"`{interface}` is a radio netcfgd manages and is configured for, but \
				 another daemon is already running a supplicant on it: the control \
				 socket at {} was bound by a process netcfgd did not start, so netcfgd \
				 will not take the radio from it (0125). **Nothing here is \
				 misconfigured** -- the radio is somebody else's until they let \
				 go.\n\nHand it over with:\n\n    systemctl stop NetworkManager\n    \
				 systemctl stop wpa_supplicant\n\nBoth, because wpa_supplicant runs \
				 independently of NetworkManager and keeps this socket bound on its \
				 own -- stopping NetworkManager alone leaves netcfgd declining \
				 forever, which is what \"netcfgd stops working without \
				 NetworkManager\" actually is. netcfgd picks the radio up on the next \
				 reconcile. To leave it to them instead, set `managed = false` here.",
				socket.display()
			))
		}
		_ => Some(format!(
			"`{interface}` is a radio, and netcfgd has no `wifi` policy for it -- so it \
			 does not manage the radio and has started no supplicant, which is why there \
			 is nothing to scan with. Add this and netcfgd will run one:\n\n    \
			 device {interface} {{\n        wifi {{\n            autoconnect = true\n  \
			      }}\n    }}\n\n`ncfg config put radio -` will take it on standard input. \
			 Until then a scan can only work through somebody else's supplicant, which is \
			 what NetworkManager was providing."
		)),
	}
}

#[cfg(test)]
mod diagnosis_tests {
	use super::why_no_supplicant;

	/// **The case that produced no diagnosis at all.**
	///
	/// A radio netcfgd manages, configured, with another daemon holding the
	/// control socket -- which is what an operator running `NetworkManager`
	/// meets. This arm returned `None`, so the caller fell back to a message
	/// listing what the cause *might* be, and netcfgd kept to itself a fault
	/// it had already identified.
	///
	/// The first fix keyed on whether the socket *answers*, and was silent in
	/// exactly this case: `NetworkManager` drives its supplicant over D-Bus and
	/// it does not reply on the control interface, so the socket exists and
	/// stays mute. The question is who bound it, not whether it talks.
	#[test]
	fn a_foreign_supplicant_is_named_rather_than_guessed_at() {
		let dir = std::env::temp_dir().join(format!("ncfg-diag-{}", std::process::id()));
		let sys = dir.join("sys");
		let ctrl = dir.join("ctrl");
		let _ = std::fs::create_dir_all(sys.join("radio0").join("wireless"));
		let _ = std::fs::create_dir_all(&ctrl);
		// SAFETY-adjacent: these are process-wide, and this test is the only
		// reader of them. The suite runs tests in threads, so the paths are
		// keyed on the pid to keep two runs apart rather than two threads.
		std::env::set_var("NCFG_SYS_CLASS_NET", &sys);
		std::env::set_var("NCFG_WPA_CTRL_DIR", &ctrl);
		std::env::set_var("NCFG_RUN_DIR", dir.join("run"));

		// Built from JSON rather than a literal: `Device` has no `Default`, and
		// a literal here would have to be edited every time the struct gains a
		// field -- which is how a test comes to assert a shape nobody meant.
		// One device grafted onto a default document: `Device` has no
		// `Default`, and spelling the whole struct out here would have to be
		// edited every time it gains a field -- which is how a test comes to
		// assert a shape nobody meant.
		let mut document = netcfgd_model::Document::default();
		let device: netcfgd_model::Device =
			serde_json::from_str(r#"{"name":"radio0","managed":true,"wifi":{}}"#)
				.expect("fixture device");
		document.devices.push(device);

		// No socket: netcfgd has simply not started one, and the caller's own
		// message is the right one.
		assert!(
			why_no_supplicant(Some(&document), "radio0").is_none(),
			"with nothing bound there is nothing to diagnose"
		);

		// Somebody else's, bound and mute.
		let socket = std::os::unix::net::UnixDatagram::bind(ctrl.join("radio0"));
		assert!(socket.is_ok(), "could not bind a stand-in socket");
		let said = why_no_supplicant(Some(&document), "radio0")
			.expect("a bound socket netcfgd did not start must be explained");
		assert!(
			said.contains("another daemon is already running a supplicant"),
			"the diagnosis must name the cause, not list candidates: {said}"
		);
		assert!(
			said.contains("systemctl stop wpa_supplicant"),
			"and must name BOTH units, since stopping NetworkManager alone \
			 leaves the socket bound: {said}"
		);

		let _ = std::fs::remove_dir_all(&dir);
	}
}

/// Find the `network` block this scan result belongs to, for labelling a scan.
///
/// The rule itself is `netcfgd_model::wifi::network_for`, shared with the
/// observation, which needs the same answer to rank an associated network's
/// metric against its interface's preference. This wrapper is only the
/// `Option<&Document>` the socket paths happen to hold.
fn configured_for<'a>(
	document: Option<&'a Document>,
	ssid: &Ssid,
	bssid: &str,
) -> Option<&'a WifiNetwork> {
	netcfgd_model::wifi::network_for(&document?.networks, ssid, bssid)
}

/// The name as text, where it happens to be text.
///
/// Absent rather than mangled, so a client can tell "this name is not UTF-8"
/// from "this name is empty". Lossy conversion would put a replacement
/// character in a list the operator is trying to recognise their own network
/// in.
fn name_of(ssid: &Ssid) -> Option<String> {
	std::str::from_utf8(ssid.as_bytes())
		.ok()
		.map(std::borrow::ToOwned::to_owned)
}

/// `SCAN`, then `SCAN_RESULTS`.
pub(crate) fn scan(document: Option<&Document>, interface: &str) -> Response {
	if let Err(message) = check_backend(document, interface) {
		return Response::error(message);
	}
	let client = match connect(interface) {
		Ok(client) => client,
		// The document's answer first where it has one: it says what to change
		// rather than what is missing.
		Err(message) => {
			return Response::error(why_no_supplicant(document, interface).unwrap_or(message))
		}
	};

	// A scan already in progress answers FAIL, which is not a failure worth
	// reporting: the results are about to be fresh either way. Anything else
	// wrong will surface on the read below.
	let _ = client.command("SCAN");

	let body = match client.ask("SCAN_RESULTS") {
		Ok(body) => body,
		Err(error) => return Response::error(format!("scan failed on `{interface}`: {error}")),
	};

	let mut entries: Vec<ScanEntry> = parse_scan_results(&body)
		.into_iter()
		.map(|result| ScanEntry {
			secured: result.is_secured(),
			enterprise: result.is_enterprise(),
			ssid: result.ssid.to_hex(),
			name: name_of(&result.ssid),
			configured: configured_for(document, &result.ssid, &result.bssid)
				.map(|network| network.id.clone()),
			// **Asked only where the flags say fast transition.** The domain
			// lives in `BSS <bssid>` rather than in `SCAN_RESULTS`, so it
			// costs one round trip per access point -- and with fifty
			// networks in range, asking every one would make a scan
			// noticeably slower to serve something almost none of them have.
			// The flags are already parsed and say which ones can answer.
			mobility_domain: result
				.does_fast_transition()
				.then(|| {
					client
						.ask(&format!("BSS {}", result.bssid))
						.ok()
						.and_then(|reply| parse_mobility_domain(&reply))
				})
				.flatten(),
			bssid: result.bssid,
			frequency: result.frequency,
			signal: result.signal,
		})
		.collect();

	// Strongest first, because that is the order the question is asked in.
	// A stable sort, so two access points at the same level keep the
	// supplicant's ordering rather than swapping between scans.
	entries.sort_by(|left, right| right.signal.cmp(&left.signal));
	Response::WifiScan(Box::new(ScanReport {
		interface: interface.to_owned(),
		access_points: entries,
	}))
}

/// `STATUS`, resolved back to the document where possible.
pub(crate) fn status(document: Option<&Document>, interface: &str) -> Response {
	let client = match connect(interface) {
		Ok(client) => client,
		Err(message) => return Response::error(message),
	};
	let body = match client.ask("STATUS") {
		Ok(body) => body,
		Err(error) => return Response::error(format!("cannot read `{interface}`: {error}")),
	};
	let status = parse_status(&body);

	// The supplicant reports the SSID here already decoded from its own hex,
	// but escaped the same way as everywhere else.
	let ssid = status_field(&status, "ssid")
		.map(netcfgd_supplicant::protocol::printf_decode)
		.and_then(|octets| Ssid::new(octets).ok());

	Response::WifiStatus(Box::new(WifiState {
		interface: interface.to_owned(),
		state: status_field(&status, "wpa_state")
			.unwrap_or("UNKNOWN")
			.to_owned(),
		ssid: ssid.as_ref().map(Ssid::to_hex),
		name: ssid.as_ref().and_then(name_of),
		bssid: status_field(&status, "bssid").map(std::borrow::ToOwned::to_owned),
		// The associated BSSID is the second half: a network identified by
		// address rather than by name is exactly the one whose SSID cannot
		// answer "which of my networks is this?".
		network: ssid
			.as_ref()
			.and_then(|ssid| {
				configured_for(document, ssid, status_field(&status, "bssid").unwrap_or(""))
			})
			.map(|network| network.id.clone()),
	}))
}

/// Join a network the configuration already describes.
pub(crate) fn connect_to(
	document: Option<&Document>,
	secrets_dir: &Path,
	interface: &str,
	wanted: &str,
) -> Response {
	if let Err(message) = check_backend(document, interface) {
		return Response::error(message);
	}

	// The lookup is what makes `connect` mean "join one of these" rather than
	// "join anything", and the refusal has to say so plainly or it reads as
	// the network being missing rather than the name being unknown. Since
	// 0124 the same caller may add a network as well, so this is no longer a
	// permission boundary between two tiers -- it is the difference between
	// naming something that exists and naming something that does not, and
	// the message says what to do about it.
	let Some(document) = document else {
		return Response::error("no configuration is loaded, so there is nothing to join");
	};
	let Some(network) = document
		.networks
		.iter()
		.find(|network| network.id == wanted)
	else {
		let known: Vec<&str> = document
			.networks
			.iter()
			.map(|network| network.id.as_str())
			.collect();
		return Response::error(format!(
			"no `network` block called `{wanted}`. This joins networks the configuration \
			 already describes; `ncfg wifi add` writes a new one. Configured: {}",
			if known.is_empty() {
				"none".to_owned()
			} else {
				known.join(", ")
			}
		));
	};

	let client = match connect(interface) {
		Ok(client) => client,
		Err(message) => return Response::error(message),
	};

	// Already present? The supplicant was populated at apply time, so the
	// usual case is selecting something that is already there. Adding a second
	// copy would leave two entries for one network and make LIST_NETWORKS
	// unreadable.
	let listed = match client.ask("LIST_NETWORKS") {
		Ok(body) => parse_network_list(&body),
		Err(error) => return Response::error(format!("cannot list networks: {error}")),
	};
	// Matched by name, and only where the document states one. A network whose
	// name is learned from a scan has nothing to compare here, so it is always
	// added afresh rather than matched against something with a different name.
	let existing = network.ssid.as_ref().and_then(|ssid| {
		listed
			.iter()
			.find(|entry| entry.ssid == *ssid)
			.map(|entry| entry.id)
	});

	let id = if let Some(id) = existing {
		id
	} else {
		// Materialising too, for the reason `netcfgd-apply` does: a network
		// with a stored certificate has to produce a path here as well, and a
		// resolver that could read secrets but not write a certificate would
		// join the same network from the command line and refuse it from a
		// connect.
		let resolver = Resolver::with_secrets_dir(secrets_dir)
			.materialising_into(netcfgd_apply::kernel::certs_dir());
		// The device's policy, or permanent. Without this a network joined
		// from the command line would go in with a different address policy
		// from the same network added at apply time -- quietly leaking the
		// hardware address an apply would have hidden.
		let policy = document
			.devices
			.iter()
			.find(|device| device.name == interface)
			.and_then(|device| device.wifi.as_ref())
			.map_or(netcfgd_model::MacPolicy::Permanent, |wifi| wifi.mac_policy);
		match add_network(&client, network, policy, &resolver) {
			Ok(id) => id,
			Err(error) => return Response::error(format!("cannot configure `{wanted}`: {error}")),
		}
	};

	// SELECT_NETWORK rather than ENABLE_NETWORK: it disables the others, which
	// is what "join this one" means. ENABLE would leave the supplicant free to
	// pick a different network it also knows about, and the operator would
	// have asked for one thing and got another.
	match client.command(&format!("SELECT_NETWORK {id}")) {
		Ok(()) => Response::Ok,
		Err(error) => Response::error(format!("cannot join `{wanted}`: {error}")),
	}
}

/// Leave the current network without forgetting it.
pub(crate) fn disconnect(document: Option<&Document>, interface: &str) -> Response {
	if let Err(message) = check_backend(document, interface) {
		return Response::error(message);
	}
	let client = match connect(interface) {
		Ok(client) => client,
		Err(message) => return Response::error(message),
	};
	// DISCONNECT, not REMOVE_NETWORK: the network stays configured and stays
	// in the supplicant, so reconnecting does not need the credential resolved
	// again. It also means the next reconcile does not see a network missing
	// and put it back, which would undo the disconnect a second later.
	match client.command("DISCONNECT") {
		Ok(()) => Response::Ok,
		Err(error) => Response::error(format!("cannot disconnect `{interface}`: {error}")),
	}
}

/// Who is associated with an access point this machine runs.
///
/// The `access_point` block is found first, and its absence is the answer
/// rather than an error about a socket: an interface with no access point on
/// it has no stations, and saying "no control socket" would send an operator
/// looking for a broken hostapd that was never meant to exist.
pub(crate) fn ap_stations(
	document: Option<&Document>,
	run_dir: &Path,
	interface: &str,
) -> Response {
	let Some(access_point) = document.and_then(|document| {
		document
			.access_points
			.iter()
			.find(|access_point| access_point.device == interface)
	}) else {
		return Response::error(format!(
			"`{interface}` runs no access point, so nothing is associated with it. \
			 An `access_point` block naming `device = \"{interface}\"` is what would \
			 put one there"
		));
	};

	let found = match netcfgd_hostapd::stations(run_dir, interface) {
		Ok(found) => found,
		Err(message) => return Response::error(message),
	};

	// Whether the ACL names a station is answered from the document rather
	// than from hostapd, deliberately: the document is the authority
	// (constraint 1), and the difference between the two is the thing worth
	// seeing. A station that is connected *and* listed on a deny list means
	// hostapd has not been told about a list that changed.
	let listed = |address: &str| {
		access_point
			.access_control
			.as_ref()
			.is_some_and(|acl| acl.stations.iter().any(|station| station == address))
	};

	let stations = found
		.into_iter()
		.map(|station| StationEntry {
			listed: listed(&station.address),
			address: station.address,
			authorized: station.authorized,
			signal: station.signal_dbm,
			connected_seconds: station.connected_seconds,
			inactive_msec: station.inactive_msec,
			rx_bytes: station.rx_bytes,
			tx_bytes: station.tx_bytes,
		})
		.collect();

	Response::ApStations(Box::new(StationReport {
		interface: interface.to_owned(),
		access_point: access_point.id.clone(),
		access_control: access_point.access_control.as_ref().map(|acl| acl.policy),
		stations,
	}))
}

/// Add a wireless network to the configuration, for a client that cannot write
/// the file itself.
///
/// Decision 0117. The request carries typed fields and never config text, so
/// the daemon renders the block and this function's shape is what bounds the
/// privilege: there is no field here that could name a hook, a path or a
/// `run_as`, and a hook's `run_as` defaults to root.
///
/// The write, the credential and the compile-it-back check are
/// `netcfgd_host::wifi_profile`'s, shared with `ncfg wifi add` -- two
/// implementations of "what a `network` block looks like" is the drift this
/// tree keeps finding.
/// Named `configure_network` and not `add_network`, because
/// `netcfgd_supplicant::add_network` already means something different one
/// layer down -- telling a running supplicant about a network. This writes a
/// config file. Two things called "add a network" in one module is how a
/// reader ends up sure they know which one a call site meant.
pub(crate) struct Wanted<'a> {
	pub(crate) ssid_hex: &'a str,
	pub(crate) id: Option<&'a str>,
	pub(crate) passphrase: Option<&'a str>,
	pub(crate) proto: Option<&'a str>,
	pub(crate) hidden: bool,
	pub(crate) metric: Option<u32>,
	pub(crate) eap: Option<&'a netcfgd_proto::EapRequest>,
}

/// The `@secret:` reference a stored certificate name becomes.
///
/// **The one place the socket's names turn into configuration**, and the only
/// form they can take. A request carries a *name*; the configuration written
/// from it says `@secret:<name>`, which the compiler lowers to a stored source
/// and never to a path. A caller cannot reach the path form from here because
/// there is nothing to write it in -- 0117's construction, applied to the
/// field 0117 refused to accept for exactly this reason.
fn stored_reference(name: Option<&String>) -> Option<String> {
	name.map(|name| format!("@secret:{name}"))
}

/// The security an `eap` request describes.
///
/// # Errors
///
/// A method netcfgd does not implement, named rather than silently accepted:
/// the supplicant would refuse the network later and say so only in its log.
fn eap_security(eap: &netcfgd_proto::EapRequest) -> Result<wifi_profile::Security, String> {
	match eap.method.as_str() {
		"peap" | "ttls" | "tls" | "pwd" => {}
		other => {
			return Err(format!(
				"`{other}` is not an EAP method netcfgd implements; it is peap, ttls, \
				 tls or pwd"
			))
		}
	}
	if eap.identity.trim().is_empty() {
		return Err(
			"an enterprise network needs an `identity`, which is who you are to the \
			 authentication server -- often a username, often with a realm"
				.to_owned(),
		);
	}
	Ok(wifi_profile::Security::Eap {
		method: eap.method.clone(),
		identity: Some(eap.identity.clone()),
		anonymous_identity: eap.anonymous_identity.clone(),
		ca_cert: stored_reference(eap.ca_cert.as_ref()),
		client_cert: stored_reference(eap.client_cert.as_ref()),
		phase2: eap.phase2.clone(),
	})
}

pub(crate) fn configure_network(
	document: Option<&Document>,
	config_dir: &std::path::Path,
	factory_dir: &std::path::Path,
	wanted: &Wanted<'_>,
) -> Response {
	let Wanted {
		ssid_hex,
		id,
		passphrase,
		proto,
		hidden,
		metric,
		eap,
	} = *wanted;
	let Ok(ssid) = Ssid::from_hex(ssid_hex) else {
		return Response::error(format!(
			"`{ssid_hex}` is not a usable ssid: it has to be lowercase hex of 0 to \
			 32 octets, because an ssid is not guaranteed to be text"
		));
	};

	// The label defaults to the ssid read as text, which is what an operator
	// means by "the network's name" whenever the two coincide. Where they do
	// not -- an ssid that is not UTF-8 -- the caller has to say, because a
	// label is a filename and this will not invent one.
	let derived = String::from_utf8(ssid.as_bytes().to_vec()).ok();
	let Some(id) = id.map(ToOwned::to_owned).or(derived) else {
		return Response::error(
			"this ssid is not text, so it cannot be used as a name. Send an `id` \
			 as well: the ssid itself is kept exactly, as hex"
				.to_owned(),
		);
	};

	// Refused before anything is written. A second block with the same label is
	// a compile error, which would break every interface on the machine to add
	// one network.
	if let Some(existing) =
		document.and_then(|document| document.networks.iter().find(|network| network.id == id))
	{
		return Response::error(format!(
			"a network `{}` is already configured. Change it by editing the \
			 configuration, or remove it and add it again",
			existing.id
		));
	}

	// An enterprise network is its own shape and takes the branch before the
	// personal one: `proto` pins a WPA generation for a passphrase and means
	// nothing here, and saying so beats writing a network that will not join.
	let security = if let Some(eap) = eap {
		if proto.is_some() {
			return Response::error(
				"a `proto` was given with an `eap` block. `proto` pins the generation \
				 protecting a passphrase, and an enterprise network negotiates its own"
					.to_owned(),
			);
		}
		match eap_security(eap) {
			Ok(security) => security,
			Err(message) => return Response::error(message),
		}
	} else {
		// An open network with a passphrase is refused rather than quietly
		// dropping one of the two: the caller believes one of those things and
		// it is not this function's business to pick.
		match (passphrase, proto) {
			(None, None) => wifi_profile::Security::Open,
			(None, Some(_)) => {
				return Response::error(
					"a `proto` was given with no passphrase. An open network has no \
				 generation to pin"
						.to_owned(),
				)
			}
			(Some(_), proto) => wifi_profile::Security::Psk {
				proto: proto.map(ToOwned::to_owned),
			},
		}
	};
	if let Some(proto) = proto {
		if proto != "wpa2" && proto != "wpa3" {
			return Response::error(format!(
				"`{proto}` is not a generation this understands; it is `wpa2` or \
				 `wpa3`, and leaving it out negotiates both"
			));
		}
	}

	let profile = wifi_profile::Profile {
		id,
		ssid,
		hidden,
		metric,
		security,
	};

	match wifi_profile::install(config_dir, factory_dir, &profile, passphrase) {
		Ok(_) => Response::Ok,
		Err(error) => Response::error(error),
	}
}

#[cfg(test)]
mod tests {
	/// What activation writes must actually plan a supplicant.
	///
	/// **The check the first version of this feature did not have, and the
	/// bug it would have caught.** Activation wrote a `device` block, reported
	/// success, and planned nothing -- because the planner walks
	/// `desired.interfaces` and a device nothing has an `interface` block for
	/// is never visited. Every layer passed: the request was well formed, the
	/// tier was right, the file was written, the pane redrew. The operator got
	/// "cannot reach the supplicant" and no reason.
	///
	/// So this asserts the *outcome* rather than the text. Comparing the
	/// written block against an expected string would have passed just as
	/// happily against the broken one; what makes this test worth having is
	/// that it compiles the file and asks the planner what it would do.
	#[test]
	fn what_activation_writes_plans_a_supplicant() {
		let mut sources = netcfgd_compile::SourceMap::new();
		sources.add(
			"radio-wlan0.conf",
			netcfgd_host::config::radio_blocks("wlan0"),
		);
		let document = netcfgd_compile::compile(&sources, &mut netcfgd_compile::NoHooks)
			.unwrap_or_else(|diagnostics| {
				panic!(
					"activation writes something that does not compile:\n{}",
					diagnostics.render(&sources)
				)
			});

		// A radio that exists, because `radios_of` asks the kernel's answer
		// rather than the document's -- a `wifi { }` section is not a claim
		// that the interface is one.
		let observed = netcfgd_model::Observed {
			links: vec![netcfgd_model::ObservedLink {
				name: "wlan0".to_owned(),
				index: 2,
				kind: String::new(),
				wireless: true,
				network: None,
				up: false,
				carrier: true,
				reachable: None,
				probe_detail: None,
				mtu: 1500,
				mac: None,
				master: None,
				parent: None,
				offloads: Vec::new(),
				ipv6_token: None,
				qdisc: None,
				qdisc_bandwidth_bits: None,
				qdisc_ingress: false,
				ingress_redirect: None,
				forwarding: None,
				privacy: None,
				accept_ra: None,
				rfkill: None,
				ownership: netcfgd_model::Ownership::Unknown,
				private_key_loaded: false,
				wireguard: None,
				bond: None,
				bridge: None,
				macvlan: None,
				vlan: None,
				tunnel: None,
				vxlan: None,
			}],
			..Default::default()
		};

		let plan = netcfgd_plan::plan(&document, &observed, &netcfgd_plan::PlanOptions::default());
		let names: Vec<&str> = plan.actions.iter().map(|action| action.op.name()).collect();
		assert!(
			names.contains(&"backend.start"),
			"activating a radio plans no supplicant, so it would change nothing: {names:?}"
		);
	}
}
