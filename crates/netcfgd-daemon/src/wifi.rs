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

use netcfgd_model::device::WifiBackend;
use netcfgd_model::{Document, Ssid, WifiNetwork};
use netcfgd_proto::{Response, ScanEntry, ScanReport, StationEntry, StationReport, WifiState};
use netcfgd_secret::Resolver;
use netcfgd_supplicant::protocol::{
	parse_network_list, parse_scan_results, parse_status, status_field,
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
			 stateless mode (docs/decisions/0014). Use `backend = \"wpa_supplicant\"`."
		)),
	}
}

/// Find the `network` block this scan result belongs to, for labelling a scan.
///
/// By SSID, and by BSSID for a network that has no SSID to match on -- one that
/// names access points instead and learns the name from them. Without the
/// second, exactly the networks whose whole point is being identified by
/// address would show as unconfigured in a scan, which is the list an operator
/// checks to see whether netcfgd knows about what it can see.
fn configured_for<'a>(
	document: Option<&'a Document>,
	ssid: &Ssid,
	bssid: &str,
) -> Option<&'a WifiNetwork> {
	document?.networks.iter().find(|network| {
		network.ssid.as_ref().map_or_else(
			|| {
				network
					.bssid
					.iter()
					.any(|listed| listed.eq_ignore_ascii_case(bssid))
			},
			|stated| stated == ssid,
		)
	})
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
		Err(message) => return Response::error(message),
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
			ssid: result.ssid.to_hex(),
			name: name_of(&result.ssid),
			configured: configured_for(document, &result.ssid, &result.bssid)
				.map(|network| network.id.clone()),
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

	// The lookup is the permission boundary, not a convenience. A caller in
	// the `wifi` tier can reach exactly the networks somebody with `admin`
	// wrote down, and the refusal has to say that plainly or it reads as the
	// network being missing rather than the operation being out of scope.
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
			"no `network` block called `{wanted}`. This can only join networks the \
			 configuration already describes; adding one means writing config, which needs \
			 the admin tier (docs/decisions/0013). Configured: {}",
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
		let resolver = Resolver::with_secrets_dir(secrets_dir);
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
