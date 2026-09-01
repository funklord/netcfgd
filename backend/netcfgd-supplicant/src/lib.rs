#![forbid(unsafe_code)]

//! Driving `wpa_supplicant` over its control socket.
//!
//! Decision 0014 makes `wpa_supplicant` the floor rather than the fallback, and
//! decision 0015 says it holds no state: netcfgd supplies every network at
//! apply time and removes them when the document stops asking. This crate is
//! the mechanism for both, and for wired 802.1X (decision 0008), which speaks
//! the same protocol through the same socket.
//!
//! The split is deliberate. [`protocol`] and [`network`] are pure text and can
//! be tested exhaustively on a machine with no radio and no supplicant
//! installed; [`client`] is the socket, and needs a running daemon to say
//! anything about.

pub mod client;
pub mod network;
pub mod protocol;

pub use client::{is_reply_socket, nothing_is_listening, Client, DEFAULT_CTRL_DIR, IMPATIENT};
pub use network::{mac_addr_value, settings, wired_settings, Setting, Unsupported};
pub use protocol::{Event, NetworkEntry, Reply, ScanResult};

use netcfgd_model::WifiNetwork;
use netcfgd_secret::Resolver;
use std::io;
use std::path::{Path, PathBuf};

/// Where the control sockets are.
///
/// Overridable so a test can point at a directory that is not the real one: a
/// network namespace is not a mount namespace, so without this a test would
/// share `/run/wpa_supplicant` with whatever the host is running.
///
/// One function rather than the three byte-identical copies this replaces, in
/// `netcfgd-apply`, `netcfgd-daemon` and the daemon's wifi commands. Three
/// copies of a path and an environment variable is three chances for them to
/// stop agreeing, and the crate that owns `DEFAULT_CTRL_DIR` is where the
/// question belongs.
#[must_use]
pub fn ctrl_dir() -> PathBuf {
	std::env::var_os("NCFG_WPA_CTRL_DIR")
		.map_or_else(|| PathBuf::from(DEFAULT_CTRL_DIR), PathBuf::from)
}

// The observation's deadline is `client::IMPATIENT`, which this crate
// re-exports: one second, for the reason recorded there.

/// Does the supplicant on `interface` answer its control socket?
///
/// A question about the *process*, not about wifi: a supplicant that has bound
/// its socket and stopped answering looks, from every other angle netcfgd has,
/// exactly like one that is working and has not associated yet.
///
/// `false` covers "the socket is gone" as well as "it did not answer in time",
/// and deliberately: netcfgd asks this only of a supplicant it believes is
/// running, and a running process whose socket has vanished is not in a state
/// anything should be configured against.
#[must_use]
pub fn answers(dir: &Path, interface: &str) -> bool {
	Client::connect_within(dir, interface, client::IMPATIENT).is_ok()
}

/// The network a supplicant is currently associated with: its name, and the
/// access point serving it.
///
/// Both halves come back because resolving an association to a configured
/// network needs both -- a network that lists BSSIDs instead of an SSID is
/// identified by the second (`netcfgd_model::wifi::network_for`).
///
/// `None` covers every way there is no answer: the socket is gone, the
/// supplicant is scanning rather than associated, or the name is not a name
/// this crate will accept. The observation asks this only of a supplicant it
/// already believes is running, and treats no answer as no association -- so a
/// wireless link falls back to its interface's own preference rather than
/// borrowing a stale network's metric.
///
/// **Impatient, for the reason `answers` is.** This runs on every observation,
/// and a supplicant that has stopped answering must not hold the cycle open.
#[must_use]
pub fn associated(dir: &Path, interface: &str) -> Option<(netcfgd_model::Ssid, String)> {
	let client = Client::connect_within(dir, interface, client::IMPATIENT).ok()?;
	let body = client.ask("STATUS").ok()?;
	let status = protocol::parse_status(&body);
	// The supplicant reports the name here already decoded from its own hex,
	// but escaped the same way as everywhere else.
	let ssid = protocol::status_field(&status, "ssid")
		.map(protocol::printf_decode)
		.and_then(|octets| netcfgd_model::Ssid::new(octets).ok())?;
	let bssid = protocol::status_field(&status, "bssid")
		.unwrap_or_default()
		.to_owned();
	Some((ssid, bssid))
}

/// Remove every network the supplicant currently holds.
///
/// Decision 0015: called before adding anything, so a supplicant started by
/// something else -- or one that survived a netcfgd crash -- does not
/// contribute networks the document cannot account for.
///
/// # Errors
///
/// Returns an error if the supplicant refuses or the socket fails.
pub fn clear_networks(client: &Client) -> io::Result<()> {
	client.command("REMOVE_NETWORK all")
}

/// Configure a wired 802.1X port: one network, enabled, nothing else.
///
/// A wired supplicant has exactly one thing to authenticate with, so this
/// clears first -- the port cannot be "on" two profiles, and leaving a stale
/// one would let the supplicant fall back to it.
///
/// # Errors
///
/// Returns an error if a credential cannot be resolved or the supplicant
/// refuses a setting.
pub fn configure_wired(
	client: &Client,
	eap: &netcfgd_model::EapConfig,
	resolver: &Resolver,
) -> Result<u32, Box<dyn std::error::Error>> {
	clear_networks(client)?;
	let settings = wired_settings(eap, resolver)?;

	let id: u32 = client.ask("ADD_NETWORK")?.trim().parse().map_err(|_| {
		io::Error::new(
			io::ErrorKind::InvalidData,
			"ADD_NETWORK did not answer with a network id",
		)
	})?;
	for setting in &settings {
		if let Err(error) = client.command(&setting.command(id)) {
			let _ = client.command(&format!("REMOVE_NETWORK {id}"));
			return Err(Box::new(io::Error::new(
				io::ErrorKind::InvalidData,
				format!("{} was refused: {error}", setting.redacted(id)),
			)));
		}
	}
	client.command(&format!("ENABLE_NETWORK {id}"))?;
	Ok(id)
}

/// Add one network and enable it, returning the supplicant's id for it.
///
/// # Errors
///
/// Returns an error if the network cannot be expressed, a secret cannot be
/// resolved, or the supplicant refuses a setting.
/// The SSID the listed access points are advertising.
///
/// A document may name access points instead of a name -- "the one in the
/// lobby", by address -- and something has to turn that into an SSID before the
/// supplicant is configured, because **WPA derives its key from the passphrase
/// and the SSID**. `wpa_supplicant`'s wildcard, which matches any name, is
/// documented as working for plaintext access points only, and for the same
/// reason.
///
/// Read from `SCAN_RESULTS`, which is what the supplicant last saw. No `SCAN`
/// is issued: a scan takes seconds, interrupts traffic on the radio, and this
/// runs inside an apply. If the access point is not in the last results the
/// honest answer is that netcfgd cannot see it -- with its address in the
/// message, because "network not found" about a network named by address is
/// not a sentence anybody can act on.
///
/// # Errors
///
/// If none of the listed access points is in range, or if they disagree about
/// what the network is called -- which means they are not one network, and
/// joining either under one profile would be netcfgd picking for the operator.
fn resolve_ssid(
	client: &Client,
	network: &WifiNetwork,
) -> Result<netcfgd_model::Ssid, Box<dyn std::error::Error>> {
	let body = client.ask("SCAN_RESULTS")?;
	pick_ssid(network, &protocol::parse_scan_results(&body))
}

/// Which name the listed access points agree on, given what was seen.
///
/// Split from the socket so the choosing can be checked without one: "none of
/// them is in range" and "they are on different networks" are the two answers
/// that matter and neither needs a supplicant to produce.
///
/// # Errors
///
/// If none of the listed access points was seen, or if the ones that were
/// disagree about the network's name.
pub fn pick_ssid(
	network: &WifiNetwork,
	seen: &[protocol::ScanResult],
) -> Result<netcfgd_model::Ssid, Box<dyn std::error::Error>> {
	let mut found: Vec<(&str, &netcfgd_model::Ssid)> = Vec::new();
	for wanted in &network.bssid {
		if let Some(result) = seen
			.iter()
			.find(|result| result.bssid.eq_ignore_ascii_case(wanted))
		{
			found.push((wanted.as_str(), &result.ssid));
		}
	}

	let Some((at_address, advertised)) = found.first().copied() else {
		return Err(Box::new(io::Error::new(
			io::ErrorKind::NotFound,
			format!(
				"none of the access points `{}` names is in range, so its network name \
				 could not be read: {}",
				network.id,
				network.bssid.join(", ")
			),
		)));
	};

	// Every one that *is* in range has to agree. Two addresses advertising
	// different names are two networks, and one passphrase cannot be right for
	// both -- WPA's key is derived per SSID.
	if let Some((elsewhere, differently)) =
		found.iter().find(|(_, name)| *name != advertised).copied()
	{
		return Err(Box::new(io::Error::new(
			io::ErrorKind::InvalidData,
			format!(
				"`{}` lists access points that are on different networks: {at_address} \
				 advertises {} and {elsewhere} advertises {}",
				network.id,
				advertised.to_hex(),
				differently.to_hex()
			),
		)));
	}
	Ok(advertised.clone())
}

///
/// # Errors
///
/// Propagates a control-socket failure, a network `wpa_supplicant` will not
/// take, and -- for a network named by address rather than by name -- a failure
/// to read that name off the last scan.
pub fn add_network(
	client: &Client,
	network: &WifiNetwork,
	policy: netcfgd_model::MacPolicy,
	resolver: &Resolver,
) -> Result<u32, Box<dyn std::error::Error>> {
	// Resolved before anything is sent, so a network whose access points are
	// out of range leaves nothing half-configured behind.
	let learned;
	let network = if network.ssid.is_some() {
		network
	} else {
		let mut copy = network.clone();
		copy.ssid = Some(resolve_ssid(client, network)?);
		learned = copy;
		&learned
	};

	let settings = settings(network, policy, resolver)?;

	let id: u32 = client.ask("ADD_NETWORK")?.trim().parse().map_err(|_| {
		io::Error::new(
			io::ErrorKind::InvalidData,
			"ADD_NETWORK did not answer with a network id",
		)
	})?;

	for setting in &settings {
		if let Err(error) = client.command(&setting.command(id)) {
			// The half-configured network is worse than none: it would sit in
			// the supplicant's list looking like something netcfgd put there
			// on purpose. Remove it before reporting, and report the redacted
			// form -- the failing command may be the one carrying the
			// passphrase.
			let _ = client.command(&format!("REMOVE_NETWORK {id}"));
			return Err(Box::new(io::Error::new(
				io::ErrorKind::InvalidData,
				format!("{} was refused: {error}", setting.redacted(id)),
			)));
		}
	}

	if network.autoconnect {
		client.command(&format!("ENABLE_NETWORK {id}"))?;
	} else {
		// Present but not joined: `ncfg wifi up` selects it later. A network
		// left enabled would be joined the moment it came in range, which is
		// not what `autoconnect = false` asks for.
		client.command(&format!("DISABLE_NETWORK {id}"))?;
	}

	Ok(id)
}
