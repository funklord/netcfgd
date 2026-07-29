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

#![forbid(unsafe_code)]

pub mod client;
pub mod network;
pub mod protocol;

pub use client::{Client, DEFAULT_CTRL_DIR};
pub use network::{settings, Setting, Unsupported};
pub use protocol::{Event, NetworkEntry, Reply, ScanResult};

use netcfgd_model::WifiNetwork;
use netcfgd_secret::Resolver;
use std::io;

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

/// Add one network and enable it, returning the supplicant's id for it.
///
/// # Errors
///
/// Returns an error if the network cannot be expressed, a secret cannot be
/// resolved, or the supplicant refuses a setting.
pub fn add_network(
	client: &Client,
	network: &WifiNetwork,
	resolver: &Resolver,
) -> Result<u32, Box<dyn std::error::Error>> {
	let settings = settings(network, resolver)?;

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
