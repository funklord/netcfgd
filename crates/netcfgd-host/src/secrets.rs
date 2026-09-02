//! The credentials this machine holds, by name and never by value.
//!
//! **One walk of the document, in one place.** `ncfg secret set` reported which
//! blocks refer to a name, and the socket needs the same knowledge inverted --
//! every name and who refers to it. Two walks would be two chances to miss a
//! shape when the model grows one, and the model has grown three since this was
//! written: stored certificates, a wireguard peer's preshared key, and 802.1X
//! on a wired port.
//!
//! Nothing here reads a secret's contents. The store is consulted only for
//! whether a file exists, which is what makes "referenced but not stored" --
//! a network that will never join -- answerable without handling the value.

use netcfgd_proto::SecretEntry;
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

/// Where a credential lives. The same path `ncfg secret set` writes.
fn secret_path(config_dir: &Path, name: &str) -> std::path::PathBuf {
	config_dir.join("secrets").join(name)
}

/// Every credential name, whether the store holds it, and who refers to it.
///
/// The union of two sets rather than either alone, because the interesting
/// faults are opposite ways round. A referenced name with no file is a network
/// that will never join, and it fails at association time with an error about
/// the radio rather than about the missing passphrase. A stored name nothing
/// refers to is a credential still on the machine after whatever wanted it was
/// deleted.
#[must_use]
pub fn list(config_dir: &Path, document: Option<&netcfgd_model::Document>) -> Vec<SecretEntry> {
	let referenced = document.map(references).unwrap_or_default();

	let mut names: BTreeSet<String> = referenced.keys().cloned().collect();
	if let Ok(entries) = std::fs::read_dir(config_dir.join("secrets")) {
		for entry in entries.flatten() {
			// A directory in there is not a secret, and neither is a name that
			// is not text -- `@secret:` cannot spell either.
			if entry.file_type().is_ok_and(|kind| kind.is_file()) {
				if let Some(name) = entry.file_name().to_str() {
					names.insert(name.to_owned());
				}
			}
		}
	}

	names
		.into_iter()
		.map(|name| SecretEntry {
			stored: secret_path(config_dir, &name).is_file(),
			used_by: referenced.get(&name).cloned().unwrap_or_default(),
			name,
		})
		.collect()
}

/// The blocks that refer to one name.
///
/// # Panics
///
/// Never: the map is built by [`references`] and a missing key is an empty
/// list, which is the honest answer for a stored secret nothing uses.
#[must_use]
pub fn referring_to(document: &netcfgd_model::Document, name: &str) -> Vec<String> {
	references(document).remove(name).unwrap_or_default()
}

/// Every `@secret:` reference in a document, by name.
fn references(document: &netcfgd_model::Document) -> BTreeMap<String, Vec<String>> {
	let mut users: BTreeMap<String, Vec<String>> = BTreeMap::new();
	let mut note = |what: &str, reference: &netcfgd_model::SecretRef| {
		users
			.entry(reference.name.clone())
			.or_default()
			.push(what.to_owned());
	};
	// Devices: a WireGuard key belongs to the thing being created (0155).
	for interface in &document.devices {
		if let netcfgd_model::InterfaceKind::WireGuard(wireguard) = &interface.kind {
			note(
				&format!("interface {} (private key)", interface.name),
				&wireguard.private_key,
			);
			for peer in &wireguard.peers {
				if let Some(preshared) = &peer.preshared_key {
					note(
						&format!("interface {} (peer {})", interface.name, peer.name),
						preshared,
					);
				}
			}
		}
		if let netcfgd_model::InterfaceKind::Pppoe(pppoe) = &interface.kind {
			note(&format!("interface {}", interface.name), &pppoe.password);
		}
	}

	for interface in &document.interfaces {
		if let Some(dot1x) = &interface.dot1x {
			if let Some(password) = &dot1x.password {
				note(&format!("interface {} (802.1X)", interface.name), password);
			}
			// Only a *stored* key is a secret this command put there. One
			// given as a path is a file the operator manages, and reporting it
			// as an unused secret would be wrong in both directions -- it is
			// not this store's, and `ncfg secret set` cannot create it.
			if let Some(netcfgd_model::CertSource::Stored(key)) = &dot1x.private_key {
				note(
					&format!("interface {} (802.1X client key)", interface.name),
					key,
				);
			}
		}
	}
	for network in &document.networks {
		match &network.security {
			netcfgd_model::Security::Psk(psk) => {
				note(&format!("network {}", network.id), &psk.passphrase);
			}
			netcfgd_model::Security::Eap(eap) => {
				if let Some(password) = &eap.password {
					note(&format!("network {}", network.id), password);
				}
				if let Some(netcfgd_model::CertSource::Stored(key)) = &eap.private_key {
					note(&format!("network {} (client key)", network.id), key);
				}
				// The certificates too, now that they can be stored content:
				// a client sends `ca_cert = "@secret:corp-ca"` and this is
				// what tells the operator the store has it.
				for (source, what) in [
					(&eap.ca_cert, "CA certificate"),
					(&eap.client_cert, "client certificate"),
				] {
					if let Some(netcfgd_model::CertSource::Stored(reference)) = source {
						note(&format!("network {} ({what})", network.id), reference);
					}
				}
			}
			netcfgd_model::Security::Open | netcfgd_model::Security::Owe => {}
		}
	}
	for found in users.values_mut() {
		found.sort_unstable();
		found.dedup();
	}
	users
}
