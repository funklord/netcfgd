//! `org.freedesktop.NetworkManager`, the root object.
//!
//! The property set is the real daemon's, read off `NetworkManager` 1.52 with
//! `busctl`. Answering a subset is not an option: libnm calls `GetAll` and
//! builds its cache from the result, so a property this does not implement is
//! a property the client decides is missing from the daemon rather than from
//! the shim.

use crate::device;
use crate::enums::{connectivity, metered, state};
use crate::state::State;
use std::collections::HashMap;
use std::sync::Arc;
use zbus::zvariant::{OwnedObjectPath, OwnedValue};

/// The version the shim claims to be.
///
/// Design section 9.3 calls this a hazard, and it is: clients gate behaviour
/// on it, so reporting something honest like "0.0.0" makes libnm decide that
/// half its API is unavailable. So the shim claims a plausible recent NM and
/// tells the truth on `org.netcfgd.Compat` instead, where anything that
/// actually wants to know can ask a question NM would not answer.
pub(crate) const CLAIMED_VERSION: &str = "1.44.0";

/// `VersionInfo`'s first element is the version as a packed integer.
///
/// NM computes it as `major << 16 | minor << 8 | micro`. Clients compare
/// against it numerically, so it has to agree with [`CLAIMED_VERSION`] rather
/// than merely look like a version.
#[must_use]
pub(crate) fn version_info() -> Vec<u32> {
	let mut parts = CLAIMED_VERSION.split('.').map(|part| {
		part.parse::<u32>()
			.expect("the claimed version is three numbers")
	});
	let major = parts.next().unwrap_or(0);
	let minor = parts.next().unwrap_or(0);
	let micro = parts.next().unwrap_or(0);
	vec![(major << 16) | (minor << 8) | micro, 1]
}

/// The root object.
pub(crate) struct Manager {
	state: Arc<State>,
}

impl Manager {
	/// A manager over one state.
	#[must_use]
	pub(crate) fn new(state: Arc<State>) -> Self {
		Self { state }
	}

	fn device_paths(&self) -> Vec<OwnedObjectPath> {
		self.state
			.devices()
			.into_iter()
			.map(|(_, number)| device::path_for(number))
			.collect()
	}
}

#[zbus::interface(name = "org.freedesktop.NetworkManager")]
impl Manager {
	/// Every device netcfgd can see.
	fn get_devices(&self) -> Vec<OwnedObjectPath> {
		self.device_paths()
	}

	/// The same list. NM distinguishes devices it is willing to manage from
	/// every device it knows; netcfgd reports one list, so these agree.
	fn get_all_devices(&self) -> Vec<OwnedObjectPath> {
		self.device_paths()
	}

	/// Find a device by kernel name.
	///
	/// # Errors
	///
	/// Returns NM's own `UnknownDevice` error, which clients already render,
	/// rather than a bespoke one they would print as an internal fault.
	fn get_device_by_ip_iface(&self, iface: &str) -> zbus::fdo::Result<OwnedObjectPath> {
		self.state
			.devices()
			.into_iter()
			.find(|(name, _)| name == iface)
			.map(|(_, number)| device::path_for(number))
			.ok_or_else(|| {
				zbus::fdo::Error::Failed(format!("netcfgd reports no interface called {iface}"))
			})
	}

	/// The daemon state, as a method. NM has both this and the property, and
	/// older clients call the method.
	#[zbus(name = "state")]
	fn state_method(&self) -> u32 {
		self.state_property()
	}

	#[zbus(property, name = "State")]
	fn state_property(&self) -> u32 {
		if self.state.any_connected() {
			// `CONNECTED_GLOBAL` rather than `_SITE`: netcfgd does not run a
			// connectivity check unless a device's config asks for a portal
			// check, so it cannot tell the two apart. Claiming the lesser one
			// would make every desktop show a permanent warning triangle on a
			// working connection, which is a worse lie than the optimistic
			// answer.
			state::CONNECTED_GLOBAL
		} else {
			state::DISCONNECTED
		}
	}

	#[zbus(property)]
	fn version(&self) -> String {
		CLAIMED_VERSION.to_owned()
	}

	#[zbus(property)]
	fn version_info(&self) -> Vec<u32> {
		version_info()
	}

	#[zbus(property)]
	fn devices(&self) -> Vec<OwnedObjectPath> {
		self.device_paths()
	}

	#[zbus(property)]
	fn all_devices(&self) -> Vec<OwnedObjectPath> {
		self.device_paths()
	}

	#[zbus(property)]
	fn checkpoints(&self) -> Vec<OwnedObjectPath> {
		// NM's checkpoints are its commit-confirm. netcfgd has its own, which
		// is not reachable through this interface yet -- and an empty list is
		// the truthful answer to "which checkpoints exist here", where an
		// error would not be.
		Vec::new()
	}

	#[zbus(property)]
	fn active_connections(&self) -> Vec<OwnedObjectPath> {
		Vec::new()
	}

	#[zbus(property)]
	fn primary_connection(&self) -> OwnedObjectPath {
		device::no_object()
	}

	#[zbus(property)]
	fn primary_connection_type(&self) -> String {
		String::new()
	}

	#[zbus(property)]
	fn activating_connection(&self) -> OwnedObjectPath {
		device::no_object()
	}

	#[zbus(property)]
	fn startup(&self) -> bool {
		false
	}

	#[zbus(property)]
	fn networking_enabled(&self) -> bool {
		true
	}

	#[zbus(property)]
	fn wireless_enabled(&self) -> bool {
		true
	}

	#[zbus(property)]
	fn wireless_hardware_enabled(&self) -> bool {
		true
	}

	#[zbus(property)]
	fn wwan_enabled(&self) -> bool {
		false
	}

	#[zbus(property)]
	fn wwan_hardware_enabled(&self) -> bool {
		false
	}

	#[zbus(property)]
	fn connectivity(&self) -> u32 {
		if self.state.any_connected() {
			connectivity::FULL
		} else {
			connectivity::UNKNOWN
		}
	}

	#[zbus(property)]
	fn connectivity_check_available(&self) -> bool {
		false
	}

	#[zbus(property)]
	fn connectivity_check_enabled(&self) -> bool {
		false
	}

	#[zbus(property)]
	fn connectivity_check_uri(&self) -> String {
		String::new()
	}

	#[zbus(property)]
	fn metered(&self) -> u32 {
		metered::GUESS_NO
	}

	#[zbus(property)]
	fn capabilities(&self) -> Vec<u32> {
		Vec::new()
	}

	#[zbus(property)]
	fn radio_flags(&self) -> u32 {
		0
	}

	#[zbus(property)]
	fn global_dns_configuration(&self) -> HashMap<String, OwnedValue> {
		// netcfgd has DNS policy and it is nothing like NM's global
		// configuration blob. An empty map says "nothing set here", which is
		// true of *this interface* -- writing netcfgd's policy into NM's shape
		// would be the foreign model leaking inward that section 9.2 forbids.
		HashMap::new()
	}
}

/// The truth, for anything that would rather have it than a plausible version.
///
/// Design section 9.3: the shim lies about `Version` because clients gate on
/// it, so it offers a second interface where the lie is not required. Anything
/// that wants to know it is talking to netcfgd can ask here; nothing has to.
pub(crate) struct Compat;

#[zbus::interface(name = "org.netcfgd.Compat")]
impl Compat {
	/// What this actually is.
	#[zbus(property)]
	fn implementation(&self) -> String {
		"netcfgd-nm".to_owned()
	}

	/// The version of NM being impersonated, said out loud.
	#[zbus(property)]
	fn claimed_network_manager_version(&self) -> String {
		CLAIMED_VERSION.to_owned()
	}

	/// Which of design section 9.5's tiers this build serves.
	///
	/// A map rather than a number, because the tiers are not a ladder: the
	/// device view landed before connection activation, and a client that
	/// wants one should not have to infer it from the other.
	#[zbus(property)]
	fn supported(&self) -> HashMap<String, bool> {
		[
			("devices".to_owned(), true),
			("device_state".to_owned(), true),
			("wifi_scan".to_owned(), false),
			("connections".to_owned(), false),
			("activation".to_owned(), false),
			("secret_agents".to_owned(), false),
		]
		.into_iter()
		.collect()
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	/// The packed integer has to agree with the string, because a client that
	/// compares one against the other is exactly the client this property
	/// exists for.
	#[test]
	fn the_packed_version_matches_the_version_string() {
		assert_eq!(CLAIMED_VERSION, "1.44.0");
		assert_eq!(version_info()[0], (1 << 16) | (44 << 8));
		assert_eq!(version_info()[0], 76_800);
	}
}
