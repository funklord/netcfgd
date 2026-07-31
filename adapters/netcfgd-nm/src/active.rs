//! `org.freedesktop.NetworkManager.Connection.Active`.
//!
//! An active connection is a pairing: this profile, on this device. It is not
//! stored -- it is derived on every read from what netcfgd observes, the same
//! way everything else here is. A radio associated with a known network is one;
//! an interface that is up and addressed is another.
//!
//! It is also the object that makes a desktop look right. `nmcli device status`
//! fills its CONNECTION column from here, an applet draws its icon from the
//! state, and a settings panel finds its "disconnect" button by looking for one
//! of these on the device.

use crate::enums::active_state;
use crate::state::{Activation, State};
use crate::{device, settings};
use std::sync::Arc;
use zbus::zvariant::OwnedObjectPath;

/// The object path for an active connection number.
#[must_use]
pub(crate) fn path_for(number: u32) -> OwnedObjectPath {
	OwnedObjectPath::try_from(format!(
		"/org/freedesktop/NetworkManager/ActiveConnection/{number}"
	))
	.expect("an active connection path built from a number is always valid")
}

/// One active connection.
pub(crate) struct Active {
	state: Arc<State>,
	activation: Activation,
}

impl Active {
	/// An active connection object for one pairing.
	#[must_use]
	pub(crate) fn new(state: Arc<State>, activation: Activation) -> Self {
		Self { state, activation }
	}

	fn profile(&self) -> Option<settings::Profile> {
		self.state.profile(&self.activation.identity)
	}

	/// Whether this pairing is still one netcfgd reports.
	fn live(&self) -> bool {
		self.state
			.active()
			.iter()
			.any(|other| other == &self.activation)
	}
}

#[zbus::interface(
	name = "org.freedesktop.NetworkManager.Connection.Active",
	introspection_docs = false
)]
impl Active {
	/// The profile this activates.
	#[zbus(property)]
	fn connection(&self) -> OwnedObjectPath {
		self.state
			.profiles()
			.into_iter()
			.find(|(profile, _)| profile.identity() == self.activation.identity)
			.map_or_else(device::no_object, |(_, number)| settings::path_for(number))
	}

	/// The access point, for a wireless activation.
	///
	/// NM calls this the specific object, and it is what a client uses to draw
	/// the signal strength of the network you are actually on rather than of
	/// the strongest one in the list.
	#[zbus(property)]
	fn specific_object(&self) -> OwnedObjectPath {
		self.state
			.associated_number(&self.activation.interface)
			.map_or_else(device::no_object, crate::accesspoint::path_for)
	}

	#[zbus(property)]
	fn id(&self) -> String {
		self.profile()
			.map(|profile| profile.id())
			.unwrap_or_default()
	}

	#[zbus(property)]
	fn uuid(&self) -> String {
		self.profile()
			.map(|profile| settings::uuid_of(&profile))
			.unwrap_or_default()
	}

	#[zbus(property, name = "Type")]
	fn kind(&self) -> String {
		self.profile()
			.map(|profile| profile.kind().to_owned())
			.unwrap_or_default()
	}

	#[zbus(property)]
	fn devices(&self) -> Vec<OwnedObjectPath> {
		self.state
			.devices()
			.into_iter()
			.find(|(name, _)| name == &self.activation.interface)
			.map(|(_, number)| vec![device::path_for(number)])
			.unwrap_or_default()
	}

	#[zbus(property)]
	fn state(&self) -> u32 {
		if self.live() {
			active_state::ACTIVATED
		} else {
			// The object outlives the activation by however long it takes the
			// main loop to unregister it. Saying "deactivating" in that window
			// is truer than claiming it is still up, and it is a state clients
			// already animate.
			active_state::DEACTIVATING
		}
	}

	#[zbus(property)]
	fn state_flags(&self) -> u32 {
		// IS_MASTER is not set, LAYER2_READY and IP4_READY are. netcfgd does
		// not report the two separately, and an activation it reports at all
		// is one that has an address.
		crate::enums::activation_flag::LAYER2_READY | crate::enums::activation_flag::IP4_READY
	}

	/// Whether this carries the default route.
	///
	/// Asked of the observation rather than assumed from the config: an
	/// interface with a default route is the one an applet marks as the
	/// connection you are on, and a machine with two uplinks has an answer
	/// that changes.
	#[zbus(property)]
	fn default(&self) -> bool {
		self.state
			.has_default_route(&self.activation.interface, false)
	}

	#[zbus(property, name = "Default6")]
	fn default6(&self) -> bool {
		self.state
			.has_default_route(&self.activation.interface, true)
	}

	#[zbus(property)]
	fn vpn(&self) -> bool {
		false
	}

	#[zbus(property)]
	fn controller(&self) -> OwnedObjectPath {
		device::no_object()
	}

	/// NM's older spelling of `Controller`, which clients still read.
	#[zbus(property)]
	fn master(&self) -> OwnedObjectPath {
		device::no_object()
	}

	#[zbus(property)]
	fn ip4_config(&self) -> OwnedObjectPath {
		device::no_object()
	}

	#[zbus(property)]
	fn ip6_config(&self) -> OwnedObjectPath {
		device::no_object()
	}

	#[zbus(property)]
	fn dhcp4_config(&self) -> OwnedObjectPath {
		device::no_object()
	}

	#[zbus(property)]
	fn dhcp6_config(&self) -> OwnedObjectPath {
		device::no_object()
	}
}
