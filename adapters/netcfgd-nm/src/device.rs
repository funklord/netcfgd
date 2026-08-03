//! `org.freedesktop.NetworkManager.Device`, and the two per-kind interfaces.
//!
//! One netcfgd link becomes one NM device. The property set is not invented:
//! it was read off a running `NetworkManager` 1.52 with `busctl` and is
//! implemented in full, because libnm fetches all properties of an interface
//! at once and a missing one is not a missing feature to it -- it is a
//! malformed object.
//!
//! Everything here is derived from the observed link. Nothing is stored, and
//! nothing is asked of netcfgd that a plain `ncfg status` would not answer.

use crate::enums::{capability, device_state, device_type, interface_flag, metered, state_reason};
use crate::state::State;
use netcfgd_model::ObservedLink;
use std::sync::Arc;
use zbus::zvariant::OwnedObjectPath;

/// The object path for a device number.
#[must_use]
pub(crate) fn path_for(number: u32) -> OwnedObjectPath {
	OwnedObjectPath::try_from(format!("/org/freedesktop/NetworkManager/Devices/{number}"))
		.expect("a device path built from a number is always valid")
}

/// The path clients use for "there is no object here".
#[must_use]
pub(crate) fn no_object() -> OwnedObjectPath {
	OwnedObjectPath::try_from("/").expect("the root path is valid")
}

/// Whether the kernel calls this interface a radio.
///
/// The same test netcfgd's own executor uses to decide which driver to start a
/// supplicant with: `/sys/class/net/<name>/wireless` exists for a radio and
/// does not for anything else. Cheaper than asking nl80211 and it needs no
/// privilege.
///
/// The fallback rather than the answer: [`crate::state::State::is_radio`] asks
/// the document first. A `device` block with a `wifi` section is netcfgd's own
/// definition of a radio -- it is what makes the planner start a supplicant --
/// and deferring to it means the shim and the daemon cannot disagree about
/// which interfaces are wireless. This covers a radio with no `device` block,
/// which is a machine that has one and has not configured it.
#[must_use]
pub(crate) fn has_sysfs_wireless(interface: &str) -> bool {
	std::path::Path::new("/sys/class/net")
		.join(interface)
		.join("wireless")
		.exists()
}

/// Which flavour of device object one link becomes.
///
/// There are seven, and the reason there are seven rather than a dozen was found
/// by pointing a real `nmcli` at this: **libnm decides what a device is from
/// the interfaces present on the object, not from the `DeviceType` property**.
/// A device carrying only `org.freedesktop.NetworkManager.Device` is not a
/// device with an unknown type -- it is a device libnm does not put in its
/// cache at all, so `nmcli device status` silently omitted five of six.
///
/// So every device gets exactly one per-kind interface, and [`type_of`] agrees
/// with it by construction. A bridge is a `Generic` device whose
/// `TypeDescription` says "bridge" rather than a `Bridge` device, which is
/// NM's own idiom for something it has no special handling for -- and which
/// leaves `.Device.Bridge` free to be implemented properly later without
/// having shipped a device that claims to be one and has none of its
/// properties.
///
/// `WireGuard` is the first kind to leave `Generic` on those terms, and it left
/// only once the properties existed to leave with: NM's
/// `.Device.WireGuard` carries a public key, a listen port and a firewall
/// mark, none of which netcfgd could observe until decision 0054. Claiming the
/// type without them would have been the shipped-a-lie case this paragraph
/// warns about, which is why the constant sat unused in `enums.rs` until now.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Flavour {
	/// The loopback.
	Loopback,
	/// A radio.
	Wireless,
	/// A real NIC that is not a radio.
	Wired,
	/// A `WireGuard` tunnel.
	WireGuard,
	/// A bridge.
	Bridge,
	/// A bond.
	Bond,
	/// Anything else netcfgd can create.
	Generic,
}

/// What flavour a link is.
///
/// `radio` is the caller's answer to "is this wireless", which is a question
/// about the configuration and sysfs rather than about the link -- taking it as
/// an argument is what keeps this a pure function of things a test can supply.
#[must_use]
pub(crate) fn flavour_of(link: &ObservedLink, radio: bool) -> Flavour {
	// Being a radio outranks the link kind, and outranks being called `lo`.
	// That is not a convenience: netcfgd's planner starts a supplicant on any
	// managed device carrying a `wifi` block, whatever the kernel calls the
	// link, so a shim that decided otherwise would show a device as wired
	// while the daemon drove it as wireless. Agreeing with the daemon is worth
	// more than second-guessing the operator.
	if radio {
		return Flavour::Wireless;
	}
	if link.name == "lo" {
		return Flavour::Loopback;
	}
	// An empty kind is what the kernel reports for a device with no rtnetlink
	// link-kind: a real NIC. Which of the two it is does not come from the name
	// -- `eth0` is a convention, not a fact.
	if link.kind.is_empty() {
		return Flavour::Wired;
	}
	// The kernel's own word for the link kind, which is also netcfgd's. Not the
	// presence of `link.wireguard`: that is the observation of a device's
	// contents and it is absent for a device netcfgd has created and not yet
	// configured, so keying on it would move a device between types depending
	// on how far an apply had got.
	// Three kinds have left `Generic`, and each left on the same terms: NM
	// defines an interface for it and netcfgd can answer every property on that
	// interface from what it already observes. A bridge and a bond want a
	// hardware address, a carrier and a list of enslaved devices -- and the
	// observation carries `master` on every link, which is that list read from
	// the other end. Nothing in the core changed to make this possible, which
	// is the test constraint 6 sets for an adapter wanting a concept.
	match link.kind.as_str() {
		"wireguard" => Flavour::WireGuard,
		"bridge" => Flavour::Bridge,
		"bond" => Flavour::Bond,
		_ => Flavour::Generic,
	}
}

/// NM's device type for a netcfgd link.
///
/// Derived from the flavour rather than from the kind, so the number and the
/// interface can never disagree. `GENERIC` rather than `UNKNOWN` for everything
/// else: generic is NM's own word for a real device it has no special handling
/// for, while unknown is what clients draw as a fault.
#[must_use]
pub(crate) fn type_of(link: &ObservedLink, radio: bool) -> u32 {
	match flavour_of(link, radio) {
		Flavour::Loopback => device_type::LOOPBACK,
		Flavour::Wireless => device_type::WIFI,
		Flavour::Wired => device_type::ETHERNET,
		Flavour::WireGuard => device_type::WIREGUARD,
		Flavour::Bridge => device_type::BRIDGE,
		Flavour::Bond => device_type::BOND,
		Flavour::Generic => device_type::GENERIC,
	}
}

/// NM's device state for a netcfgd link.
///
/// Four states out of NM's twelve, and the mapping is deliberately
/// conservative. netcfgd has no notion of "this device is currently being
/// configured": an apply is a plan that runs to completion, so the honest
/// answers are the resting ones.
#[must_use]
pub(crate) fn state_of(link: &ObservedLink, has_address: bool) -> (u32, u32) {
	if !link.up {
		return (device_state::UNAVAILABLE, state_reason::UNKNOWN);
	}
	if !link.carrier {
		return (device_state::UNAVAILABLE, state_reason::CARRIER);
	}
	if has_address {
		(device_state::ACTIVATED, state_reason::NONE)
	} else {
		(device_state::DISCONNECTED, state_reason::NONE)
	}
}

/// One device.
pub(crate) struct Device {
	state: Arc<State>,
	interface: String,
}

impl Device {
	/// A device object for one interface.
	#[must_use]
	pub(crate) fn new(state: Arc<State>, interface: String) -> Self {
		Self { state, interface }
	}

	/// The link as last observed, or a placeholder.
	///
	/// A device whose link has gone is answered rather than errored: the
	/// object is unregistered a moment later, and a client that asked in the
	/// gap gets "unavailable" instead of a D-Bus error it would show the user.
	fn link(&self) -> Option<ObservedLink> {
		self.state.link(&self.interface)
	}
}

#[zbus::interface(
	name = "org.freedesktop.NetworkManager.Device",
	introspection_docs = false
)]
impl Device {
	/// The kernel name.
	#[zbus(property)]
	fn interface(&self) -> String {
		self.interface.clone()
	}

	/// The name IP is configured on, which for netcfgd is always the same one.
	#[zbus(property)]
	fn ip_interface(&self) -> String {
		self.interface.clone()
	}

	/// A unique, stable identifier. NM uses the sysfs path; so does this.
	#[zbus(property)]
	fn udi(&self) -> String {
		format!("/sys/class/net/{}", self.interface)
	}

	/// NM's `Path`, which is the hardware path and not an object path.
	#[zbus(property)]
	fn path(&self) -> String {
		String::new()
	}

	#[zbus(property)]
	fn driver(&self) -> String {
		// Honest rather than invented. netcfgd does not read the driver name,
		// and NM itself answers "unknown" for anything it did not learn from
		// udev -- which is what its own loopback device reports.
		"unknown".to_owned()
	}

	#[zbus(property)]
	fn driver_version(&self) -> String {
		String::new()
	}

	#[zbus(property)]
	fn firmware_version(&self) -> String {
		String::new()
	}

	#[zbus(property)]
	fn device_type(&self) -> u32 {
		self.link().as_ref().map_or(device_type::UNKNOWN, |link| {
			type_of(link, self.state.is_radio(&self.interface))
		})
	}

	#[zbus(property)]
	fn state(&self) -> u32 {
		self.state_reason().0
	}

	#[zbus(property)]
	fn state_reason(&self) -> (u32, u32) {
		// Unmanaged outranks everything, including having an address: the
		// device may well be working, and netcfgd is not the reason. NM's own
		// idiom is that an unmanaged device reports `UNMANAGED` whatever it is
		// doing, so a client shows it and offers nothing.
		if !self.state.is_managed(&self.interface) {
			return (device_state::UNMANAGED, state_reason::NONE);
		}
		let Some(link) = self.link() else {
			return (device_state::UNAVAILABLE, state_reason::UNKNOWN);
		};
		// An activation on this device settles it, whatever the addressing
		// says. A radio associated with a known network is connected even
		// before a lease arrives, and reporting `disconnected` while also
		// reporting an active connection on the same object is a contradiction
		// a client resolves by believing whichever it read second.
		if self
			.state
			.active()
			.iter()
			.any(|activation| activation.interface == self.interface)
		{
			return (device_state::ACTIVATED, state_reason::NONE);
		}
		state_of(&link, self.state.has_address(&self.interface))
	}

	#[zbus(property)]
	fn managed(&self) -> bool {
		self.state.is_managed(&self.interface)
	}

	#[zbus(property)]
	fn autoconnect(&self) -> bool {
		true
	}

	#[zbus(property)]
	fn firmware_missing(&self) -> bool {
		false
	}

	#[zbus(property)]
	fn nm_plugin_missing(&self) -> bool {
		false
	}

	#[zbus(property)]
	fn real(&self) -> bool {
		true
	}

	#[zbus(property)]
	fn mtu(&self) -> u32 {
		self.link().map_or(0, |link| link.mtu)
	}

	#[zbus(property)]
	fn hw_address(&self) -> String {
		self.link()
			.and_then(|link| link.mac)
			.unwrap_or_default()
			.to_uppercase()
	}

	#[zbus(property)]
	fn capabilities(&self) -> u32 {
		let mut flags = capability::NM_SUPPORTED;
		if let Some(link) = self.link() {
			if link.kind.is_empty() {
				flags |= capability::CARRIER_DETECT;
			} else {
				flags |= capability::IS_SOFTWARE;
			}
		}
		flags
	}

	#[zbus(property)]
	fn interface_flags(&self) -> u32 {
		let Some(link) = self.link() else { return 0 };
		let mut flags = 0;
		if link.up {
			flags |= interface_flag::UP;
		}
		if link.carrier {
			flags |= interface_flag::LOWER_UP;
		}
		flags
	}

	#[zbus(property)]
	fn metered(&self) -> u32 {
		metered::UNKNOWN
	}

	#[zbus(property)]
	fn physical_port_id(&self) -> String {
		String::new()
	}

	#[zbus(property)]
	fn ip4_connectivity(&self) -> u32 {
		crate::enums::connectivity::UNKNOWN
	}

	#[zbus(property)]
	fn ip6_connectivity(&self) -> u32 {
		crate::enums::connectivity::UNKNOWN
	}

	/// The addressing this device actually has, in each family.
	///
	/// What a settings panel's "Details" tab reads. These were `/` until the
	/// objects behind them existed, and a panel opened on a working connection
	/// showed nothing at all.
	#[zbus(property)]
	fn ip4_config(&self) -> OwnedObjectPath {
		self.state
			.devices()
			.into_iter()
			.find(|(name, _)| name == &self.interface)
			.map_or_else(no_object, |(_, number)| {
				crate::ipconfig::path_for(number, false)
			})
	}

	#[zbus(property)]
	fn ip6_config(&self) -> OwnedObjectPath {
		self.state
			.devices()
			.into_iter()
			.find(|(name, _)| name == &self.interface)
			.map_or_else(no_object, |(_, number)| {
				crate::ipconfig::path_for(number, true)
			})
	}

	#[zbus(property)]
	fn dhcp4_config(&self) -> OwnedObjectPath {
		no_object()
	}

	#[zbus(property)]
	fn dhcp6_config(&self) -> OwnedObjectPath {
		no_object()
	}

	/// The activation on this device.
	///
	/// What fills `nmcli device status`'s CONNECTION column, and what a
	/// settings panel looks for to decide whether to offer "disconnect".
	#[zbus(property)]
	fn active_connection(&self) -> OwnedObjectPath {
		self.state
			.active()
			.iter()
			.find(|activation| activation.interface == self.interface)
			.map_or_else(no_object, |activation| {
				crate::active::path_for(self.state.active_number(activation))
			})
	}

	/// Profiles that could be activated here.
	///
	/// Every `network` block for a radio, because an SSID may be in range of
	/// any of them; for anything else, the profile that names this interface.
	/// A client uses this to populate the menu of what you could connect to.
	#[zbus(property)]
	fn available_connections(&self) -> Vec<OwnedObjectPath> {
		let radio = self.state.is_radio(&self.interface);
		self.state
			.profiles()
			.into_iter()
			.filter(|(profile, _)| match profile {
				crate::settings::Profile::Network(_) => radio,
				crate::settings::Profile::Interface(interface) => {
					!radio && interface.name == self.interface
				}
			})
			.map(|(_, number)| crate::settings::path_for(number))
			.collect()
	}

	#[zbus(property)]
	fn ports(&self) -> Vec<OwnedObjectPath> {
		Vec::new()
	}

	#[zbus(property)]
	fn lldp_neighbors(&self) -> Vec<std::collections::HashMap<String, zbus::zvariant::OwnedValue>> {
		Vec::new()
	}
}

/// The wired half of a device.
pub(crate) struct Wired {
	state: Arc<State>,
	interface: String,
}

impl Wired {
	/// A wired interface for one device.
	#[must_use]
	pub(crate) fn new(state: Arc<State>, interface: String) -> Self {
		Self { state, interface }
	}
}

#[zbus::interface(
	name = "org.freedesktop.NetworkManager.Device.Wired",
	introspection_docs = false
)]
impl Wired {
	#[zbus(property)]
	fn hw_address(&self) -> String {
		self.state
			.link(&self.interface)
			.and_then(|link| link.mac)
			.unwrap_or_default()
			.to_uppercase()
	}

	#[zbus(property)]
	fn perm_hw_address(&self) -> String {
		self.hw_address()
	}

	#[zbus(property)]
	fn carrier(&self) -> bool {
		self.state
			.link(&self.interface)
			.is_some_and(|link| link.carrier)
	}

	#[zbus(property)]
	fn speed(&self) -> u32 {
		// netcfgd reads link modes only where the ethtool block asks it to,
		// and does not apply them (the offloads are a different message). Zero
		// is NM's answer for a speed it does not know, not an assertion that
		// the link is idle.
		0
	}

	#[zbus(property)]
	fn s390_subchannels(&self) -> Vec<String> {
		Vec::new()
	}
}

/// The loopback marker.
///
/// No properties at all, which is not an omission -- the real daemon's
/// `.Device.Loopback` has none either. Its whole job is to exist, so that a
/// client knows which of NM's device classes to build.
pub(crate) struct Loopback;

#[zbus::interface(
	name = "org.freedesktop.NetworkManager.Device.Loopback",
	introspection_docs = false
)]
impl Loopback {}

/// Anything netcfgd can create that NM has no specific class for.
pub(crate) struct Generic {
	state: Arc<State>,
	interface: String,
}

impl Generic {
	/// A generic interface for one device.
	#[must_use]
	pub(crate) fn new(state: Arc<State>, interface: String) -> Self {
		Self { state, interface }
	}
}

#[zbus::interface(
	name = "org.freedesktop.NetworkManager.Device.Generic",
	introspection_docs = false
)]
impl Generic {
	#[zbus(property)]
	fn hw_address(&self) -> String {
		self.state
			.link(&self.interface)
			.and_then(|link| link.mac)
			.unwrap_or_default()
			.to_uppercase()
	}

	/// What this actually is, in netcfgd's own vocabulary.
	///
	/// NM puts a short noun here and clients display it verbatim, so a bridge
	/// reads as "bridge" and a WireGuard interface as "wireguard". That is the
	/// netcfgd link kind unchanged, which is the honest answer and happens to
	/// be the one a user of both tools would recognise.
	#[zbus(property)]
	fn type_description(&self) -> String {
		self.state
			.link(&self.interface)
			.map(|link| link.kind)
			.unwrap_or_default()
	}
}

/// What is enslaved to one master, as object paths.
///
/// Read from the other end: netcfgd observes `master` on each link, which is
/// the kernel's own answer, and this inverts it. A device NM has not numbered
/// yet is left out rather than given a guessed path -- a client that follows an
/// object path expects to find something there.
fn slaves_of(state: &State, master: &str) -> Vec<zbus::zvariant::OwnedObjectPath> {
	let numbers = state.devices();
	state
		.links()
		.into_iter()
		.filter(|link| link.master.as_deref() == Some(master))
		.filter_map(|link| {
			numbers
				.iter()
				.find(|(name, _)| *name == link.name)
				.map(|(_, number)| path_for(*number))
		})
		.collect()
}

/// The bridge half of a device.
///
/// Three properties, which is what NM defines for one, and every one of them is
/// something netcfgd already observes. A bridge that claims the type and cannot
/// list what is on it is the case the `Flavour` comment above warns about.
pub(crate) struct Bridge {
	state: Arc<State>,
	interface: String,
}

impl Bridge {
	/// A bridge interface for one device.
	#[must_use]
	pub(crate) fn new(state: Arc<State>, interface: String) -> Self {
		Self { state, interface }
	}
}

#[zbus::interface(
	name = "org.freedesktop.NetworkManager.Device.Bridge",
	introspection_docs = false
)]
impl Bridge {
	#[zbus(property)]
	fn hw_address(&self) -> String {
		self.state
			.link(&self.interface)
			.and_then(|link| link.mac)
			.unwrap_or_default()
			.to_uppercase()
	}

	/// Whether the bridge itself has carrier.
	///
	/// The kernel gives a bridge carrier when a port has it, so this is the
	/// observation unchanged rather than something summed up here.
	#[zbus(property)]
	fn carrier(&self) -> bool {
		self.state
			.link(&self.interface)
			.is_some_and(|link| link.carrier)
	}

	/// The devices enslaved to it.
	#[zbus(property)]
	fn slaves(&self) -> Vec<zbus::zvariant::OwnedObjectPath> {
		slaves_of(&self.state, &self.interface)
	}
}

/// The bond half of a device.
///
/// The same three properties as a bridge, and NM defines them on a separate
/// interface rather than sharing one -- so this is a separate type saying the
/// same things, which is what the wire wants.
pub(crate) struct Bond {
	state: Arc<State>,
	interface: String,
}

impl Bond {
	/// A bond interface for one device.
	#[must_use]
	pub(crate) fn new(state: Arc<State>, interface: String) -> Self {
		Self { state, interface }
	}
}

#[zbus::interface(
	name = "org.freedesktop.NetworkManager.Device.Bond",
	introspection_docs = false
)]
impl Bond {
	#[zbus(property)]
	fn hw_address(&self) -> String {
		self.state
			.link(&self.interface)
			.and_then(|link| link.mac)
			.unwrap_or_default()
			.to_uppercase()
	}

	#[zbus(property)]
	fn carrier(&self) -> bool {
		self.state
			.link(&self.interface)
			.is_some_and(|link| link.carrier)
	}

	#[zbus(property)]
	fn slaves(&self) -> Vec<zbus::zvariant::OwnedObjectPath> {
		slaves_of(&self.state, &self.interface)
	}
}

/// The `WireGuard` half of a device.
///
/// Three properties, which is all NM defines for one. They are the device's
/// own configuration rather than its peers: NM has no peer list on the device
/// interface at all -- peers live in a connection profile there -- so this is
/// the whole of what a client can ask about a running tunnel.
pub(crate) struct WireGuard {
	state: Arc<State>,
	interface: String,
}

impl WireGuard {
	/// A `WireGuard` interface for one device.
	#[must_use]
	pub(crate) fn new(state: Arc<State>, interface: String) -> Self {
		Self { state, interface }
	}

	/// What the observation says this device holds, if anything.
	fn observed(&self) -> Option<netcfgd_model::ObservedWireGuard> {
		self.state
			.link(&self.interface)
			.and_then(|link| link.wireguard)
	}
}

#[zbus::interface(
	name = "org.freedesktop.NetworkManager.Device.WireGuard",
	introspection_docs = false
)]
impl WireGuard {
	/// The device's public key, as octets.
	///
	/// NM types this `ay` and means the raw key, not its base64 spelling --
	/// libnm hands it to `nm_utils_base64secret_...` shaped helpers for
	/// display. Empty where netcfgd could not read one, which is a device with
	/// no private key loaded: a tunnel that has been created and not
	/// configured, and not a value to invent.
	///
	/// A public key is not a secret. It is the thing an operator hands the
	/// other end, and decision 0029's rule about secrets not travelling is
	/// about the private one -- which is in neither the observation nor the
	/// document, so there is nothing here to leak.
	#[zbus(property)]
	fn public_key(&self) -> Vec<u8> {
		self.observed()
			.and_then(|state| state.public_key)
			.map(|key| key.as_bytes().to_vec())
			.unwrap_or_default()
	}

	/// The UDP port it listens on, or zero.
	///
	/// Zero is NM's own spelling for "none" here, and it is also the kernel's:
	/// a device with an ephemeral port reports the port it was given, and one
	/// that has not been configured reports nothing at all.
	#[zbus(property)]
	fn listen_port(&self) -> u16 {
		self.observed()
			.and_then(|state| state.listen_port)
			.unwrap_or_default()
	}

	/// The firewall mark on outgoing packets, or zero for none.
	#[zbus(property)]
	fn fw_mark(&self) -> u32 {
		self.observed()
			.and_then(|state| state.fwmark)
			.unwrap_or_default()
	}
}

/// The wireless half of a device.
pub(crate) struct Wireless {
	state: Arc<State>,
	interface: String,
}

impl Wireless {
	/// A wireless interface for one device.
	#[must_use]
	pub(crate) fn new(state: Arc<State>, interface: String) -> Self {
		Self { state, interface }
	}
}

#[zbus::interface(
	name = "org.freedesktop.NetworkManager.Device.Wireless",
	introspection_docs = false
)]
impl Wireless {
	#[zbus(property)]
	fn hw_address(&self) -> String {
		self.state
			.link(&self.interface)
			.and_then(|link| link.mac)
			.unwrap_or_default()
			.to_uppercase()
	}

	#[zbus(property)]
	fn perm_hw_address(&self) -> String {
		self.hw_address()
	}

	#[zbus(property)]
	fn mode(&self) -> u32 {
		// Infrastructure: a station on somebody else's network. An
		// `access_point` block would make this `AP`, and saying so needs the
		// document rather than the observation -- which is the next commit's
		// work, not a guess this one should make.
		crate::enums::wifi_mode::INFRA
	}

	#[zbus(property)]
	fn bitrate(&self) -> u32 {
		0
	}

	/// What the radio can negotiate.
	///
	/// Not zero, and the difference matters more than it looks: libnm checks
	/// this before it will even offer a profile, so a radio reporting nothing
	/// makes every secured network "not compatible with the device" and the
	/// activation never reaches netcfgd at all. That is what `nmcli connection
	/// up` said until this was written.
	///
	/// netcfgd cannot ask the radio what it supports -- it delegates to
	/// `wpa_supplicant` and does not speak nl80211's capability dump -- so this
	/// is what any radio a supplicant will drive can do: both cipher suites,
	/// both WPA generations, and both bands. A card too old for RSN would be
	/// described generously here and fail at association with the supplicant's
	/// own message, which is a better failure than being invisible.
	#[zbus(property)]
	fn wireless_capabilities(&self) -> u32 {
		use crate::enums::wifi_capability as capability;
		capability::CIPHER_TKIP
			| capability::CIPHER_CCMP
			| capability::WPA
			| capability::RSN
			| capability::AP
			| capability::FREQ_VALID
			| capability::FREQ_2GHZ
			| capability::FREQ_5GHZ
	}

	/// When the last scan finished, in `CLOCK_BOOTTIME` milliseconds.
	///
	/// Milliseconds here and seconds on an access point's `LastSeen`, which is
	/// not a mistake to tidy up: NM defines the two properties on different
	/// units, clients divide accordingly, and being consistent with ourselves
	/// would be inconsistent with every reader.
	///
	/// -1 means never, which is what a radio reports until something asks it to
	/// scan.
	#[zbus(property)]
	fn last_scan(&self) -> i64 {
		self.state
			.last_scan_seconds(&self.interface)
			.map_or(-1, |seconds| i64::from(seconds) * 1000)
	}

	#[zbus(property)]
	fn access_points(&self) -> Vec<OwnedObjectPath> {
		self.state
			.access_points(&self.interface)
			.into_iter()
			.map(|(_, number)| crate::accesspoint::path_for(number))
			.collect()
	}

	#[zbus(property)]
	fn active_access_point(&self) -> OwnedObjectPath {
		self.state
			.associated_number(&self.interface)
			.map_or_else(no_object, crate::accesspoint::path_for)
	}

	/// Every access point this radio can see.
	fn get_all_access_points(&self) -> Vec<OwnedObjectPath> {
		self.access_points()
	}

	/// The deprecated spelling, which `nm-applet` still calls on older paths.
	fn get_access_points(&self) -> Vec<OwnedObjectPath> {
		self.access_points()
	}

	/// Scan, now.
	///
	/// The one method here that makes the radio do something, which is why
	/// nothing else triggers a scan: NM clients call this when a menu opens,
	/// and a shim that scanned on a timer would keep a radio busy for nobody.
	///
	/// The options dictionary is accepted and ignored. NM uses it to carry a
	/// list of SSIDs to probe for, which is how hidden networks are found;
	/// netcfgd's socket takes no such argument, and inventing one for this
	/// would be the adapter shaping the core that constraint 6 forbids.
	///
	/// # Errors
	///
	/// Returns netcfgd's own message. "No supplicant is running on wlan0" is
	/// the useful half of a failed scan, and passing it through means the
	/// applet shows it.
	// The macro generates a reference to the argument whether it is used or
	// not, so an underscore name is both required and complained about.
	#[allow(clippy::used_underscore_binding)]
	fn request_scan(
		&self,
		options: std::collections::HashMap<String, zbus::zvariant::Value<'_>>,
	) -> zbus::fdo::Result<()> {
		// Accepted and dropped, deliberately and visibly. An underscore name
		// would say the same thing less loudly, and the interface macro
		// references the binding either way.
		drop(options);
		self.state
			.request_scan(&self.interface)
			.map_err(zbus::fdo::Error::Failed)
	}

	/// An access point came into range.
	///
	/// libnm keeps its own list and updates it from these rather than re-reading
	/// the property, so an applet whose menu is open while a scan completes
	/// depends on this to show what arrived.
	#[zbus(signal)]
	pub(crate) async fn access_point_added(
		emitter: &zbus::object_server::SignalEmitter<'_>,
		access_point: zbus::zvariant::ObjectPath<'_>,
	) -> zbus::Result<()>;

	/// And went out of it.
	#[zbus(signal)]
	pub(crate) async fn access_point_removed(
		emitter: &zbus::object_server::SignalEmitter<'_>,
		access_point: zbus::zvariant::ObjectPath<'_>,
	) -> zbus::Result<()>;
}

#[cfg(test)]
mod tests {
	use super::*;

	fn link(name: &str, kind: &str) -> ObservedLink {
		ObservedLink {
			name: name.to_owned(),
			index: 2,
			kind: kind.to_owned(),
			up: true,
			carrier: true,
			mtu: 1500,
			mac: Some("aa:bb:cc:dd:ee:ff".to_owned()),
			master: None,
			parent: None,
			offloads: Vec::new(),
			ipv6_token: None,
			qdisc: None,
			qdisc_bandwidth_bits: None,
			qdisc_ingress: false,
			ingress_redirect: None,
			forwarding: None,
			ownership: netcfgd_model::Ownership::Unknown,
			private_key_loaded: false,
			wireguard: None,
			bond: None,
			bridge: None,
			macvlan: None,
			vlan: None,
			tunnel: None,
			vxlan: None,
		}
	}

	/// The loopback is the one device identified by name rather than by kind:
	/// the kernel gives it no link kind, so it is otherwise indistinguishable
	/// from a NIC.
	#[test]
	fn the_loopback_is_a_loopback_and_not_an_ethernet() {
		assert_eq!(flavour_of(&link("lo", ""), false), Flavour::Loopback);
		assert_eq!(type_of(&link("lo", ""), false), 32);
	}

	/// A `device` block with a `wifi` section makes a radio, whatever the
	/// kernel calls the link. That is what netcfgd's planner does -- it starts
	/// a supplicant on any managed device with that block -- and a shim
	/// disagreeing would show a device as wired while the daemon drove it as
	/// wireless.
	#[test]
	fn the_configuration_decides_what_is_a_radio() {
		assert_eq!(flavour_of(&link("wlan0", ""), true), Flavour::Wireless);
		assert_eq!(type_of(&link("wlan0", ""), true), 2);
		// Including over a link kind, which is how a test without a radio
		// arranges to have one.
		assert_eq!(
			flavour_of(&link("probe0", "dummy"), true),
			Flavour::Wireless
		);
		assert_eq!(
			flavour_of(&link("probe0", "dummy"), false),
			Flavour::Generic
		);
	}

	/// Everything with a link kind is generic, and specifically not `UNKNOWN`.
	///
	/// `GENERIC` is NM's word for a real device it has no special handling
	/// for; `UNKNOWN` is what an applet draws as broken. netcfgd has kinds NM
	/// has never heard of -- `ifb` is one -- and they are not broken devices.
	#[test]
	fn everything_with_a_link_kind_is_generic_rather_than_unknown() {
		for kind in ["vlan", "vxlan", "gre", "ifb", "dummy", "veth"] {
			assert_eq!(
				flavour_of(&link("x0", kind), false),
				Flavour::Generic,
				"for kind {kind}"
			);
			assert_eq!(type_of(&link("x0", kind), false), 14, "for kind {kind}");
		}
	}

	/// A `WireGuard` device is the one kind that has left `Generic`.
	///
	/// It left because the properties existed to leave with (decision 0054);
	/// until the observation carried a public key, a listen port and a firewall
	/// mark, claiming the type would have shipped a device that says what it is
	/// and cannot answer a single question about itself.
	#[test]
	fn a_wireguard_link_is_a_wireguard_device() {
		assert_eq!(
			flavour_of(&link("wg0", "wireguard"), false),
			Flavour::WireGuard
		);
		assert_eq!(type_of(&link("wg0", "wireguard"), false), 29);
		// And a radio still outranks it, for the reason every other kind does:
		// agreeing with the daemon about what it is driving is worth more than
		// second-guessing the operator.
		assert_eq!(
			flavour_of(&link("wg0", "wireguard"), true),
			Flavour::Wireless
		);
	}

	/// A bridge and a bond are themselves, on the same terms `WireGuard` left on.
	///
	/// Every property NM defines for either is something netcfgd already
	/// observes -- a hardware address, a carrier, and the enslaved devices,
	/// which is the `master` field on every other link read from the other end.
	/// Nothing in the core changed to make this possible, which is the test
	/// constraint 6 sets for an adapter that wants a concept.
	#[test]
	fn a_bridge_and_a_bond_are_themselves() {
		assert_eq!(flavour_of(&link("br0", "bridge"), false), Flavour::Bridge);
		assert_eq!(type_of(&link("br0", "bridge"), false), 13);
		assert_eq!(flavour_of(&link("bond0", "bond"), false), Flavour::Bond);
		assert_eq!(type_of(&link("bond0", "bond"), false), 10);
	}

	/// The type and the interface are derived from one answer, because libnm
	/// reads the interface list and `nmcli` prints the type, and a device that
	/// says `bridge` while carrying `.Device.Generic` is a device those two
	/// disagree about.
	#[test]
	fn the_type_number_always_agrees_with_the_flavour() {
		for (kind, flavour, number) in [
			("bridge", Flavour::Bridge, 13),
			("dummy", Flavour::Generic, 14),
			("", Flavour::Wired, 1),
		] {
			let link = link("probe0", kind);
			assert_eq!(flavour_of(&link, false), flavour);
			assert_eq!(type_of(&link, false), number);
		}
	}

	#[test]
	fn a_link_that_is_down_is_unavailable_whatever_else_is_true() {
		let mut down = link("eth0", "");
		down.up = false;
		assert_eq!(state_of(&down, true).0, device_state::UNAVAILABLE);
	}

	/// No cable is a different answer from no address, and the reason field is
	/// where the difference shows up. An applet renders "cable unplugged" from
	/// it.
	#[test]
	fn a_link_with_no_carrier_says_so_in_the_reason() {
		let mut unplugged = link("eth0", "");
		unplugged.carrier = false;
		assert_eq!(
			state_of(&unplugged, false),
			(device_state::UNAVAILABLE, state_reason::CARRIER)
		);
		assert_eq!(
			state_of(&link("eth0", ""), false),
			(device_state::DISCONNECTED, state_reason::NONE)
		);
		assert_eq!(
			state_of(&link("eth0", ""), true),
			(device_state::ACTIVATED, state_reason::NONE)
		);
	}
}
