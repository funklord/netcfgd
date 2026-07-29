//! Per-device policy: what netcfgd may touch, and how a radio behaves.

use serde::{Deserialize, Serialize};

/// How a device is identified.
///
/// Every present field must match. Matching is preferred over naming because a
/// name is assigned by the kernel and can move between boots, while a MAC or a
/// PCI path does not.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct DeviceMatch {
	/// Hardware address.
	#[serde(skip_serializing_if = "Option::is_none")]
	pub mac: Option<String>,
	/// Bus path, for example `pci-0000:03:00.0`.
	#[serde(skip_serializing_if = "Option::is_none")]
	pub path: Option<String>,
	/// Driver name.
	#[serde(skip_serializing_if = "Option::is_none")]
	pub driver: Option<String>,
	/// Glob against the kernel name.
	#[serde(skip_serializing_if = "Option::is_none")]
	pub name_glob: Option<String>,
}

/// Which supplicant drives a radio.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WifiBackend {
	/// Prefer iwd where present.
	#[default]
	Auto,
	/// iwd.
	Iwd,
	/// `wpa_supplicant`. Wired 802.1X always uses this one, since iwd has no
	/// wired driver.
	WpaSupplicant,
}

/// Radio power saving.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Powersave {
	/// Leave the driver's default alone.
	#[default]
	Default,
	/// Force on.
	On,
	/// Force off.
	Off,
}

/// Policy for a wifi device, as distinct from a network profile.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct WifiDevicePolicy {
	/// Which supplicant.
	pub backend: WifiBackend,
	/// Whether to connect to known networks without being asked.
	pub autoconnect: bool,
	/// Whether to probe for a captive portal after association.
	pub portal_check: bool,
	/// Regulatory domain, ISO 3166-1 alpha-2.
	#[serde(skip_serializing_if = "Option::is_none")]
	pub regdom: Option<String>,
	/// Power saving.
	pub powersave: Powersave,
	/// What hardware address this radio presents.
	#[serde(default)]
	pub mac_policy: MacPolicy,
	/// Whether to randomise the address used while scanning.
	///
	/// Separate from [`WifiDevicePolicy::mac_policy`] because it is a
	/// different exposure: scanning broadcasts probe requests to everyone in
	/// range, whether or not anything is ever joined. A device that randomises
	/// on association and not on scan is trackable by a passive listener in a
	/// cafe it never connected to.
	#[serde(default)]
	pub scan_randomization: bool,
}

impl Default for WifiDevicePolicy {
	fn default() -> Self {
		Self {
			backend: WifiBackend::Auto,
			autoconnect: true,
			portal_check: false,
			regdom: None,
			powersave: Powersave::Default,
			mac_policy: MacPolicy::Permanent,
			scan_randomization: false,
		}
	}
}

/// A device netcfgd knows about.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Device {
	/// Kernel name, for example `wlan0`.
	pub name: String,
	/// How to recognise it, where the name alone is not enough.
	#[serde(skip_serializing_if = "Option::is_none", default)]
	pub r#match: Option<DeviceMatch>,
	/// When false, netcfgd never touches this device at all.
	#[serde(default = "crate::default_true")]
	pub managed: bool,
	/// Radio policy, for wifi devices.
	#[serde(skip_serializing_if = "Option::is_none", default)]
	pub wifi: Option<WifiDevicePolicy>,
}

/// What hardware address a radio presents.
///
/// A wifi client that always uses its permanent address is trackable across
/// every network it has ever joined, by anyone who has seen it twice. Every
/// other supplicant grew a way to change that; netcfgd could not express it,
/// which meant the answer was "whatever the supplicant's default happens to
/// be" -- and that is a privacy property nobody chose.
///
/// The three values are named for what they do rather than for what a
/// particular supplicant calls them, and the mapping is written down where it
/// is applied rather than implied here.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MacPolicy {
	/// The hardware address. Trackable, and sometimes required -- a network
	/// with MAC-based admission control is the usual reason.
	#[default]
	Permanent,
	/// A fresh address for each network joined, kept for the duration of the
	/// association.
	///
	/// The useful middle: an access point sees one consistent client for the
	/// length of a session, and two networks cannot correlate their visitors.
	PerNetwork,
	/// A fresh address for every association, including reconnecting to the
	/// same network.
	///
	/// Strongest, and it breaks anything that recognises a returning client:
	/// DHCP reservations, captive portal sessions, MAC-based admission.
	PerConnection,
}

impl MacPolicy {
	/// The name as the config spells it.
	#[must_use]
	pub fn name(self) -> &'static str {
		match self {
			Self::Permanent => "permanent",
			Self::PerNetwork => "per_network",
			Self::PerConnection => "per_connection",
		}
	}
}

/// An access point netcfgd runs, rather than joins.
///
/// Bound to a device, unlike [`crate::WifiNetwork`], which deliberately is
/// not: a station profile describes a network that may be in range of any
/// radio, while an access point is a thing one specific radio is doing.
///
/// Nothing implements this yet. It is in the schema because the model freezes
/// at M4 and adding it afterwards is a major version bump -- the same reason
/// `BackendKind::Builtin` is there (project.md section 8, row 4). A config
/// asking for one is refused by name, with the milestone.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AccessPoint {
	/// Handle for this access point. Sorting key.
	pub id: String,
	/// The network name to broadcast.
	pub ssid: crate::Ssid,
	/// Which radio runs it.
	pub device: String,
	/// How stations authenticate.
	///
	/// The same type as a station profile's, and not every variant makes
	/// sense here -- an access point cannot be `Owe` transition-mode without
	/// a second BSS, and `Eap` means pointing at a RADIUS server rather than
	/// holding a credential. Validation belongs with the implementation,
	/// which does not exist, so the type stays wide rather than pretending to
	/// a precision nothing enforces yet.
	pub security: crate::Security,
	/// Channel to operate on. Absent means the implementation chooses.
	#[serde(skip_serializing_if = "Option::is_none", default)]
	pub channel: Option<u16>,
	/// Band, where the channel number alone is ambiguous.
	#[serde(skip_serializing_if = "Option::is_none", default)]
	pub band: Option<String>,
	/// Whether to suppress the SSID in beacons.
	///
	/// Not a security measure and not documented as one: it stops the network
	/// appearing in a list and makes every client that knows it broadcast the
	/// name while probing, which is worse than the problem.
	#[serde(default)]
	pub hidden: bool,
	/// Country code the access point advertises.
	#[serde(skip_serializing_if = "Option::is_none", default)]
	pub regdom: Option<String>,
}
