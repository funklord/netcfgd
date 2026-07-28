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
}

impl Default for WifiDevicePolicy {
	fn default() -> Self {
		Self {
			backend: WifiBackend::Auto,
			autoconnect: true,
			portal_check: false,
			regdom: None,
			powersave: Powersave::Default,
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
