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
	/// The URL to fetch to find out whether something is intercepting traffic.
	///
	/// **The operator's URL, never netcfgd's.** 0061 refused a boolean with a
	/// default inside netcfgd, and the reason has not changed: a network daemon
	/// that reaches out to a fixed address to decide whether the internet works
	/// is a third party learning when this machine joins a network, and that is
	/// the wrong default however carefully the address is chosen. `None` -- the
	/// ordinary case -- probes nothing at all.
	///
	/// **`http://` only, and that is not a limitation.** A captive portal works
	/// by intercepting a request and answering it with something else, which
	/// TLS exists to prevent: over `https` a portal produces a certificate
	/// error rather than a redirect, and a check that cannot be intercepted
	/// cannot detect interception. Every implementation of this does it in
	/// clear for the same reason. An `https` URL is refused with that sentence
	/// rather than accepted and quietly useless (0095).
	#[serde(skip_serializing_if = "Option::is_none")]
	pub portal_check: Option<String>,
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
			portal_check: None,
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
	///
	/// Enforced at the planner's action choke point (decision 0035). Before
	/// that it was honoured only by the filter deciding which devices are
	/// radios, so the flag read as documentation rather than as a control.
	#[serde(default = "crate::default_true")]
	pub managed: bool,
	/// What to do on the way out of being managed.
	#[serde(default)]
	pub on_unmanage: OnUnmanage,
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

/// What netcfgd does with a device it is about to stop managing.
///
/// A policy rather than an action, so it can sit in the configuration while the
/// device is still managed and mean "if you ever stop, do this". That also
/// keeps it a *state*: `Clear` says the desired state of the device is that
/// netcfgd owns nothing on it, which the planner reaches and then stops,
/// without any edge-triggered machinery to get wrong.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OnUnmanage {
	/// Walk away and change nothing.
	///
	/// The right answer when handing an interface to another daemon: you set
	/// `managed = false` because something else is taking over, and having
	/// netcfgd pull the addresses out on its way past is the failure the flag
	/// exists to prevent.
	#[default]
	Leave,
	/// Remove everything netcfgd owns first, then walk away.
	///
	/// The right answer when the hardware is leaving your hands, because
	/// walking away otherwise strands credentials: a `WireGuard` key stays
	/// loaded in the kernel, a supplicant keeps its passphrases, and a running
	/// hostapd keeps its generated configuration.
	///
	/// Defined by ownership rather than by content, which is what lets one
	/// rule apply to every device: it removes objects carrying netcfgd's tag
	/// and stops backends netcfgd started, and touches nothing else. Whoever
	/// takes the device over keeps their own configuration.
	Clear,
}

/// An access point netcfgd runs, rather than joins.
///
/// Bound to a device, unlike [`crate::WifiNetwork`], which deliberately is
/// not: a station profile describes a network that may be in range of any
/// radio, while an access point is a thing one specific radio is doing.
///
/// Rendered to a `hostapd` configuration by `netcfgd-hostapd` (decision
/// 0026). It was in the schema for a milestone before anything implemented it,
/// because the model freezes at M4 and adding it afterwards is a major version
/// bump -- the same reason `BackendKind::Builtin` is there (project.md section
/// 8, row 4).
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
	/// Which stations this access point will talk to at all.
	///
	/// Absent means everyone, which is what an access point without an
	/// `access_control` block does.
	#[serde(skip_serializing_if = "Option::is_none", default)]
	pub access_control: Option<AccessControl>,
}

/// A station list, and which way to read it.
///
/// This is the single-host half of Ubiquiti-style roaming (decision 0036).
/// Forcing a client onto one access point is done by making every *other*
/// access point refuse it, so the operation that matters is per-station and
/// per-AP, and the decision about which AP owns a station is coordination
/// between machines -- section 11's territory, not this.
///
/// One list rather than two, because hostapd has one: `macaddr_acl` selects
/// *either* `accept_mac_file` or `deny_mac_file`, and a configuration naming
/// both would have half of it silently ignored.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AccessControl {
	/// Whether the stations are the only ones allowed, or the only ones
	/// refused.
	pub policy: AclPolicy,
	/// The stations, lowercase `aa:bb:cc:dd:ee:ff`, sorted and deduplicated.
	///
	/// Normalised at compile time so that two documents meaning the same thing
	/// hash the same, and so that comparing against what hostapd reports over
	/// its control socket is a string comparison rather than a parse.
	pub stations: Vec<String>,
}

/// Which way an [`AccessControl`] list reads.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AclPolicy {
	/// Everyone except the listed stations. `macaddr_acl=0`.
	///
	/// The one Zero Handoff uses: a station is denied everywhere except the
	/// access point meant to serve it.
	Deny,
	/// Only the listed stations. `macaddr_acl=1`.
	///
	/// Note what this is not. A MAC address is asserted by the station and
	/// changed with one command, so this keeps honest devices off a network
	/// and stops nobody who does not want to be stopped. It is a policy
	/// mechanism, not a security one, and anything that must be secure belongs
	/// in `wifi { .. }` where the key material is.
	Allow,
}

impl AclPolicy {
	/// The value hostapd's `macaddr_acl` takes for this policy.
	#[must_use]
	pub fn macaddr_acl(self) -> &'static str {
		match self {
			Self::Deny => "0",
			Self::Allow => "1",
		}
	}

	/// The control-socket command prefix that edits this list at runtime.
	#[must_use]
	pub fn ctrl_command(self) -> &'static str {
		match self {
			Self::Deny => "DENY_ACL",
			Self::Allow => "ACCEPT_ACL",
		}
	}
}

/// Parse and normalise one station address.
///
/// Accepts the two spellings people actually write -- `aa:bb:cc:dd:ee:ff` and
/// `aa-bb-cc-dd-ee-ff`, in either case -- and produces the lowercase colon
/// form, which is what hostapd prints and therefore what a comparison against
/// its live list has to be in. Bare `aabbccddeeff` is refused: it is one
/// transposition away from being unreadable, and an ACL is the wrong place to
/// guess.
///
/// # Errors
///
/// Returns the reason the text is not a station address, phrased for an
/// operator reading a diagnostic.
pub fn normalize_station(text: &str) -> Result<String, String> {
	let separator = if text.contains('-') { '-' } else { ':' };
	let parts: Vec<&str> = text.split(separator).collect();
	if parts.len() != 6 {
		return Err(format!(
			"a station address is six colon-separated octets, such as \
			 `aa:bb:cc:dd:ee:ff`; `{text}` has {}",
			parts.len()
		));
	}
	let mut out = String::with_capacity(17);
	for (index, part) in parts.iter().enumerate() {
		if part.len() != 2 || !part.bytes().all(|byte| byte.is_ascii_hexdigit()) {
			return Err(format!(
				"`{part}` is not a two-digit hex octet, in the station address `{text}`"
			));
		}
		if index > 0 {
			out.push(':');
		}
		out.push_str(&part.to_ascii_lowercase());
	}
	Ok(out)
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn a_station_address_normalises_to_lowercase_colons() {
		// Both spellings and both cases reach the one form hostapd prints, so
		// that comparing the document against a live list is string equality.
		for text in [
			"aa:bb:cc:dd:ee:ff",
			"AA:BB:CC:DD:EE:FF",
			"aa-bb-cc-dd-ee-ff",
			"AA-BB-CC-DD-EE-FF",
		] {
			assert_eq!(
				normalize_station(text).as_deref(),
				Ok("aa:bb:cc:dd:ee:ff"),
				"{text}"
			);
		}
		assert_eq!(
			normalize_station("00:11:22:33:44:55").as_deref(),
			Ok("00:11:22:33:44:55")
		);
	}

	#[test]
	fn what_is_not_a_station_address_is_refused_rather_than_repaired() {
		// The bare form is refused on purpose: `aabbccddeeff` with one digit
		// dropped is still eleven plausible characters, and an ACL is the wrong
		// place to accept something that might be a typo.
		for text in [
			"aabbccddeeff",
			"aa:bb:cc:dd:ee",
			"aa:bb:cc:dd:ee:ff:00",
			"aa:bb:cc:dd:ee:gg",
			"aa:bb:cc:dd:ee:f",
			"aa:bb:cc:dd:ee:fff",
			"",
			"ff:ff:ff:ff:ff:ff ",
		] {
			assert!(normalize_station(text).is_err(), "{text} should be refused");
		}
	}

	#[test]
	fn the_two_policies_carry_hostapds_own_spellings() {
		assert_eq!(AclPolicy::Deny.macaddr_acl(), "0");
		assert_eq!(AclPolicy::Allow.macaddr_acl(), "1");
		assert_eq!(AclPolicy::Deny.ctrl_command(), "DENY_ACL");
		assert_eq!(AclPolicy::Allow.ctrl_command(), "ACCEPT_ACL");
	}
}
