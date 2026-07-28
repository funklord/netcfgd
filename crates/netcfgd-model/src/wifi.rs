//! Wifi network profiles, and the octet string an SSID actually is.

use crate::address::AddressSource;
use crate::dns::DnsPolicy;
use crate::hook::HookRef;
use crate::route::Route;
use crate::security::Security;
use serde::de::Error as DeError;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// The maximum length of an SSID, in octets.
pub const SSID_MAX_LEN: usize = 32;

/// An SSID: 0 to 32 arbitrary octets.
///
/// Not a string. 802.11 places no encoding requirement on an SSID, and real
/// networks ship ones that are not valid UTF-8 -- so this is bytes, and the
/// JSON encoding is lowercase hex rather than a string that would have to lie
/// about what it holds or fail to round-trip.
#[derive(Debug, Clone, Default, PartialEq, Eq, PartialOrd, Ord)]
pub struct Ssid(Vec<u8>);

impl Ssid {
	/// Wrap octets, rejecting anything longer than [`SSID_MAX_LEN`].
	///
	/// # Errors
	///
	/// Returns [`crate::Error::SsidTooLong`] if there are more than 32 octets.
	pub fn new(octets: Vec<u8>) -> Result<Self, crate::Error> {
		if octets.len() > SSID_MAX_LEN {
			return Err(crate::Error::SsidTooLong { len: octets.len() });
		}
		Ok(Self(octets))
	}

	/// The octets.
	#[must_use]
	pub fn as_bytes(&self) -> &[u8] {
		&self.0
	}

	/// Lowercase hex, which is the canonical encoding.
	#[must_use]
	pub fn to_hex(&self) -> String {
		let mut out = String::with_capacity(self.0.len() * 2);
		for byte in &self.0 {
			// Two lowercase hex digits, always. `write!` would pull in
			// formatting machinery for something this small.
			out.push(char::from(HEX[usize::from(byte >> 4)]));
			out.push(char::from(HEX[usize::from(byte & 0x0f)]));
		}
		out
	}

	/// Parse lowercase hex.
	///
	/// # Errors
	///
	/// Returns [`crate::Error::SsidNotHex`] for anything that is not an even
	/// number of lowercase hex digits, and [`crate::Error::SsidTooLong`] for
	/// more than 32 octets. Uppercase is refused rather than accepted, because
	/// two spellings of one SSID would break the byte-identical guarantee.
	pub fn from_hex(text: &str) -> Result<Self, crate::Error> {
		if text.len() % 2 != 0 {
			return Err(crate::Error::SsidNotHex);
		}
		let bytes = text.as_bytes();
		let mut octets = Vec::with_capacity(text.len() / 2);
		for pair in bytes.chunks_exact(2) {
			let hi = hex_digit(pair[0]).ok_or(crate::Error::SsidNotHex)?;
			let lo = hex_digit(pair[1]).ok_or(crate::Error::SsidNotHex)?;
			octets.push((hi << 4) | lo);
		}
		Self::new(octets)
	}
}

const HEX: &[u8; 16] = b"0123456789abcdef";

fn hex_digit(byte: u8) -> Option<u8> {
	match byte {
		b'0'..=b'9' => Some(byte - b'0'),
		b'a'..=b'f' => Some(byte - b'a' + 10),
		_ => None,
	}
}

impl Serialize for Ssid {
	fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
		serializer.serialize_str(&self.to_hex())
	}
}

impl<'de> Deserialize<'de> for Ssid {
	fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
		let text = String::deserialize(deserializer)?;
		Self::from_hex(&text).map_err(D::Error::custom)
	}
}

/// A remembered wifi network.
///
/// A profile, not a binding: it is not attached to a device, because the same
/// network is reachable from whichever radio is present.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WifiNetwork {
	/// Stable key, usually the SSID rendered as text. Sorting key.
	pub id: String,
	/// The SSID as octets.
	pub ssid: Ssid,
	/// Whether the network hides its SSID in beacons.
	#[serde(default)]
	pub hidden: bool,
	/// How it is secured.
	pub security: Security,
	/// Higher wins when several known networks are in range.
	#[serde(default)]
	pub priority: i32,
	/// Whether to join without being asked.
	#[serde(default = "crate::default_true")]
	pub autoconnect: bool,
	/// Whether the link is metered.
	#[serde(default)]
	pub metered: bool,
	/// Pin association to one BSSID.
	#[serde(skip_serializing_if = "Option::is_none", default)]
	pub bssid_pin: Option<String>,
	/// Addressing to apply once associated.
	#[serde(default)]
	pub addressing: Vec<AddressSource>,
	/// Routes to install once associated.
	#[serde(default)]
	pub routes: Vec<Route>,
	/// DNS scope for this network.
	#[serde(skip_serializing_if = "Option::is_none", default)]
	pub dns: Option<DnsPolicy>,
	/// Hook references.
	#[serde(default)]
	pub hooks: Vec<HookRef>,
}
