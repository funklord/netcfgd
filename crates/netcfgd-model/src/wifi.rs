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

/// When a client should look for a better access point on the same network.
///
/// **The oldest thing wifi does, and the one netcfgd could not ask for.** An ESS
/// is several access points sharing one SSID, and a station picks whichever of
/// them it hears best -- walk down the corridor and the laptop moves to the
/// nearer one. `wpa_supplicant` does that itself, within one network block, and
/// only while a `bgscan` module is asking it to look; without one it re-selects
/// only after the link has already gone, which is a client that roams by first
/// losing the network.
///
/// Stated as an intent rather than as `wpa_supplicant`'s string. The operator says
/// how weak is weak and how often to look; `netcfgd-supplicant` renders the
/// module, the way every other backend detail is rendered rather than passed
/// through (design section 8). A `bgscan="simple:30:-70:300"` in a config file
/// would be netcfgd asking the operator to know which supplicant is underneath.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RoamPolicy {
	/// Below this, in dBm, the radio is weak enough to look for better.
	///
	/// `wpa_supplicant` scans at `interval` while the signal is under this and
	/// at `slow_interval` while it is over -- so this is the whole of "when
	/// should a laptop start looking", and -70 dBm is the usual answer.
	pub signal: i32,
	/// Seconds between scans while the signal is below `signal`.
	pub interval: u32,
	/// Seconds between scans while it is above.
	///
	/// Not zero and not absent: a station that stops looking entirely once it
	/// is comfortable never notices the access point it walked past, which is
	/// the failure this whole policy exists to avoid.
	pub slow_interval: u32,
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
	/// The SSID as octets, when the document states one.
	///
	/// `None` means "whatever the access points in `bssid` call themselves",
	/// and netcfgd reads it from a scan before configuring the supplicant.
	/// That is not a convenience: **WPA derives its key from the passphrase
	/// *and* the SSID**, so a secured network cannot be joined without one --
	/// `wpa_supplicant`'s own wildcard-SSID example is marked "plaintext APs
	/// only" for exactly that reason. The name has to be learned, not skipped.
	///
	/// Requires a non-empty `bssid`: with neither an SSID nor an access point
	/// to ask, there is nothing to identify the network by at all.
	#[serde(skip_serializing_if = "Option::is_none", default)]
	pub ssid: Option<Ssid>,
	/// Whether the network hides its SSID in beacons.
	#[serde(default)]
	pub hidden: bool,
	/// How it is secured.
	pub security: Security,
	/// How much this network is preferred, on one scale, for both questions
	/// that word can mean.
	///
	/// **Lower wins, and it is a route metric** -- the same number and the
	/// same scale as an interface's `preference`, because it becomes the same
	/// thing. While the radio is associated to this network, its interface's
	/// routes take this metric instead of the interface's own.
	///
	/// **This is the only way to rank a wired link against a *network*.** An
	/// interface's `preference` is fixed, so a radio carries one ranking
	/// whichever network it joined -- and "the office wifi beats this
	/// ethernet, the cafe wifi does not" was inexpressible. The unit on the
	/// wireless side has to be the network, because that is the thing that
	/// changes.
	///
	/// **It also decides which network to join**, which is the job the
	/// separate `priority` used to do. `wpa_supplicant` still needs an
	/// ordering and still gets one; netcfgd derives it here rather than
	/// asking an operator for a second number that runs the other way up
	/// (0154). Nothing is lost, because a supplicant priority only ever
	/// separates networks that are in range at the same moment, and a network
	/// preferred for its routes is the one to join.
	///
	/// Absent means the interface's `preference` applies unchanged and the
	/// supplicant is told nothing, which is what every machine that has never
	/// needed this gets.
	#[serde(skip_serializing_if = "Option::is_none", default)]
	pub metric: Option<u32>,
	/// Whether to join without being asked.
	#[serde(default = "crate::default_true")]
	pub autoconnect: bool,
	/// Whether the link is metered.
	#[serde(default)]
	pub metered: bool,
	/// The access points this network may use, if it is restricted to any.
	///
	/// Empty is the ordinary network: associate with whatever is advertising
	/// the SSID, which is what wifi has always done.
	///
	/// **One entry pins; several choose.** `wpa_supplicant` spells those
	/// differently -- `bssid` refuses everything else, `bssid_accept` limits
	/// selection to a set and picks among them by signal -- and the difference
	/// matters: a list is "any of these, whichever is best", which is a
	/// perfectly ordinary way to describe one site's access points.
	///
	/// A single entry is the opposite of [`RoamPolicy`] and refused alongside
	/// it: a network pinned to one access point has nowhere to roam. A *list*
	/// is not -- roaming among a named set is exactly what an operator who
	/// listed them would want.
	#[serde(default, skip_serializing_if = "Vec::is_empty")]
	pub bssid: Vec<String>,
	/// When to look for a better access point on this same network.
	///
	/// `None` is `wpa_supplicant`'s own default: look only after the link is
	/// gone. That stays the default because a background scan costs airtime
	/// and interrupts traffic, and a machine that never moves -- a router, a
	/// server with a radio -- should not be paying for it.
	#[serde(skip_serializing_if = "Option::is_none", default)]
	pub roam: Option<RoamPolicy>,
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

/// Which configured network an association is on.
///
/// By SSID, and by BSSID for a network that has no SSID to match on -- one that
/// names access points instead and learns the name from them. Without the
/// second, exactly the networks whose whole point is being identified by
/// address would show as unconfigured, which is the list an operator checks to
/// see whether netcfgd knows about what it can see.
///
/// **Here rather than in either caller, because there are two.** The socket
/// answers "which network is this radio on?" for a client, and the observation
/// answers it for the planner, which ranks a network's `metric` against an
/// interface's `preference`. Two copies of this rule could disagree, and the
/// disagreement would show up as a route metric that does not match what the
/// window says the machine is associated with.
#[must_use]
pub fn network_for<'a>(
	networks: &'a [WifiNetwork],
	ssid: &Ssid,
	bssid: &str,
) -> Option<&'a WifiNetwork> {
	networks.iter().find(|network| {
		network.ssid.as_ref().map_or_else(
			|| {
				network
					.bssid
					.iter()
					.any(|listed| listed.eq_ignore_ascii_case(bssid))
			},
			|stated| stated == ssid,
		)
	})
}

/// The highest rank a derived join order takes, for a metric of 0.
///
/// Above any metric worth writing -- an interface's `preference` is offered in
/// the same range -- and small enough to scale into a narrower range without
/// the arithmetic needing care.
pub const RANK_CEILING: u32 = 4096;

/// Which network to join first, derived from how its routes rank.
///
/// **The directions are opposite, which is the whole reason this exists.** A
/// metric is a route metric: lower wins, and it is comparable with an
/// interface's `preference`. Every backend that orders networks for joining --
/// `wpa_supplicant`'s `priority`, `NetworkManager`'s `autoconnect-priority` --
/// counts the other way, higher winning. Asking an operator for both numbers
/// was asking them to hold two scales at once for one idea, and every tooltip
/// describing either had to explain the other (0154).
///
/// Subtracted from a ceiling rather than negated, because a backend treats a
/// missing priority as 0 and 0 is a legitimate metric -- the best one. A metric
/// at or past the ceiling floors at 0 rather than wrapping, so an absurd number
/// ranks last instead of first.
///
/// `None` where the network names no metric, and then the backend is told
/// nothing at all: that is its own default, and writing a number there would
/// invent a ranking the document did not ask for.
///
/// **Shared rather than written per backend.** Two copies of an inversion are
/// two chances to inject the sign error this is here to prevent, and a wrong
/// one is silent -- the machine simply prefers the wrong network. A backend
/// whose own range is narrower scales this result rather than recomputing it.
#[must_use]
pub fn join_rank(metric: Option<u32>) -> Option<u32> {
	metric.map(|metric| RANK_CEILING.saturating_sub(metric))
}
