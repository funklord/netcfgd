//! ethtool, over its generic netlink family.
//!
//! Decision 0016 said this needed "an `unsafe` ioctl outside `netcfgd-sys` or
//! generic netlink family resolution". The second was built for `WireGuard` at
//! M4, so the cost is already paid and `SIOCETHTOOL` is not needed: the
//! `ethtool` family has existed since Linux 5.6 and does everything the
//! ioctl does.
//!
//! **Only the offloads.** The model also carries ring sizes, link modes and
//! wake-on-LAN, and those are not here. The reason is verification, not
//! effort: a veth accepts a features set, and refuses a link-modes set with a
//! bare `EINVAL`; ring and `WoL` messages are `EOPNOTSUPP` on anything that is
//! not a physical NIC. Every netlink bug this project has shipped -- the
//! `WireGuard` flags attribute, the nftables meta key, the qdisc rate unit --
//! was found by writing to a real kernel and reading it back, and none of them
//! would have been found by writing an encoder carefully. So the settings that
//! can only be exercised against hardware this build cannot safely write to
//! stay unimplemented and stay warned about.
//!
//! Features are named, not numbered. The kernel's bit indices are not stable
//! across versions and are not a wire contract; the names are. Sending
//! `ETHTOOL_A_BITSET_BIT_NAME` lets the kernel do the lookup, which also makes
//! a feature the driver has never heard of a clean failure rather than the
//! wrong bit being set.

use crate::genl::{payload_attrs, Family, Genl, GenlHeader};
use crate::wire::{AttrBuf, Attrs};
use std::io;

/// `ETHTOOL_MSG_FEATURES_GET` and `..._SET`.
///
/// Twelve, not ten. Ten is `ETHTOOL_MSG_WOL_SET`, and sending a features
/// payload to the wake-on-LAN setter is a bare `EINVAL` that reads exactly
/// like a malformed bitset -- which is where an hour went. The `GET` next door
/// is right, which is what made the encoder look like the suspect.
const ETHTOOL_MSG_FEATURES_GET: u8 = 11;
const ETHTOOL_MSG_FEATURES_SET: u8 = 12;

/// `ETHTOOL_A_HEADER_DEV_NAME`, inside the header nest every message carries.
const ETHTOOL_A_HEADER_DEV_NAME: u16 = 2;

/// `ETHTOOL_A_FEATURES_HEADER`, `..._WANTED`, `..._ACTIVE`.
const ETHTOOL_A_FEATURES_HEADER: u16 = 1;
const ETHTOOL_A_FEATURES_WANTED: u16 = 3;
const ETHTOOL_A_FEATURES_ACTIVE: u16 = 4;

/// `ETHTOOL_A_BITSET_*`.
const ETHTOOL_A_BITSET_NOMASK: u16 = 1;
const ETHTOOL_A_BITSET_BITS: u16 = 3;
/// `ETHTOOL_A_BITSET_BITS_BIT`, the type every element of the list carries.
const ETHTOOL_A_BITSET_BITS_BIT: u16 = 1;
/// `ETHTOOL_A_BITSET_BIT_*`.
const ETHTOOL_A_BITSET_BIT_NAME: u16 = 2;
const ETHTOOL_A_BITSET_BIT_VALUE: u16 = 3;

/// `NLA_F_NESTED`, which the ethtool family's parsers require.
const NLA_F_NESTED: u16 = 0x8000;

/// An ethtool connection.
///
/// Holds the resolved family, because resolving it is a round trip and the
/// answer does not change while the process runs.
#[derive(Debug)]
pub struct Ethtool {
	genl: Genl,
	family: Family,
}

impl Ethtool {
	/// Open a generic netlink socket and resolve the `ethtool` family.
	///
	/// # Errors
	///
	/// Returns the underlying `io::Error`. `ENOENT` means this kernel predates
	/// the netlink interface, which is Linux 5.6.
	pub fn open() -> io::Result<Self> {
		let mut genl = Genl::open()?;
		let family = genl.family("ethtool")?;
		Ok(Self { genl, family })
	}

	/// Which of the named features are currently on.
	///
	/// # Errors
	///
	/// Returns the errno the kernel replied with. `EOPNOTSUPP` means the
	/// device has no ethtool operations at all.
	pub fn active_features(&mut self, device: &str) -> io::Result<Vec<String>> {
		let replies = self.genl.request(
			&self.family,
			GenlHeader {
				cmd: ETHTOOL_MSG_FEATURES_GET,
				version: 1,
			},
			0,
			&header(device, ETHTOOL_A_FEATURES_HEADER),
		)?;

		let mut out = Vec::new();
		for payload in &replies {
			let Some(active) = payload_attrs(payload)
				.find(|attr| attr.kind & !NLA_F_NESTED == ETHTOOL_A_FEATURES_ACTIVE)
			else {
				continue;
			};
			// `ACTIVE` comes back as a no-mask bitset, which is a *list*: a
			// bit that appears is on, and one that does not is off. Reading it
			// as a mask bitset and looking for `BIT_VALUE` finds nothing and
			// reports every feature disabled.
			out.extend(listed_names(active.value));
		}
		out.sort_unstable();
		out.dedup();
		Ok(out)
	}

	/// Turn features on or off by name.
	///
	/// # Errors
	///
	/// Returns the errno the kernel replied with. A name the driver does not
	/// know is `EINVAL` rather than a silent no-op, which is the point of
	/// sending names.
	pub fn set_features(&mut self, device: &str, wanted: &[(&str, bool)]) -> io::Result<()> {
		let mut bits = AttrBuf::new();
		for (name, on) in wanted {
			let mut bit = AttrBuf::new();
			bit.push_str(ETHTOOL_A_BITSET_BIT_NAME, name);
			if *on {
				// A flag: present means on, absent means off. There is no
				// "false" encoding, so writing a zero here would read as on.
				bit.push(ETHTOOL_A_BITSET_BIT_VALUE, &[]);
			}
			bits.push(ETHTOOL_A_BITSET_BITS_BIT | NLA_F_NESTED, bit.as_bytes());
		}

		// A mask bitset, deliberately without `NOMASK`: it says "change
		// exactly these and leave everything else alone". The no-mask form
		// would mean "this is the complete set of enabled features", which
		// would turn off every offload the document does not mention.
		let mut bitset = AttrBuf::new();
		bitset.push(ETHTOOL_A_BITSET_BITS | NLA_F_NESTED, bits.as_bytes());

		let mut attrs = header(device, ETHTOOL_A_FEATURES_HEADER);
		attrs.push(ETHTOOL_A_FEATURES_WANTED | NLA_F_NESTED, bitset.as_bytes());

		self.genl.request(
			&self.family,
			GenlHeader {
				cmd: ETHTOOL_MSG_FEATURES_SET,
				version: 1,
			},
			crate::wire::flags::NLM_F_ACK,
			&attrs,
		)?;
		Ok(())
	}
}

/// The header nest every ethtool message begins with.
fn header(device: &str, header_attr: u16) -> AttrBuf {
	let mut inner = AttrBuf::new();
	inner.push_str(ETHTOOL_A_HEADER_DEV_NAME, device);
	let mut attrs = AttrBuf::new();
	attrs.push(header_attr | NLA_F_NESTED, inner.as_bytes());
	attrs
}

/// The names listed in a no-mask bitset.
fn listed_names(bitset: &[u8]) -> Vec<String> {
	let attrs = Attrs::new(bitset);
	// Without `NOMASK` this is a mask bitset and a listed bit means "this bit
	// is being talked about", not "this bit is on". Nothing here sends one, so
	// reading it as a list would be wrong rather than merely useless.
	if !attrs
		.clone()
		.any(|attr| attr.kind & !NLA_F_NESTED == ETHTOOL_A_BITSET_NOMASK)
	{
		return Vec::new();
	}
	let Some(bits) = attrs
		.clone()
		.find(|attr| attr.kind & !NLA_F_NESTED == ETHTOOL_A_BITSET_BITS)
	else {
		return Vec::new();
	};
	Attrs::new(bits.value)
		.filter_map(|bit| {
			Attrs::new(bit.value)
				.find(|attr| attr.kind & !NLA_F_NESTED == ETHTOOL_A_BITSET_BIT_NAME)
				.and_then(|attr| attr.string())
		})
		.collect()
}
