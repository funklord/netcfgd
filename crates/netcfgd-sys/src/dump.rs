//! Dump requests, and decoding their replies into flat records.
//!
//! The records are this crate's own types rather than `netcfgd-model`'s,
//! because this crate depends on nothing but libc and the kernel. Turning them
//! into an `Observed` is `netcfgd-observe`'s job, and keeping the two apart is
//! what lets the decoding be tested against captured bytes with no model in
//! sight.

use crate::wire::{self, flags, ifa, ifla, msg_type, rta, AttrBuf, Attrs};
use std::net::IpAddr;

/// `IFF_UP` from `net/if.h`. Spelled out rather than taken from libc, where it
/// is a `c_int` and would need a cast that clippy is right to object to.
const IFF_UP: u32 = 0x1;

/// A link, as decoded from one `RTM_NEWLINK` message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinkRecord {
	/// Interface index.
	pub index: u32,
	/// Interface name.
	pub name: String,
	/// Link kind from the `LINKINFO` nest: `bridge`, `vlan`, and so on. Empty
	/// for a plain device.
	pub kind: String,
	/// Whether `IFF_UP` is set.
	pub up: bool,
	/// Whether the kernel reports carrier.
	pub carrier: bool,
	/// MTU.
	pub mtu: u32,
	/// Hardware address.
	pub mac: Option<String>,
	/// Index of the master, where enslaved.
	pub master: Option<u32>,
	/// The IPv6 interface identifier set with `ip token`, if any.
	///
	/// Reported inside `IFLA_AF_SPEC`'s `AF_INET6` block. All-zero means no
	/// token, which is how the kernel spells "none" -- so it is read as
	/// absence rather than as the address `::`.
	pub ipv6_token: Option<std::net::IpAddr>,
}

/// An address, as decoded from one `RTM_NEWADDR` message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AddressRecord {
	/// Index of the interface carrying it.
	pub index: u32,
	/// The address.
	pub address: IpAddr,
	/// Prefix length.
	pub prefix_len: u8,
	/// `IFA_PROTO`, where the kernel supplied it.
	pub proto: Option<u8>,
}

impl AddressRecord {
	/// The address in CIDR notation, which is how the model spells it.
	#[must_use]
	pub fn cidr(&self) -> String {
		format!("{}/{}", self.address, self.prefix_len)
	}
}

/// A route, as decoded from one `RTM_NEWROUTE` message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteRecord {
	/// Output interface index.
	pub index: Option<u32>,
	/// Destination, or `None` for a default route.
	pub destination: Option<IpAddr>,
	/// Destination prefix length.
	pub dst_len: u8,
	/// Next hop.
	pub gateway: Option<IpAddr>,
	/// Metric.
	pub metric: Option<u32>,
	/// Table id.
	pub table: u32,
	/// Preferred source.
	pub prefsrc: Option<IpAddr>,
	/// `rtm_protocol`.
	pub protocol: u8,
	/// `rtm_scope`.
	pub scope: u8,
}

impl RouteRecord {
	/// The destination in the model's spelling: CIDR, or `default`.
	#[must_use]
	pub fn destination_text(&self) -> String {
		match self.destination {
			Some(address) => format!("{address}/{}", self.dst_len),
			None => "default".to_owned(),
		}
	}
}

/// Build a link dump request body.
#[must_use]
pub fn link_request() -> (Vec<u8>, AttrBuf) {
	let mut body = Vec::new();
	wire::IfInfo::default().encode(&mut body);
	(body, AttrBuf::new())
}

/// Build an address dump request body.
#[must_use]
pub fn address_request() -> (Vec<u8>, AttrBuf) {
	let mut body = Vec::new();
	// Family 0 means "every family", which is what a dump wants.
	wire::IfAddr::default().encode(&mut body);
	(body, AttrBuf::new())
}

/// Build a route dump request body.
#[must_use]
pub fn route_request() -> (Vec<u8>, AttrBuf) {
	let mut body = Vec::new();
	wire::RtMsg::default().encode(&mut body);
	(body, AttrBuf::new())
}

/// The flags a dump request carries.
#[must_use]
pub const fn dump_flags() -> u16 {
	flags::NLM_F_REQUEST | flags::NLM_F_DUMP
}

/// The message type each dump asks for.
pub mod requests {
	/// Links.
	pub const LINK: u16 = super::msg_type::RTM_GETLINK;
	/// Addresses.
	pub const ADDRESS: u16 = super::msg_type::RTM_GETADDR;
	/// Routes.
	pub const ROUTE: u16 = super::msg_type::RTM_GETROUTE;
	/// Bridge VLANs, which come back on the link dump under another family.
	pub const BRIDGE_VLAN: u16 = super::msg_type::RTM_GETLINK;
}

/// Decode one `RTM_NEWLINK` payload.
#[must_use]
pub fn decode_link(payload: &[u8]) -> Option<LinkRecord> {
	let info = wire::IfInfo::decode(payload)?;
	let attrs = Attrs::new(payload.get(wire::IFINFO_LEN..)?);

	let name = attrs.get(ifla::IFNAME).and_then(|attr| attr.string())?;
	let mtu = attrs
		.get(ifla::MTU)
		.and_then(|attr| attr.u32())
		.unwrap_or(0);
	let mac = attrs.get(ifla::ADDRESS).and_then(|attr| attr.mac());
	let master = attrs.get(ifla::MASTER).and_then(|attr| attr.u32());

	// Two levels down: IFLA_AF_SPEC, then the AF_INET6 block. Present in an
	// ordinary link dump, so this needs no second request.
	let ipv6_token = attrs
		.get(IFLA_AF_SPEC)
		.and_then(|spec| Attrs::new(spec.value).get(AF_INET6))
		.and_then(|inet6| Attrs::new(inet6.value).get(IFLA_INET6_TOKEN))
		.and_then(|attr| attr.ip())
		// The kernel reports `::` for a device with no token. Reading that as
		// an address would make every interface look as though it had one.
		.filter(|address| !address.is_unspecified());

	// The kind lives one level down, inside the LINKINFO nest. Its absence is
	// normal: a plain ethernet device has no kind.
	let kind = attrs
		.get(ifla::LINKINFO)
		.and_then(|nest| {
			Attrs::new(nest.value)
				.get(ifla::INFO_KIND)
				.and_then(|attr| attr.string())
		})
		.unwrap_or_default();

	// IFF_UP is the administrative flag. Carrier is separate and has its own
	// attribute, because a link can be up with the cable out -- conflating the
	// two is how a plan decides to reconfigure a perfectly good interface.
	let up = info.flags & IFF_UP != 0;
	let carrier = attrs
		.get(ifla::CARRIER)
		.and_then(|attr| attr.u8())
		.is_none_or(|value| value != 0);

	Some(LinkRecord {
		index: u32::try_from(info.index).unwrap_or(0),
		name,
		kind,
		up,
		carrier,
		mtu,
		mac,
		master,
		ipv6_token,
	})
}

/// Decode one `RTM_NEWADDR` payload.
#[must_use]
pub fn decode_address(payload: &[u8]) -> Option<AddressRecord> {
	let info = wire::IfAddr::decode(payload)?;
	let attrs = Attrs::new(payload.get(wire::IFADDR_LEN..)?);

	// IFA_LOCAL is the address on this host; IFA_ADDRESS is the peer on a
	// point-to-point link and the same thing everywhere else. Preferring LOCAL
	// is what makes a PPP interface report its own address rather than the
	// far end's.
	let address = attrs
		.get(ifa::LOCAL)
		.or_else(|| attrs.get(ifa::ADDRESS))
		.and_then(|attr| attr.ip())?;

	Some(AddressRecord {
		index: info.index,
		address,
		prefix_len: info.prefix_len,
		proto: attrs.get(ifa::PROTO).and_then(|attr| attr.u8()),
	})
}

/// Decode one `RTM_NEWROUTE` payload.
#[must_use]
pub fn decode_route(payload: &[u8]) -> Option<RouteRecord> {
	let info = wire::RtMsg::decode(payload)?;
	let attrs = Attrs::new(payload.get(wire::RTMSG_LEN..)?);

	// RTA_TABLE carries the table id when it does not fit in the byte-wide
	// rtm_table, which is every table above 255.
	let table = attrs
		.get(rta::TABLE)
		.and_then(|attr| attr.u32())
		.unwrap_or_else(|| u32::from(info.table));

	Some(RouteRecord {
		index: attrs.get(rta::OIF).and_then(|attr| attr.u32()),
		destination: attrs.get(rta::DST).and_then(|attr| attr.ip()),
		dst_len: info.dst_len,
		gateway: attrs.get(rta::GATEWAY).and_then(|attr| attr.ip()),
		metric: attrs.get(rta::PRIORITY).and_then(|attr| attr.u32()),
		table,
		prefsrc: attrs.get(rta::PREFSRC).and_then(|attr| attr.ip()),
		protocol: info.protocol,
		scope: info.scope,
	})
}

/// `AF_BRIDGE`, the address family a bridge's VLAN configuration lives under.
pub const AF_BRIDGE: u8 = 7;

/// `AF_INET6`, which inside `IFLA_AF_SPEC` is the attribute *type* of the
/// nest holding per-device IPv6 settings.
pub const AF_INET6: u16 = 10;

/// `IFLA_INET6_TOKEN`, inside that nest.
pub const IFLA_INET6_TOKEN: u16 = 7;
/// `RTEXT_FILTER_BRVLAN`. Without it a bridge link dump reports no VLANs at
/// all, which reads as "this bridge has none" rather than "you did not ask".
const RTEXT_FILTER_BRVLAN: u32 = 2;
/// `IFLA_EXT_MASK`.
const IFLA_EXT_MASK: u16 = 29;
/// `IFLA_AF_SPEC`.
pub const IFLA_AF_SPEC: u16 = 26;
/// `IFLA_BRIDGE_FLAGS`, inside `AF_SPEC`.
pub const IFLA_BRIDGE_FLAGS: u16 = 0;
/// `IFLA_BRIDGE_VLAN_INFO`, inside `AF_SPEC`.
pub const IFLA_BRIDGE_VLAN_INFO: u16 = 2;

/// `BRIDGE_FLAGS_MASTER`: the change is for the bridge this port belongs to.
pub const BRIDGE_FLAGS_MASTER: u16 = 1;
/// `BRIDGE_FLAGS_SELF`: the change is for this device itself.
///
/// The distinction matters and is easy to get backwards. Configuring a VLAN on
/// a *port* is a MASTER operation -- the bridge is being told which VLANs that
/// port carries. Configuring one on the *bridge device* is SELF, and is what
/// lets the bridge itself terminate traffic in that VLAN.
pub const BRIDGE_FLAGS_SELF: u16 = 2;

/// `BRIDGE_VLAN_INFO_RANGE_BEGIN` and `..._END`: the kernel's compression of
/// consecutive ids into a pair rather than one entry each.
const RANGE_BEGIN: u16 = 8;
const RANGE_END: u16 = 16;

/// `BRIDGE_VLAN_INFO_PVID`: untagged ingress joins this VLAN.
pub const BRIDGE_VLAN_INFO_PVID: u16 = 2;
/// `BRIDGE_VLAN_INFO_UNTAGGED`: egress leaves without a tag.
pub const BRIDGE_VLAN_INFO_UNTAGGED: u16 = 4;

/// One VLAN on one bridge port, as the kernel reports it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct BridgeVlanRecord {
	/// Which interface carries it.
	pub index: u32,
	/// The VLAN id.
	pub vid: u16,
	/// Untagged ingress joins this VLAN.
	pub pvid: bool,
	/// Egress leaves without a tag.
	pub untagged: bool,
}

/// Build a bridge VLAN dump request.
///
/// A separate dump from the ordinary link one, because it needs a different
/// family and an explicit filter -- asking for links the usual way returns
/// bridges with their VLAN configuration omitted rather than empty.
#[must_use]
pub fn bridge_vlan_request() -> (Vec<u8>, AttrBuf) {
	let mut body = Vec::new();
	wire::IfInfo {
		family: AF_BRIDGE,
		..wire::IfInfo::default()
	}
	.encode(&mut body);
	let mut attrs = AttrBuf::new();
	attrs.push_u32(IFLA_EXT_MASK, RTEXT_FILTER_BRVLAN);
	(body, attrs)
}

/// Decode the VLANs in one `AF_BRIDGE` link payload.
///
/// Returns several records per message: a bridge port with four VLANs arrives
/// as one link with four `BRIDGE_VLAN_INFO` attributes, and the kernel
/// compresses consecutive ids into ranges.
#[must_use]
pub fn decode_bridge_vlans(payload: &[u8]) -> Vec<BridgeVlanRecord> {
	let Some(info) = wire::IfInfo::decode(payload) else {
		return Vec::new();
	};
	let Some(rest) = payload.get(wire::IFINFO_LEN..) else {
		return Vec::new();
	};
	let Some(spec) = Attrs::new(rest).get(IFLA_AF_SPEC) else {
		return Vec::new();
	};

	let index = u32::try_from(info.index).unwrap_or(0);
	let mut out = Vec::new();
	let mut range_start: Option<BridgeVlanRecord> = None;

	for attr in Attrs::new(spec.value) {
		if attr.kind != IFLA_BRIDGE_VLAN_INFO || attr.value.len() < 4 {
			continue;
		}
		let flags = u16::from_ne_bytes(attr.value[0..2].try_into().unwrap_or([0, 0]));
		let vid = u16::from_ne_bytes(attr.value[2..4].try_into().unwrap_or([0, 0]));
		let record = BridgeVlanRecord {
			index,
			vid,
			pvid: flags & BRIDGE_VLAN_INFO_PVID != 0,
			untagged: flags & BRIDGE_VLAN_INFO_UNTAGGED != 0,
		};

		// The kernel compresses `vid 10` through `vid 20` into a pair of
		// entries flagged RANGE_BEGIN and RANGE_END rather than eleven
		// entries. Expanding here means everything above works in single
		// VLANs and never has to know ranges exist.
		if flags & RANGE_BEGIN != 0 {
			range_start = Some(record);
			continue;
		}
		if flags & RANGE_END != 0 {
			if let Some(start) = range_start.take() {
				for vid in start.vid..=record.vid {
					out.push(BridgeVlanRecord { vid, ..start });
				}
				continue;
			}
		}
		out.push(record);
	}

	// A range that never ended is a truncated message rather than a range to
	// the end of the space; taking the first entry alone is the conservative
	// reading, since inventing 4094 VLANs would have netcfgd delete them.
	if let Some(start) = range_start {
		out.push(start);
	}
	out.sort_unstable();
	out
}
