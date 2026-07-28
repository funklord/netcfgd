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
