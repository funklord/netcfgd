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
	/// Alternative names, from the `IFLA_PROP_LIST` nest.
	///
	/// netcfgd stamps one on every link it creates, which is how a link's
	/// ownership survives losing `/run` (0136). Repeated attributes rather
	/// than one, so this is a list -- a device may carry names from several
	/// sources and netcfgd must not assume its own is the only one.
	pub altnames: Vec<String>,
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
	/// Index of the device this virtual link rides on, where it has one.
	///
	/// From the outer `IFLA_LINK` for every kind that reports one there, and from
	/// the `INFO_DATA` nest for a `VXLAN`, which is the one kind that does not.
	pub parent: Option<u32>,
	/// A bond's own settings, where this link is one.
	///
	/// From the same `INFO_DATA` nest a bridge's comes from, decoded with the
	/// bond's numbering -- which is why the two are read separately rather than
	/// by one function that takes a kind.
	pub bond: Option<BondInfo>,
	/// A bridge's own settings, where this link is one.
	///
	/// From `IFLA_INFO_DATA` inside the `LINKINFO` nest -- the same place the
	/// kind comes from, one attribute along. Read because a bridge configured
	/// at creation and never compared is a bridge whose edited `stp` or
	/// `forward_delay` does nothing, and the name of a bridge encodes neither.
	pub bridge: Option<BridgeInfo>,
	/// A macvlan's own settings, where this link is one.
	pub macvlan: Option<MacvlanInfo>,
	/// A VLAN's id and tag protocol, where this link is one.
	///
	/// Read even though neither can be *set* on a live device: the kernel
	/// accepts a change to either and ignores it, so the only way to apply an
	/// edited id is to make the interface again -- and knowing that it differs is
	/// what decides to.
	pub vlan: Option<VlanInfo>,
	/// A point-to-point tunnel's endpoints, where this link is one.
	///
	/// Three attribute families answer to this one struct -- GRE, the ip
	/// tunnels and geneve -- and which one a kind belongs to is
	/// [`tunnel_family`]'s answer rather than a guess from the name.
	pub tunnel: Option<TunnelInfo>,
	/// A `VXLAN`'s own settings, where this link is one.
	pub vxlan: Option<VxlanInfo>,
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
///
/// `vlan` and `vxlan` are two of the locals, and clippy is right that the names
/// are one letter apart. They are the kernel's own words for two different link
/// kinds, and the style rule here is one word per concept everywhere -- inventing
/// a synonym for either to please the lint would put a name in this file that
/// appears nowhere else in the tree or in `ip -d link show`.
#[must_use]
#[allow(clippy::similar_names)]
pub fn decode_link(payload: &[u8]) -> Option<LinkRecord> {
	let info = wire::IfInfo::decode(payload)?;
	let attrs = Attrs::new(payload.get(wire::IFINFO_LEN..)?);

	let name = attrs.get(ifla::IFNAME).and_then(|attr| attr.string())?;
	let mtu = attrs
		.get(ifla::MTU)
		.and_then(|attr| attr.u32())
		.unwrap_or(0);
	// `IFLA_ALT_IFNAME` repeats inside the nest, so this iterates rather than
	// asking for one: `Attrs::get` stops at the first match and would read a
	// device with three names as a device with one.
	let altnames = attrs
		.get(ifla::PROP_LIST)
		.map(|nest| {
			wire::Attrs::new(nest.value)
				.filter(|attr| attr.kind == ifla::ALT_IFNAME)
				.filter_map(|attr| attr.string())
				.collect()
		})
		.unwrap_or_default();
	let mac = attrs.get(ifla::ADDRESS).and_then(|attr| attr.mac());
	let master = attrs.get(ifla::MASTER).and_then(|attr| attr.u32());
	let outer_parent = attrs.get(ifla::LINK).and_then(|attr| attr.u32());

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

	// Only for a bridge: every kind puts something different in this nest, and
	// decoding one kind's numbering out of another's is how a VXLAN comes to
	// report a forward delay.
	let info_data = || {
		attrs
			.get(ifla::LINKINFO)
			.and_then(|nest| Attrs::new(nest.value).get(IFLA_INFO_DATA))
	};
	let bond = (kind == "bond")
		.then(|| info_data().map(|data| bond_info(data.value)))
		.flatten();
	let bridge = (kind == "bridge")
		.then(|| {
			attrs
				.get(ifla::LINKINFO)
				.and_then(|nest| Attrs::new(nest.value).get(IFLA_INFO_DATA))
				.map(|data| bridge_info(data.value))
		})
		.flatten();
	let macvlan = (kind == "macvlan")
		.then(|| info_data().map(|data| macvlan_info(data.value)))
		.flatten();
	let vlan = (kind == "vlan")
		.then(|| info_data().map(|data| vlan_info(data.value)))
		.flatten();
	let vxlan = (kind == "vxlan")
		.then(|| info_data().map(|data| vxlan_info(data.value)))
		.flatten();
	let tunnel = tunnel_family(&kind)
		.and_then(|family| info_data().map(|data| tunnel_info(family, data.value)));

	// A VXLAN reports its underlay inside its own nest and *not* in the outer
	// attribute every other kind uses -- measured, because the two disagreeing is
	// how a parent came to be sent to the wrong place for years. Everything else
	// reports it outside, tunnels included: the kernel reads a tunnel's underlay
	// from the nest and reports it here.
	let parent = outer_parent.or_else(|| vxlan.and_then(|vxlan| vxlan.link));

	Some(LinkRecord {
		altnames,
		index: u32::try_from(info.index).unwrap_or(0),
		name,
		kind,
		up,
		carrier,
		mtu,
		mac,
		master,
		parent,
		bond,
		bridge,
		macvlan,
		vlan,
		tunnel,
		vxlan,
		ipv6_token,
	})
}

/// What a bridge reports about itself.
///
/// In the units the kernel uses, which are hundredths of a second for the three
/// timers. The conversion to seconds belongs where the conversion *to* the
/// kernel already is, so that one place owns it -- a reader that divided here
/// and a writer that multiplied there is how the same bridge comes to differ
/// from itself by a factor of a hundred.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct BridgeInfo {
	/// Whether spanning tree is on.
	pub stp: bool,
	/// Forward delay, in hundredths of a second.
	pub forward_delay: Option<u32>,
	/// Hello interval, in hundredths of a second.
	pub hello_time: Option<u32>,
	/// Address ageing time, in hundredths of a second.
	pub ageing_time: Option<u32>,
	/// Bridge priority.
	pub priority: Option<u16>,
	/// Whether the bridge is VLAN-aware.
	pub vlan_filtering: bool,
}

/// What a bond reports about itself.
///
/// Only the two netcfgd sets. A bond has thirty-odd parameters and reading all
/// of them would put a page of kernel detail in `/run` to answer a question
/// about two.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct BondInfo {
	/// Bonding mode, as the kernel numbers them.
	pub mode: Option<u8>,
	/// Link monitoring interval in milliseconds.
	pub miimon: Option<u32>,
}

/// The bond attributes read back, numbered as `if_link.h` numbers them.
mod ifla_bond {
	pub(super) const MODE: u16 = 1;
	pub(super) const MIIMON: u16 = 3;
}

/// Decode a bond's `INFO_DATA`.
fn bond_info(data: &[u8]) -> BondInfo {
	let attrs = Attrs::new(data);
	BondInfo {
		mode: attrs.get(ifla_bond::MODE).and_then(|attr| attr.u8()),
		miimon: attrs.get(ifla_bond::MIIMON).and_then(|attr| attr.u32()),
	}
}

/// `IFLA_INFO_DATA`, one along from the kind in the `LINKINFO` nest.
const IFLA_INFO_DATA: u16 = 2;
/// The bridge attributes read back, numbered as `if_link.h` numbers them.
mod ifla_br {
	pub(super) const FORWARD_DELAY: u16 = 1;
	pub(super) const HELLO_TIME: u16 = 2;
	pub(super) const AGEING_TIME: u16 = 4;
	pub(super) const STP_STATE: u16 = 5;
	pub(super) const PRIORITY: u16 = 6;
	pub(super) const VLAN_FILTERING: u16 = 7;
}

/// Decode a bridge's `INFO_DATA`.
fn bridge_info(data: &[u8]) -> BridgeInfo {
	let attrs = Attrs::new(data);
	BridgeInfo {
		// The kernel reports the STP *state*, which is 0 for off and non-zero
		// for a running protocol. A bool is what the document holds.
		stp: attrs
			.get(ifla_br::STP_STATE)
			.and_then(|attr| attr.u32())
			.is_some_and(|state| state != 0),
		forward_delay: attrs.get(ifla_br::FORWARD_DELAY).and_then(|a| a.u32()),
		hello_time: attrs.get(ifla_br::HELLO_TIME).and_then(|a| a.u32()),
		ageing_time: attrs.get(ifla_br::AGEING_TIME).and_then(|a| a.u32()),
		// **Two bytes, not four.** `IFLA_BR_PRIORITY` is a `__u16` in
		// `if_link.h`, and `u32()` needs four bytes or it returns nothing --
		// so this read a bridge's priority as absent on every kernel, always.
		// Nothing noticed because the planner did not compare the field; the
		// moment it did, the apply set the priority and the observation still
		// said `<absent>`, and the plan asked for it again for ever. The
		// writer had it right, which is what makes the two-byte width the
		// answer rather than a guess. `u16()`'s own doc names this trap:
		// netlink is not consistent about integer widths and the header gives
		// no hint.
		priority: attrs.get(ifla_br::PRIORITY).and_then(|a| a.u16()),
		vlan_filtering: attrs
			.get(ifla_br::VLAN_FILTERING)
			.and_then(|attr| attr.u8())
			.is_some_and(|value| value != 0),
	}
}

/// What a macvlan reports about itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct MacvlanInfo {
	/// The mode, as the kernel numbers them: 1, 2, 4, 8 and 16.
	///
	/// Flags rather than an enumeration, which is not obvious and matters: the
	/// kernel's validator rejects any other value outright, so 0 for the first
	/// mode and 3 for the fourth are `EINVAL` rather than a wrong mode. Kept as
	/// the number here and named in `netcfgd-observe`, the way a bond's mode is.
	pub mode: Option<u32>,
}

/// The macvlan attributes, numbered as `if_link.h` numbers them.
mod ifla_macvlan {
	pub(super) const MODE: u16 = 1;
}

/// Decode a macvlan's `INFO_DATA`.
fn macvlan_info(data: &[u8]) -> MacvlanInfo {
	let attrs = Attrs::new(data);
	MacvlanInfo {
		mode: attrs.get(ifla_macvlan::MODE).and_then(|attr| attr.u32()),
	}
}

/// What a VLAN reports about itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct VlanInfo {
	/// The VLAN id.
	pub id: Option<u16>,
	/// The tag protocol, as an ethertype: `0x8100` or `0x88a8`.
	pub protocol: Option<u16>,
}

/// The VLAN attributes, numbered as `if_link.h` numbers them.
mod ifla_vlan {
	pub(super) const ID: u16 = 1;
	pub(super) const PROTOCOL: u16 = 5;
}

/// Decode a VLAN's `INFO_DATA`.
fn vlan_info(data: &[u8]) -> VlanInfo {
	let attrs = Attrs::new(data);
	VlanInfo {
		id: attrs.get(ifla_vlan::ID).and_then(|attr| attr.u16()),
		// Big-endian, because it is an ethertype and the kernel reads and
		// reports it as one -- the same asymmetry the writing half has.
		protocol: attrs
			.get(ifla_vlan::PROTOCOL)
			.and_then(|attr| be_u16(attr.value)),
	}
}

/// What a `VXLAN` reports about itself.
///
/// Only what netcfgd can set. Two of the four cannot be corrected once the
/// device exists -- the kernel refuses a changed `id` and refuses the `port`
/// even at the value it already has -- and they are read anyway, because the
/// plan's job is to say that they differ.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct VxlanInfo {
	/// The VXLAN network identifier.
	pub id: Option<u32>,
	/// Index of the underlay device, which lives in the nest for this kind alone.
	pub link: Option<u32>,
	/// Source address for the outer header.
	pub local: Option<IpAddr>,
	/// Remote unicast address, or the multicast group.
	pub remote: Option<IpAddr>,
	/// Destination UDP port.
	pub port: Option<u16>,
}

/// The `VXLAN` attributes, numbered as `if_link.h` numbers them.
///
/// The v4 and v6 endpoints are different attributes rather than one attribute
/// with two lengths, so both numbers are read and whichever arrived is the
/// answer.
mod ifla_vxlan {
	pub(super) const ID: u16 = 1;
	pub(super) const GROUP: u16 = 2;
	pub(super) const LINK: u16 = 3;
	pub(super) const LOCAL: u16 = 4;
	pub(super) const PORT: u16 = 15;
	pub(super) const GROUP6: u16 = 16;
	pub(super) const LOCAL6: u16 = 17;
}

/// Decode a `VXLAN`'s `INFO_DATA`.
fn vxlan_info(data: &[u8]) -> VxlanInfo {
	let attrs = Attrs::new(data);
	let either = |v4: u16, v6: u16| {
		attrs
			.get(v4)
			.or_else(|| attrs.get(v6))
			.and_then(|attr| attr.ip())
			// An all-zero endpoint is how the kernel spells "none", and it
			// reports one for a VXLAN that was given neither -- so it is read as
			// absence rather than as the address 0.0.0.0, which the document
			// cannot say and nothing would match.
			.filter(|address| !address.is_unspecified())
	};
	VxlanInfo {
		id: attrs.get(ifla_vxlan::ID).and_then(|attr| attr.u32()),
		link: attrs.get(ifla_vxlan::LINK).and_then(|attr| attr.u32()),
		local: either(ifla_vxlan::LOCAL, ifla_vxlan::LOCAL6),
		remote: either(ifla_vxlan::GROUP, ifla_vxlan::GROUP6),
		// Big-endian, like every port number on the wire.
		port: attrs
			.get(ifla_vxlan::PORT)
			.and_then(|attr| be_u16(attr.value)),
	}
}

/// Which attribute numbering a tunnel kind's `INFO_DATA` uses.
///
/// Three families for seven kinds, and reading one with another's constants is
/// how a tunnel comes to report somebody else's field: GRE puts its endpoints at
/// 6 and 7 where an ip tunnel has them at 2 and 3, and geneve puts its VNI at 1
/// where GRE has a flags word.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TunnelFamily {
	/// `IFLA_GRE_*`: gre, gretap and ip6gre.
	Gre,
	/// `IFLA_IPTUN_*`: ipip, sit and ip6tnl.
	IpTunnel,
	/// `IFLA_GENEVE_*`, numbered on its own.
	Geneve,
}

/// Which family a kernel link kind belongs to, for the kinds netcfgd builds.
///
/// Matched exactly rather than by substring. The writing half asks whether the
/// kind contains `gre`, which is safe there because it is only ever handed one
/// of seven names netcfgd chose; here the string comes from the kernel and could
/// be any link kind on the machine, and a kind this does not know is one nothing
/// is compared for.
#[must_use]
pub fn tunnel_family(kind: &str) -> Option<TunnelFamily> {
	match kind {
		"gre" | "gretap" | "ip6gre" => Some(TunnelFamily::Gre),
		"ipip" | "sit" | "ip6tnl" => Some(TunnelFamily::IpTunnel),
		"geneve" => Some(TunnelFamily::Geneve),
		_ => None,
	}
}

/// What a point-to-point tunnel reports about itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct TunnelInfo {
	/// Local endpoint.
	pub local: Option<IpAddr>,
	/// Remote endpoint.
	pub remote: Option<IpAddr>,
	/// Outer TTL, where the kind has one. Zero means inherit.
	pub ttl: Option<u8>,
	/// The GRE key, or a geneve tunnel's VNI, which netcfgd spells the same way.
	pub key: Option<u32>,
}

/// The GRE attributes, numbered as `if_link.h` numbers them.
mod ifla_gre {
	pub(super) const IFLAGS: u16 = 2;
	pub(super) const IKEY: u16 = 4;
	pub(super) const LOCAL: u16 = 6;
	pub(super) const REMOTE: u16 = 7;
	pub(super) const TTL: u16 = 8;
}

/// The ip tunnel attributes, which are numbered differently from GRE's.
mod ifla_iptun {
	pub(super) const LOCAL: u16 = 2;
	pub(super) const REMOTE: u16 = 3;
	pub(super) const TTL: u16 = 4;
}

/// The geneve attributes, numbered on their own again.
mod ifla_geneve {
	pub(super) const ID: u16 = 1;
	pub(super) const REMOTE: u16 = 2;
	pub(super) const TTL: u16 = 4;
	pub(super) const REMOTE6: u16 = 7;
}

/// `GRE_KEY`, the flag bit that says the key field means anything.
///
/// The kernel emits `IKEY` and `OKEY` whether or not the tunnel has a key, so a
/// zero there is ambiguous: it is either no key or the key `0`, which a document
/// may legitimately ask for. The flag is what distinguishes them, and reading it
/// is what keeps `key = 0` from differing from itself forever.
const GRE_KEY_FLAG: u16 = 0x2000;

/// Decode a tunnel's `INFO_DATA` with its own family's numbering.
fn tunnel_info(family: TunnelFamily, data: &[u8]) -> TunnelInfo {
	let attrs = Attrs::new(data);
	// An unset endpoint comes back as all zeroes rather than as an absent
	// attribute, and the document spells that `None`.
	let address = |kind: u16| {
		attrs
			.get(kind)
			.and_then(|attr| attr.ip())
			.filter(|address| !address.is_unspecified())
	};
	match family {
		TunnelFamily::Gre => TunnelInfo {
			local: address(ifla_gre::LOCAL),
			remote: address(ifla_gre::REMOTE),
			ttl: attrs.get(ifla_gre::TTL).and_then(|attr| attr.u8()),
			key: attrs
				.get(ifla_gre::IFLAGS)
				.and_then(|attr| be_u16(attr.value))
				.is_some_and(|flags| flags & GRE_KEY_FLAG != 0)
				.then(|| {
					attrs
						.get(ifla_gre::IKEY)
						.and_then(|attr| be_u32(attr.value))
				})
				.flatten(),
		},
		TunnelFamily::IpTunnel => TunnelInfo {
			local: address(ifla_iptun::LOCAL),
			remote: address(ifla_iptun::REMOTE),
			ttl: attrs.get(ifla_iptun::TTL).and_then(|attr| attr.u8()),
			// No such thing on an ip tunnel. `None` is "nothing to compare",
			// which is what the document's key means here too.
			key: None,
		},
		TunnelFamily::Geneve => TunnelInfo {
			// A geneve tunnel has no local endpoint netcfgd sets.
			local: None,
			remote: attrs
				.get(ifla_geneve::REMOTE)
				.or_else(|| attrs.get(ifla_geneve::REMOTE6))
				.and_then(|attr| attr.ip())
				.filter(|address| !address.is_unspecified()),
			ttl: attrs.get(ifla_geneve::TTL).and_then(|attr| attr.u8()),
			// The VNI, which netcfgd's model spells `key` because a geneve
			// tunnel needs one and there is no separate field for it.
			key: attrs.get(ifla_geneve::ID).and_then(|attr| attr.u32()),
		},
	}
}

/// A big-endian `u16` from an attribute's bytes.
///
/// Netlink is native-endian except where it carries something the wire defines,
/// which is why a port and a GRE flags word need this and a mode does not.
fn be_u16(value: &[u8]) -> Option<u16> {
	value.get(..2)?.try_into().ok().map(u16::from_be_bytes)
}

/// A big-endian `u32`, for a GRE key.
fn be_u32(value: &[u8]) -> Option<u32> {
	value.get(..4)?.try_into().ok().map(u32::from_be_bytes)
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

#[cfg(test)]
mod tests {
	use super::{bridge_info, ifla_br};

	/// One netlink attribute, padded to four bytes as the wire format requires.
	fn attr(kind: u16, payload: &[u8]) -> Vec<u8> {
		let len = u16::try_from(4 + payload.len()).expect("small");
		let mut out = len.to_ne_bytes().to_vec();
		out.extend_from_slice(&kind.to_ne_bytes());
		out.extend_from_slice(payload);
		while out.len() % 4 != 0 {
			out.push(0);
		}
		out
	}

	/// A bridge's priority is two bytes, and was read as four.
	///
	/// `IFLA_BR_PRIORITY` is a `__u16` in `if_link.h`, and the accessor for a
	/// `u32` needs four bytes or it returns nothing -- so this field read as
	/// absent on every kernel, always. Nothing noticed because the planner did
	/// not compare it; the moment it did, an apply set the priority and the
	/// observation still said `<absent>`, so the plan asked for it again for
	/// ever.
	///
	/// The `ageing_time` beside it is the control: a genuine `u32` in the same
	/// blob, so a test that read both as the same width would fail on one of
	/// them whichever width it chose.
	#[test]
	fn a_bridge_priority_is_two_bytes_wide() {
		let mut data = attr(ifla_br::AGEING_TIME, &30_000_u32.to_ne_bytes());
		data.extend(attr(ifla_br::PRIORITY, &200_u16.to_ne_bytes()));

		let info = bridge_info(&data);
		assert_eq!(info.priority, Some(200), "a two-byte priority was not read");
		assert_eq!(
			info.ageing_time,
			Some(30_000),
			"the u32 control did not read"
		);
	}
}
