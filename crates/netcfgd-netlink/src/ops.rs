//! The mutating half of rtnetlink.
//!
//! Every request here asks for an acknowledgement, so a failure surfaces as an
//! errno at the call site rather than as state that quietly did not change.
//! Nothing in this module is `unsafe`: the requests are built by `wire` and
//! handed to the socket, which is where the syscalls live.

use crate::socket::Netlink;
use crate::wire::{self, flags, ifa, ifla, msg_type, rta, AttrBuf};
use std::io;
use std::net::IpAddr;

/// `RTN_UNICAST`.
const RTN_UNICAST: u8 = 1;
/// `RT_TABLE_MAIN`.
pub const RT_TABLE_MAIN: u32 = 254;
/// `RT_TABLE_UNSPEC`, used when the real table id goes in `RTA_TABLE`.
const RT_TABLE_UNSPEC: u8 = 0;
/// `RT_SCOPE_UNIVERSE`.
const RT_SCOPE_UNIVERSE: u8 = 0;
/// `RT_SCOPE_LINK`.
const RT_SCOPE_LINK: u8 = 253;
/// `RTNH_F_ONLINK`.
const RTNH_F_ONLINK: u32 = 4;
/// `IFLA_INFO_DATA`, inside a `LINKINFO` nest.
const IFLA_INFO_DATA: u16 = 2;
/// `IFLA_VLAN_ID`, inside a vlan's `INFO_DATA`.
const IFLA_VLAN_ID: u16 = 1;
/// `IFLA_VLAN_PROTOCOL`. Big-endian on the wire, unlike almost everything
/// else here -- it carries an ethertype, and the kernel reads it as one.
const IFLA_VLAN_PROTOCOL: u16 = 5;
/// `IFLA_LINK`, the parent a virtual link rides on.
const IFLA_LINK: u16 = 5;
/// `IFLA_LINKINFO` sub-attributes for a bridge.
const IFLA_BR_FORWARD_DELAY: u16 = 1;
const IFLA_BR_STP_STATE: u16 = 5;
/// `IFLA_BOND_*`.
const IFLA_BOND_MODE: u16 = 1;
const IFLA_BOND_MIIMON: u16 = 3;
/// `IFLA_VXLAN_*`.
const IFLA_VXLAN_ID: u16 = 1;
const IFLA_VXLAN_GROUP: u16 = 2;
const IFLA_VXLAN_LOCAL: u16 = 4;
const IFLA_VXLAN_PORT: u16 = 15;
const IFLA_VXLAN_GROUP6: u16 = 16;
const IFLA_VXLAN_LOCAL6: u16 = 17;
/// `VETH_INFO_PEER`, whose payload is a whole nested `ifinfomsg` plus
/// attributes rather than a plain value -- veth is the one link type created
/// two-at-a-time, so the peer's entire definition rides inside the first.
const VETH_INFO_PEER: u16 = 1;
/// `IFF_UP`, from `net/if.h`.
const IFF_UP: u32 = 0x1;

/// What kind of link to create.
///
/// Only the kinds this build can actually construct. Anything else is refused
/// by name rather than attempted and half-made.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NewLink {
	/// A bridge.
	Bridge,
	/// A dummy interface.
	Dummy,
	/// A VLAN on `parent`.
	Vlan {
		/// Index of the parent interface.
		parent: u32,
		/// VLAN id.
		id: u16,
		/// Tag protocol identifier, as an ethertype: `0x8100` or `0x88a8`.
		protocol: u16,
	},
	/// A bond.
	Bond {
		/// Bonding mode, as the kernel numbers them.
		mode: u8,
		/// Link monitoring interval in milliseconds.
		miimon: Option<u32>,
	},
	/// A VXLAN.
	Vxlan {
		/// VXLAN network identifier.
		id: u32,
		/// Index of the underlay interface, where one is named.
		parent: Option<u32>,
		/// Source address for the outer header.
		local: Option<std::net::IpAddr>,
		/// Remote unicast address, or the multicast group.
		remote: Option<std::net::IpAddr>,
		/// Destination UDP port.
		port: Option<u16>,
	},
	/// A veth pair. Creating one end creates both.
	Veth {
		/// The name of the other end.
		peer: String,
	},
}

/// Bridge attributes, applied after creation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct BridgeAttrs {
	/// Spanning tree.
	pub stp: bool,
	/// Forward delay in seconds.
	pub forward_delay: Option<u32>,
}

impl NewLink {
	/// The `IFLA_INFO_DATA` nest for this kind, where it has one.
	fn info_data(&self, name: &str) -> Option<AttrBuf> {
		let mut data = AttrBuf::new();
		match self {
			Self::Bridge | Self::Dummy => return None,
			Self::Vlan { id, protocol, .. } => {
				data.push(IFLA_VLAN_ID, &id.to_ne_bytes());
				// Big-endian: it is an ethertype, and the kernel reads it as
				// one. Sending it native-endian is refused outright -- the
				// kernel knows only 0x8100 and 0x88a8 and rejects the
				// byte-swapped values -- so this fails loudly rather than
				// producing a link that tags with nonsense. Verified by
				// sending the wrong one.
				data.push(IFLA_VLAN_PROTOCOL, &protocol.to_be_bytes());
			}
			Self::Bond { mode, miimon } => {
				data.push_u8(IFLA_BOND_MODE, *mode);
				if let Some(interval) = miimon {
					data.push_u32(IFLA_BOND_MIIMON, *interval);
				}
			}
			Self::Vxlan {
				id,
				local,
				remote,
				port,
				..
			} => {
				data.push_u32(IFLA_VXLAN_ID, *id);
				// The v4 and v6 attributes are different numbers, so the
				// family decides which one is sent rather than the value being
				// coerced into a single field.
				if let Some(address) = local {
					data.push_ip(
						if address.is_ipv6() {
							IFLA_VXLAN_LOCAL6
						} else {
							IFLA_VXLAN_LOCAL
						},
						*address,
					);
				}
				if let Some(address) = remote {
					data.push_ip(
						if address.is_ipv6() {
							IFLA_VXLAN_GROUP6
						} else {
							IFLA_VXLAN_GROUP
						},
						*address,
					);
				}
				if let Some(port) = port {
					// Big-endian, like every port number on the wire.
					data.push(IFLA_VXLAN_PORT, &port.to_be_bytes());
				}
			}
			Self::Veth { peer } => {
				// The peer's whole definition, not just its name: an
				// `ifinfomsg` followed by its own attributes, nested inside
				// this one. veth is the only link type created in pairs and
				// this is why its encoding looks unlike the others.
				let mut peer_attrs = AttrBuf::new();
				peer_attrs.push_str(ifla::IFNAME, peer);

				let mut nested = Vec::new();
				wire::IfInfo::default().encode(&mut nested);
				nested.extend_from_slice(peer_attrs.as_bytes());
				data.push(VETH_INFO_PEER, &nested);

				let _ = name;
			}
		}
		Some(data)
	}

	fn kind_name(&self) -> &'static str {
		match self {
			Self::Bridge => "bridge",
			Self::Dummy => "dummy",
			Self::Vlan { .. } => "vlan",
			Self::Bond { .. } => "bond",
			Self::Vxlan { .. } => "vxlan",
			Self::Veth { .. } => "veth",
		}
	}
}

/// Parse `de:ad:be:ef:00:01`.
///
/// # Errors
///
/// Returns `InvalidInput` for anything that is not six colon-separated hex
/// octets.
pub fn parse_mac(text: &str) -> io::Result<[u8; 6]> {
	let mut out = [0_u8; 6];
	let mut parts = text.split(':');
	for slot in &mut out {
		let part = parts
			.next()
			.ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "mac is too short"))?;
		*slot = u8::from_str_radix(part, 16)
			.map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "mac has a bad octet"))?;
	}
	if parts.next().is_some() {
		return Err(io::Error::new(
			io::ErrorKind::InvalidInput,
			"mac is too long",
		));
	}
	Ok(out)
}

/// The flags a change request carries: acknowledge it, so failure is visible.
const fn ack_flags() -> u16 {
	flags::NLM_F_REQUEST | flags::NLM_F_ACK
}

impl Netlink {
	/// Add an address, stamped with netcfgd's protocol tag.
	///
	/// The tag is what makes the address ours for drift detection. A kernel
	/// before 5.18 ignores the unknown attribute, which is exactly the
	/// read-back decision 0002 relies on: the next dump says which happened.
	///
	/// # Errors
	///
	/// Returns the errno the kernel replied with.
	pub fn add_address(
		&mut self,
		index: u32,
		address: IpAddr,
		prefix_len: u8,
		proto: u8,
	) -> io::Result<()> {
		let mut body = Vec::new();
		wire::IfAddr {
			family: family_of(address),
			prefix_len,
			flags: 0,
			scope: 0,
			index,
		}
		.encode(&mut body);

		let mut attrs = AttrBuf::new();
		// IFA_LOCAL is this host's address. IFA_ADDRESS must be sent too, and
		// for anything but a point-to-point link it is the same value.
		attrs.push_ip(ifa::LOCAL, address);
		attrs.push_ip(ifa::ADDRESS, address);
		attrs.push_u8(ifa::PROTO, proto);

		self.request(
			msg_type::RTM_NEWADDR,
			ack_flags() | flags::NLM_F_CREATE | flags::NLM_F_REPLACE,
			&body,
			&attrs,
		)?;
		Ok(())
	}

	/// Remove an address.
	///
	/// # Errors
	///
	/// Returns the errno the kernel replied with.
	pub fn del_address(&mut self, index: u32, address: IpAddr, prefix_len: u8) -> io::Result<()> {
		let mut body = Vec::new();
		wire::IfAddr {
			family: family_of(address),
			prefix_len,
			flags: 0,
			scope: 0,
			index,
		}
		.encode(&mut body);

		let mut attrs = AttrBuf::new();
		attrs.push_ip(ifa::LOCAL, address);
		attrs.push_ip(ifa::ADDRESS, address);

		self.request(msg_type::RTM_DELADDR, ack_flags(), &body, &attrs)?;
		Ok(())
	}

	/// Install a route, stamped with netcfgd's protocol tag.
	///
	/// # Errors
	///
	/// Returns the errno the kernel replied with.
	#[allow(clippy::too_many_arguments)]
	pub fn add_route(&mut self, route: &RouteSpec) -> io::Result<()> {
		self.route_request(
			route,
			msg_type::RTM_NEWROUTE,
			ack_flags() | flags::NLM_F_CREATE,
		)
	}

	/// Remove a route.
	///
	/// # Errors
	///
	/// Returns the errno the kernel replied with.
	pub fn del_route(&mut self, route: &RouteSpec) -> io::Result<()> {
		self.route_request(route, msg_type::RTM_DELROUTE, ack_flags())
	}

	fn route_request(
		&mut self,
		route: &RouteSpec,
		kind: u16,
		request_flags: u16,
	) -> io::Result<()> {
		let family = route
			.destination
			.map_or_else(|| route.gateway.map_or(2, family_of), family_of);

		// A table id above 255 does not fit rtm_table and goes in RTA_TABLE
		// instead, with the byte set to unspec so the kernel knows to look.
		let (table_byte, table_attr) = if route.table <= 255 {
			#[allow(clippy::cast_possible_truncation)]
			(route.table as u8, None)
		} else {
			(RT_TABLE_UNSPEC, Some(route.table))
		};

		let mut body = Vec::new();
		wire::RtMsg {
			family,
			dst_len: route.dst_len,
			src_len: 0,
			tos: 0,
			table: table_byte,
			protocol: route.proto,
			// A route with a gateway reaches beyond the link; one without is
			// on the link itself, and the kernel rejects it at universe scope.
			scope: if route.gateway.is_some() {
				RT_SCOPE_UNIVERSE
			} else {
				RT_SCOPE_LINK
			},
			kind: RTN_UNICAST,
			flags: if route.onlink { RTNH_F_ONLINK } else { 0 },
		}
		.encode(&mut body);

		let mut attrs = AttrBuf::new();
		if let Some(destination) = route.destination {
			attrs.push_ip(rta::DST, destination);
		}
		if let Some(gateway) = route.gateway {
			attrs.push_ip(rta::GATEWAY, gateway);
		}
		attrs.push_u32(rta::OIF, route.index);
		if let Some(metric) = route.metric {
			attrs.push_u32(rta::PRIORITY, metric);
		}
		if let Some(source) = route.source {
			attrs.push_ip(rta::PREFSRC, source);
		}
		if let Some(table) = table_attr {
			attrs.push_u32(rta::TABLE, table);
		}

		self.request(kind, request_flags, &body, &attrs)?;
		Ok(())
	}

	/// Bring a link up or down.
	///
	/// # Errors
	///
	/// Returns the errno the kernel replied with.
	pub fn set_link_up(&mut self, index: u32, up: bool) -> io::Result<()> {
		let mut body = Vec::new();
		wire::IfInfo {
			family: 0,
			kind: 0,
			index: i32::try_from(index).unwrap_or(0),
			flags: if up { IFF_UP } else { 0 },
			// `change` is the mask of which flag bits this message sets, and
			// omitting it is how a request to bring one interface up silently
			// clears every other flag.
			change: IFF_UP,
		}
		.encode(&mut body);

		self.request(msg_type::RTM_NEWLINK, ack_flags(), &body, &AttrBuf::new())?;
		Ok(())
	}

	/// Set an attribute that lives on the link itself.
	fn set_link_attr(&mut self, index: u32, attrs: &AttrBuf) -> io::Result<()> {
		let mut body = Vec::new();
		wire::IfInfo {
			family: 0,
			kind: 0,
			index: i32::try_from(index).unwrap_or(0),
			flags: 0,
			change: 0,
		}
		.encode(&mut body);
		self.request(msg_type::RTM_NEWLINK, ack_flags(), &body, attrs)?;
		Ok(())
	}

	/// Set the MTU.
	///
	/// # Errors
	///
	/// Returns the errno the kernel replied with.
	pub fn set_link_mtu(&mut self, index: u32, mtu: u32) -> io::Result<()> {
		let mut attrs = AttrBuf::new();
		attrs.push_u32(ifla::MTU, mtu);
		self.set_link_attr(index, &attrs)
	}

	/// Set the hardware address.
	///
	/// # Errors
	///
	/// Returns the errno the kernel replied with.
	pub fn set_link_mac(&mut self, index: u32, mac: [u8; 6]) -> io::Result<()> {
		let mut attrs = AttrBuf::new();
		attrs.push(ifla::ADDRESS, &mac);
		self.set_link_attr(index, &attrs)
	}

	/// Enslave to a master, or release when `master` is `None`.
	///
	/// # Errors
	///
	/// Returns the errno the kernel replied with.
	pub fn set_link_master(&mut self, index: u32, master: Option<u32>) -> io::Result<()> {
		let mut attrs = AttrBuf::new();
		// Master index zero is how netlink spells "no master".
		attrs.push_u32(ifla::MASTER, master.unwrap_or(0));
		self.set_link_attr(index, &attrs)
	}

	/// Create a link.
	///
	/// # Errors
	///
	/// Returns the errno the kernel replied with.
	pub fn create_link(&mut self, name: &str, kind: &NewLink) -> io::Result<()> {
		let mut info = AttrBuf::new();
		info.push_str(ifla::INFO_KIND, kind.kind_name());
		if let Some(data) = kind.info_data(name) {
			info.push(IFLA_INFO_DATA, data.as_bytes());
		}

		let mut attrs = AttrBuf::new();
		attrs.push_str(ifla::IFNAME, name);
		// The parent a virtual link rides on. A vlan must have one; a vxlan
		// may, and without it the kernel routes the underlay itself.
		if let NewLink::Vlan { parent, .. }
		| NewLink::Vxlan {
			parent: Some(parent),
			..
		} = kind
		{
			attrs.push_u32(IFLA_LINK, *parent);
		}
		attrs.push(ifla::LINKINFO, info.as_bytes());

		let mut body = Vec::new();
		wire::IfInfo::default().encode(&mut body);

		self.request(
			msg_type::RTM_NEWLINK,
			ack_flags() | flags::NLM_F_CREATE | flags::NLM_F_EXCL,
			&body,
			&attrs,
		)?;
		Ok(())
	}

	/// Set bridge attributes on an existing bridge.
	///
	/// Separate from creation because they are separately reconcilable: a
	/// bridge that exists with the wrong forward delay should be corrected,
	/// not deleted and remade, and deleting a bridge takes its members down
	/// with it.
	///
	/// # Errors
	///
	/// Returns the errno the kernel replied with.
	pub fn set_bridge_attrs(&mut self, index: u32, attrs: BridgeAttrs) -> io::Result<()> {
		let mut data = AttrBuf::new();
		data.push_u32(IFLA_BR_STP_STATE, u32::from(attrs.stp));
		if let Some(delay) = attrs.forward_delay {
			// The kernel counts forward delay in hundredths of a second, and
			// the config counts it in seconds because that is what every other
			// tool and every piece of documentation uses.
			data.push_u32(IFLA_BR_FORWARD_DELAY, delay.saturating_mul(100));
		}

		let mut info = AttrBuf::new();
		info.push_str(ifla::INFO_KIND, "bridge");
		info.push(IFLA_INFO_DATA, data.as_bytes());

		let mut outer = AttrBuf::new();
		outer.push(ifla::LINKINFO, info.as_bytes());

		let mut body = Vec::new();
		wire::IfInfo {
			index: i32::try_from(index).unwrap_or(0),
			..wire::IfInfo::default()
		}
		.encode(&mut body);

		self.request(msg_type::RTM_NEWLINK, ack_flags(), &body, &outer)?;
		Ok(())
	}

	/// Delete a link.
	///
	/// # Errors
	///
	/// Returns the errno the kernel replied with.
	pub fn delete_link(&mut self, index: u32) -> io::Result<()> {
		let mut body = Vec::new();
		wire::IfInfo {
			index: i32::try_from(index).unwrap_or(0),
			..wire::IfInfo::default()
		}
		.encode(&mut body);
		self.request(msg_type::RTM_DELLINK, ack_flags(), &body, &AttrBuf::new())?;
		Ok(())
	}
}

/// Everything needed to install or remove one route.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteSpec {
	/// Output interface index.
	pub index: u32,
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
	pub source: Option<IpAddr>,
	/// Protocol tag.
	pub proto: u8,
	/// Whether the gateway is reachable without a covering address.
	pub onlink: bool,
}

/// `AF_INET` or `AF_INET6`, as the kernel numbers them.
fn family_of(address: IpAddr) -> u8 {
	if address.is_ipv4() {
		2
	} else {
		10
	}
}
