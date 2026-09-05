//! The mutating half of rtnetlink.
//!
//! Every request here asks for an acknowledgement, so a failure surfaces as an
//! errno at the call site rather than as state that quietly did not change.
//! Nothing in this module is `unsafe`: the requests are built by `wire` and
//! handed to the socket, which is where the syscalls live.

use crate::dump;
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
const IFLA_BR_HELLO_TIME: u16 = 2;
const IFLA_BR_AGEING_TIME: u16 = 4;
const IFLA_BR_STP_STATE: u16 = 5;
const IFLA_BR_PRIORITY: u16 = 6;
const IFLA_BR_VLAN_FILTERING: u16 = 7;
/// `IFLA_BOND_*`.
const IFLA_BOND_MODE: u16 = 1;
const IFLA_BOND_MIIMON: u16 = 3;
/// `IFLA_VXLAN_*`.
const IFLA_VXLAN_ID: u16 = 1;
const IFLA_VXLAN_GROUP: u16 = 2;
/// The underlay device, which for a `VXLAN` is **inside** the `INFO_DATA` nest
/// and not the outer `IFLA_LINK` every other kind here uses.
///
/// Measured, after the outer one was sent for as long as VXLANs have existed
/// and did nothing at all: `vxlan_nl2conf` reads `data[IFLA_VXLAN_LINK]` and
/// nothing reads `tb[IFLA_LINK]`, so a document naming a parent got a VXLAN
/// whose outer packets the kernel routed itself. `ip` shows the difference in
/// one word -- its VXLAN says `dev base0` and netcfgd's said nothing.
const IFLA_VXLAN_LINK: u16 = 3;
const IFLA_VXLAN_LOCAL: u16 = 4;
const IFLA_VXLAN_PORT: u16 = 15;
const IFLA_VXLAN_GROUP6: u16 = 16;
const IFLA_VXLAN_LOCAL6: u16 = 17;
/// `IFLA_VRF_TABLE`.
const IFLA_VRF_TABLE: u16 = 1;
/// `IFLA_MACVLAN_MODE`.
const IFLA_MACVLAN_MODE: u16 = 1;
/// `IFLA_IPTUN_*`, for ipip, sit and ip6tnl.
///
/// `LINK` is the underlay device, in the nest for the reason a `VXLAN`'s is:
/// the kernel reads it from here and reports it in the outer `IFLA_LINK`, which
/// is what makes `ip link show` print `tun0@base0` for a tunnel whose parent was
/// never sent as an outer attribute.
const IFLA_IPTUN_LINK: u16 = 1;
const IFLA_IPTUN_LOCAL: u16 = 2;
const IFLA_IPTUN_REMOTE: u16 = 3;
const IFLA_IPTUN_TTL: u16 = 4;

/// `IFLA_GRE_*`, which are numbered differently from the ip tunnels.
///
/// They do not share numbering, and assuming they did is how the first version
/// of this failed: GRE puts its flags and keys at 2..5 and the endpoints at
/// 6 and 7, where an ip tunnel has the endpoints at 2 and 3. Sending an ip
/// tunnel's numbering to GRE puts the local address in `IFLA_GRE_IFLAGS` and
/// the kernel answers `EINVAL`.
const IFLA_GRE_LINK: u16 = 1;
const IFLA_GRE_IFLAGS: u16 = 2;
const IFLA_GRE_OFLAGS: u16 = 3;
const IFLA_GRE_IKEY: u16 = 4;
const IFLA_GRE_OKEY: u16 = 5;
const IFLA_GRE_LOCAL: u16 = 6;
const IFLA_GRE_REMOTE: u16 = 7;
const IFLA_GRE_TTL: u16 = 8;

/// `GRE_KEY`, the flag that says a key is present.
///
/// GRE carries a key only if the corresponding flag bit is set in `IFLAGS` and
/// `OFLAGS`. Setting the key alone produces a tunnel that silently ignores it,
/// which is worse than an error: two ends configured with different keys would
/// pass traffic anyway.
const GRE_KEY_FLAG: u16 = 0x2000;
/// `IFLA_GENEVE_ID` and `REMOTE`, which are numbered on their own.
const IFLA_GENEVE_ID: u16 = 1;
const IFLA_GENEVE_REMOTE: u16 = 2;
// **3, not 4. 4 is `IFLA_GENEVE_TOS`.** Checked against this machine's
// `/usr/include/linux/if_link.h`: the enum runs UNSPEC, ID, REMOTE, TTL, TOS,
// PORT, COLLECT_METADATA, REMOTE6 -- and `REMOTE6 = 7` below pins the
// numbering, so there is no off-by-one anywhere else in the group.
//
// The reader carried the same wrong number, so a geneve tunnel's `ttl` was
// written into the outer DSCP, the read-back agreed with it, and the plan
// converged silently: no drift, no error, and `ip -d link show` reporting
// `tos 0x40` with no ttl at all. Two wrong halves round-tripping is a state no
// comparison in this codebase can see, which is why the constant is checked
// against the header rather than against ourselves.
const IFLA_GENEVE_TTL: u16 = 3;
const IFLA_GENEVE_REMOTE6: u16 = 7;

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
	/// An intermediate functional block, which exists to be redirected to.
	///
	/// The kernel cannot shape traffic on the way in -- there is no queue to
	/// hold it, because the packets have already arrived. An `ifb` is the
	/// standard way round that: received traffic is redirected onto it, where
	/// it becomes egress and can be queued like anything else.
	Ifb,
	/// A veth pair. Creating one end creates both.
	Veth {
		/// The name of the other end.
		peer: String,
	},
	/// A VRF master owning a routing table.
	Vrf {
		/// The table its members' routes go into.
		table: u32,
	},
	/// A macvlan on `parent`.
	Macvlan {
		/// Index of the interface it sits on.
		parent: u32,
		/// The kernel's mode number.
		mode: u32,
	},
	/// A point-to-point tunnel.
	Tunnel(TunnelSpec),
	/// A `WireGuard` device.
	///
	/// The link is ordinary rtnetlink; everything that makes it a tunnel --
	/// keys, peers, allowed IPs -- goes over generic netlink afterwards. See
	/// [`crate::wg`].
	WireGuard,
}

/// What a point-to-point tunnel is made of.
///
/// A struct rather than six fields in the variant, for the reason [`VlanChange`]
/// is one: the encoder below needs all of them, and two of the six are addresses
/// of the same type -- the pair a transposition would swap without the compiler
/// noticing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TunnelSpec {
	/// The kernel's name for the encapsulation.
	pub kind: &'static str,
	/// Index of the underlay interface, where one is named.
	///
	/// Sent inside the tunnel's own `INFO_DATA` nest, which is where the kernel
	/// reads it -- not the outer `IFLA_LINK`, which it ignores.
	pub parent: Option<u32>,
	/// Local endpoint.
	pub local: Option<std::net::IpAddr>,
	/// Remote endpoint.
	pub remote: Option<std::net::IpAddr>,
	/// Outer TTL.
	pub ttl: Option<u8>,
	/// GRE key, or a geneve tunnel's VNI, where the kind has one.
	pub key: Option<u32>,
}

/// One change to a bridge VLAN.
///
/// A struct rather than five positional booleans: `set_bridge_vlan(i, 10,
/// true, true, false, true)` is a line nobody can read, and three of those
/// five mean something different if transposed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VlanChange {
	/// The VLAN id.
	pub vid: u16,
	/// Untagged ingress joins this VLAN.
	pub pvid: bool,
	/// Egress leaves untagged.
	pub untagged: bool,
	/// The bridge device itself rather than a port.
	pub on_self: bool,
	/// Adding rather than removing.
	pub add: bool,
}

/// Bridge attributes, applied after creation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct BridgeAttrs {
	/// Spanning tree.
	pub stp: bool,
	/// Forward delay in seconds.
	pub forward_delay: Option<u32>,
	/// Hello interval in seconds.
	pub hello_time: Option<u32>,
	/// Address ageing time in seconds.
	pub ageing_time: Option<u32>,
	/// Bridge priority.
	pub priority: Option<u16>,
	/// Whether the bridge is VLAN-aware.
	pub vlan_filtering: bool,
}

/// The `INFO_DATA` for a tunnel.
///
/// Its own function only because the three attribute families -- geneve, GRE
/// and the ip tunnels -- disagree about numbering, and saying so takes more
/// room than the code does.
fn tunnel_data(data: &mut AttrBuf, tunnel: &TunnelSpec, changing: bool) {
	let TunnelSpec {
		kind,
		parent,
		local,
		remote,
		ttl,
		key,
	} = *tunnel;
	// geneve numbers its attributes independently of the ip/gre
	// family, so it cannot share the block below -- and using the
	// wrong numbers produces a tunnel the kernel accepts with the
	// remote landing in a field that means something else.
	if kind == "geneve" {
		// A geneve tunnel has no underlay device: there is no attribute for one
		// in its family, and `ip` offers no `dev` for it either. A document that
		// names a parent for one is refused at compile time rather than silently
		// dropped here.
		let _ = parent;
		// A geneve tunnel needs a VNI; the model has no separate
		// field for one, so the GRE key doubles as it. Named here
		// because that reuse is not obvious from the config.
		//
		// Left out on a change, because the kernel refuses a VNI that differs
		// and refuses it as the whole message -- which would take the remote
		// beside it down too. A geneve keeps what a change request leaves out
		// (measured), so omitting it is not the same as clearing it, and the
		// planner is what says the VNI has moved.
		if !changing {
			data.push_u32(IFLA_GENEVE_ID, key.unwrap_or(0));
		}
		if let Some(address) = remote {
			data.push_ip(
				if address.is_ipv6() {
					IFLA_GENEVE_REMOTE6
				} else {
					IFLA_GENEVE_REMOTE
				},
				address,
			);
		}
		if let Some(ttl) = ttl {
			data.push_u8(IFLA_GENEVE_TTL, ttl);
		}
	} else if kind.contains("gre") {
		if let Some(parent) = parent {
			data.push_u32(IFLA_GRE_LINK, parent);
		}
		if let Some(key) = key {
			// The flags first: a key with no flag bit is ignored,
			// and two ends with different keys would then pass
			// traffic as though neither had one. One key both
			// ways -- separate in and out keys exist and nothing
			// has asked for them.
			data.push(IFLA_GRE_IFLAGS, &GRE_KEY_FLAG.to_be_bytes());
			data.push(IFLA_GRE_OFLAGS, &GRE_KEY_FLAG.to_be_bytes());
			data.push(IFLA_GRE_IKEY, &key.to_be_bytes());
			data.push(IFLA_GRE_OKEY, &key.to_be_bytes());
		}
		if let Some(address) = local {
			data.push_ip(IFLA_GRE_LOCAL, address);
		}
		if let Some(address) = remote {
			data.push_ip(IFLA_GRE_REMOTE, address);
		}
		if let Some(ttl) = ttl {
			data.push_u8(IFLA_GRE_TTL, ttl);
		}
	} else {
		if let Some(parent) = parent {
			data.push_u32(IFLA_IPTUN_LINK, parent);
		}
		if let Some(address) = local {
			data.push_ip(IFLA_IPTUN_LOCAL, address);
		}
		if let Some(address) = remote {
			data.push_ip(IFLA_IPTUN_REMOTE, address);
		}
		if let Some(ttl) = ttl {
			data.push_u8(IFLA_IPTUN_TTL, ttl);
		}
	}
}

impl NewLink {
	/// The `IFLA_INFO_DATA` nest for this kind, where it has one.
	///
	/// `changing` says whether this nest is for a device that already exists.
	/// Three attributes come out when it is set, and every one was measured
	/// rather than assumed: a VXLAN's `port`, which the kernel refuses **whether
	/// or not the value differs** -- `vxlan_nl2conf` answers `EOPNOTSUPP` on the
	/// attribute's presence, so a nest carrying it can never correct a remote --
	/// and a VXLAN's `id` and a geneve tunnel's, which are refused when they
	/// differ and would take the endpoint beside them down with them. Decision
	/// 0058.
	fn info_data(&self, name: &str, changing: bool) -> Option<AttrBuf> {
		let mut data = AttrBuf::new();
		match self {
			Self::Bridge | Self::Dummy | Self::WireGuard | Self::Ifb => return None,
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
				parent,
				local,
				remote,
				port,
			} => {
				// Left out on a change, for the reason the port below is and
				// with one difference: the kernel refuses a VNI only when the
				// value differs, so restating the current one would work. It is
				// omitted anyway, because a VXLAN keeps what a change request
				// leaves out (measured) and because sending a value whose only
				// acceptable form is "the same as now" says nothing.
				if !changing {
					data.push_u32(IFLA_VXLAN_ID, *id);
				}
				// The underlay, which goes here and not in the outer
				// `IFLA_LINK` -- see the constant. The kernel takes it on a
				// change too, so this one is not conditional on `changing`.
				if let Some(parent) = parent {
					data.push_u32(IFLA_VXLAN_LINK, *parent);
				}
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
				// Only when the device is being made. On a change the kernel
				// refuses this attribute's presence outright, at any value, and
				// takes the whole message down with it.
				if let (Some(port), false) = (port, changing) {
					// Big-endian, like every port number on the wire.
					data.push(IFLA_VXLAN_PORT, &port.to_be_bytes());
				}
			}
			Self::Vrf { table } => data.push_u32(IFLA_VRF_TABLE, *table),
			Self::Macvlan { mode, .. } => data.push_u32(IFLA_MACVLAN_MODE, *mode),
			Self::Tunnel(tunnel) => tunnel_data(&mut data, tunnel, changing),
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
			Self::Ifb => "ifb",
			Self::Veth { .. } => "veth",
			Self::WireGuard => "wireguard",
			Self::Vrf { .. } => "vrf",
			Self::Macvlan { .. } => "macvlan",
			Self::Tunnel(tunnel) => tunnel.kind,
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
		if let Some(data) = kind.info_data(name, false) {
			info.push(IFLA_INFO_DATA, data.as_bytes());
		}

		let mut attrs = AttrBuf::new();
		attrs.push_str(ifla::IFNAME, name);
		// The parent a virtual link rides on -- for the two kinds that read it
		// here. A VLAN must have one and a macvlan must have one, and both take
		// it as the outer `IFLA_LINK`.
		//
		// A VXLAN and a tunnel do not: their underlay is an attribute inside
		// their own `INFO_DATA` nest, and the outer one is ignored. It was sent
		// there for as long as both kinds have existed, so `parent = "base0"` on
		// either produced a device with no underlay at all and nothing said so.
		if let NewLink::Vlan { parent, .. } | NewLink::Macvlan { parent, .. } = kind {
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

	/// Give a link an alternative name.
	///
	/// netcfgd uses this to mark the links it creates, so that ownership is
	/// legible from the kernel rather than only from `/run` -- decision 0136,
	/// which is decision 0002's argument applied to the object kind that has
	/// no protocol field to stamp.
	///
	/// The property list is add-and-remove rather than set, so this takes its
	/// own message type: `IFLA_PROP_LIST` sent on an ordinary `RTM_NEWLINK` is
	/// ignored, which is the kind of silence that produces a marker nobody
	/// notices is missing.
	///
	/// # Errors
	///
	/// Returns the errno the kernel replied with. `EEXIST` means the name is
	/// already taken -- alternative names share the lookup namespace with real
	/// ones -- and the caller decides whether that is fatal. For netcfgd it is
	/// not: an unmarked link falls back to the recorded state, which is where
	/// it was before this existed.
	pub fn add_altname(&mut self, index: u32, altname: &str) -> io::Result<()> {
		if altname.is_empty() || altname.len() >= wire::ALT_IFNAME_MAX {
			return Err(io::Error::new(
				io::ErrorKind::InvalidInput,
				format!(
					"an alternative name must be 1 to {} bytes, not {}",
					wire::ALT_IFNAME_MAX - 1,
					altname.len()
				),
			));
		}

		let mut props = AttrBuf::new();
		props.push_str(ifla::ALT_IFNAME, altname);

		let mut attrs = AttrBuf::new();
		attrs.push(ifla::PROP_LIST | wire::NLA_F_NESTED, props.as_bytes());

		let mut body = Vec::new();
		wire::IfInfo {
			index: i32::try_from(index).unwrap_or(0),
			..wire::IfInfo::default()
		}
		.encode(&mut body);

		self.request(msg_type::RTM_NEWLINKPROP, ack_flags(), &body, &attrs)?;
		Ok(())
	}

	/// Re-send a kind's own settings to a device that already exists.
	///
	/// The same nest [`Netlink::create_link`] builds, through the same function,
	/// which is the property decision 0057 insisted on for a bridge: two
	/// encoders for one kind is how the create path and the correct-an-existing
	/// path come to disagree about what the kind is.
	///
	/// **The whole nest, not the field that moved.** Measured, because the
	/// families disagree: a request carrying only `IFLA_GRE_REMOTE` leaves a GRE
	/// tunnel with no local address, no TTL and no key, since `ipgre_netlink_parms`
	/// starts from a zeroed struct -- while a VXLAN and a geneve keep what the
	/// request leaves out. `ip` hides this by reading the device and refilling
	/// every field before it sends anything, so the obvious experiment says the
	/// kernel merges when it does not. Sending everything makes the device match
	/// what a freshly created one from the same document would be, under either
	/// rule.
	///
	/// Not for a bridge or a bond: their settings are not part of [`NewLink`] --
	/// a bridge takes none at creation -- and each has its own function above.
	///
	/// # Errors
	///
	/// Returns the errno the kernel replied with. `EINVAL` and `EOPNOTSUPP` are
	/// the interesting ones: they mean the kernel will not take an attribute on a
	/// device that exists, which the planner is meant to have said instead of
	/// asking for.
	pub fn set_link_kind(&mut self, index: u32, kind: &NewLink, name: &str) -> io::Result<()> {
		let mut info = AttrBuf::new();
		info.push_str(ifla::INFO_KIND, kind.kind_name());
		if let Some(data) = kind.info_data(name, true) {
			info.push(IFLA_INFO_DATA, data.as_bytes());
		}

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
		// The kernel counts these in hundredths of a second and the config
		// counts them in seconds, because that is what every other tool and
		// every piece of documentation uses. Ageing time is the same unit --
		// which is easy to miss, since it is the one measured in minutes by
		// habit.
		if let Some(delay) = attrs.forward_delay {
			data.push_u32(IFLA_BR_FORWARD_DELAY, delay.saturating_mul(100));
		}
		if let Some(hello) = attrs.hello_time {
			data.push_u32(IFLA_BR_HELLO_TIME, hello.saturating_mul(100));
		}
		if let Some(ageing) = attrs.ageing_time {
			data.push_u32(IFLA_BR_AGEING_TIME, ageing.saturating_mul(100));
		}
		if let Some(priority) = attrs.priority {
			data.push(IFLA_BR_PRIORITY, &priority.to_ne_bytes());
		}
		data.push_u8(IFLA_BR_VLAN_FILTERING, u8::from(attrs.vlan_filtering));

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

	/// Set a bond's mode and monitoring interval on a bond that exists.
	///
	/// The kernel takes both on a live bond, which was asked rather than
	/// assumed -- `ip link set bond0 type bond mode balance-rr` moves one, and
	/// the same shape of request on a VLAN succeeds and changes nothing.
	///
	/// # Errors
	///
	/// Returns the errno the kernel replied with.
	pub fn set_bond_attrs(
		&mut self,
		index: u32,
		mode: Option<u8>,
		miimon: Option<u32>,
	) -> io::Result<()> {
		let mut data = AttrBuf::new();
		// Left out where the caller says so, because the kernel takes a mode
		// only on a bond with no members and rejects the whole message
		// otherwise -- monitoring interval included.
		if let Some(mode) = mode {
			data.push_u8(IFLA_BOND_MODE, mode);
		}
		if let Some(interval) = miimon {
			data.push_u32(IFLA_BOND_MIIMON, interval);
		}

		let mut info = AttrBuf::new();
		info.push_str(ifla::INFO_KIND, "bond");
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

	/// Add or remove a VLAN on a bridge port, or on the bridge itself.
	///
	/// `on_self` picks which, and getting it backwards is the mistake this
	/// interface exists to make hard: a VLAN on a *port* is a MASTER
	/// operation, because the bridge is being told what that port carries. A
	/// VLAN on the *bridge device* is SELF, and is what lets the bridge
	/// terminate traffic in that VLAN itself.
	///
	/// # Errors
	///
	/// Returns the errno the kernel replied with. `EOPNOTSUPP` here almost
	/// always means the bridge does not have `vlan_filtering` on, in which
	/// case per-port VLANs are not a thing it has.
	pub fn set_bridge_vlan(&mut self, index: u32, vlan: VlanChange) -> io::Result<()> {
		let VlanChange {
			vid,
			pvid,
			untagged,
			on_self,
			add,
		} = vlan;
		let mut spec = AttrBuf::new();
		spec.push(
			dump::IFLA_BRIDGE_FLAGS,
			&if on_self {
				dump::BRIDGE_FLAGS_SELF
			} else {
				dump::BRIDGE_FLAGS_MASTER
			}
			.to_ne_bytes(),
		);

		// `struct bridge_vlan_info { __u16 flags; __u16 vid; }`, in that
		// order. Two little integers, and swapping them produces a request
		// for VLAN 0 with nonsense flags that the kernel may well accept.
		let mut flags = 0_u16;
		if pvid {
			flags |= dump::BRIDGE_VLAN_INFO_PVID;
		}
		if untagged {
			flags |= dump::BRIDGE_VLAN_INFO_UNTAGGED;
		}
		let mut vlan_info = Vec::with_capacity(4);
		vlan_info.extend_from_slice(&flags.to_ne_bytes());
		vlan_info.extend_from_slice(&vid.to_ne_bytes());
		spec.push(dump::IFLA_BRIDGE_VLAN_INFO, &vlan_info);

		let mut attrs = AttrBuf::new();
		attrs.push(dump::IFLA_AF_SPEC, spec.as_bytes());

		let mut body = Vec::new();
		wire::IfInfo {
			family: dump::AF_BRIDGE,
			index: i32::try_from(index).unwrap_or(0),
			..wire::IfInfo::default()
		}
		.encode(&mut body);

		let kind = if add {
			msg_type::RTM_SETLINK
		} else {
			msg_type::RTM_DELLINK
		};
		self.request(kind, ack_flags(), &body, &attrs)?;
		Ok(())
	}

	/// Set the IPv6 interface identifier, or clear it with `::`.
	///
	/// `ip token set ::5 dev eth0`. The prefix still comes from the router
	/// advertisement; this fixes the host half, which is the only way to have
	/// a predictable IPv6 address on a prefix that can change.
	///
	/// The kernel is particular about when it will accept one, and each
	/// refusal is `EINVAL` with nothing to distinguish it: the device must be
	/// up and ready, it must accept router advertisements, and its router
	/// solicitation count must be non-zero. A token on a device that forwards
	/// is therefore refused, because forwarding turns RA acceptance off --
	/// which is a real configuration somebody will write, since a router is
	/// exactly the machine you want at a predictable address.
	///
	/// # Errors
	///
	/// Returns the errno the kernel replied with.
	pub fn set_ipv6_token(&mut self, index: u32, token: std::net::IpAddr) -> io::Result<()> {
		let mut inet6 = AttrBuf::new();
		inet6.push_ip(dump::IFLA_INET6_TOKEN, token);

		// The family is the attribute *type* here, not a field: `IFLA_AF_SPEC`
		// holds one nest per address family, keyed by the family number.
		let mut spec = AttrBuf::new();
		spec.push(dump::AF_INET6, inet6.as_bytes());

		let mut attrs = AttrBuf::new();
		attrs.push(dump::IFLA_AF_SPEC, spec.as_bytes());

		let mut body = Vec::new();
		wire::IfInfo {
			index: i32::try_from(index).unwrap_or(0),
			..wire::IfInfo::default()
		}
		.encode(&mut body);

		self.request(msg_type::RTM_SETLINK, ack_flags(), &body, &attrs)?;
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
