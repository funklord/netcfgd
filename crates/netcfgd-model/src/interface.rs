//! Interfaces: what they are, and what netcfgd configures on them.

use crate::address::{AddressSource, PrefixRef};
use crate::dns::DnsPolicy;
use crate::hook::HookRef;
use crate::route::Route;
use crate::secret::SecretRef;
use crate::security::EapConfig;
use crate::DriftPolicy;
use serde::{Deserialize, Serialize};
use std::net::IpAddr;

/// VLAN encapsulation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VlanProtocol {
	/// 802.1Q.
	#[default]
	Dot1q,
	/// 802.1ad, stacked.
	Dot1ad,
}

impl VlanProtocol {
	/// The ethertype the kernel wants in `IFLA_VLAN_PROTOCOL`.
	#[must_use]
	pub fn ethertype(self) -> u16 {
		match self {
			Self::Dot1q => 0x8100,
			Self::Dot1ad => 0x88a8,
		}
	}
}

/// How a bond distributes traffic across its members.
///
/// An enum rather than the string it used to be. A string accepts
/// `active_backup` and `activebackup` and `ActiveBackup`, all of which the
/// kernel rejects at apply time -- so the config compiles, the plan looks
/// right, and the failure arrives with the interface half-built. The names
/// are the ones `iproute2` and every piece of bonding documentation use.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum BondMode {
	/// Round robin across members.
	#[serde(rename = "balance-rr")]
	BalanceRr,
	/// One member active, the rest standing by. The safe default: it needs
	/// nothing of the switch, where most of the others need a cooperating one.
	#[default]
	#[serde(rename = "active-backup")]
	ActiveBackup,
	/// Hash-based distribution.
	#[serde(rename = "balance-xor")]
	BalanceXor,
	/// Everything on every member.
	#[serde(rename = "broadcast")]
	Broadcast,
	/// LACP. Needs a switch configured for it.
	#[serde(rename = "802.3ad")]
	Ieee8023ad,
	/// Adaptive transmit load balancing.
	#[serde(rename = "balance-tlb")]
	BalanceTlb,
	/// Adaptive load balancing.
	#[serde(rename = "balance-alb")]
	BalanceAlb,
}

impl BondMode {
	/// The number the kernel uses in `IFLA_BOND_MODE`.
	#[must_use]
	pub fn number(self) -> u8 {
		match self {
			Self::BalanceRr => 0,
			Self::ActiveBackup => 1,
			Self::BalanceXor => 2,
			Self::Broadcast => 3,
			Self::Ieee8023ad => 4,
			Self::BalanceTlb => 5,
			Self::BalanceAlb => 6,
		}
	}

	/// The name as the config spells it.
	#[must_use]
	pub fn name(self) -> &'static str {
		match self {
			Self::BalanceRr => "balance-rr",
			Self::ActiveBackup => "active-backup",
			Self::BalanceXor => "balance-xor",
			Self::Broadcast => "broadcast",
			Self::Ieee8023ad => "802.3ad",
			Self::BalanceTlb => "balance-tlb",
			Self::BalanceAlb => "balance-alb",
		}
	}

	/// Parse the config spelling.
	#[must_use]
	pub fn parse(text: &str) -> Option<Self> {
		[
			Self::BalanceRr,
			Self::ActiveBackup,
			Self::BalanceXor,
			Self::Broadcast,
			Self::Ieee8023ad,
			Self::BalanceTlb,
			Self::BalanceAlb,
		]
		.into_iter()
		.find(|mode| mode.name() == text)
	}
}

/// A bridge.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct BridgeConfig {
	/// Member interface names.
	pub members: Vec<String>,
	/// Spanning tree.
	pub stp: bool,
	/// Forward delay in seconds.
	#[serde(skip_serializing_if = "Option::is_none")]
	pub forward_delay: Option<u32>,
	/// Hello interval in seconds.
	#[serde(skip_serializing_if = "Option::is_none")]
	pub hello_time: Option<u32>,
	/// How long a learned address survives without traffic, in seconds.
	#[serde(skip_serializing_if = "Option::is_none")]
	pub ageing_time: Option<u32>,
	/// Bridge priority, which decides the root in a spanning tree.
	#[serde(skip_serializing_if = "Option::is_none")]
	pub priority: Option<u16>,
	/// Whether the bridge is VLAN-aware.
	///
	/// Off by default, as in the kernel. Turning it on changes what the bridge
	/// does with tagged frames, so it is never inferred from the presence of
	/// VLAN interfaces elsewhere in the document -- a bridge quietly becoming
	/// VLAN-aware would drop untagged traffic that used to pass.
	#[serde(default)]
	pub vlan_filtering: bool,
}

/// A bond.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BondConfig {
	/// Member interface names.
	pub members: Vec<String>,
	/// How traffic is distributed across the members.
	#[serde(default)]
	pub mode: BondMode,
	/// MII monitoring interval in milliseconds.
	#[serde(skip_serializing_if = "Option::is_none", default)]
	pub miimon: Option<u32>,
}

/// A VLAN.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VlanConfig {
	/// Parent interface.
	pub parent: String,
	/// VLAN id.
	pub id: u16,
	/// Encapsulation.
	#[serde(default)]
	pub protocol: VlanProtocol,
}

/// A VXLAN.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VxlanConfig {
	/// VNI.
	pub id: u32,
	/// Underlay interface the tunnel rides on.
	///
	/// Optional, and the difference matters: without it the kernel routes the
	/// outer packets itself, which is usually what is wanted on a host with
	/// one uplink and never what is wanted on a host with several.
	#[serde(skip_serializing_if = "Option::is_none", default)]
	pub parent: Option<String>,
	/// Local endpoint.
	#[serde(skip_serializing_if = "Option::is_none", default)]
	pub local: Option<IpAddr>,
	/// Remote endpoint.
	#[serde(skip_serializing_if = "Option::is_none", default)]
	pub remote: Option<IpAddr>,
	/// UDP port.
	#[serde(skip_serializing_if = "Option::is_none", default)]
	pub port: Option<u16>,
}

/// One VLAN on a bridge port, or on the bridge device itself.
///
/// Per-port VLAN membership is how a switch is provisioned on any current
/// kernel: DSA presents switch ports as ordinary interfaces, and telling the
/// bridge which VLANs a port carries is what `swconfig` used to do.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BridgeVlan {
	/// The VLAN id.
	pub vid: u16,
	/// Untagged traffic arriving on this port joins this VLAN.
	///
	/// At most one per port, which the compiler checks -- the kernel accepts a
	/// second and silently moves the PVID, so two ports' worth of config
	/// merged from drop-ins could change which VLAN untagged traffic lands in
	/// with nothing reporting it.
	#[serde(default)]
	pub pvid: bool,
	/// Traffic leaves this port without a tag.
	#[serde(default)]
	pub untagged: bool,
}

/// A VRF: a routing table with an interface in front of it.
///
/// The reason this exists is an inconsistency the pre-freeze format audit
/// found in netcfgd's own model. [`crate::RoutingRule`] has an `l3mdev` flag
/// -- "match packets belonging to a VRF master" -- and nothing could create
/// the master. A rule that can only ever match something the tool cannot build
/// is a field that reads as supported and is not.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VrfConfig {
	/// The routing table this VRF's members use.
	///
	/// Required, and the whole point: enslaving an interface to a VRF moves
	/// its routes into this table. A VRF without one would be a device that
	/// isolates traffic into nowhere.
	pub table: u32,
}

/// How a macvlan relates to the interface it sits on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MacvlanMode {
	/// Members cannot talk to each other, only to the outside. The default
	/// because it is the one with no surprising reachability.
	#[default]
	Private,
	/// Members reach each other through the parent's upstream switch, if the
	/// switch reflects frames.
	Vepa,
	/// Members reach each other directly. The usual choice for containers.
	Bridge,
	/// One member, promiscuous, for passing a whole segment through.
	Passthru,
}

impl MacvlanMode {
	/// The name `iproute2` uses.
	#[must_use]
	pub fn name(self) -> &'static str {
		match self {
			Self::Private => "private",
			Self::Vepa => "vepa",
			Self::Bridge => "bridge",
			Self::Passthru => "passthru",
		}
	}
}

/// A macvlan: another MAC address on somebody else's NIC.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MacvlanConfig {
	/// The interface it sits on.
	pub parent: String,
	/// How members see each other.
	#[serde(default)]
	pub mode: MacvlanMode,
}

/// Which encapsulation a point-to-point tunnel uses.
///
/// One variant per kernel link kind, and one model type for all of them,
/// because they take the same parameters and differ only in the name sent to
/// the kernel. Five `InterfaceKind` variants carrying identical fields would
/// be five places to keep in step.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TunnelKind {
	/// GRE over IPv4.
	Gre,
	/// GRE over IPv4, carrying ethernet.
	Gretap,
	/// GRE over IPv6.
	Ip6gre,
	/// IPv4 in IPv4.
	Ipip,
	/// IPv6 in IPv4. Also what a 6to4 or 6rd tunnel is.
	Sit,
	/// IPv6 in IPv6.
	Ip6tnl,
	/// Geneve, which is `VXLAN`'s successor and takes a remote like a tunnel.
	Geneve,
}

impl TunnelKind {
	/// The kernel's name for this link kind.
	#[must_use]
	pub fn name(self) -> &'static str {
		match self {
			Self::Gre => "gre",
			Self::Gretap => "gretap",
			Self::Ip6gre => "ip6gre",
			Self::Ipip => "ipip",
			Self::Sit => "sit",
			Self::Ip6tnl => "ip6tnl",
			Self::Geneve => "geneve",
		}
	}

	/// Whether the outer header is IPv6.
	#[must_use]
	pub fn is_v6(self) -> bool {
		matches!(self, Self::Ip6gre | Self::Ip6tnl)
	}
}

/// A point-to-point tunnel.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TunnelConfig {
	/// Which encapsulation.
	///
	/// Named `mode` and not `kind`, which is what it wants to be called.
	/// [`InterfaceKind`] is serialised with an internal tag named `kind`, so a
	/// variant whose inner struct also has a `kind` produces JSON with the
	/// field twice -- which serde writes happily and refuses to read back.
	/// Found by the schema witness the moment every variant was serialised in
	/// one document, and fixed here rather than frozen in.
	pub mode: TunnelKind,
	/// Local endpoint.
	#[serde(skip_serializing_if = "Option::is_none", default)]
	pub local: Option<IpAddr>,
	/// Remote endpoint.
	#[serde(skip_serializing_if = "Option::is_none", default)]
	pub remote: Option<IpAddr>,
	/// Underlay interface, where one is named.
	#[serde(skip_serializing_if = "Option::is_none", default)]
	pub parent: Option<String>,
	/// Outer TTL. Zero means inherit from the inner packet.
	#[serde(skip_serializing_if = "Option::is_none", default)]
	pub ttl: Option<u8>,
	/// GRE key, for the kinds that have one.
	#[serde(skip_serializing_if = "Option::is_none", default)]
	pub key: Option<u32>,
}

/// Whether a tun/tap device carries IP packets or ethernet frames.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TunMode {
	/// Layer 3: IP packets, no ethernet header.
	#[default]
	Tun,
	/// Layer 2: full ethernet frames.
	Tap,
}

/// A persistent tun or tap device.
///
/// In the schema and not implemented, and the reason is specific: unlike every
/// other link kind here, tun and tap are not created over rtnetlink. They come
/// from a `TUNSETIFF` ioctl on `/dev/net/tun`, which is an ioctl outside the
/// one crate permitted `unsafe` -- the same wall `LinkSettings` hit, and it
/// does not fall to the generic netlink work that cleared ethtool's.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TunConfig {
	/// Layer 3 or layer 2.
	#[serde(default)]
	pub mode: TunMode,
	/// User permitted to attach to it.
	#[serde(skip_serializing_if = "Option::is_none", default)]
	pub owner: Option<String>,
	/// Group permitted to attach to it.
	#[serde(skip_serializing_if = "Option::is_none", default)]
	pub group: Option<String>,
}

/// A `WireGuard` peer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WgPeer {
	/// Local label, for diagnostics. Sorting key for the peer list.
	pub name: String,
	/// The peer's public key.
	pub public_key: crate::Key,
	/// Optional pre-shared key, by reference.
	#[serde(skip_serializing_if = "Option::is_none", default)]
	pub preshared_key: Option<SecretRef>,
	/// Endpoint, host and port.
	#[serde(skip_serializing_if = "Option::is_none", default)]
	pub endpoint: Option<String>,
	/// Prefixes routed to this peer.
	pub allowed_ips: Vec<String>,
	/// Persistent keepalive in seconds.
	#[serde(skip_serializing_if = "Option::is_none", default)]
	pub keepalive: Option<u16>,
}

/// A `WireGuard` interface.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WireGuardConfig {
	/// The interface's private key, by reference.
	pub private_key: SecretRef,
	/// Listen port.
	#[serde(skip_serializing_if = "Option::is_none", default)]
	pub listen_port: Option<u16>,
	/// Firewall mark applied to outgoing packets.
	#[serde(skip_serializing_if = "Option::is_none", default)]
	pub fwmark: Option<u32>,
	/// Peers, sorted by name.
	pub peers: Vec<WgPeer>,
}

/// A `PPPoE` session.
///
/// Implemented by pppd. Present because a large share of DSL and fibre
/// services still attach this way, and a tool that cannot configure the WAN of
/// the device it targets is unfinished (`docs/decisions/0009`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PppoeConfig {
	/// The ethernet interface the session runs over.
	pub parent: String,
	/// PPP username.
	pub username: String,
	/// PPP password, by reference.
	pub password: SecretRef,
	/// Service name, where the provider requires one.
	#[serde(skip_serializing_if = "Option::is_none", default)]
	pub service: Option<String>,
	/// Access concentrator name, where the provider requires one.
	#[serde(skip_serializing_if = "Option::is_none", default)]
	pub ac: Option<String>,
}

/// A veth pair.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VethConfig {
	/// The other end's name.
	pub peer: String,
}

/// What kind of thing an interface is.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum InterfaceKind {
	/// A real NIC.
	Physical,
	/// A bridge.
	Bridge(BridgeConfig),
	/// A bond.
	Bond(BondConfig),
	/// A VLAN sub-interface.
	Vlan(VlanConfig),
	/// A VXLAN.
	Vxlan(VxlanConfig),
	/// A `WireGuard` tunnel.
	WireGuard(WireGuardConfig),
	/// A `PPPoE` session.
	Pppoe(PppoeConfig),
	/// A dummy interface.
	Dummy,
	/// One end of a veth pair.
	Veth(VethConfig),
	/// A VRF master.
	Vrf(VrfConfig),
	/// A macvlan on another interface.
	Macvlan(MacvlanConfig),
	/// A point-to-point tunnel.
	Tunnel(TunnelConfig),
	/// A persistent tun or tap device. Unimplemented; see [`TunConfig`].
	Tun(TunConfig),
	/// An intermediate functional block, which exists to be redirected to.
	///
	/// Never written by hand. netcfgd synthesises one per interface that asks
	/// for `ingress_bandwidth`, the same way it synthesises an interface for a
	/// bridge member that has no block of its own -- so link creation,
	/// ownership and teardown all work on it without knowing what it is for.
	Ifb,
}

/// Which queueing discipline a link drains its transmit queue with.
///
/// A closed set, not a free string. Decision 0023 keeps netcfgd to the root
/// qdisc and to schedulers that need no classes or filters underneath them, and
/// an open string would make that line invisible: `htb` would compile, apply,
/// and produce a class-less shaper that drops everything.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QdiscKind {
	/// Flow queueing with `CoDel`. The sane default for anything congested.
	FqCodel,
	/// Common Applications Kept Enhanced: fair queueing plus a shaper, so it
	/// needs no class tree to limit a rate. The uplink one.
	Cake,
	/// Fair queueing with pacing. For a host originating a lot of TCP.
	Fq,
	/// The historical default: three priority bands, no fairness.
	PfifoFast,
	/// No queue at all, which is what virtual devices usually want.
	Noqueue,
}

impl QdiscKind {
	/// The name the kernel knows it by, which is also the config spelling.
	#[must_use]
	pub fn name(self) -> &'static str {
		match self {
			Self::FqCodel => "fq_codel",
			Self::Cake => "cake",
			Self::Fq => "fq",
			Self::PfifoFast => "pfifo_fast",
			Self::Noqueue => "noqueue",
		}
	}

	/// Whether this scheduler can shape to a rate.
	///
	/// Only `cake`, which is the whole reason a rate is expressible at all
	/// without the class machinery decision 0023 refuses.
	#[must_use]
	pub fn shapes(self) -> bool {
		matches!(self, Self::Cake)
	}
}

/// The root qdisc on an interface.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QdiscPolicy {
	/// Which scheduler.
	pub kind: QdiscKind,
	/// Shaped rate in **bits** per second.
	///
	/// Bits because that is what an operator writes and what every tool
	/// prints; the kernel wants bytes and the conversion happens once, at the
	/// netlink boundary. Storing the kernel's unit here would put a division
	/// by eight in front of every reader.
	#[serde(skip_serializing_if = "Option::is_none", default)]
	pub bandwidth_bits: Option<u64>,
	/// Shaped rate for traffic arriving on this interface, in bits per second.
	///
	/// The kernel cannot queue on the way in -- the packets are already here
	/// -- so this is not another number on the same qdisc. Asking for it makes
	/// netcfgd build an `ifb` device, redirect everything arriving here onto
	/// it, and shape it there, where it has become egress. Decision 0023's
	/// amendment covers why that is allowed to use a filter when nothing else
	/// is.
	#[serde(skip_serializing_if = "Option::is_none", default)]
	pub ingress_bandwidth_bits: Option<u64>,
	/// Whether this shaper is metering traffic that has already arrived.
	///
	/// Set on the `cake` that sits on the `ifb`, never on an interface the
	/// operator named. It changes what the shaper counts: outbound it meters
	/// what it sends, inbound its only lever is dropping, so it has to account
	/// for what the sender will retransmit.
	#[serde(skip_serializing_if = "std::ops::Not::not", default)]
	pub ingress: bool,
}

/// Which daemon sends router advertisements.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RaBackend {
	/// Pick whichever is present.
	#[default]
	Auto,
	/// odhcpd.
	Odhcpd,
	/// radvd.
	Radvd,
	/// Hand the policy to a script.
	Exec(String),
}

/// Router advertisement policy for a LAN-side interface.
///
/// Policy only. netcfgd does not send router advertisements, because it
/// configures and does not serve; the implementation is odhcpd or radvd
/// (`docs/decisions/0009`).
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct RaPolicy {
	/// Which daemon.
	pub backend: RaBackend,
	/// Prefixes to advertise, usually a delegation.
	pub prefixes: Vec<PrefixRef>,
	/// Set the managed-address-configuration flag.
	pub managed: bool,
	/// Set the other-configuration flag.
	pub other_config: bool,
	/// Advertise this interface's DNS scope as RDNSS and DNSSL.
	#[serde(default = "crate::default_true")]
	pub dns: bool,
	/// Router lifetime in seconds.
	#[serde(skip_serializing_if = "Option::is_none")]
	pub lifetime: Option<u32>,
}

/// Why an interface must not be disrupted.
///
/// Something outside netcfgd depends on this interface -- an NFS root, a
/// replicating database, the session the operator is connected over. netcfgd
/// refuses to plan a disruptive action against it, and reports what it
/// declined instead (`docs/decisions/0010`).
///
/// The reason is a string rather than a boolean because the refusal text is
/// the whole value: "eth0 is critical" sends the reader looking for what is
/// critical about it, and "eth0: nfs root" tells them what to go and stop.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Guard {
	/// What depends on this interface, in the operator's own words.
	pub reason: String,
}

/// An interface and everything netcfgd configures on it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Interface {
	/// Interface name. Sorting key.
	pub name: String,
	/// What it is.
	pub kind: InterfaceKind,
	/// Whether to bring it up.
	#[serde(default = "crate::default_true")]
	pub enabled: bool,
	/// MTU.
	#[serde(skip_serializing_if = "Option::is_none", default)]
	pub mtu: Option<u32>,
	/// Hardware address to set.
	#[serde(skip_serializing_if = "Option::is_none", default)]
	pub mac: Option<String>,
	/// How addresses are acquired. Ordered; a composition, not alternatives.
	#[serde(default)]
	pub addressing: Vec<AddressSource>,
	/// Routes to install, sorted canonically.
	#[serde(default)]
	pub routes: Vec<Route>,
	/// This interface's DNS scope.
	#[serde(skip_serializing_if = "Option::is_none", default)]
	pub dns: Option<DnsPolicy>,
	/// Hook references.
	#[serde(default)]
	pub hooks: Vec<HookRef>,
	/// Drift behaviour, overriding the global default.
	#[serde(skip_serializing_if = "Option::is_none", default)]
	pub on_drift: Option<DriftPolicy>,
	/// Bridge or bond this is a member of.
	#[serde(skip_serializing_if = "Option::is_none", default)]
	pub master: Option<String>,
	/// Wired 802.1X. Wifi carries its EAP inside the network profile instead.
	#[serde(skip_serializing_if = "Option::is_none", default)]
	pub dot1x: Option<EapConfig>,
	/// Router advertisement policy, for a LAN-side interface.
	#[serde(skip_serializing_if = "Option::is_none", default)]
	pub advertise: Option<RaPolicy>,
	/// IP forwarding sysctl, and only that.
	///
	/// Never a filter rule. Decision 0022 lets netcfgd own one nftables table
	/// for NAT, on the grounds that translating addresses is addressing --
	/// deciding which packets may pass is security policy, which this project
	/// has no model of and does not want one.
	///
	/// Set on the interface packets *arrive* on, which is the LAN side of a
	/// router and not the uplink -- the kernel decides whether to forward from
	/// the ingress device's setting. Both `net.ipv4.conf.<name>.forwarding` and
	/// the IPv6 equivalent are written, and the IPv6 one has a consequence
	/// worth knowing: a forwarding interface stops accepting router
	/// advertisements, because a router is not supposed to be autoconfigured by
	/// its neighbours.
	#[serde(skip_serializing_if = "Option::is_none", default)]
	pub forwarding: Option<bool>,
	/// Where traffic arriving on this interface is redirected to.
	///
	/// Synthesised, never written: it is the `ifb` that `ingress_bandwidth`
	/// asks for. Named in the document rather than derived at apply time so
	/// that `ncfg plan` can say which device the redirect points at.
	#[serde(skip_serializing_if = "Option::is_none", default)]
	pub ingress_redirect: Option<String>,
	/// How this link drains its transmit queue.
	///
	/// The root qdisc and nothing below it: decision 0023 draws the same line
	/// here that 0022 draws for netfilter. netcfgd sets how a link behaves when
	/// it is congested, because that is a property of the link; it does not
	/// decide which traffic wins, because that is policy.
	#[serde(skip_serializing_if = "Option::is_none", default)]
	pub qdisc: Option<QdiscPolicy>,
	/// Masquerade traffic leaving this interface.
	///
	/// The uplink side of a router: every packet going out here leaves with
	/// this interface's address, so a LAN behind it reaches the internet from
	/// one address. This is the *only* packet-level rule netcfgd writes, and
	/// decision 0022 draws the line at it -- translating addresses is
	/// addressing, filtering is security policy.
	///
	/// It is the other half of [`Interface::forwarding`] and neither works
	/// alone. Forwarding without NAT sends private addresses at the internet;
	/// NAT without forwarding translates packets the kernel already dropped.
	#[serde(skip_serializing_if = "Option::is_none", default)]
	pub nat: Option<bool>,
	/// Something outside netcfgd depends on this interface.
	#[serde(skip_serializing_if = "Option::is_none", default)]
	pub guard: Option<Guard>,
	/// IPv6 interface identifier for addresses formed from a router
	/// advertisement.
	///
	/// `ip token set ::5 dev eth0`: the prefix still comes from the router,
	/// but the host part is chosen rather than derived from the hardware
	/// address or generated per RFC 7217. The reason to want it is a server
	/// that must be reachable at a predictable address on a prefix that may
	/// change -- which is otherwise the thing that makes SLAAC unusable for
	/// anything that has to be found.
	#[serde(skip_serializing_if = "Option::is_none", default)]
	pub ipv6_token: Option<String>,
	/// Driver-level settings. Unimplemented; see [`LinkSettings`].
	#[serde(skip_serializing_if = "Option::is_none", default)]
	pub link_settings: Option<LinkSettings>,
	/// How this interface ranks against others that can reach the same place.
	///
	/// Lower wins, as in a route metric -- which is what it becomes: a route
	/// on this interface that names no metric of its own takes this one, and a
	/// DHCP client started for it is told to use it too.
	///
	/// Setting it also ties the interface's routes to its carrier. That is the
	/// half that makes a laptop work: a default route down a cable that is not
	/// plugged in is a black hole, and a lower metric makes the kernel prefer
	/// it over the wifi that does work. So while an interface with a
	/// preference has no carrier, netcfgd does not install its routes, and
	/// withdraws the ones it installed.
	///
	/// Absent means netcfgd manages neither -- routes keep whatever metric
	/// they name and stay put through a carrier flap, which is what a server
	/// with one uplink wants.
	#[serde(skip_serializing_if = "Option::is_none", default)]
	pub preference: Option<u32>,
	/// VLANs this interface carries, as a bridge port or as a bridge.
	///
	/// **Authoritative where present.** A port whose config lists VLANs has
	/// exactly those, and anything else the kernel holds for it is removed --
	/// including the VLAN 1 the kernel adds by itself the moment a port joins
	/// a filtering bridge. Every real trunk setup begins by deleting that
	/// one, so leaving it because the kernel put it there would mean the
	/// document does not describe the port.
	///
	/// A port the document says nothing about keeps whatever it has. The
	/// authority is over ports that are configured, not over the bridge.
	#[serde(default)]
	pub bridge_vlans: Vec<BridgeVlan>,
}

/// Whether a tunable is left alone, turned on, or turned off.
///
/// Three states rather than a `bool`, because "netcfgd does not manage this"
/// and "netcfgd requires this off" are different instructions and produce
/// different plans. A `bool` with `Option` around it would say the same thing,
/// and reads worse at every use.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Toggle {
	/// Not managed. Whatever the driver defaults to, or somebody else set.
	#[default]
	Unmanaged,
	/// Required on.
	On,
	/// Required off.
	Off,
}

/// The kernel feature names each offload field maps onto.
///
/// In the model rather than in `netcfgd-sys` because the planner needs them
/// and the planner is pure -- it must not depend on the crate that talks to
/// the kernel. The executor reads them from here too, so there is one list.
///
/// One field can cover several features: transmit checksumming is three,
/// because a driver offers whichever of them its hardware does.
pub mod offload_names {
	/// Generic receive offload.
	pub const GRO: &[&str] = &["rx-gro"];
	/// Generic segmentation offload.
	pub const GSO: &[&str] = &["tx-generic-segmentation"];
	/// TCP segmentation offload.
	pub const TSO: &[&str] = &["tx-tcp-segmentation"];
	/// Receive checksum offload.
	pub const RX_CHECKSUM: &[&str] = &["rx-checksum"];
	/// Transmit checksum offload, in all the spellings a driver may have.
	pub const TX_CHECKSUM: &[&str] = &[
		"tx-checksum-ip-generic",
		"tx-checksum-ipv4",
		"tx-checksum-ipv6",
	];
}

/// Driver-level link settings, the `ethtool` surface.
///
/// **The offloads are applied; the rest is not.** ethtool is reached either
/// through `SIOCETHTOOL`, an ioctl the unsafe policy forbids outside
/// `netcfgd-sys`, or through its generic netlink family -- and family
/// resolution was built for `WireGuard` at M4, so that route is open and the
/// offloads go through it.
///
/// `autoneg`, `speed`, `duplex`, `wol`, `rx_ring` and `tx_ring` stay
/// unimplemented, and the reason is verification rather than effort. A veth
/// takes a features message; it refuses a link-modes set with a bare `EINVAL`,
/// and ring and wake-on-LAN messages are `EOPNOTSUPP` on anything that is not
/// a physical NIC. Every netlink bug this project has shipped was found by
/// writing to a real kernel and reading it back, so settings that can only be
/// exercised against hardware the test suite cannot safely write to are left
/// alone and reported field by field in the plan.
///
/// Deliberately not exhaustive of what ethtool can do. These are the settings
/// people actually put in configuration management -- offloads that break
/// things, ring sizes on a loaded box, a link that must be forced because
/// autonegotiation with a particular switch does not work.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LinkSettings {
	/// Autonegotiation.
	#[serde(default)]
	pub autoneg: Toggle,
	/// Forced speed in Mbit/s, where autonegotiation is off.
	#[serde(skip_serializing_if = "Option::is_none", default)]
	pub speed: Option<u32>,
	/// Forced duplex, where autonegotiation is off.
	#[serde(skip_serializing_if = "Option::is_none", default)]
	pub duplex: Option<String>,
	/// Wake-on-LAN flags, in ethtool's letter notation such as `g`.
	#[serde(skip_serializing_if = "Option::is_none", default)]
	pub wol: Option<String>,
	/// Receive ring size.
	#[serde(skip_serializing_if = "Option::is_none", default)]
	pub rx_ring: Option<u32>,
	/// Transmit ring size.
	#[serde(skip_serializing_if = "Option::is_none", default)]
	pub tx_ring: Option<u32>,
	/// Generic receive offload.
	#[serde(default)]
	pub gro: Toggle,
	/// Generic segmentation offload.
	#[serde(default)]
	pub gso: Toggle,
	/// TCP segmentation offload.
	#[serde(default)]
	pub tso: Toggle,
	/// Receive checksum offload.
	#[serde(default)]
	pub rx_checksum: Toggle,
	/// Transmit checksum offload.
	#[serde(default)]
	pub tx_checksum: Toggle,
}

impl LinkSettings {
	/// Whether anything is actually being asked for.
	///
	/// An empty block is not the same as no block in the config, but it is the
	/// same in what it produces, and a plan should not carry an action that
	/// changes nothing.
	#[must_use]
	pub fn is_empty(&self) -> bool {
		*self == Self::default()
	}
}
