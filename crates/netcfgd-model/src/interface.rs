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
}

/// A bond.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BondConfig {
	/// Member interface names.
	pub members: Vec<String>,
	/// Bonding mode, as the kernel spells it.
	pub mode: String,
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

/// A `WireGuard` peer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WgPeer {
	/// Local label, for diagnostics. Sorting key for the peer list.
	pub name: String,
	/// The peer's public key.
	pub public_key: String,
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
	/// IP forwarding sysctl. Never a firewall rule: netcfgd does not write
	/// into a ruleset it does not own.
	#[serde(skip_serializing_if = "Option::is_none", default)]
	pub forwarding: Option<bool>,
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

/// Driver-level link settings, the `ethtool` surface.
///
/// Nothing implements this yet, and the reason is worth stating: ethtool is
/// reached either through `SIOCETHTOOL`, an ioctl, or through the newer
/// generic netlink family. The first needs an `unsafe` ioctl outside
/// `netcfgd-netlink`, which constraint 4 forbids; the second needs generic
/// netlink family resolution, which is the same cost decision 0016 identified
/// for `nl80211` and has not been paid. So the type is here for the M4 freeze
/// and a config using it is refused by name.
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
