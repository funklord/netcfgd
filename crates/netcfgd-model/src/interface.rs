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
}
