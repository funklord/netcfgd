//! What the kernel and the backends currently say is true.
//!
//! The other half of the desired/observed pair (`docs/decisions/0005`). This
//! lives in the model rather than in `netcfgd-observe` because both the
//! producer and the planner depend on it, and because it is written to
//! `/run/netcfgd/observed/` where it is as much a documented artifact as the
//! desired-state document is.

use crate::route::RouteScope;
use serde::{Deserialize, Serialize};
use std::net::IpAddr;

/// Whether netcfgd installed an object.
///
/// Drift detection is meaningless without this distinction, and the asymmetry
/// between the variants is deliberate: under-claiming ownership costs a little
/// convenience, over-claiming it deletes somebody's manual change.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Ownership {
	/// Carries netcfgd's protocol tag. Ours to reconcile.
	Ours,
	/// Carries somebody else's tag, or none. Never reconciled away; reported.
	Foreign,
	/// The kernel could not tell us. Pre-5.18 kernels have no `IFA_PROTO`, so
	/// address ownership falls back to recorded prior state, which cannot
	/// distinguish our address from an identical one added by hand
	/// (`docs/decisions/0002`). Treated as [`Ownership::Foreign`] for any
	/// decision that would remove something.
	#[default]
	Unknown,
}

impl Ownership {
	/// Whether an object may be removed to satisfy the desired state.
	///
	/// Only [`Ownership::Ours`] qualifies. This is the single place that
	/// decision is made, so that no planner path can accidentally widen it.
	#[must_use]
	pub fn may_remove(self) -> bool {
		matches!(self, Self::Ours)
	}
}

/// Which addressing source produced an object.
///
/// Decision 0006 rule 7 turns on this: a missing static address is re-added,
/// but a missing DHCP address means the *lease* is gone, so the remedy is to
/// restart the backend rather than to add the address back. Without knowing
/// which source produced what, the planner would fight the DHCP client for
/// ownership of its own lease.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Origin {
	/// Written in the config.
	Static,
	/// From a `DHCPv4` lease.
	Dhcp4,
	/// From a `DHCPv6` lease.
	Dhcp6,
	/// From a router advertisement.
	Slaac,
	/// IPv4 link-local autoconfiguration.
	LinkLocal,
	/// Built from a delegated prefix.
	Delegated,
}

/// A link as the kernel reports it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObservedLink {
	/// Interface name.
	pub name: String,
	/// Kernel interface index.
	pub index: u32,
	/// Link kind as the kernel spells it: `veth`, `bridge`, `vlan`, or empty
	/// for a plain device.
	#[serde(default)]
	pub kind: String,
	/// Administrative state.
	pub up: bool,
	/// Whether the link has carrier. Distinct from `up`: an interface can be
	/// administratively up with the cable out.
	pub carrier: bool,
	/// Current MTU.
	pub mtu: u32,
	/// Current hardware address.
	#[serde(skip_serializing_if = "Option::is_none", default)]
	pub mac: Option<String>,
	/// Bridge or bond this link is enslaved to.
	#[serde(skip_serializing_if = "Option::is_none", default)]
	pub master: Option<String>,
	/// Whether netcfgd created this link.
	///
	/// Netlink has no protocol field for links, so unlike an address or a
	/// route this cannot be read back from the kernel. It comes from recorded
	/// prior state in `/run`, and it defaults to [`Ownership::Unknown`] --
	/// which means a link nobody has a record of is never deleted.
	#[serde(default)]
	pub ownership: Ownership,
}

/// An address as the kernel reports it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObservedAddress {
	/// Which interface carries it.
	pub interface: String,
	/// CIDR, as the kernel reports it.
	pub address: String,
	/// `IFA_PROTO`, where the kernel supports it.
	#[serde(skip_serializing_if = "Option::is_none", default)]
	pub proto: Option<u8>,
	/// Whether this is ours.
	pub ownership: Ownership,
	/// Which addressing source produced it, where that is recorded.
	#[serde(skip_serializing_if = "Option::is_none", default)]
	pub origin: Option<Origin>,
}

/// A route as the kernel reports it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObservedRoute {
	/// Which interface it leaves by.
	pub interface: String,
	/// CIDR, or `default`.
	pub destination: String,
	/// Next hop.
	#[serde(skip_serializing_if = "Option::is_none", default)]
	pub via: Option<IpAddr>,
	/// Metric.
	#[serde(skip_serializing_if = "Option::is_none", default)]
	pub metric: Option<u32>,
	/// Table id.
	#[serde(skip_serializing_if = "Option::is_none", default)]
	pub table: Option<u32>,
	/// Preferred source.
	#[serde(skip_serializing_if = "Option::is_none", default)]
	pub src: Option<IpAddr>,
	/// Scope.
	#[serde(skip_serializing_if = "Option::is_none", default)]
	pub scope: Option<RouteScope>,
	/// `rtm_protocol`.
	#[serde(skip_serializing_if = "Option::is_none", default)]
	pub proto: Option<u8>,
	/// Whether this is ours.
	pub ownership: Ownership,
	/// Which addressing source produced it, where that is recorded.
	#[serde(skip_serializing_if = "Option::is_none", default)]
	pub origin: Option<Origin>,
}

/// Which helper a backend entry describes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BackendKind {
	/// A `DHCPv4` client.
	Dhcp4,
	/// A `DHCPv6` client, including prefix delegation.
	Dhcp6,
	/// A supplicant, for a radio or a wired 802.1X port.
	Supplicant,
	/// A `WireGuard` device.
	WireGuard,
	/// A `PPPoE` session.
	Pppoe,
	/// A DNS delivery backend.
	Dns,
	/// A router advertisement daemon.
	RouterAdvert,
}

/// A backend process as netcfgd currently believes it to be.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObservedBackend {
	/// Which kind.
	pub kind: BackendKind,
	/// Which interface it serves.
	pub interface: String,
	/// Whether it is running.
	pub running: bool,
}

/// A DNS scope netcfgd last delivered, and what it delivered.
///
/// Read back from `/run/netcfgd/dns/`. Without it a plan could not tell an
/// already-applied policy from an unapplied one, and every run would emit a
/// `dns.apply` -- which would fail the plan-idempotence gate in section 6.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AppliedDns {
	/// Which scope: an interface name, or `globals`.
	pub scope: String,
	/// What was delivered.
	pub policy: crate::DnsPolicy,
}

/// Everything netcfgd can currently see.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Observed {
	/// Links, sorted by name.
	pub links: Vec<ObservedLink>,
	/// Addresses, sorted by interface then address.
	pub addresses: Vec<ObservedAddress>,
	/// Routes, sorted canonically.
	pub routes: Vec<ObservedRoute>,
	/// Backends, sorted by interface then kind.
	pub backends: Vec<ObservedBackend>,
	/// DNS scopes already delivered, sorted by scope.
	pub dns: Vec<AppliedDns>,
	/// Whether address ownership came from `IFA_PROTO` or from the weaker
	/// `/run` fallback.
	///
	/// `ncfg explain` reports this, because an operator deciding whether to
	/// trust a drift report needs to know which mechanism produced it
	/// (`docs/decisions/0002`).
	pub address_proto_supported: bool,
}

impl Observed {
	/// The link of this name, if the kernel has one.
	#[must_use]
	pub fn link(&self, name: &str) -> Option<&ObservedLink> {
		self.links.iter().find(|link| link.name == name)
	}

	/// Every address on an interface.
	pub fn addresses_on<'a>(
		&'a self,
		interface: &'a str,
	) -> impl Iterator<Item = &'a ObservedAddress> {
		self.addresses
			.iter()
			.filter(move |address| address.interface == interface)
	}

	/// Every route leaving an interface.
	pub fn routes_on<'a>(&'a self, interface: &'a str) -> impl Iterator<Item = &'a ObservedRoute> {
		self.routes
			.iter()
			.filter(move |route| route.interface == interface)
	}

	/// What was last delivered for a DNS scope.
	#[must_use]
	pub fn dns_for(&self, scope: &str) -> Option<&crate::DnsPolicy> {
		self.dns
			.iter()
			.find(|applied| applied.scope == scope)
			.map(|applied| &applied.policy)
	}

	/// Whether a backend of this kind is running on an interface.
	#[must_use]
	pub fn backend_running(&self, kind: BackendKind, interface: &str) -> bool {
		self.backends
			.iter()
			.any(|b| b.kind == kind && b.interface == interface && b.running)
	}

	/// Put every list in a stable order, so two observations of one system
	/// compare equal regardless of the order netlink dumped them in.
	pub fn canonicalize(&mut self) {
		self.links.sort_by(|a, b| a.name.cmp(&b.name));
		self.addresses.sort_by(|a, b| {
			a.interface
				.cmp(&b.interface)
				.then_with(|| a.address.cmp(&b.address))
		});
		self.routes.sort_by(|a, b| {
			a.interface
				.cmp(&b.interface)
				.then_with(|| a.destination.cmp(&b.destination))
				.then_with(|| a.metric.cmp(&b.metric))
		});
		self.backends.sort_by(|a, b| {
			a.interface
				.cmp(&b.interface)
				.then_with(|| a.kind.cmp(&b.kind))
		});
		self.dns.sort_by(|a, b| a.scope.cmp(&b.scope));
	}
}
