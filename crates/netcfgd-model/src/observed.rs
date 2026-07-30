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
	/// The root qdisc the kernel currently runs on this link.
	///
	/// Always present in practice -- there is no such thing as an interface
	/// without one, and an interface netcfgd has never touched reports
	/// whatever `net.core.default_qdisc` gave it. `None` means the dump did
	/// not mention it, not that there is none.
	#[serde(skip_serializing_if = "Option::is_none", default)]
	pub qdisc: Option<String>,
	/// The shaped rate in **bits** per second, where the qdisc shapes.
	#[serde(skip_serializing_if = "Option::is_none", default)]
	pub qdisc_bandwidth_bits: Option<u64>,
	/// Whether the root qdisc was told it is shaping traffic on the way in.
	#[serde(default)]
	pub qdisc_ingress: bool,
	/// The device traffic arriving here is redirected to, if any.
	#[serde(skip_serializing_if = "Option::is_none", default)]
	pub ingress_redirect: Option<String>,
	/// Whether this interface forwards, from the `forwarding` sysctls.
	///
	/// `Some(true)` only when both the IPv4 and the IPv6 one are set: half a
	/// forwarding interface routes one family and silently blackholes the
	/// other, and reporting that as "on" would make a plan claim there was
	/// nothing to do. `None` means the sysctls could not be read, which is the
	/// ordinary case in a container without `/proc/sys` mounted writable.
	#[serde(skip_serializing_if = "Option::is_none", default)]
	pub forwarding: Option<bool>,
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

/// A policy routing rule as the kernel reports it.
///
/// The same fields as [`crate::RoutingRule`] minus the `id`, which is
/// netcfgd's own handle and has no kernel counterpart, plus the ownership the
/// `FRA_PROTOCOL` tag establishes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObservedRule {
	/// Consulted in ascending order. With the family, this is the kernel's key.
	pub priority: u32,
	/// Which family it is installed in.
	pub family: crate::RuleFamily,
	/// Source selector, in CIDR form.
	#[serde(skip_serializing_if = "Option::is_none", default)]
	pub from: Option<String>,
	/// Destination selector.
	#[serde(skip_serializing_if = "Option::is_none", default)]
	pub to: Option<String>,
	/// Incoming interface selector.
	#[serde(skip_serializing_if = "Option::is_none", default)]
	pub iif: Option<String>,
	/// Outgoing interface selector.
	#[serde(skip_serializing_if = "Option::is_none", default)]
	pub oif: Option<String>,
	/// Firewall mark selector.
	#[serde(skip_serializing_if = "Option::is_none", default)]
	pub fwmark: Option<u32>,
	/// Mask applied before comparing the mark.
	#[serde(skip_serializing_if = "Option::is_none", default)]
	pub fwmask: Option<u32>,
	/// Which table it consults.
	#[serde(skip_serializing_if = "Option::is_none", default)]
	pub table: Option<u32>,
	/// What it does on a match.
	pub action: crate::RuleAction,
	/// Ignore routes shorter than this.
	#[serde(skip_serializing_if = "Option::is_none", default)]
	pub suppress_prefixlength: Option<u32>,
	/// Matches packets belonging to an l3mdev master.
	#[serde(default)]
	pub l3mdev: bool,
	/// Selectors are inverted.
	#[serde(default)]
	pub invert: bool,
	/// Whether this is ours.
	pub ownership: Ownership,
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

/// One VLAN the kernel holds on one interface.
///
/// No ownership field, unlike an address. There is no protocol tag for a
/// bridge VLAN, and unlike a link there is no useful `/run` record either --
/// the kernel creates VLAN 1 by itself, so "netcfgd did not add this" does not
/// mean "somebody else did". Authority comes from the document instead: see
/// [`crate::Interface::bridge_vlans`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObservedBridgeVlan {
	/// Which interface carries it.
	pub index: u32,
	/// The VLAN id.
	pub vid: u16,
	/// Untagged ingress joins this VLAN.
	pub pvid: bool,
	/// Egress leaves untagged.
	pub untagged: bool,
}

/// What a `DHCPv6` client obtained by prefix delegation.
///
/// Not read from the kernel: a delegated prefix is not kernel state at all
/// until something derives an address from it. It comes from the client, which
/// netcfgd does not implement (decision 0004) and therefore has to be told by
/// -- through a file the client's hook writes and the observer reads.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Delegation {
	/// The interface whose lease carries them.
	pub interface: String,
	/// The prefixes, in the order the lease listed them.
	///
	/// A list rather than one, because a lease may carry several and
	/// `PrefixRef::index` selects between them. Most connections deliver
	/// exactly one.
	pub prefixes: Vec<String>,
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
	/// Policy routing rules, sorted by family then priority.
	#[serde(default)]
	pub rules: Vec<ObservedRule>,
	/// Bridge VLANs the kernel currently holds, sorted by interface then id.
	#[serde(default)]
	pub bridge_vlans: Vec<ObservedBridgeVlan>,
	/// Prefixes delegated to this host, sorted by interface.
	#[serde(default)]
	pub delegations: Vec<Delegation>,
	/// Interfaces netcfgd set the root qdisc on, sorted.
	///
	/// Recorded for the same reason as [`Observed::forwarding_applied`]: a
	/// qdisc carries no owner, and every interface has one whether or not
	/// anybody chose it. An interface already running `cake` when netcfgd
	/// first started is not netcfgd's to reset.
	#[serde(default)]
	pub qdisc_applied: Vec<String>,
	/// Interfaces netcfgd installed an ingress redirect on, sorted.
	#[serde(default)]
	pub ingress_applied: Vec<String>,
	/// Interfaces netcfgd turned forwarding on for, sorted.
	///
	/// Recorded rather than inferred, because a sysctl carries no owner. An
	/// interface that was already forwarding when netcfgd first ran is not in
	/// here and never gets turned off -- somebody else's `sysctl.conf` is not
	/// netcfgd's to undo. One that netcfgd switched on is, which is what makes
	/// deleting `forwarding` from the document mean something.
	#[serde(default)]
	pub forwarding_applied: Vec<String>,
	/// Interfaces netcfgd's own nftables table currently masquerades, sorted.
	///
	/// Empty where the table does not exist, and also where the kernel has no
	/// `nf_tables` at all -- the two are indistinguishable from here and the
	/// planner treats them the same, because "no NAT is installed" is the true
	/// statement in both cases. What separates them is what happens on apply:
	/// a missing subsystem fails loudly there.
	#[serde(default)]
	pub nat: Vec<String>,
	/// Tables other than netcfgd's that translate source addresses, sorted.
	///
	/// Decision 0022 refuses to delete these and reports them instead: a
	/// second source-NAT chain on the same hook translates the same packets
	/// twice, and the table it lives in almost certainly holds filtering
	/// netcfgd cannot evaluate.
	#[serde(default)]
	pub nat_conflicts: Vec<String>,
	/// Whether address ownership came from `IFA_PROTO` or from the weaker
	/// `/run` fallback.
	///
	/// `ncfg explain` reports this, because an operator deciding whether to
	/// trust a drift report needs to know which mechanism produced it
	/// (`docs/decisions/0002`).
	pub address_proto_supported: bool,
}

impl Observed {
	/// The prefixes delegated on an interface.
	#[must_use]
	pub fn delegation(&self, interface: &str) -> Option<&Delegation> {
		self.delegations
			.iter()
			.find(|entry| entry.interface == interface)
	}

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
