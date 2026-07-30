//! The action taxonomy from project.md section 4.
//!
//! Every action is idempotent by construction, carries the reason it exists,
//! and declares its inverse so commit-confirm can revert without deriving one
//! after the fact -- when the network may already be unreachable.

use netcfgd_model::RoutingRule;
use netcfgd_model::{BackendKind, DnsPolicy, HookPhase, InterfaceKind, Route, WgPeer};
use serde::{Deserialize, Serialize};

/// What an action does.
///
/// The whole taxonomy is here even where this build emits only part of it. It
/// is the vocabulary the control socket will speak, and a reader comparing
/// this against section 4 should find the same list rather than a subset that
/// happens to match the current milestone.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum Op {
	/// Create a link that does not exist.
	LinkCreate {
		/// Interface name.
		name: String,
		/// What to create.
		kind: Box<InterfaceKind>,
	},
	/// Remove a link netcfgd created.
	LinkDelete {
		/// Interface name.
		name: String,
	},
	/// Set the MTU.
	LinkSetMtu {
		/// Interface name.
		name: String,
		/// New MTU.
		mtu: u32,
	},
	/// Set the hardware address.
	LinkSetMac {
		/// Interface name.
		name: String,
		/// New address.
		mac: String,
	},
	/// Enslave to a bridge or bond.
	LinkSetMaster {
		/// Interface name.
		name: String,
		/// The master.
		master: String,
	},
	/// Release from a bridge or bond.
	LinkUnsetMaster {
		/// Interface name.
		name: String,
	},
	/// Bring a link up.
	LinkUp {
		/// Interface name.
		name: String,
	},
	/// Take a link down.
	LinkDown {
		/// Interface name.
		name: String,
	},
	/// Add an address.
	AddrAdd {
		/// Interface name.
		iface: String,
		/// CIDR.
		addr: String,
		/// Preferred lifetime in seconds.
		preferred_lifetime: Option<u32>,
		/// Valid lifetime in seconds.
		valid_lifetime: Option<u32>,
	},
	/// Remove an address.
	AddrDel {
		/// Interface name.
		iface: String,
		/// CIDR.
		addr: String,
	},
	/// Install a route.
	RouteAdd {
		/// Interface name.
		iface: String,
		/// The route.
		route: Box<Route>,
	},
	/// Remove a route.
	RouteDel {
		/// Interface name.
		iface: String,
		/// The route.
		route: Box<Route>,
	},
	/// Start a helper.
	BackendStart {
		/// Which helper.
		kind: BackendKind,
		/// Which interface it serves.
		iface: String,
	},
	/// Stop a helper.
	BackendStop {
		/// Which helper.
		kind: BackendKind,
		/// Which interface it serves.
		iface: String,
	},
	/// Reconfigure a running helper.
	BackendReload {
		/// Which helper.
		kind: BackendKind,
		/// Which interface it serves.
		iface: String,
	},
	/// Put a VLAN on a bridge port, or on the bridge itself.
	BridgeVlanAdd {
		/// Which interface.
		iface: String,
		/// The VLAN id.
		vid: u16,
		/// Untagged ingress joins this VLAN.
		pvid: bool,
		/// Egress leaves untagged.
		untagged: bool,
		/// Whether this is the bridge device rather than a port.
		on_self: bool,
	},
	/// Take one off.
	BridgeVlanDel {
		/// Which interface.
		iface: String,
		/// The VLAN id.
		vid: u16,
		/// Whether this is the bridge device rather than a port.
		on_self: bool,
	},
	/// Hand a radio its network profiles.
	WifiSetProfiles {
		/// Which device.
		device: String,
		/// Profile ids.
		profiles: Vec<String>,
	},
	/// Join a network.
	WifiAssociate {
		/// Which device.
		device: String,
		/// Which profile.
		network_id: String,
	},
	/// Leave the current network.
	WifiDisassociate {
		/// Which device.
		device: String,
	},
	/// Set the regulatory domain.
	WifiSetRegdom {
		/// Which device.
		device: String,
		/// ISO 3166-1 alpha-2.
		country: String,
	},
	/// Configure a `WireGuard` device.
	WgSetDevice {
		/// Interface name.
		iface: String,
		/// Private key, by reference.
		private_key_ref: String,
		/// Listen port.
		listen_port: Option<u16>,
		/// Firewall mark.
		fwmark: Option<u32>,
	},
	/// Replace a `WireGuard` device's peers.
	WgSetPeers {
		/// Interface name.
		iface: String,
		/// The peers.
		peers: Vec<WgPeer>,
	},
	/// Deliver a DNS scope through its mode's backend.
	DnsApply {
		/// Which scope: an interface name, or `globals`.
		scope: String,
		/// The policy.
		policy: Box<DnsPolicy>,
	},
	/// Set or clear the IPv6 interface identifier.
	LinkSetIpv6Token {
		/// Interface name.
		name: String,
		/// The identifier, or `::` to clear it.
		token: String,
	},
	/// Install a policy routing rule.
	RuleAdd {
		/// The rule.
		rule: Box<RoutingRule>,
	},
	/// Remove one netcfgd installed.
	RuleDel {
		/// The rule.
		rule: Box<RoutingRule>,
	},
	/// Set the root qdisc on an interface.
	///
	/// The root and nothing below it (decision 0023). Sent as a replace, so
	/// there is no moment where the interface is on the kernel default -- on a
	/// shaped uplink that moment is a window of unshaped traffic.
	QdiscSet {
		/// Interface name.
		iface: String,
		/// The scheduler, as the kernel spells it.
		kind: String,
		/// Shaped rate in bits per second, for the schedulers that shape.
		bandwidth_bits: Option<u64>,
		/// Whether this shaper is metering traffic that has already arrived.
		ingress: bool,
	},
	/// Put the kernel's default root qdisc back.
	///
	/// Not deletion in the sense `addr.del` is: every interface has a qdisc,
	/// so removing netcfgd's means `net.core.default_qdisc` returns
	/// immediately. There is no state in between and nothing to restore.
	QdiscReset {
		/// Interface name.
		iface: String,
	},
	/// Send everything arriving on an interface to another device.
	///
	/// An ingress qdisc plus one `matchall` classifier with one `mirred`
	/// action -- the only filter netcfgd generates, and it carries no policy:
	/// it matches every packet unconditionally and the sole variable is where
	/// they land. Decision 0023's amendment.
	IngressRedirect {
		/// Interface traffic arrives on.
		iface: String,
		/// Device it is redirected to.
		target: String,
	},
	/// Remove the ingress qdisc, and the redirect hanging off it.
	IngressRedirectClear {
		/// Interface traffic arrives on.
		iface: String,
	},
	/// Turn IP forwarding on or off for one interface.
	///
	/// A sysctl and nothing else -- see [`netcfgd_model::Interface::forwarding`]
	/// for why this is the ingress side and what it does to IPv6 router
	/// advertisements.
	SysctlSetForwarding {
		/// Interface name.
		iface: String,
		/// Whether packets arriving here may be forwarded.
		enabled: bool,
	},
	/// Replace netcfgd's nftables table with one masquerading these interfaces.
	///
	/// One action for the whole table rather than one per rule, because that is
	/// what the kernel does: an nftables change is a transaction, and netcfgd
	/// sends the delete and every rule inside a single one. Splitting it into
	/// per-rule actions would describe a sequence of states the kernel never
	/// passes through.
	///
	/// An empty list removes the table. That is how a document that stops
	/// asking for NAT is honoured, and it is why this is not `NatAdd`.
	NatReplace {
		/// Interfaces to masquerade, sorted. Empty removes the table.
		uplinks: Vec<String>,
	},
	/// Run a hook.
	HookRun {
		/// Which interface's lifecycle.
		iface: String,
		/// Which phase.
		phase: HookPhase,
		/// Absolute path to the script.
		path: String,
	},
	/// Start a commit-confirm window.
	CommitArm {
		/// How long before automatic revert.
		window_seconds: u32,
	},
	/// Confirm within the window.
	CommitConfirm,
	/// Revert to a previous document.
	CommitRevert {
		/// Which document to go back to.
		to_document_hash: String,
	},
}

impl Op {
	/// A stable short name, for logs and for `ncfg plan` output.
	#[must_use]
	#[allow(clippy::match_same_arms)]
	pub fn name(&self) -> &'static str {
		match self {
			Self::LinkCreate { .. } => "link.create",
			Self::LinkDelete { .. } => "link.delete",
			Self::LinkSetMtu { .. } => "link.set_mtu",
			Self::LinkSetMac { .. } => "link.set_mac",
			Self::LinkSetMaster { .. } => "link.set_master",
			Self::LinkUnsetMaster { .. } => "link.unset_master",
			Self::LinkUp { .. } => "link.up",
			Self::LinkDown { .. } => "link.down",
			Self::AddrAdd { .. } => "addr.add",
			Self::AddrDel { .. } => "addr.del",
			Self::RouteAdd { .. } => "route.add",
			Self::RouteDel { .. } => "route.del",
			Self::BackendStart { .. } => "backend.start",
			Self::BackendStop { .. } => "backend.stop",
			Self::BridgeVlanAdd { .. } => "bridge.vlan.add",
			Self::BridgeVlanDel { .. } => "bridge.vlan.del",
			Self::BackendReload { .. } => "backend.reload",
			Self::WifiSetProfiles { .. } => "wifi.set_profiles",
			Self::WifiAssociate { .. } => "wifi.associate",
			Self::WifiDisassociate { .. } => "wifi.disassociate",
			Self::WifiSetRegdom { .. } => "wifi.set_regdom",
			Self::WgSetDevice { .. } => "wg.set_device",
			Self::WgSetPeers { .. } => "wg.set_peers",
			Self::DnsApply { .. } => "dns.apply",
			Self::LinkSetIpv6Token { .. } => "link.set_ipv6_token",
			Self::RuleAdd { .. } => "rule.add",
			Self::RuleDel { .. } => "rule.del",
			Self::QdiscSet { .. } => "qdisc.set",
			Self::IngressRedirect { .. } => "ingress.redirect",
			Self::IngressRedirectClear { .. } => "ingress.redirect.clear",
			Self::QdiscReset { .. } => "qdisc.reset",
			Self::SysctlSetForwarding { .. } => "sysctl.set_forwarding",
			Self::NatReplace { .. } => "nat.replace",
			Self::HookRun { .. } => "hook.run",
			Self::CommitArm { .. } => "commit.arm",
			Self::CommitConfirm => "commit.confirm",
			Self::CommitRevert { .. } => "commit.revert",
		}
	}

	/// Whether this action can interrupt traffic on the interface it touches.
	///
	/// A guard blocks the disruptive ones (`docs/decisions/0010`). The list is
	/// wider than "removes the link" on purpose: changing the address on an
	/// interface carrying an NFS mount breaks it exactly as thoroughly as
	/// downing it, and enslaving an interface to a bridge moves its addresses.
	///
	/// `link.set_mtu` counts as disruptive deliberately. Lowering an MTU
	/// interrupts traffic in flight and raising it can black-hole a path until
	/// PMTU discovery catches up; a guard that allowed it for convenience
	/// would be a guard nobody could rely on.
	#[must_use]
	pub fn is_disruptive(&self) -> bool {
		match self {
			Self::LinkDelete { .. }
			| Self::LinkDown { .. }
			| Self::LinkSetMaster { .. }
			| Self::LinkUnsetMaster { .. }
			| Self::LinkSetMac { .. }
			| Self::LinkSetMtu { .. }
			| Self::AddrDel { .. }
			| Self::RouteDel { .. }
			| Self::BackendStop { .. }
			| Self::BackendReload { .. }
			| Self::WifiDisassociate { .. }
			| Self::WifiAssociate { .. }
			| Self::WgSetDevice { .. }
			| Self::WgSetPeers { .. }
			// Removing a VLAN from a port stops traffic in it reaching that
			// port, which is the same kind of interruption as taking an
			// address away.
			| Self::BridgeVlanDel { .. }
			// Clearing a redirect stops everything arriving on the interface
			// being shaped, which on a saturated line is the difference
			// between a working connection and an unusable one -- the same
			// kind of loss as withdrawing a route.
			// Withdrawing a rule sends traffic back to the main table, which
			// on a policy-routed host is the difference between reaching a
			// network and not.
			| Self::RuleDel { .. }
			| Self::IngressRedirectClear { .. } => true,
			// Turning forwarding off cuts every host behind this interface
			// off from everything in front of it, which is a worse
			// interruption than taking one address away. Turning it on
			// interrupts nothing, so a guard has no reason to block it and
			// blocking it would leave a router that cannot route.
			Self::SysctlSetForwarding { enabled, .. } => !enabled,
			Self::LinkCreate { .. }
			| Self::LinkUp { .. }
			| Self::AddrAdd { .. }
			| Self::RouteAdd { .. }
			| Self::BackendStart { .. }
			| Self::WifiSetProfiles { .. }
			| Self::WifiSetRegdom { .. }
			| Self::DnsApply { .. }
			| Self::HookRun { .. }
			| Self::CommitArm { .. }
			| Self::CommitConfirm
			| Self::BridgeVlanAdd { .. }
			// Replacing a qdisc discards whatever is queued on the interface,
			// which is a few milliseconds of loss that TCP absorbs -- not the
			// kind of interruption a guard exists to prevent. Calling it
			// disruptive would block the one change that fixes a link which is
			// already dropping packets from bufferbloat.
			| Self::QdiscSet { .. }
			| Self::QdiscReset { .. }
			| Self::IngressRedirect { .. }
			// Not because replacing the table is harmless -- withdrawing NAT
			// cuts off a whole LAN. It is because `interface()` returns
			// nothing for this op, so no guard can match it anyway, and
			// claiming otherwise would suggest a protection that does not
			// exist. The commit-confirm inverse is what covers this one.
			| Self::NatReplace { .. }
			// Adding a rule changes which table a packet consults, which can
			// move traffic -- but a guard protects an interface, and a rule
			// names at most one incidentally. Removing one is the disruptive
			// direction and is covered below.
			| Self::RuleAdd { .. }
			// Changing the host half of an address the router supplies does
			// change an address -- but SLAAC addresses are not netcfgd's and
			// the old one lingers until it expires, so nothing is cut off at
			// the moment of the change.
			| Self::LinkSetIpv6Token { .. }
			| Self::CommitRevert { .. } => false,
		}
	}

	/// Which interface this acts on, where it acts on one.
	#[must_use]
	pub fn interface(&self) -> Option<&str> {
		match self {
			Self::LinkCreate { name, .. }
			| Self::LinkDelete { name }
			| Self::LinkSetMtu { name, .. }
			| Self::LinkSetMac { name, .. }
			| Self::LinkSetMaster { name, .. }
			| Self::LinkUnsetMaster { name }
			| Self::LinkUp { name }
			| Self::LinkSetIpv6Token { name, .. }
			| Self::LinkDown { name } => Some(name),
			Self::BridgeVlanAdd { iface, .. }
			| Self::BridgeVlanDel { iface, .. }
			| Self::AddrAdd { iface, .. }
			| Self::AddrDel { iface, .. }
			| Self::RouteAdd { iface, .. }
			| Self::RouteDel { iface, .. }
			| Self::BackendStart { iface, .. }
			| Self::BackendStop { iface, .. }
			| Self::BackendReload { iface, .. }
			| Self::WgSetDevice { iface, .. }
			| Self::WgSetPeers { iface, .. }
			| Self::SysctlSetForwarding { iface, .. }
			| Self::QdiscSet { iface, .. }
			| Self::QdiscReset { iface }
			| Self::IngressRedirect { iface, .. }
			| Self::IngressRedirectClear { iface }
			| Self::HookRun { iface, .. } => Some(iface),
			Self::WifiSetProfiles { device, .. }
			| Self::WifiAssociate { device, .. }
			| Self::WifiDisassociate { device }
			| Self::WifiSetRegdom { device, .. } => Some(device),
			// Deliberately not attributed to an interface even though it
			// names several: the table is one object and replacing it is one
			// change to the host, so a guard on any single uplink has no
			// standing to refuse it.
			// A rule is host-wide: `iif`/`oif` are selectors, not ownership,
			// so attributing it to an interface would let a guard on an
			// unrelated device refuse it.
			Self::RuleAdd { .. }
			| Self::RuleDel { .. }
			| Self::NatReplace { .. }
			| Self::DnsApply { .. }
			| Self::CommitArm { .. }
			| Self::CommitConfirm
			| Self::CommitRevert { .. } => None,
		}
	}
}

/// Which desired field differs from which observed field, and how.
///
/// Carried on every action so that `ncfg plan` can say *why* rather than only
/// *what*. An action list without reasons is a black box with extra steps.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Reason {
	/// Which interface, where the action has one.
	#[serde(skip_serializing_if = "Option::is_none", default)]
	pub interface: Option<String>,
	/// Dotted path into the document, for example `addressing[0]`.
	pub field: String,
	/// The desired value, rendered.
	pub desired: String,
	/// The observed value, rendered, or `<absent>`.
	pub observed: String,
}

impl Reason {
	/// A reason for something that does not exist yet.
	#[must_use]
	pub fn absent(interface: &str, field: impl Into<String>, desired: impl Into<String>) -> Self {
		Self {
			interface: Some(interface.to_owned()),
			field: field.into(),
			desired: desired.into(),
			observed: "<absent>".to_owned(),
		}
	}

	/// A reason for something that exists but differs.
	#[must_use]
	pub fn differs(
		interface: &str,
		field: impl Into<String>,
		desired: impl Into<String>,
		observed: impl Into<String>,
	) -> Self {
		Self {
			interface: Some(interface.to_owned()),
			field: field.into(),
			desired: desired.into(),
			observed: observed.into(),
		}
	}

	/// A reason for removing something the config no longer asks for.
	#[must_use]
	pub fn unwanted(
		interface: &str,
		field: impl Into<String>,
		observed: impl Into<String>,
	) -> Self {
		Self {
			interface: Some(interface.to_owned()),
			field: field.into(),
			desired: "<absent>".to_owned(),
			observed: observed.into(),
		}
	}
}

/// One step of a plan.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Action {
	/// Position in the plan, and the handle `depends_on` refers to.
	pub id: u32,
	/// What to do.
	pub op: Op,
	/// Why this is here.
	pub reason: Reason,
	/// Actions that must complete first.
	pub depends_on: Vec<u32>,
	/// How to undo it. `None` means irreversible, and the plan warns.
	#[serde(skip_serializing_if = "Option::is_none", default)]
	pub inverse: Option<Op>,
}
