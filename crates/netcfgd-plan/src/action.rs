//! The action taxonomy from project.md section 4.
//!
//! Every action is idempotent by construction, carries the reason it exists,
//! and declares its inverse so commit-confirm can revert without deriving one
//! after the fact -- when the network may already be unreachable.

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
			Self::BackendReload { .. } => "backend.reload",
			Self::WifiSetProfiles { .. } => "wifi.set_profiles",
			Self::WifiAssociate { .. } => "wifi.associate",
			Self::WifiDisassociate { .. } => "wifi.disassociate",
			Self::WifiSetRegdom { .. } => "wifi.set_regdom",
			Self::WgSetDevice { .. } => "wg.set_device",
			Self::WgSetPeers { .. } => "wg.set_peers",
			Self::DnsApply { .. } => "dns.apply",
			Self::HookRun { .. } => "hook.run",
			Self::CommitArm { .. } => "commit.arm",
			Self::CommitConfirm => "commit.confirm",
			Self::CommitRevert { .. } => "commit.revert",
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
			| Self::LinkDown { name } => Some(name),
			Self::AddrAdd { iface, .. }
			| Self::AddrDel { iface, .. }
			| Self::RouteAdd { iface, .. }
			| Self::RouteDel { iface, .. }
			| Self::BackendStart { iface, .. }
			| Self::BackendStop { iface, .. }
			| Self::BackendReload { iface, .. }
			| Self::WgSetDevice { iface, .. }
			| Self::WgSetPeers { iface, .. }
			| Self::HookRun { iface, .. } => Some(iface),
			Self::WifiSetProfiles { device, .. }
			| Self::WifiAssociate { device, .. }
			| Self::WifiDisassociate { device }
			| Self::WifiSetRegdom { device, .. } => Some(device),
			Self::DnsApply { .. }
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
