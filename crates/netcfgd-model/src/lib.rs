#![forbid(unsafe_code)]

//! The desired-state document: the one artifact everything else in netcfgd
//! hangs off.
//!
//! This crate is pure. It performs no I/O, touches no hardware, and reads no
//! clock or environment, because the planner's testability depends on the
//! whole path from config text to action list being a function (project.md
//! section 5). Nothing here may acquire a dependency that breaks that.
//!
//! Three invariants are enforced rather than documented:
//!
//! - **Determinism.** The same logical document encodes to byte-identical
//!   output. Lists sort by a declared key, field order is the declaration
//!   order, there are no floats and no unordered maps anywhere in these types.
//!   See [`Document::canonicalize`].
//! - **No silent field-dropping.** Every struct denies unknown fields, so a
//!   document carrying something this build does not understand is rejected
//!   whole rather than being quietly reinterpreted.
//! - **No secret material.** Secrets appear only as [`SecretRef`]
//!   indirections, and delegated prefixes only as [`PrefixRef`]. Neither type
//!   can hold a value, which is what makes a document safe to write to `/run`
//!   and, eventually, to transmit.

pub mod address;
pub mod canonical;
pub mod control;
pub mod device;
pub mod dns;
pub mod hash;
pub mod hook;
pub mod interface;
pub mod key;
pub mod observed;
pub mod route;
pub mod rule;
pub mod secret;
pub mod security;
pub mod wifi;

pub use address::{
	derive_from_delegation, AddressSource, Delegated, Dhcp4, Dhcp6, PdRequest, PrefixRef, Slaac,
	Static,
};
pub use control::{Control, Principal, Tier};
pub use device::{
	normalize_station, AccessControl, AccessPoint, AclPolicy, Device, DeviceMatch, MacPolicy,
	OnUnmanage, WifiDevicePolicy,
};
pub use dns::{DnsMode, DnsPolicy, DnsServer, DnsTransport, Dnssec, RoutingDomain};
pub use hook::{HookPhase, HookRef};
pub use interface::{
	BondMode, BridgeVlan, Guard, Interface, InterfaceKind, LinkSettings, MacvlanConfig,
	MacvlanMode, QdiscKind, QdiscPolicy, RaPolicy, Toggle, TunConfig, TunMode, TunnelConfig,
	TunnelKind, VlanProtocol, VrfConfig, WgPeer,
};
pub use key::Key;
pub use observed::{
	AppliedDns, BackendKind, Delegation, Observed, ObservedAddress, ObservedBackend,
	ObservedBridgeVlan, ObservedLink, ObservedRoute, ObservedRule, Origin, Ownership,
};
pub use route::{Route, RouteScope};
pub use rule::{RoutingRule, RuleAction, RuleFamily};
pub use secret::{SecretProvider, SecretRef};
pub use security::{EapConfig, EapMethod, Security};
pub use wifi::{Ssid, WifiNetwork};

use serde::{Deserialize, Serialize};

/// `#[serde(default)]` needs a function, and several fields default to true.
pub(crate) fn default_true() -> bool {
	true
}

/// The schema version this build produces and accepts.
///
/// **Pinned at 1.0 until netcfgd ships, deliberately** (decision 0038).
/// Versioning is a promise to consumers, and before a release there are none:
/// counting minor bumps across a schema still being designed produces a number
/// that measures how much work happened rather than what anybody can rely on.
///
/// This is not a licence to change the schema quietly. The two witnesses under
/// `docs/schema/` still move on every change and still have to be blessed
/// deliberately (decision 0020), which is the mechanism that was ever doing
/// the work -- the version was a weaker second signal alongside it.
///
/// Bumping `major` means a consumer of the old version must refuse the
/// document outright, which is what [`Document::from_json`] does. `minor`
/// starts counting at the first release.
pub const SCHEMA_VERSION: Version = Version { major: 1, minor: 0 };

/// A `{major, minor}` schema version.
///
/// Compared by `major` only when deciding whether a document is readable; a
/// higher `minor` from a newer producer is still rejected, but by the
/// unknown-field rule rather than by this type, since a newer minor that
/// happens to use no new fields is genuinely readable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Version {
	/// Incompatible revision. A differing major is a hard refusal.
	pub major: u16,
	/// Additive revision. A higher minor may still be readable.
	pub minor: u16,
}

/// What to do when observed state stops matching desired state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DriftPolicy {
	/// Say so and change nothing. The default, deliberately: over-claiming
	/// ownership deletes somebody's manual change, under-claiming only costs
	/// convenience.
	#[default]
	Report,
	/// Put it back the way the config says.
	Reconcile,
	/// Do not even look.
	Ignore,
}

/// Where the system hostname comes from.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HostnamePolicy {
	/// netcfgd does not manage the hostname.
	#[default]
	None,
	/// Take it from a DHCP lease.
	FromDhcp,
	/// A fixed name from the config.
	Static(String),
}

/// Host-wide policy that per-interface settings compose over.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Globals {
	/// The fallback DNS scope. Per-interface policies are scopes in their own
	/// right rather than overlays on this one; see `docs/decisions/0007`.
	pub dns: DnsPolicy,
	/// Drift behaviour for interfaces that do not state their own.
	pub on_drift_default: DriftPolicy,
	/// Default commit-confirm window in seconds.
	pub confirm_default: Option<u32>,
	/// Hostname handling.
	pub hostname_policy: HostnamePolicy,
	/// Who may do what over the control socket.
	pub control: Control,
}

/// The whole-host desired state.
///
/// This is the canonical form. The per-interface files under
/// `/run/netcfgd/desired/` are projections of it for convenience, not separate
/// documents.
#[derive(Debug, Clone, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Document {
	/// Schema version of this document.
	pub schema_version: Version,
	/// Informational provenance, excluded from equality. Two documents that
	/// differ only here describe the same desired state, and a plan computed
	/// from either must be identical.
	#[serde(skip_serializing_if = "Option::is_none", default)]
	pub generated_by: Option<String>,
	/// Host-wide policy.
	pub globals: Globals,
	/// Per-device policy, sorted by name. Not addressing; see [`Interface`].
	pub devices: Vec<Device>,
	/// Interfaces, sorted by name.
	pub interfaces: Vec<Interface>,
	/// Wifi profiles, sorted by id. Not bound to a device.
	pub networks: Vec<WifiNetwork>,
	/// Policy routing rules, sorted by priority. Host-wide, not per-interface
	/// -- see [`rule`] for why.
	#[serde(default)]
	pub rules: Vec<RoutingRule>,
	/// Access points this host runs, sorted by id. Unimplemented; see
	/// [`AccessPoint`].
	#[serde(default)]
	pub access_points: Vec<AccessPoint>,
}

// `generated_by` is provenance, not state. Deriving PartialEq would make a
// document produced by a different build compare unequal to an identical one,
// and the reconciler would see a change where there is none.
impl PartialEq for Document {
	fn eq(&self, other: &Self) -> bool {
		self.schema_version == other.schema_version
			&& self.globals == other.globals
			&& self.devices == other.devices
			&& self.interfaces == other.interfaces
			&& self.networks == other.networks
			&& self.rules == other.rules
			&& self.access_points == other.access_points
	}
}

impl Default for Document {
	fn default() -> Self {
		Self {
			schema_version: SCHEMA_VERSION,
			generated_by: None,
			globals: Globals::default(),
			devices: Vec::new(),
			interfaces: Vec::new(),
			networks: Vec::new(),
			rules: Vec::new(),
			access_points: Vec::new(),
		}
	}
}

/// Why a document was refused.
///
/// Every variant names the thing that was wrong specifically enough to fix it.
/// "Invalid document" is not a diagnostic.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
	/// The document's major version differs from this build's.
	SchemaMajor {
		/// What the document claims.
		found: Version,
		/// What this build speaks.
		expected: Version,
	},
	/// Two entries share a key that must be unique.
	DuplicateKey {
		/// Which collection.
		collection: &'static str,
		/// The repeated key.
		key: String,
	},
	/// An interface names more than one of an addressing source that may
	/// appear at most once. See `docs/decisions/0006` rule 1.
	RepeatedAddressSource {
		/// The interface.
		interface: String,
		/// Which source kind was repeated.
		source: &'static str,
	},
	/// A DNS mode was asked for routing domains it cannot express. See
	/// `docs/decisions/0007`.
	DnsModeCannotRoute {
		/// Where the policy came from: an interface name, or `globals`.
		scope: String,
		/// The mode that cannot route.
		mode: &'static str,
	},
	/// An SSID was longer than the 32 octets 802.11 allows.
	SsidTooLong {
		/// How many octets were supplied.
		len: usize,
	},
	/// An SSID hex string was not valid hex.
	SsidNotHex,
	/// A Curve25519 key was not 44 characters of base64.
	BadKey {
		/// How long the text actually was.
		len: usize,
	},
	/// A hook path was not absolute.
	HookPathNotAbsolute {
		/// The offending path.
		path: String,
	},
	/// The document could not be parsed at all.
	Syntax(String),
}

impl std::fmt::Display for Error {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		match self {
			Self::SchemaMajor { found, expected } => write!(
				f,
				"document schema {}.{} is not readable by this build, which speaks {}.{}",
				found.major, found.minor, expected.major, expected.minor
			),
			Self::DuplicateKey { collection, key } => {
				write!(f, "duplicate {collection} entry: {key}")
			}
			Self::RepeatedAddressSource { interface, source } => write!(
				f,
				"interface {interface} names {source} more than once; at most one is allowed"
			),
			Self::DnsModeCannotRoute { scope, mode } => write!(
				f,
				"dns scope {scope} uses routing domains, which mode {mode} cannot express"
			),
			Self::SsidTooLong { len } => {
				write!(f, "ssid is {len} octets; the maximum is 32")
			}
			Self::SsidNotHex => write!(f, "ssid is not a valid lowercase hex string"),
			Self::BadKey { len } => write!(
				f,
				"a key is 44 characters of base64 ending in `=`, and this one is {len}"
			),
			Self::HookPathNotAbsolute { path } => {
				write!(f, "hook path {path} is not absolute")
			}
			Self::Syntax(msg) => write!(f, "malformed document: {msg}"),
		}
	}
}

impl std::error::Error for Error {}
