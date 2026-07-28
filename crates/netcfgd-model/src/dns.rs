//! DNS policy as a per-link scope, and what each delivery mode can express.

use serde::{Deserialize, Serialize};
use std::net::IpAddr;

/// How a resolved DNS policy reaches the system.
///
/// A mode is a contract with a specific tool, not a preference. There is
/// deliberately no `Auto`: the mode decides where queries go, and that is not
/// something to pick by heuristic (`docs/decisions/0007`).
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DnsMode {
	/// netcfgd does not manage DNS.
	#[default]
	None,
	/// Write `/etc/resolv.conf` directly.
	WriteResolvConf,
	/// Hand a flat per-interface blob to any `resolvconf` implementation.
	Resolvconf,
	/// Use openresolv's `private_interfaces` and subscriber mechanism, which
	/// carries scopes. The path to recommend: no systemd, and the same
	/// upstream as the dhcpcd this project already delegates leases to.
	Openresolv,
	/// Hand scopes to `systemd-resolved`. Pulls in systemd on any host that
	/// selects it, which is why it is one mode among several and never a
	/// default.
	Resolved,
	/// Write dnsmasq configuration directly.
	Dnsmasq,
	/// Write unbound configuration directly.
	Unbound,
	/// Hand the whole scoped structure to a script as JSON on stdin. The
	/// escape hatch; it receives scopes, not a flattened list.
	Exec(String),
}

impl DnsMode {
	/// Whether this mode can express per-domain query routing.
	///
	/// `resolv.conf` cannot: its `search` line is suffix completion, not
	/// routing, and there is no per-domain server concept in the format. A
	/// config that asks a flat mode for routing domains is an error rather
	/// than something to flatten, because flattening sends internal queries to
	/// a public resolver.
	#[must_use]
	pub fn can_route(&self) -> bool {
		match self {
			Self::None | Self::WriteResolvConf | Self::Resolvconf => false,
			Self::Openresolv | Self::Resolved | Self::Dnsmasq | Self::Unbound | Self::Exec(_) => {
				true
			}
		}
	}

	/// A stable name for diagnostics.
	#[must_use]
	pub fn name(&self) -> &'static str {
		match self {
			Self::None => "none",
			Self::WriteResolvConf => "write_resolv_conf",
			Self::Resolvconf => "resolvconf",
			Self::Openresolv => "openresolv",
			Self::Resolved => "resolved",
			Self::Dnsmasq => "dnsmasq",
			Self::Unbound => "unbound",
			Self::Exec(_) => "exec",
		}
	}
}

/// A single upstream resolver.
///
/// A bare address cannot carry a port or the name to validate a certificate
/// against, so this is a struct from the start even though `DoT` lands much
/// later -- widening it after the M4 freeze would be a major version bump.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DnsServer {
	/// The resolver's address.
	pub addr: IpAddr,
	/// Non-default port.
	#[serde(skip_serializing_if = "Option::is_none", default)]
	pub port: Option<u16>,
	/// Name to expect in the server's certificate, for `DnsTransport::Tls`.
	#[serde(skip_serializing_if = "Option::is_none", default)]
	pub sni: Option<String>,
}

/// A suffix whose queries route to this scope's servers.
///
/// Kept separate from `search`, which is suffix completion. resolved spells
/// both as one list distinguished by a `~` prefix; that is an accident of its
/// config format and a reliable source of confusion, and only one of the two
/// is universally supported.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RoutingDomain {
	/// The suffix, or `"."` for the catch-all scope.
	pub suffix: String,
	/// Whether this scope's servers are used *only* for this suffix.
	#[serde(default)]
	pub exclusive: bool,
}

/// DNSSEC validation posture, passed to a backend that implements it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Dnssec {
	/// Do not validate.
	#[default]
	No,
	/// Validate where the zone is signed; do not fail otherwise.
	Allow,
	/// Require validation.
	Yes,
}

/// Transport to the upstream resolver.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DnsTransport {
	/// Port 53, cleartext.
	#[default]
	Plain,
	/// DNS over TLS.
	Tls,
	/// DNS over HTTPS.
	Https,
}

/// One DNS scope: an interface's, or the host-wide fallback.
///
/// A per-interface policy is a scope in its own right. It is never merged into
/// a single global server list at compile time, because doing so destroys the
/// per-link structure at the earliest and least recoverable moment
/// (`docs/decisions/0007`).
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct DnsPolicy {
	/// How this scope reaches the system.
	pub mode: DnsMode,
	/// Upstream resolvers for this scope.
	pub servers: Vec<DnsServer>,
	/// Suffix completion. Every mode supports it.
	pub search: Vec<String>,
	/// Query routing. Only scope-capable modes support it.
	pub domains: Vec<RoutingDomain>,
	/// Resolver options passed through verbatim.
	pub options: Vec<String>,
	/// DNSSEC posture, where the backend implements it.
	#[serde(skip_serializing_if = "Option::is_none")]
	pub dnssec: Option<Dnssec>,
	/// Transport, where the backend implements it.
	#[serde(skip_serializing_if = "Option::is_none")]
	pub transport: Option<DnsTransport>,
}

impl DnsPolicy {
	/// Whether this scope asks for anything its mode cannot deliver.
	#[must_use]
	pub fn needs_routing(&self) -> bool {
		!self.domains.is_empty()
	}
}
