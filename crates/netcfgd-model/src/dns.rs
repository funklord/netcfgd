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

	/// Whether this scope has nothing to deliver.
	///
	/// `dns { }` with no servers, no search and no options is a block that asks
	/// for nothing, and a scope for it is an action that does nothing. The mode
	/// is not consulted: a mode alone delivers no configuration, it only says
	/// how configuration would be delivered if there were any.
	#[must_use]
	pub fn is_empty(&self) -> bool {
		self.servers.is_empty()
			&& self.search.is_empty()
			&& self.domains.is_empty()
			&& self.options.is_empty()
	}
}

/// Every DNS scope a document asks for, given what has been observed.
///
/// **One function, called by both the planner and the executor**, because they
/// have to agree and once did not. The planner learned that a modem helper's
/// report contributes nameservers (decision 0006 rule 4) and the executor kept
/// building its scope list from the document alone, so the plan said
/// `dns.apply` and the delivery wrote a `resolv.conf` with nothing in it. That
/// is the same failure `make executor-policy` exists to prevent one crate over,
/// and the same answer: not two implementations kept in step, one implementation.
///
/// Scopes are owned rather than borrowed because one of them does not exist in
/// the document -- it is synthesised from an observation, and there is nothing
/// to borrow it from.
///
/// The order is deterministic: globals first, then interfaces in document
/// order. `netcfgd-dns` reverses that when it flattens, on purpose -- a
/// specific answer is consulted before the fallback -- and that is its business
/// rather than this function's.
#[must_use]
pub fn scopes(document: &crate::Document, observed: &crate::Observed) -> Vec<(String, DnsPolicy)> {
	let mut scopes: Vec<(String, DnsPolicy)> = Vec::new();
	let global_mode = &document.globals.dns.mode;
	if *global_mode != DnsMode::None {
		scopes.push(("globals".to_owned(), document.globals.dns.clone()));
	}

	for interface in &document.interfaces {
		// An unmanaged device contributes no scope. `dns.apply` is host-wide,
		// so it names no interface and the planner's usual choke point does not
		// see it -- this is where it has to be asked.
		if document
			.devices
			.iter()
			.any(|device| device.name == interface.name && !device.managed)
		{
			continue;
		}

		let reported = reported_servers(interface, observed);
		match (&interface.dns, reported.is_empty()) {
			// A policy with a mode of its own and nothing to say. `dns { }`
			// with no servers, no search and no options is a block that asks
			// for nothing, and a scope for it is an action that does nothing.
			(Some(policy), true) if policy.is_empty() => {}
			(Some(policy), true) => {
				scopes.push((interface.name.clone(), inheriting(policy, global_mode)));
			}
			// Rule 4: a source contributes nameservers and they merge with what
			// the document wrote. The document's come first, so
			// first-occurrence-wins means a server an operator chose beats one
			// the network handed out.
			(Some(policy), false) => {
				let mut merged = inheriting(policy, global_mode);
				merged.servers.extend(reported);
				merged.servers.dedup();
				scopes.push((interface.name.clone(), merged));
			}
			// No `dns` block, but something reported servers. The mode is not a
			// choice: `netcfgd-dns` refuses a delivery whose scopes disagree
			// about it, so the only value that is not an error is the one the
			// rest of the host uses.
			(None, false) if *global_mode != DnsMode::None => {
				let mut policy = DnsPolicy {
					mode: global_mode.clone(),
					..DnsPolicy::default()
				};
				policy.servers.extend(reported);
				scopes.push((interface.name.clone(), policy));
			}
			// Servers reported and nowhere to put them, because this host
			// manages no DNS. Skipped rather than pushed with a `None` mode: a
			// scope that delivers nothing is still an action in the plan, and an
			// action that does nothing is one somebody reads and dismisses on
			// every run. A host that does not manage DNS should not start
			// because a modem appeared.
			(None, _) => {}
		}
	}
	scopes
}

/// A policy with the host's mode filled in where it states none of its own.
///
/// **The mode is not a per-interface choice.** `netcfgd-dns` refuses a delivery
/// whose scopes disagree about it, because a host cannot both own `resolv.conf`
/// and hand it to `resolvconf`. So `none` on a scope that has something to
/// deliver can only mean "not stated", and the only value that is not an error
/// is the one the rest of the host uses.
///
/// This closes a defect older than the modem work that surfaced while merging
/// two implementations of the scope list into one: `dns = "9.9.9.9"` on an
/// interface compiles to a policy with mode `none`, and the executor dropped
/// the scope -- so an operator wrote a nameserver down and netcfgd silently
/// ignored it. Nothing failed and nothing warned; the server simply never
/// reached `resolv.conf`.
fn inheriting(policy: &DnsPolicy, global_mode: &DnsMode) -> DnsPolicy {
	if policy.mode != DnsMode::None {
		return policy.clone();
	}
	DnsPolicy {
		mode: global_mode.clone(),
		..policy.clone()
	}
}

/// The nameservers an interface's sources contribute, from what was observed.
///
/// Only a `modem` source contributes any today -- a DHCP lease's servers belong
/// to the client that took the lease, which writes them itself. Gated on the
/// document actually asking for the source, because a report netcfgd has no
/// instruction about is an observation, and a resolver is not something to
/// configure off a file somebody dropped in `/run`.
fn reported_servers(interface: &crate::Interface, observed: &crate::Observed) -> Vec<DnsServer> {
	if !interface
		.addressing
		.iter()
		.any(|source| matches!(source, crate::AddressSource::Modem(_)))
	{
		return Vec::new();
	}
	observed
		.modems
		.iter()
		.filter(|modem| modem.interface == interface.name)
		.flat_map(|modem| modem.nameservers.iter())
		.filter_map(|server| {
			// Kept as text by the reader on purpose, so one bad line does not
			// discard a report. This is where it has to become an address.
			Some(DnsServer {
				addr: server.parse().ok()?,
				port: None,
				sni: None,
			})
		})
		.collect()
}
