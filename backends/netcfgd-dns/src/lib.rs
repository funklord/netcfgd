#![forbid(unsafe_code)]

//! Delivering DNS configuration to whatever resolver the host runs.
//!
//! Decision 0007 makes each mode a contract with a specific tool, and makes
//! the compiler refuse a config asking a mode for something it cannot express.
//! By the time anything here runs, the policy is known to fit the mode.
//!
//! The scope-capable modes never flatten. That is the rule the whole module is
//! arranged around: silently collapsing split DNS sends internal queries to a
//! public resolver, which is a disclosure rather than a degradation. A mode
//! that cannot route refuses the config at compile time (decision 0007); a
//! mode that can route is delivered here with its scopes intact.

pub mod render;

pub use render::{Flat, Scope};

use netcfgd_model::{AppliedDns, DnsMode, DnsPolicy, DnsTransport};
use std::io::Write;
use std::path::Path;
use std::process::{Command, Stdio};

/// Where `resolv.conf` lives.
pub const RESOLV_CONF: &str = "/etc/resolv.conf";

/// Deliver every scope, and report what was delivered.
///
/// The report is what the next plan compares against, so it has to describe
/// what was actually written rather than what was asked for -- otherwise an
/// apply that half-failed would look settled and the idempotence gate would
/// pass on a lie.
///
/// # Errors
///
/// Returns a message naming the mode and what went wrong.
pub fn deliver(
	scopes: &[Scope<'_>],
	resolv_conf_path: &Path,
	run_dir: &Path,
) -> Result<Vec<AppliedDns>, String> {
	if scopes.is_empty() {
		return Ok(Vec::new());
	}

	// Every scope in one delivery must agree on the mode: a host cannot both
	// own resolv.conf and hand it to resolvconf. Disagreement is a config
	// error rather than something to resolve by picking one.
	let mode = &scopes[0].policy.mode;
	if let Some(other) = scopes
		.iter()
		.find(|scope| std::mem::discriminant(&scope.policy.mode) != std::mem::discriminant(mode))
	{
		return Err(format!(
			"scopes disagree about the dns mode: {} wants {} and {} wants {}",
			scopes[0].name,
			mode.name(),
			other.name,
			other.policy.mode.name()
		));
	}

	let delivered = match mode {
		DnsMode::None => Vec::new(),
		DnsMode::WriteResolvConf => write_resolv_conf(scopes, resolv_conf_path)?,
		DnsMode::Resolvconf => hand_to_resolvconf(scopes, false)?,
		DnsMode::Openresolv => hand_to_resolvconf(scopes, true)?,
		DnsMode::Resolved => hand_to_resolved(scopes)?,
		DnsMode::Dnsmasq => write_forwarder(scopes, Forwarder::Dnsmasq)?,
		DnsMode::Unbound => write_forwarder(scopes, Forwarder::Unbound)?,
		DnsMode::Exec(command) => hand_to_script(scopes, command)?,
	};

	record(&delivered, run_dir)?;
	Ok(delivered)
}

fn write_resolv_conf(scopes: &[Scope<'_>], path: &Path) -> Result<Vec<AppliedDns>, String> {
	let flat = render::flatten(scopes);
	let text = render::resolv_conf(&flat, "netcfgd");

	// Temp file plus rename, as everywhere else netcfgd writes: a resolver
	// reading during the write must see the old file or the new one, never
	// half of each. A truncated resolv.conf is a machine that cannot resolve
	// anything.
	let temporary = path.with_extension("netcfgd.tmp");
	std::fs::write(&temporary, &text)
		.map_err(|error| format!("could not write {}: {error}", temporary.display()))?;
	std::fs::rename(&temporary, path)
		.map_err(|error| format!("could not replace {}: {error}", path.display()))?;

	Ok(applied(scopes))
}

/// Hand each scope to `resolvconf`.
///
/// `openresolv` adds one thing: `-p` marks an interface *private*, so its
/// servers are queried only for the domains its blob names. That is exactly
/// this model's exclusive routing domain, arrived at independently, and it is
/// why decision 0007 makes `Openresolv` a separate mode rather than a
/// capability discovered from whichever resolvconf is installed.
///
/// A scope with no exclusive domain is handed over the same way in both modes,
/// so the difference shows up only where it means something.
fn hand_to_resolvconf(scopes: &[Scope<'_>], openresolv: bool) -> Result<Vec<AppliedDns>, String> {
	for scope in scopes {
		// `resolvconf -a` keys on an interface name, so the global scope needs
		// one too. `lo.netcfgd` is the conventional shape for a subscriber
		// that is not really an interface.
		let key = if scope.name == "globals" {
			"lo.netcfgd".to_owned()
		} else {
			format!("{}.netcfgd", scope.name)
		};

		let private = openresolv && scope.policy.domains.iter().any(|domain| domain.exclusive);

		let mut command = Command::new("resolvconf");
		command.args(["-a", &key]);
		if private {
			command.arg("-p");
		}
		let mut child =
			command
				.stdin(Stdio::piped())
				.spawn()
				.map_err(|error| match error.kind() {
					std::io::ErrorKind::NotFound => {
						"resolvconf is not installed; use dns_mode = \"write_resolv_conf\" \
					 or install openresolv"
							.to_owned()
					}
					_ => format!("could not run resolvconf: {error}"),
				})?;

		if let Some(stdin) = child.stdin.as_mut() {
			stdin
				.write_all(render::resolvconf_blob(scope.policy).as_bytes())
				.map_err(|error| format!("could not write to resolvconf: {error}"))?;
		}
		let status = child
			.wait()
			.map_err(|error| format!("resolvconf did not finish: {error}"))?;
		if !status.success() {
			// The likeliest cause of a failure with `-p` is a resolvconf that
			// is not openresolv, and the two share a command name -- so the
			// message says which mode to use instead rather than leaving the
			// operator to work out that their resolvconf is the wrong one.
			if private {
				return Err(format!(
					"`resolvconf -a {key} -p` exited with {status}. `-p` is openresolv's, \
					 and several tools install a `resolvconf`; if this one is not \
					 openresolv, split DNS cannot be delivered through it -- use \
					 mode = \"resolvconf\" for flat delivery, and drop the exclusive \
					 routing domains"
				));
			}
			return Err(format!("resolvconf -a {key} exited with {status}"));
		}
	}
	Ok(applied(scopes))
}

/// Hand each scope to `systemd-resolved` through `resolvectl`.
///
/// Through the command rather than D-Bus, for the reason decision 0014 gave
/// about iwd: a D-Bus client would be the largest thing in this repository.
/// The objection 0014 raised to `iwctl` does not apply here, and the
/// difference is worth naming -- nothing below parses `resolvectl`'s output.
/// Passing arguments to a documented command is a contract; scraping an
/// interactive tool's display is not.
fn hand_to_resolved(scopes: &[Scope<'_>]) -> Result<Vec<AppliedDns>, String> {
	for scope in scopes {
		// resolved is per-link and has no global scope of its own, so the
		// globals scope goes to the loopback -- which is where resolved puts
		// its own fallback configuration too.
		let link = if scope.name == "globals" {
			"lo"
		} else {
			scope.name
		};

		let servers: Vec<String> = scope
			.policy
			.servers
			.iter()
			.map(|server| server.addr.to_string())
			.collect();
		run_resolvectl("dns", link, &servers)?;

		// resolved spells an exclusive routing domain with a leading `~`, and
		// a search domain without one. The model already distinguishes them,
		// so this is a rendering rather than a decision.
		let mut domains: Vec<String> = scope
			.policy
			.domains
			.iter()
			.map(|domain| {
				if domain.exclusive {
					format!("~{}", domain.suffix)
				} else {
					domain.suffix.clone()
				}
			})
			.collect();
		domains.extend(scope.policy.search.iter().cloned());
		if !domains.is_empty() {
			run_resolvectl("domain", link, &domains)?;
		}
	}
	Ok(applied(scopes))
}

fn run_resolvectl(verb: &str, link: &str, values: &[String]) -> Result<(), String> {
	let status = Command::new("resolvectl")
		.arg(verb)
		.arg(link)
		.args(values)
		.status()
		.map_err(|error| match error.kind() {
			std::io::ErrorKind::NotFound => {
				"resolvectl is not installed, so systemd-resolved is not running here; \
				 mode = \"resolved\" needs it"
					.to_owned()
			}
			_ => format!("could not run resolvectl: {error}"),
		})?;
	if !status.success() {
		return Err(format!("`resolvectl {verb} {link}` exited with {status}"));
	}
	Ok(())
}

/// Which forwarding resolver a configuration file is for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Forwarder {
	Dnsmasq,
	Unbound,
}

impl Forwarder {
	fn name(self) -> &'static str {
		match self {
			Self::Dnsmasq => "dnsmasq",
			Self::Unbound => "unbound",
		}
	}

	/// Where the generated file goes.
	///
	/// Overridable so a test can point somewhere that is not the host's real
	/// resolver configuration -- the same reason `NCFG_RESOLV_CONF` exists,
	/// and it exists because a test very nearly rewrote this machine's.
	fn path(self) -> std::path::PathBuf {
		let variable = match self {
			Self::Dnsmasq => "NCFG_DNSMASQ_CONF",
			Self::Unbound => "NCFG_UNBOUND_CONF",
		};
		std::env::var_os(variable).map_or_else(
			|| match self {
				Self::Dnsmasq => std::path::PathBuf::from("/etc/dnsmasq.d/netcfgd.conf"),
				Self::Unbound => {
					std::path::PathBuf::from("/etc/unbound/unbound.conf.d/netcfgd.conf")
				}
			},
			std::path::PathBuf::from,
		)
	}
}

/// Write a forwarding resolver's configuration.
///
/// Both express a routing domain as "send this suffix to these servers", which
/// is what makes them scope-capable -- dnsmasq as `server=/suffix/address` and
/// unbound as a `forward-zone` stanza. The two spellings mean the same thing,
/// which is decision 0007's whole premise.
fn write_forwarder(scopes: &[Scope<'_>], forwarder: Forwarder) -> Result<Vec<AppliedDns>, String> {
	let text = match forwarder {
		Forwarder::Dnsmasq => render::dnsmasq_conf(scopes),
		Forwarder::Unbound => render::unbound_conf(scopes),
	};
	let path = forwarder.path();

	if let Some(parent) = path.parent() {
		// Not created if it is missing: an absent `/etc/dnsmasq.d` means
		// dnsmasq is not installed or does not read that directory, and
		// creating it would leave a file nothing consumes while reporting
		// success. Constraint 2 -- the filesystem reflects use -- cuts both
		// ways.
		if !parent.is_dir() {
			return Err(format!(
				"{} does not exist, so {} is not installed here or does not read it; \
				 mode = \"{}\" needs it",
				parent.display(),
				forwarder.name(),
				forwarder.name()
			));
		}
	}

	let temporary = path.with_extension("netcfgd.tmp");
	std::fs::write(&temporary, &text)
		.map_err(|error| format!("could not write {}: {error}", temporary.display()))?;
	std::fs::rename(&temporary, &path)
		.map_err(|error| format!("could not replace {}: {error}", path.display()))?;

	Ok(applied(scopes))
}

/// Hand the whole scoped structure to a script, as JSON on stdin.
///
/// The escape hatch, and the only backend that receives scopes rather than a
/// rendering of them -- decision 0007 is explicit that a site wanting
/// resolved's `MulticastDNS` or anything else outside the model puts it here.
///
/// Run without a shell. The command is a config value, and a shell would make
/// the DNS mode a place where a config file becomes arbitrary code with word
/// splitting attached -- the same rule the secret resolver's exec provider
/// follows.
fn hand_to_script(scopes: &[Scope<'_>], command: &str) -> Result<Vec<AppliedDns>, String> {
	let mut parts = command.split_whitespace();
	let program = parts
		.next()
		.ok_or_else(|| "the exec dns mode needs a command".to_owned())?;

	let mut child = Command::new(program)
		.args(parts)
		.stdin(Stdio::piped())
		.spawn()
		.map_err(|error| match error.kind() {
			std::io::ErrorKind::NotFound => format!("the dns script `{program}` is not there"),
			_ => format!("could not run {program}: {error}"),
		})?;

	if let Some(stdin) = child.stdin.as_mut() {
		stdin
			.write_all(render::scopes_json(scopes).as_bytes())
			.map_err(|error| format!("could not write to {program}: {error}"))?;
	}
	let status = child
		.wait()
		.map_err(|error| format!("{program} did not finish: {error}"))?;
	if !status.success() {
		return Err(format!("the dns script `{program}` exited with {status}"));
	}
	Ok(applied(scopes))
}

fn applied(scopes: &[Scope<'_>]) -> Vec<AppliedDns> {
	scopes
		.iter()
		.map(|scope| AppliedDns {
			scope: scope.name.to_owned(),
			policy: scope.policy.clone(),
		})
		.collect()
}

/// Write the rendered scope table where `cat` can reach it.
///
/// Decision 0007's partial mitigation for the one place principle 2 bends:
/// once DNS is handed to another daemon, the effective behaviour lives in that
/// daemon's head. netcfgd can at least make its own half greppable, so a
/// disagreement between the two is diffable rather than a matter of opinion.
fn record(delivered: &[AppliedDns], run_dir: &Path) -> Result<(), String> {
	let dir = run_dir.join("dns");
	std::fs::create_dir_all(&dir)
		.map_err(|error| format!("could not create {}: {error}", dir.display()))?;

	for entry in delivered {
		let mut text = format!(
			"# scope: {}\n# mode:  {}\n",
			entry.scope,
			entry.policy.mode.name()
		);
		text.push_str(&render::resolvconf_blob(&entry.policy));
		for domain in &entry.policy.domains {
			text.push_str(&format!(
				"# routing domain {}{}\n",
				domain.suffix,
				if domain.exclusive { " (exclusive)" } else { "" }
			));
		}
		let path = dir.join(format!("{}.conf", entry.scope));
		std::fs::write(&path, text)
			.map_err(|error| format!("could not write {}: {error}", path.display()))?;
	}
	Ok(())
}

/// Collect the scopes a document asks for, in a deterministic order.
#[must_use]
pub fn scopes_of(document: &netcfgd_model::Document) -> Vec<Scope<'_>> {
	let mut scopes = Vec::new();
	if document.globals.dns.mode != DnsMode::None {
		scopes.push(Scope {
			name: "globals",
			policy: &document.globals.dns,
		});
	}
	for interface in &document.interfaces {
		if let Some(policy) = &interface.dns {
			if policy.mode != DnsMode::None {
				scopes.push(Scope {
					name: &interface.name,
					policy,
				});
			}
		}
	}
	scopes
}

/// One scope, for the executor's per-scope `dns.apply` action.
#[must_use]
pub fn single<'a>(name: &'a str, policy: &'a DnsPolicy) -> Vec<Scope<'a>> {
	vec![Scope { name, policy }]
}
