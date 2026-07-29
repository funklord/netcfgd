#![forbid(unsafe_code)]

//! Delivering DNS configuration to whatever resolver the host runs.
//!
//! Decision 0007 makes each mode a contract with a specific tool, and makes
//! the compiler refuse a config asking a mode for something it cannot express.
//! By the time anything here runs, the policy is known to fit the mode.
//!
//! Only the flat modes are implemented. `Openresolv`, `Resolved`, `Dnsmasq`
//! and `Unbound` carry scopes and land with M4; each is refused by name rather
//! than silently treated as flat, because silently flattening split DNS sends
//! internal queries to a public resolver.

pub mod render;

pub use render::{Flat, Scope};

use netcfgd_model::{AppliedDns, DnsMode, DnsPolicy};
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
		DnsMode::Resolvconf => hand_to_resolvconf(scopes)?,
		other => {
			return Err(format!(
				"the {} dns backend is not implemented in this build; \
				 the scope-capable modes land with M4",
				other.name()
			))
		}
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

fn hand_to_resolvconf(scopes: &[Scope<'_>]) -> Result<Vec<AppliedDns>, String> {
	for scope in scopes {
		// `resolvconf -a` keys on an interface name, so the global scope needs
		// one too. `lo.netcfgd` is the conventional shape for a subscriber
		// that is not really an interface.
		let key = if scope.name == "globals" {
			"lo.netcfgd".to_owned()
		} else {
			format!("{}.netcfgd", scope.name)
		};

		let mut child = Command::new("resolvconf")
			.args(["-a", &key])
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
			return Err(format!("resolvconf -a {key} exited with {status}"));
		}
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
