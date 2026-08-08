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

	replace(path, &text)?;

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

	replace(&path, &text)?;

	Ok(applied(scopes))
}

/// Put `text` at `path`, through a temporary in the same directory.
///
/// A resolver reading during the write must see the old file or the new one
/// and never half of each: a truncated `resolv.conf` is a machine that cannot
/// resolve anything.
///
/// **The temporary's name is what makes that true for more than one writer.**
/// Both call sites named it after the target alone -- `resolv.netcfgd.tmp` for
/// every writer there will ever be -- and netcfgd applies from two processes,
/// `ncfg apply` and the daemon, either of which may deliver DNS. Interleaved,
/// one writer's bytes are renamed into place by the other writer's rename and
/// the loser's rename fails with `ENOENT` on a file it had just written. So
/// the pid and a counter are in the name: the pid because the second writer is
/// another process, the counter because it need not be.
///
/// One function rather than two copies for the same reason it was worth
/// finding: the copies had the same defect, and a fix applied to the one that
/// was noticed leaves the other reading as though it were safe.
///
/// The leading dot is not decoration. One of these directories is read by a
/// glob and the other by a program: `unbound.conf.d/*.conf` does not match a
/// name beginning with a dot, and dnsmasq's `conf-dir` always skips one. The
/// name this replaced -- `netcfgd.netcfgd.tmp` -- relied on the extension
/// alone, which is the weaker of the two guarantees and the only one dnsmasq
/// documents as configurable.
fn replace(path: &std::path::Path, text: &str) -> Result<(), String> {
	use std::sync::atomic::{AtomicU64, Ordering};

	/// Distinguishes one call from the next within a process.
	static SEQUENCE: AtomicU64 = AtomicU64::new(0);

	let name = path.file_name().map_or_else(
		|| "netcfgd".to_owned(),
		|name| name.to_string_lossy().into_owned(),
	);
	let temporary = path
		.parent()
		.unwrap_or_else(|| std::path::Path::new("."))
		.join(format!(
			".{name}.netcfgd.{}.{}",
			std::process::id(),
			SEQUENCE.fetch_add(1, Ordering::Relaxed)
		));

	let outcome = std::fs::write(&temporary, text)
		.map_err(|error| format!("could not write {}: {error}", temporary.display()))
		.and_then(|()| {
			std::fs::rename(&temporary, path)
				.map_err(|error| format!("could not replace {}: {error}", path.display()))
		});
	if outcome.is_err() {
		// A failed rename would otherwise leave the staging file next to the
		// resolver's own configuration for ever, which is how a full disk
		// turns into a directory nobody can read.
		let _ = std::fs::remove_file(&temporary);
	}
	outcome
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

/// One scope, for the executor's per-scope `dns.apply` action.
#[must_use]
pub fn single<'a>(name: &'a str, policy: &'a DnsPolicy) -> Vec<Scope<'a>> {
	vec![Scope { name, policy }]
}

#[cfg(test)]
mod tests {
	use super::replace;

	/// Two writers of one resolver file must not tread on each other.
	///
	/// netcfgd applies from two processes -- `ncfg apply` and the daemon --
	/// and either may deliver DNS, so `/etc/resolv.conf` had one staging name
	/// for every writer there would ever be. The loser of that race renames a
	/// file that is no longer there, and the caller is told it could not
	/// replace `resolv.conf` when it had in fact written it perfectly well.
	///
	/// Threads, because a temporary named after the process alone would pass a
	/// two-process test and still be one path for every thread inside one.
	#[test]
	fn two_writers_of_one_file_do_not_share_a_temporary() {
		let dir = netcfgd_testdir::TestDir::new("dns-two-writers");
		let path = dir.join("resolv.conf");
		let texts = [
			"nameserver 192.0.2.1\n".repeat(2048),
			"nameserver 192.0.2.2\n".repeat(2048),
		];

		std::thread::scope(|scope| {
			for text in &texts {
				let path = path.clone();
				scope.spawn(move || {
					for _ in 0..200 {
						replace(&path, text).expect("another writer must not fail this one");
					}
				});
			}
		});

		let final_text = std::fs::read_to_string(&path).expect("the file is there");
		assert!(
			texts.contains(&final_text),
			"{} bytes, neither writer's content",
			final_text.len()
		);
	}

	/// And nothing is left beside it for the resolver to find.
	///
	/// The staging file is a dotfile so that `unbound.conf.d/*.conf` cannot
	/// glob it and dnsmasq's `conf-dir` skips it, but the stronger property is
	/// that it is not there at all once the write returns.
	#[test]
	fn the_staging_file_does_not_outlive_the_write() {
		let dir = netcfgd_testdir::TestDir::new("dns-staging");
		let path = dir.join("netcfgd.conf");
		replace(&path, "server=192.0.2.1\n").expect("written");

		let left: Vec<String> = std::fs::read_dir(&dir)
			.expect("readable")
			.filter_map(Result::ok)
			.map(|entry| entry.file_name().to_string_lossy().into_owned())
			.filter(|name| name != "netcfgd.conf")
			.collect();
		assert!(left.is_empty(), "{left:?}");
	}
}
