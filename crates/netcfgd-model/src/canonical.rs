//! Canonicalisation, validation and the JSON encoding.
//!
//! The guarantee this module exists to provide: one logical document has
//! exactly one byte sequence. Plan diffs and caching are only trustworthy if
//! that holds, so it is tested rather than asserted.

use crate::address::check_multiplicity;
use crate::dns::DnsPolicy;
use crate::{Document, Error, InterfaceKind, SCHEMA_VERSION};

impl Document {
	/// Put every list in its declared order.
	///
	/// Sorting is by the key the schema names -- interfaces by name, networks
	/// by id, `WireGuard` peers by name -- never by insertion order, which
	/// depends on which drop-in file happened to be read first.
	pub fn canonicalize(&mut self) {
		self.devices.sort_by(|a, b| a.name.cmp(&b.name));
		self.interfaces.sort_by(|a, b| a.name.cmp(&b.name));
		self.networks.sort_by(|a, b| a.id.cmp(&b.id));
		self.rules.sort();
		self.access_points.sort_by(|a, b| a.id.cmp(&b.id));

		for interface in &mut self.interfaces {
			interface.routes.sort();
			interface.hooks.sort();
			if let InterfaceKind::WireGuard(wg) = &mut interface.kind {
				wg.peers.sort_by(|a, b| a.name.cmp(&b.name));
				for peer in &mut wg.peers {
					peer.allowed_ips.sort();
				}
			}
			if let InterfaceKind::Bridge(bridge) = &mut interface.kind {
				bridge.members.sort();
			}
			if let InterfaceKind::Bond(bond) = &mut interface.kind {
				bond.members.sort();
			}
			if let Some(dns) = &mut interface.dns {
				canonicalize_dns(dns);
			}
			if let Some(ra) = &mut interface.advertise {
				ra.prefixes.sort();
			}
		}

		for network in &mut self.networks {
			network.routes.sort();
			network.hooks.sort();
			if let Some(dns) = &mut network.dns {
				canonicalize_dns(dns);
			}
		}

		canonicalize_dns(&mut self.globals.dns);
	}

	/// Check every invariant that makes a document meaningful.
	///
	/// # Errors
	///
	/// Returns the first violation found, named specifically enough to fix.
	pub fn validate(&self) -> Result<(), Error> {
		if self.schema_version.major != SCHEMA_VERSION.major {
			return Err(Error::SchemaMajor {
				found: self.schema_version,
				expected: SCHEMA_VERSION,
			});
		}

		check_unique("device", self.devices.iter().map(|d| d.name.as_str()))?;
		check_unique("interface", self.interfaces.iter().map(|i| i.name.as_str()))?;
		check_unique("network", self.networks.iter().map(|n| n.id.as_str()))?;

		check_dns_capability("globals", &self.globals.dns)?;

		for interface in &self.interfaces {
			check_multiplicity(&interface.name, &interface.addressing)?;
			if let Some(dns) = &interface.dns {
				check_dns_capability(&interface.name, dns)?;
			}
			for hook in &interface.hooks {
				if !hook.path.starts_with('/') {
					return Err(Error::HookPathNotAbsolute {
						path: hook.path.clone(),
					});
				}
			}
		}

		for network in &self.networks {
			check_multiplicity(&network.id, &network.addressing)?;
			if let Some(dns) = &network.dns {
				check_dns_capability(&network.id, dns)?;
			}
			for hook in &network.hooks {
				if !hook.path.starts_with('/') {
					return Err(Error::HookPathNotAbsolute {
						path: hook.path.clone(),
					});
				}
			}
		}

		Ok(())
	}

	/// Canonicalise, validate, and encode as JSON.
	///
	/// The output is byte-identical for any two documents that describe the
	/// same desired state, whatever order their parts arrived in.
	///
	/// # Errors
	///
	/// Returns a validation error, or a serialisation error as
	/// [`Error::Syntax`].
	pub fn to_json_canonical(&self) -> Result<String, Error> {
		let mut doc = self.clone();
		doc.canonicalize();
		doc.validate()?;
		serde_json::to_string_pretty(&doc).map_err(|e| Error::Syntax(e.to_string()))
	}

	/// Parse a document, rejecting anything this build cannot fully represent.
	///
	/// # Errors
	///
	/// Returns [`Error::Syntax`] for malformed input or for a field this build
	/// does not recognise, and a validation error otherwise. An unknown field
	/// is refused rather than ignored: silently dropping one would mean acting
	/// on a subset of what the author wrote.
	pub fn from_json(text: &str) -> Result<Self, Error> {
		let doc: Self = serde_json::from_str(text).map_err(|e| Error::Syntax(e.to_string()))?;
		doc.validate()?;
		Ok(doc)
	}
}

fn canonicalize_dns(dns: &mut DnsPolicy) {
	dns.servers.sort();
	dns.domains.sort();
	// `search` and `options` are ordered by the author and stay that way:
	// resolver search order is semantic, so sorting them would change what
	// the config means rather than normalise how it is written.
}

fn check_unique<'a>(
	collection: &'static str,
	keys: impl Iterator<Item = &'a str>,
) -> Result<(), Error> {
	let mut seen: Vec<&str> = Vec::new();
	for key in keys {
		if seen.contains(&key) {
			return Err(Error::DuplicateKey {
				collection,
				key: key.to_owned(),
			});
		}
		seen.push(key);
	}
	Ok(())
}

fn check_dns_capability(scope: &str, dns: &DnsPolicy) -> Result<(), Error> {
	if dns.needs_routing() && !dns.mode.can_route() {
		return Err(Error::DnsModeCannotRoute {
			scope: scope.to_owned(),
			mode: dns.mode.name(),
		});
	}
	Ok(())
}
