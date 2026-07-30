//! `/run/netcfgd/`: what netcfgd knows about its own past, in greppable files.
//!
//! Principle 2 in practice. Everything here is plain JSON that answers a
//! question without netcfgd running: what did it decide, what did it see, what
//! did it do, and which objects does it believe are its own.

use netcfgd_apply::kernel::Effects;
use netcfgd_apply::Journal;
use netcfgd_model::{Document, Observed, Origin};
use netcfgd_observe::PriorState;
use serde::{Deserialize, Serialize};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

/// Where runtime state lives when nothing says otherwise.
pub const DEFAULT_RUN_DIR: &str = "/run/netcfgd";

/// The `/run` directory to use.
#[must_use]
pub fn resolve_dir(explicit: Option<&str>) -> PathBuf {
	if let Some(path) = explicit {
		return PathBuf::from(path);
	}
	if let Ok(path) = std::env::var("NCFG_RUN_DIR") {
		return PathBuf::from(path);
	}
	PathBuf::from(DEFAULT_RUN_DIR)
}

/// The on-disk form of what netcfgd recorded about its own actions.
///
/// A separate type from [`PriorState`] because this one is a file format and
/// has to stay readable across versions, while the other is a working
/// structure. Keeping them apart means changing one does not silently change
/// what is on disk.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct OwnedState {
	/// Links netcfgd created.
	pub created_links: Vec<String>,
	/// Addresses netcfgd installed.
	pub addresses: Vec<OwnedObject>,
	/// Routes netcfgd installed.
	pub routes: Vec<OwnedObject>,
	/// Backends netcfgd started.
	pub backends: Vec<netcfgd_model::ObservedBackend>,
	/// DNS scopes netcfgd delivered.
	pub dns: Vec<netcfgd_model::AppliedDns>,
}

/// Where a `DHCPv6` client's hook records what it was delegated.
///
/// One file per interface, one prefix per line, blank lines and `#` comments
/// ignored. Not JSON, because the thing that writes it is a shell script the
/// client runs and a shell script that has to emit valid JSON is a shell
/// script that will one day emit invalid JSON. A line of text it cannot get
/// wrong.
#[must_use]
pub fn prefixes_dir(run_dir: &Path) -> PathBuf {
	run_dir.join("prefixes")
}

/// Read every delegation a client has reported.
///
/// A missing directory is not an error: it means no client has reported one,
/// which is the state of every machine that is not a router.
#[must_use]
pub fn read_delegations(run_dir: &Path) -> Vec<netcfgd_model::Delegation> {
	let Ok(entries) = fs::read_dir(prefixes_dir(run_dir)) else {
		return Vec::new();
	};
	let mut out: Vec<netcfgd_model::Delegation> = entries
		.flatten()
		.filter_map(|entry| {
			let interface = entry.file_name().to_str()?.to_owned();
			let body = fs::read_to_string(entry.path()).ok()?;
			let prefixes: Vec<String> = body
				.lines()
				.map(str::trim)
				.filter(|line| !line.is_empty() && !line.starts_with('#'))
				.map(ToOwned::to_owned)
				.collect();
			// An empty file means the lease expired and the hook recorded
			// that, which is different from no file at all only in that it
			// says so deliberately. Both produce no prefixes.
			Some(netcfgd_model::Delegation {
				interface,
				prefixes,
			})
		})
		.collect();
	out.sort_by(|a, b| a.interface.cmp(&b.interface));
	out
}

/// The prior state an observation needs: what netcfgd did, plus what a client
/// reported.
///
/// One function so the two callers cannot disagree about whether delegations
/// are included -- which is the same divergence `State::executor` exists to
/// prevent on the other side.
#[must_use]
pub fn prior_state(run_dir: &Path) -> PriorState {
	let mut prior = read_owned(run_dir).to_prior();
	prior.delegations = read_delegations(run_dir);
	prior
}

/// One object netcfgd installed, and which source asked for it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OwnedObject {
	/// Which interface.
	pub interface: String,
	/// The address in CIDR form, or the route destination.
	pub key: String,
	/// Which addressing source produced it.
	pub origin: Origin,
}

impl OwnedState {
	/// Turn this into the form `netcfgd-observe` consumes.
	#[must_use]
	pub fn to_prior(&self) -> PriorState {
		PriorState {
			created_links: self.created_links.clone(),
			address_origins: self
				.addresses
				.iter()
				.map(|object| (object.interface.clone(), object.key.clone(), object.origin))
				.collect(),
			route_origins: self
				.routes
				.iter()
				.map(|object| (object.interface.clone(), object.key.clone(), object.origin))
				.collect(),
			backends: self.backends.clone(),
			dns: self.dns.clone(),
			// Not from this file. A delegation is not something netcfgd did,
			// it is something a client was told, so it is recorded separately
			// and folded in by [`prior_state`].
			delegations: Vec::new(),
		}
	}

	/// Fold in what an apply just did.
	///
	/// Removals are applied before additions so that replacing an address in
	/// one plan leaves exactly one record, not zero.
	pub fn absorb(&mut self, effects: &Effects) {
		self.created_links
			.retain(|name| !effects.deleted_links.contains(name));
		for name in &effects.created_links {
			if !self.created_links.contains(name) {
				self.created_links.push(name.clone());
			}
		}

		self.addresses.retain(|object| {
			!effects
				.removed_addresses
				.iter()
				.any(|(iface, key)| iface == &object.interface && key == &object.key)
		});
		for (interface, key, origin) in &effects.added_addresses {
			self.addresses
				.retain(|object| !(object.interface == *interface && object.key == *key));
			self.addresses.push(OwnedObject {
				interface: interface.clone(),
				key: key.clone(),
				origin: *origin,
			});
		}

		self.routes.retain(|object| {
			!effects
				.removed_routes
				.iter()
				.any(|(iface, key)| iface == &object.interface && key == &object.key)
		});
		for (interface, key, origin) in &effects.added_routes {
			self.routes
				.retain(|object| !(object.interface == *interface && object.key == *key));
			self.routes.push(OwnedObject {
				interface: interface.clone(),
				key: key.clone(),
				origin: *origin,
			});
		}

		self.backends.retain(|backend| {
			!effects
				.stopped_backends
				.iter()
				.any(|(kind, iface)| *kind == backend.kind && iface == &backend.interface)
		});
		for (kind, interface) in &effects.started_backends {
			if !self
				.backends
				.iter()
				.any(|b| b.kind == *kind && &b.interface == interface)
			{
				self.backends.push(netcfgd_model::ObservedBackend {
					kind: *kind,
					interface: interface.clone(),
					running: true,
				});
			}
		}

		for applied in &effects.applied_dns {
			self.dns.retain(|existing| existing.scope != applied.scope);
			self.dns.push(applied.clone());
		}
	}
}

/// Read recorded state, treating an absent or unreadable file as empty.
///
/// An unreadable `/run` file must not stop netcfgd working -- it is derived
/// and disposable by design (constraint 1), and the worst case of treating it
/// as empty is that netcfgd under-claims ownership, which is the safe
/// direction.
#[must_use]
pub fn read_owned(run_dir: &Path) -> OwnedState {
	let path = run_dir.join("owned.json");
	fs::read_to_string(path)
		.ok()
		.and_then(|text| serde_json::from_str(&text).ok())
		.unwrap_or_default()
}

/// Write recorded state.
///
/// # Errors
///
/// Returns an `io::Error` if the directory cannot be created or the file
/// cannot be written.
pub fn write_owned(run_dir: &Path, state: &OwnedState) -> io::Result<()> {
	let text = serde_json::to_string_pretty(state)
		.map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
	write_atomic(&run_dir.join("owned.json"), &text)
}

/// Write the per-interface projections of a whole-host document.
///
/// Section 2 is explicit that the whole-host document is canonical and these
/// are "projections for convenience, not separate documents". They exist so
/// that `cat /run/netcfgd/desired/eth0.json` answers a question about one
/// interface without a reader having to find it inside the whole file --
/// which is the same reason the observed side has them.
///
/// # Errors
///
/// Returns an `io::Error`.
fn write_projections<T: serde::Serialize>(dir: &Path, entries: &[(String, T)]) -> io::Result<()> {
	// Removed first, so an interface dropped from the config does not leave a
	// stale file claiming it is still configured. Principle 2 depends on what
	// is in /run being true, not merely once-true.
	if dir.is_dir() {
		for entry in fs::read_dir(dir)?.filter_map(Result::ok) {
			if entry.path().extension().is_some_and(|ext| ext == "json") {
				let _ = fs::remove_file(entry.path());
			}
		}
	}
	if entries.is_empty() {
		// No interfaces, no directory. Section 4.6: the filesystem reflects
		// use, not capability.
		return Ok(());
	}
	fs::create_dir_all(dir)?;
	for (name, value) in entries {
		let text = serde_json::to_string_pretty(value)
			.map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
		write_atomic(&dir.join(format!("{name}.json")), &text)?;
	}
	Ok(())
}

/// Write the desired document, so `cat` can answer what netcfgd decided.
///
/// # Errors
///
/// Returns an `io::Error`, or the model's own error rendered as one.
pub fn write_desired(run_dir: &Path, document: &Document) -> io::Result<()> {
	let text = document
		.to_json_canonical()
		.map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error.to_string()))?;
	write_atomic(&run_dir.join("desired.json"), &text)?;

	let projections: Vec<(String, &netcfgd_model::Interface)> = document
		.interfaces
		.iter()
		.map(|interface| (interface.name.clone(), interface))
		.collect();
	write_projections(&run_dir.join("desired"), &projections)
}

/// Write the provenance table, so `ncfg explain` can name a file and line
/// without recompiling the configuration.
///
/// # Errors
///
/// Returns an `io::Error`.
pub fn write_provenance(
	run_dir: &Path,
	provenance: &netcfgd_compile::Provenance,
) -> io::Result<()> {
	let text = serde_json::to_string_pretty(provenance)
		.map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
	write_atomic(&run_dir.join("provenance.json"), &text)
}

/// Read it back, treating an absent or unreadable file as empty -- an
/// explanation without file positions is still worth printing.
#[must_use]
pub fn read_provenance(run_dir: &Path) -> netcfgd_compile::Provenance {
	fs::read_to_string(run_dir.join("provenance.json"))
		.ok()
		.and_then(|text| serde_json::from_str(&text).ok())
		.unwrap_or_default()
}

/// Write the observed model.
///
/// # Errors
///
/// Returns an `io::Error`.
pub fn write_observed(run_dir: &Path, observed: &Observed) -> io::Result<()> {
	let text = serde_json::to_string_pretty(observed)
		.map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
	write_atomic(&run_dir.join("observed.json"), &text)?;

	// One file per link, carrying that link and everything on it, so a reader
	// asking about eth0 does not have to filter the whole-host view.
	let projections: Vec<(String, serde_json::Value)> = observed
		.links
		.iter()
		.map(|link| {
			(
				link.name.clone(),
				serde_json::json!({
					"link": link,
					"addresses": observed.addresses_on(&link.name).collect::<Vec<_>>(),
					"routes": observed.routes_on(&link.name).collect::<Vec<_>>(),
				}),
			)
		})
		.collect();
	write_projections(&run_dir.join("observed"), &projections)
}

/// Write the journal of the last apply.
///
/// # Errors
///
/// Returns an `io::Error`.
pub fn write_journal(run_dir: &Path, journal: &Journal) -> io::Result<()> {
	let text = journal
		.to_json()
		.map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
	write_atomic(&run_dir.join("plan.last.json"), &text)
}

/// Write via a temporary file and a rename.
///
/// # Errors
///
/// Returns an `io::Error` if the directory cannot be created, or the file
/// cannot be written or renamed.
///
/// Design section 17 requires that a power cut during a write cannot leave an
/// unparseable file. Rename is atomic within a filesystem, so a reader sees
/// either the old contents or the new ones and never a half-written mixture.
pub fn write_atomic(path: &Path, text: &str) -> io::Result<()> {
	if let Some(parent) = path.parent() {
		fs::create_dir_all(parent)?;
	}
	let temporary = path.with_extension("tmp");
	fs::write(&temporary, text)?;
	fs::rename(&temporary, path)
}
