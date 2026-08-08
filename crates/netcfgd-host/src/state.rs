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
use std::collections::BTreeMap;
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
	/// `(kind, interface, count)`: starts of a backend that did not stay up.
	///
	/// Cleared the moment it is seen running, so a tunnel that has been up for a
	/// week carries nothing from an incident last month. Decision 0079.
	#[serde(default)]
	pub backend_restarts: Vec<(netcfgd_model::BackendKind, String, u32)>,
	/// DNS scopes netcfgd delivered.
	pub dns: Vec<netcfgd_model::AppliedDns>,
	/// Interfaces netcfgd turned IP forwarding on for.
	pub forwarding: Vec<String>,
	/// Interfaces netcfgd turned temporary addresses on for.
	#[serde(default)]
	pub privacy: Vec<String>,
	/// Interfaces netcfgd wrote `accept_ra` for, so that an interface which
	/// stops asking for SLAAC is put back only where netcfgd changed it.
	#[serde(default)]
	pub accept_ra: Vec<String>,
	/// What each event hook was last told, per interface and phase (0064, 0068).
	#[serde(default)]
	pub hook_state: Vec<netcfgd_model::ObservedHookState>,
	/// Interfaces netcfgd set the root qdisc on.
	pub qdisc: Vec<String>,
	/// Interfaces netcfgd installed an ingress redirect on.
	pub ingress: Vec<String>,
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
			// Staged the same way, by the script netcfgd generates for
			// odhcp6c. Decision 0113.
			if netcfgd_apply::is_staging(&interface) {
				return None;
			}
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

/// Where something that is not netcfgd records what an interface was given.
///
/// One file per interface, `key=value` lines, blank lines and `#` comments
/// ignored. Not JSON, for the reason [`prefixes_dir`] gives: the thing writing
/// it is very often a shell script -- wrapped around `umbim` or `mbimcli` for a
/// modem, or handed its values in the environment by `openvpn` or `pppd`.
///
/// **The format is a documented contract**, not an internal detail --
/// `docs/interface-report.md` is the whole of it, and decision 0045 says why the
/// writer is deliberately plural. Changing what is parsed here changes what
/// somebody else's script has to write.
///
/// Named `reported` rather than `modem` because a modem helper was merely the
/// first writer; decision 0047 has the argument for taking the name off it.
///
/// Not spelled here. `netcfgd-apply` hands this path to the scripts it
/// generates for the daemons it starts, and a reader that joined `reported` for
/// itself would be a second definition of where the contract's files live --
/// which would work until one of the two moved.
#[must_use]
pub fn report_dir(run_dir: &Path) -> PathBuf {
	netcfgd_apply::kernel::report_dir(run_dir)
}

/// Read every report that has been written.
///
/// Two places, one answer. `reported/<interface>` is the single file the
/// contract documents, written by something that is not netcfgd;
/// `reported.d/<interface>/<source>` is one file per writer, which is what
/// netcfgd's own clients use because a dual-stack interface has two of them
/// (0086).
///
/// The single file comes first and the fragments follow in name order, so a
/// `DHCPv4` lease's nameservers precede a `DHCPv6` lease's -- `dhcpcd4` before
/// `dhcpcd6` -- and the order is the same on every machine and every boot rather
/// than the filesystem's.
///
/// A missing directory means nothing is reporting, which is the state of every
/// machine with no modem and no tunnel. Unreadable and malformed files are
/// skipped rather than failing the observation, for the reason the rest of this
/// module gives: `/run` is derived and disposable, and refusing to observe a
/// machine because one file is bad is worse than observing the rest of it.
#[must_use]
pub fn read_reports(run_dir: &Path) -> Vec<netcfgd_model::ObservedReport> {
	// Interface -> the bodies to parse as one, in the order they apply.
	let mut bodies: BTreeMap<String, Vec<String>> = BTreeMap::new();

	if let Ok(entries) = fs::read_dir(report_dir(run_dir)) {
		for entry in entries.flatten() {
			let Some(interface) = entry.file_name().to_str().map(ToOwned::to_owned) else {
				continue;
			};
			// A writer's staging file is not a report. The contract tells every
			// writer to build one in this directory and `rename(2)` it over the
			// target, so the half-written file it exists to hide is sitting
			// right here -- and without this it was read as a report for an
			// interface named after the temporary file. Decision 0113.
			if netcfgd_apply::is_staging(&interface) {
				continue;
			}
			// A directory here is not a report. Nothing puts one there today,
			// and `read_to_string` would fail anyway -- said out loud because
			// the fragment tree deliberately lives somewhere else.
			let Ok(body) = fs::read_to_string(entry.path()) else {
				continue;
			};
			bodies.entry(interface).or_default().push(body);
		}
	}

	if let Ok(interfaces) = fs::read_dir(run_dir.join("reported.d")) {
		for entry in interfaces.flatten() {
			let Some(interface) = entry.file_name().to_str().map(ToOwned::to_owned) else {
				continue;
			};
			if netcfgd_apply::is_staging(&interface) {
				continue;
			}
			let Ok(fragments) = fs::read_dir(entry.path()) else {
				continue;
			};
			// Sorted, because `read_dir` order is the filesystem's and a
			// nameserver list that changed order between boots would look like
			// a change to anything comparing it.
			// And the fragments themselves, which a helper with more than one
			// source for one interface writes the same way.
			let mut paths: Vec<_> = fragments
				.flatten()
				.filter(|f| {
					f.file_name()
						.to_str()
						.is_some_and(|name| !netcfgd_apply::is_staging(name))
				})
				.map(|f| f.path())
				.collect();
			paths.sort();
			for path in paths {
				if let Ok(body) = fs::read_to_string(path) {
					bodies.entry(interface.clone()).or_default().push(body);
				}
			}
		}
	}

	bodies
		.into_iter()
		.map(|(interface, bodies)| parse_report(&interface, &bodies.join("\n")))
		.collect()
}

/// One report, parsed.
///
/// Split out from [`read_reports`] so the format -- which is somebody else's to
/// write -- is testable without a filesystem.
///
/// **Unknown keys are ignored, and that is a promise the contract makes.** It
/// is what lets a helper report `mtu=` or `operator=` before netcfgd knows what
/// to do with them, instead of every helper waiting on netcfgd to catch up. A
/// malformed value is skipped for the neighbouring reason: a bearer that came
/// up with a usable v4 address and a mangled v6 one should still get the v4.
#[must_use]
pub fn parse_report(interface: &str, body: &str) -> netcfgd_model::ObservedReport {
	let mut report = netcfgd_model::ObservedReport {
		interface: interface.to_owned(),
		addresses: Vec::new(),
		gateways: Vec::new(),
		nameservers: Vec::new(),
		search: Vec::new(),
		routes: Vec::new(),
	};
	for line in body.lines() {
		// No `#` branch, deliberately. A comment is ignored because its key
		// does not match -- `#dns=8.8.8.8` has the key `#dns` -- and a branch
		// testing for `#` on top of that is one no input can make fire, which
		// this project does not keep whatever it looks like it is guarding.
		// The *guarantee* is pinned by the tests below rather than by a line of
		// code, so it survives however the matching is written.
		let Some((key, value)) = line.trim().split_once('=') else {
			continue;
		};
		let value = value.trim();
		if value.is_empty() {
			continue;
		}
		match key.trim() {
			// Kept as text and validated where it is used, which is how every
			// other address in the observed model arrives. Parsing it here
			// would put the refusal in the reader, where the operator cannot
			// see which line of whose file was wrong.
			"address" => report.addresses.push(value.to_owned()),
			"gateway" => report.gateways.push(value.to_owned()),
			"dns" => report.nameservers.push(value.to_owned()),
			// One suffix per line, like a nameserver. A writer with several has
			// several lines, which is the shape every repeating key here has.
			"search" => report.search.push(value.to_owned()),
			// The one key with a shape of its own, because a route needs two
			// values and the contract will not make somebody number them.
			// Whether the *addresses* in it are addresses is still decided
			// where they are used.
			"route" => report.routes.extend(parse_reported_route(value)),
			_ => {}
		}
	}
	report
}

/// `<destination>` or `<destination> via <gateway>`.
///
/// Deliberately the spelling a `routes` line in a config file already uses, so
/// that somebody reading a report and somebody reading a config are reading the
/// same thing. Nothing else is accepted: a metric belongs to netcfgd rather than
/// to the writer (decision 0047 wants one that composes with `preference`), and
/// an unrecognised tail is a line the writer thought meant something, which is
/// worse to half-apply than to skip.
fn parse_reported_route(value: &str) -> Option<netcfgd_model::ReportedRoute> {
	let mut words = value.split_whitespace();
	let destination = words.next()?.to_owned();
	let via = match words.next() {
		None => None,
		Some("via") => Some(words.next()?.to_owned()),
		Some(_) => return None,
	};
	// Anything after the gateway is a word this contract does not define.
	if words.next().is_some() {
		return None;
	}
	Some(netcfgd_model::ReportedRoute { destination, via })
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
	prior.reports = read_reports(run_dir);
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
			forwarding: self.forwarding.clone(),
			privacy: self.privacy.clone(),
			backend_restarts: self.backend_restarts.clone(),
			accept_ra: self.accept_ra.clone(),
			hook_state: self.hook_state.clone(),
			qdisc: self.qdisc.clone(),
			ingress: self.ingress.clone(),
			// Not from this file. A delegation is not something netcfgd did,
			// it is something a client was told, so it is recorded separately
			// and folded in by [`prior_state`].
			delegations: Vec::new(),
			reports: Vec::new(),
		}
	}

	/// Fold in what an apply saw and did about backends that will not stay up.
	///
	/// Three rules, and the order of the first two matters when one apply both
	/// sees a backend running and starts another:
	///
	/// - **seen running clears it.** A daemon that is alive has stayed up, so
	///   whatever it did last week is not a reason to stop trying now;
	/// - **a start counts.** "Running" in the record is netcfgd's memory of
	///   having started it, which is the thing decision 0078 stopped trusting --
	///   so this counts starts that did not lead to a live process;
	/// - **a deliberate stop clears it.** The document stopped asking, so
	///   whatever the daemon was doing before is no longer being attempted.
	///
	/// Decision 0079.
	fn absorb_restarts(&mut self, effects: &Effects) {
		for (kind, interface) in &effects.observed_running {
			self.backend_restarts
				.retain(|(recorded, name, _)| recorded != kind || name != interface);
		}
		for (kind, interface) in &effects.started_backends {
			match self
				.backend_restarts
				.iter_mut()
				.find(|(recorded, name, _)| recorded == kind && name == interface)
			{
				Some((_, _, count)) => *count += 1,
				None => self.backend_restarts.push((*kind, interface.clone(), 1)),
			}
		}
		for (kind, interface) in &effects.stopped_backends {
			self.backend_restarts
				.retain(|(recorded, name, _)| recorded != kind || name != interface);
		}
	}

	/// Fold in what an apply just did.
	///
	/// Removals are applied before additions so that replacing an address in
	/// one plan leaves exactly one record, not zero.
	pub fn absorb(&mut self, effects: &Effects) {
		// Five lists of interface names, all folded the same way -- see
		// [`remember`], which is where the "off drops the record" rule is
		// written down once instead of five times.
		for (interface, enabled) in &effects.forwarding {
			remember(&mut self.forwarding, interface, *enabled);
		}

		// One record per interface and phase, replaced rather than appended: what
		// matters is what a hook was last told, and the previous answer is of no use
		// once a newer one exists.
		for (interface, phase, value) in &effects.hook_state {
			self.hook_state
				.retain(|record| &record.interface != interface || record.phase != *phase);
			self.hook_state.push(netcfgd_model::ObservedHookState {
				interface: interface.clone(),
				phase: *phase,
				value: value.clone(),
			});
		}

		for (interface, enabled) in &effects.privacy {
			remember(&mut self.privacy, interface, *enabled);
		}

		// `accept_ra` is the one whose "off" is not `false`: the value netcfgd
		// writes to give an interface back is `1`, the kernel's own default, so
		// that is what drops the record. Decision 0073.
		for (interface, value) in &effects.accept_ra {
			remember(&mut self.accept_ra, interface, *value != 1);
		}

		for (interface, set) in &effects.qdisc {
			remember(&mut self.qdisc, interface, *set);
		}

		for (interface, set) in &effects.ingress {
			remember(&mut self.ingress, interface, *set);
		}

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
		self.absorb_restarts(effects);

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
					answering: None,
					access_control: None,
					started_with: None,
					secret_matches: None,
					config_matches: None,
					advertised: Vec::new(),
				});
			}
		}

		for applied in &effects.applied_dns {
			self.dns.retain(|existing| existing.scope != applied.scope);
			self.dns.push(applied.clone());
		}
	}
}

/// Remember an interface netcfgd changed, or forget one it changed back.
///
/// Only the interfaces netcfgd switched *on* are recorded. Switching one off
/// drops the record rather than storing `false`: the question this answers is
/// "is this ours to undo later", and once it has been undone the answer is no.
///
/// One function because there are five lists of exactly this shape, and five
/// copies of a three-line rule is how two of them come to disagree about what
/// "off" means.
fn remember(list: &mut Vec<String>, interface: &str, ours: bool) {
	list.retain(|name| name != interface);
	if ours {
		list.push(interface.to_owned());
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

/// Change recorded state, with nobody else changing it in between.
///
/// **This is how ownership is recorded. [`read_owned`] and [`write_owned`] as
/// a pair are not**, and the difference is the whole reason this exists.
///
/// Six places did the pair by hand -- read, fold in what an apply just did,
/// write -- and two *processes* run them: `ncfg apply` builds a plan and drives
/// an executor in its own process, and the daemon converges on inotify, on
/// netlink events and on a socket request. Two read-modify-writes of one file
/// with nothing between them lose an update, and the direction that loses is
/// the dangerous one. [`OwnedState::absorb`] only ever folds in what *this*
/// apply did, so a pass whose own effects are empty writes back whatever it
/// read: a stale read therefore does not merely fail to record something, it
/// **puts back** a record the other process had just removed. netcfgd then
/// believes it owns an object it has already given up, and ownership is what
/// decides whether netcfgd may reset a qdisc, withdraw an address or delete a
/// link at all.
///
/// The lock is a separate file rather than `owned.json` itself, because
/// `owned.json` is replaced by a rename: a lock taken on it is a lock on an
/// inode that the next writer unlinks, which is a lock two writers can hold at
/// once. `owned.lock` is never renamed and never read.
///
/// A failure to take the lock is returned rather than swallowed. Carrying on
/// unlocked is exactly the behaviour this replaces, and a caller that wants it
/// can have it by ignoring the error -- deliberately, and in its own words.
///
/// # Errors
///
/// Returns an `io::Error` if the lock cannot be taken, or if the write fails.
pub fn update_owned<F>(run_dir: &Path, change: F) -> io::Result<()>
where
	F: FnOnce(&mut OwnedState),
{
	let _guard = netcfgd_sys::lock::FileLock::exclusive(&run_dir.join("owned.lock"))?;
	let mut owned = read_owned(run_dir);
	change(&mut owned);
	write_owned(run_dir, &owned)
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
///
/// One implementation, not two. This had its own, and the two had drifted in
/// the direction that matters: [`crate::config::write_atomically`] names its
/// temporary after the process that made it, and this one called every
/// temporary `<name>.tmp`. That is a fixed path two processes share, and two
/// processes do write here -- `ncfg apply` and the daemon both write
/// `owned.json`. Interleaved, one writer's content is renamed into place by
/// the *other* writer's rename and the loser's rename fails with `ENOENT`,
/// which five of the six call sites discard with `let _ =`. So the older copy
/// was not atomic between writers at all, only against readers.
///
/// `0o666` is what [`fs::write`] opens with, so the umask still decides the
/// mode exactly as it did before and this is not a permission change riding
/// along inside a concurrency fix. `/run/netcfgd/owned.json` carries secret
/// *digests* (0055), so tightening it is a decision to take deliberately
/// rather than in passing.
pub fn write_atomic(path: &Path, text: &str) -> io::Result<()> {
	crate::config::write_atomically(path, text.as_bytes(), 0o666)
}

#[cfg(test)]
mod tests {
	use super::*;

	/// Two writers of one `/run` file must not tread on each other.
	///
	/// `owned.json` is written by `ncfg apply` and by the daemon, and this
	/// wrote every temporary as `<name>.tmp` -- one path, shared by everyone.
	/// Interleaved, the second writer's bytes land under the first writer's
	/// rename and the loser renames a file that is no longer there, which is
	/// an `ENOENT` five of the six call sites discard with `let _ =`.
	///
	/// Threads rather than processes because the defect does not need two
	/// processes and the fix must not either: a temporary named after the pid
	/// alone is still one path for every thread in it. `netcfgd-testdir` had
	/// this written down already -- "the process id alone is not enough, tests
	/// in one binary share it" -- for its directories, while the code that
	/// writes the machine's state did not follow it.
	///
	/// Probabilistic in the direction that is safe: it can only pass when
	/// there is nothing to find, and it failed on the first round every time
	/// it was run against the implementation this replaced.
	#[test]
	fn two_writers_of_one_file_do_not_share_a_temporary() {
		let dir = netcfgd_testdir::TestDir::new("state-two-writers");
		let path = dir.join("owned.json");
		// Big enough that writing is not one instruction, which is what opens
		// the window at all.
		let texts = ["a".repeat(64 * 1024), "b".repeat(64 * 1024)];

		std::thread::scope(|scope| {
			for text in &texts {
				let path = path.clone();
				scope.spawn(move || {
					for _ in 0..200 {
						write_atomic(&path, text).expect("another writer must not fail this one");
					}
				});
			}
		});

		// And the survivor is one of them whole, never a mixture.
		let final_text = fs::read_to_string(&path).expect("the file is there");
		assert!(
			texts.contains(&final_text),
			"{} bytes, neither writer's content",
			final_text.len()
		);
	}

	/// Two updaters of the ownership record must not lose each other's changes.
	///
	/// The read-modify-write that six call sites did by hand, run from two
	/// processes: `ncfg apply` in its own, and the daemon in another. This is
	/// the defect [`update_owned`] exists for, and it is worse than "one change
	/// does not stick" -- [`OwnedState::absorb`] folds in only what *this*
	/// apply did, so a pass with nothing of its own writes back everything it
	/// read, and a stale read therefore **restores** a record the other process
	/// had just dropped. Ownership is what decides whether netcfgd may reset a
	/// qdisc or delete a link, so a restored record is the unsafe direction.
	///
	/// Deterministic rather than hopeful. Both threads start together on a
	/// barrier and hold their change open for long enough that an unlocked
	/// implementation *must* interleave; with the lock the wait is inside the
	/// critical section, so the second updater reads what the first wrote.
	/// Without it this leaves one name where there should be two, every time.
	#[test]
	fn two_updaters_do_not_lose_each_others_records() {
		let dir = netcfgd_testdir::TestDir::new("state-two-updaters");
		let names = ["veth0", "veth1"];
		let start = std::sync::Barrier::new(names.len());

		std::thread::scope(|scope| {
			for name in names {
				let start = &start;
				let run = dir.to_path_buf();
				scope.spawn(move || {
					start.wait();
					update_owned(&run, |owned| {
						owned.qdisc.push(name.to_owned());
						// Long enough that an unlocked reader has certainly
						// read, and short enough that a person waits for it.
						std::thread::sleep(std::time::Duration::from_millis(150));
					})
					.expect("the record is updatable");
				});
			}
		});

		let mut recorded = read_owned(&dir).qdisc;
		recorded.sort();
		assert_eq!(recorded, names, "an update was lost");
	}

	/// The example from `docs/interface-report.md`, verbatim. If this test and that
	/// document ever disagree, the document is right: it is what somebody else
	/// wrote their helper against.
	const REPORT: &str = "# wwan0, connected 2026-07-31T14:02:11Z via three.co.uk\n\
		address=10.64.1.23/30\n\
		gateway=10.64.1.24\n\
		dns=8.8.8.8\n\
		dns=2001:4860:4860::8888\n";

	#[test]
	fn the_documented_example_parses_to_what_it_says() {
		let report = parse_report("wwan0", REPORT);
		assert_eq!(report.interface, "wwan0");
		assert_eq!(report.addresses, ["10.64.1.23/30"]);
		assert_eq!(report.gateways, ["10.64.1.24"]);
		assert_eq!(report.nameservers, ["8.8.8.8", "2001:4860:4860::8888"]);
	}

	#[test]
	fn unknown_keys_are_ignored_which_is_a_promise() {
		// The contract says a helper may report things netcfgd does not
		// understand yet, so that helpers do not have to wait for netcfgd. A
		// reader that refused here would break every helper the day it learned
		// a new field.
		let report = parse_report(
			"wwan0",
			"mtu=1428\noperator=three.co.uk\naddress=10.0.0.1/32\nsignal=-71\n",
		);
		assert_eq!(report.addresses, ["10.0.0.1/32"]);
		assert!(report.gateways.is_empty());
	}

	#[test]
	fn a_bad_line_does_not_discard_the_good_ones() {
		// A bearer that came up with a usable v4 address and a mangled v6 one
		// should still get the v4. Losing the file over one line is the failure
		// mode that leaves somebody with no connectivity and no explanation.
		let report = parse_report(
			"wwan0",
			"address=10.0.0.1/32\nthis is not a key=value line at all\n\
			 gateway=\naddress=\n\ndns=1.1.1.1\n",
		);
		assert_eq!(report.addresses, ["10.0.0.1/32"]);
		assert!(report.gateways.is_empty(), "an empty value is not a value");
		assert_eq!(report.nameservers, ["1.1.1.1"]);
	}

	#[test]
	fn comments_and_whitespace_are_what_the_document_says_they_are() {
		let report = parse_report(
			"wwan0",
			"  # a comment, indented\n\t address = 10.0.0.1/32 \t\n\n#dns=8.8.8.8\n",
		);
		assert_eq!(report.addresses, ["10.0.0.1/32"]);
		assert!(
			report.nameservers.is_empty(),
			"a commented-out line is a comment"
		);
	}

	#[test]
	fn an_empty_report_is_a_bearer_that_is_down() {
		// Distinct from no file at all only in that somebody said so, which is
		// exactly the distinction the contract asks helpers to make while they
		// are running.
		let report = parse_report("wwan0", "");
		assert_eq!(report.interface, "wwan0");
		assert!(report.addresses.is_empty());
	}

	#[test]
	fn a_route_is_read_the_way_a_config_file_spells_one() {
		let report = parse_report(
			"vpn0",
			"route=10.0.0.0/8 via 10.8.0.1\nroute=192.168.5.0/24\n",
		);
		assert_eq!(report.routes.len(), 2);
		assert_eq!(report.routes[0].destination, "10.0.0.0/8");
		assert_eq!(report.routes[0].via.as_deref(), Some("10.8.0.1"));
		assert_eq!(report.routes[1].destination, "192.168.5.0/24");
		assert_eq!(report.routes[1].via, None);
	}

	#[test]
	fn a_route_line_the_contract_does_not_define_is_skipped() {
		// Not refused: the rest of the report is still worth having. A line
		// with a word this contract never defined is one the writer thought
		// meant something, and half-applying it is worse than dropping it --
		// `metric 50` silently ignored would be a route with a metric netcfgd
		// chose and an operator thought they had.
		let report = parse_report(
			"vpn0",
			"route=10.0.0.0/8 metric 50\nroute=10.1.0.0/16 via 10.8.0.1 metric 50\n\
			 route=10.2.0.0/16 via\nroute=10.3.0.0/16 via 10.8.0.1\n",
		);
		let kept: Vec<&str> = report
			.routes
			.iter()
			.map(|route| route.destination.as_str())
			.collect();
		assert_eq!(kept, ["10.3.0.0/16"]);
	}

	#[test]
	fn repeats_keep_the_order_they_were_written_in() {
		// The contract says so, and a nameserver list that reorders itself
		// between reads would make a plan differ from the last one for no
		// reason anybody could see.
		let report = parse_report("wwan0", "dns=9.9.9.9\ndns=1.1.1.1\ndns=8.8.8.8\n");
		assert_eq!(report.nameservers, ["9.9.9.9", "1.1.1.1", "8.8.8.8"]);
	}

	#[test]
	fn a_missing_directory_is_a_machine_with_nothing_reporting() {
		let empty = Path::new("/nonexistent/netcfgd-test-run-dir");
		assert!(read_reports(empty).is_empty());
	}

	/// Two clients on one interface, and neither loses its nameservers.
	///
	/// The whole of 0086. Before it there was one file per interface, a
	/// `DHCPv4` client already writing it, and a `DHCPv6` client that was
	/// therefore given no way to report at all -- so a v6-only network resolved
	/// nothing and a dual-stack one resolved only what v4 said.
	#[test]
	fn a_second_client_on_one_interface_does_not_displace_the_first() {
		let dir = netcfgd_testdir::TestDir::new("report-fragments");
		fs::create_dir_all(dir.join("reported")).expect("made");
		fs::create_dir_all(dir.join("reported.d").join("wan0")).expect("made");

		fs::write(
			dir.join("reported").join("wan0"),
			"address=192.0.2.10/24\ndns=8.8.8.8\n",
		)
		.expect("written");
		fs::write(
			dir.join("reported.d").join("wan0").join("dhcpcd6"),
			"dns=2001:4860:4860::8888\nsearch=example.net\n",
		)
		.expect("written");

		let reports = read_reports(&dir);
		assert_eq!(reports.len(), 1, "one interface, one report: {reports:?}");
		// The single file first, then the fragments in name order. A v4 lease's
		// resolvers before a v6 lease's, deterministically, rather than in
		// whatever order the filesystem hands them over.
		assert_eq!(
			reports[0].nameservers,
			["8.8.8.8", "2001:4860:4860::8888"],
			"a client's nameservers were lost or reordered"
		);
		// And everything else merges too, rather than the last writer winning.
		assert_eq!(reports[0].addresses.len(), 1);
		assert_eq!(reports[0].search, ["example.net"]);
	}

	/// Fragments are read in name order, whatever order the directory holds.
	///
	/// `read_dir` is the filesystem's order. A nameserver list that came back
	/// differently between boots would make a plan differ from the last one for
	/// a reason nobody could see -- the same failure the repeats test above
	/// guards inside one file.
	#[test]
	fn fragments_are_read_in_a_stable_order() {
		let dir = netcfgd_testdir::TestDir::new("report-fragment-order");
		let fragments = dir.join("reported.d").join("wan0");
		fs::create_dir_all(&fragments).expect("made");

		// Written in the order that is not the answer.
		fs::write(fragments.join("zzz"), "dns=3.3.3.3\n").expect("written");
		fs::write(fragments.join("aaa"), "dns=1.1.1.1\n").expect("written");
		fs::write(fragments.join("mmm"), "dns=2.2.2.2\n").expect("written");

		let reports = read_reports(&dir);
		assert_eq!(reports.len(), 1);
		assert_eq!(reports[0].nameservers, ["1.1.1.1", "2.2.2.2", "3.3.3.3"]);
	}

	/// An interface with only fragments is still an interface.
	///
	/// A v6-only network has no `DHCPv4` client, so nothing writes the single
	/// file -- and a reader that walked `reported/` and then decorated what it
	/// found would report nothing at all for exactly the machine this decision
	/// is about.
	#[test]
	fn an_interface_with_only_fragments_is_reported() {
		let dir = netcfgd_testdir::TestDir::new("report-fragments-only");
		let fragments = dir.join("reported.d").join("wan0");
		fs::create_dir_all(&fragments).expect("made");
		fs::write(fragments.join("dhcpcd6"), "dns=2001:db8::53\n").expect("written");

		let reports = read_reports(&dir);
		assert_eq!(reports.len(), 1, "{reports:?}");
		assert_eq!(reports[0].interface, "wan0");
		assert_eq!(reports[0].nameservers, ["2001:db8::53"]);
	}
}
