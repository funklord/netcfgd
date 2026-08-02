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
	/// Interfaces netcfgd turned IP forwarding on for.
	pub forwarding: Vec<String>,
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
/// A missing directory means nothing is reporting, which is the state of every
/// machine with no modem and no tunnel. Unreadable and malformed files are
/// skipped rather than failing the observation, for the reason the rest of this
/// module gives: `/run` is derived and disposable, and refusing to observe a
/// machine because one file is bad is worse than observing the rest of it.
#[must_use]
pub fn read_reports(run_dir: &Path) -> Vec<netcfgd_model::ObservedReport> {
	let Ok(entries) = fs::read_dir(report_dir(run_dir)) else {
		return Vec::new();
	};
	let mut out: Vec<netcfgd_model::ObservedReport> = entries
		.flatten()
		.filter_map(|entry| {
			let interface = entry.file_name().to_str()?.to_owned();
			let body = fs::read_to_string(entry.path()).ok()?;
			Some(parse_report(&interface, &body))
		})
		.collect();
	out.sort_by(|a, b| a.interface.cmp(&b.interface));
	out
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
			qdisc: self.qdisc.clone(),
			ingress: self.ingress.clone(),
			// Not from this file. A delegation is not something netcfgd did,
			// it is something a client was told, so it is recorded separately
			// and folded in by [`prior_state`].
			delegations: Vec::new(),
			reports: Vec::new(),
		}
	}

	/// Fold in what an apply just did.
	///
	/// Removals are applied before additions so that replacing an address in
	/// one plan leaves exactly one record, not zero.
	pub fn absorb(&mut self, effects: &Effects) {
		// Only the interfaces netcfgd switched *on* are recorded. Switching
		// one off drops the record rather than storing `false`: the question
		// this answers is "is this ours to turn off later", and once it is off
		// the answer is no.
		for (interface, enabled) in &effects.forwarding {
			self.forwarding.retain(|name| name != interface);
			if *enabled {
				self.forwarding.push(interface.clone());
			}
		}

		// Same shape: a reset drops the record rather than storing it, because
		// the question is "is this ours to put back", and once the kernel
		// default is restored the answer is no.
		for (interface, set) in &effects.qdisc {
			self.qdisc.retain(|name| name != interface);
			if *set {
				self.qdisc.push(interface.clone());
			}
		}

		for (interface, set) in &effects.ingress {
			self.ingress.retain(|name| name != interface);
			if *set {
				self.ingress.push(interface.clone());
			}
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
					access_control: None,
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

#[cfg(test)]
mod tests {
	use super::*;

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
}
