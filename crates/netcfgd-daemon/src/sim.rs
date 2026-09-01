//! Which SIM source netcfgd wants, per modem device.
//!
//! [0150](../../../doc/decision/0150-a-sim-source-is-chosen-the-way-an-uplink-is.md)
//! puts the choice here and the hardware poke in a `pre_up` hook;
//! [0152](../../../doc/decision/0152-a-sim-source-is-kept-until-the-probe-says-otherwise.md)
//! answers the three things 0150 left open, and this module is that answer:
//! the probe decides when a source has failed, the last source is where it
//! stops, and a working source is kept.
//!
//! **The choice lives in `/run` and the preference lives in the document.**
//! The ordered list is the operator's intent and is never written to -- that is
//! constraint 1, and it is what the component that solved this on one board had
//! to rediscover. What moves is the index, which is derived and disposable and
//! gone after a reboot, so a cold start begins at the preference again.

use netcfgd_model::{Device, Document};
use std::collections::{BTreeSet, HashMap};
use std::path::{Path, PathBuf};

/// Which source each modem device is currently on, as an index into its list.
#[derive(Debug, Default)]
pub(crate) struct Sims {
	chosen: HashMap<String, usize>,
	/// Devices that have advanced and whose link has not been cycled yet.
	///
	/// Publishing the choice is not applying it: a `pre_up` hook is what acts
	/// on the file, and `pre_up` fires on the way up. So an advance leaves a
	/// note here, the reconcile turns it into `PlanOptions::cycle`, and it is
	/// cleared once a plan carrying that cycle has been applied -- not when it
	/// is planned, so a plan that could not run is tried again rather than
	/// leaving the machine on a source nothing ever selected.
	pending: BTreeSet<String>,
}

/// Where the selection is published, per the mirror of the interface report.
fn path(run_dir: &Path, device: &str) -> PathBuf {
	run_dir.join("modem").join(device)
}

/// Every device in the document that has a modem policy.
fn modems(document: &Document) -> impl Iterator<Item = &Device> {
	document
		.devices
		.iter()
		.filter(|device| device.modem.is_some())
}

impl Sims {
	/// Bring the selection into line with a document, and publish it.
	///
	/// Called on every reload. A device that gains a modem block starts at its
	/// first source; one that loses it, or leaves the document, has its file
	/// removed rather than left behind to be read as current by a hook that
	/// has no other way of knowing.
	///
	/// The index is clamped rather than reset, so shortening the list of a
	/// device already on a later source moves it to the last one that still
	/// exists instead of silently taking it back to the first -- which would
	/// be a SIM switch nobody asked for, arriving through an edit to an
	/// unrelated part of the list.
	pub(crate) fn sync(&mut self, document: &Document, run_dir: &Path) {
		let mut present = Vec::new();
		for device in modems(document) {
			let policy = device.modem.as_ref().expect("filtered on is_some");
			present.push(device.name.clone());
			let last = policy.sim.len().saturating_sub(1);
			let index = self.chosen.entry(device.name.clone()).or_insert(0);
			*index = (*index).min(last);
			publish(
				run_dir,
				&device.name,
				policy.sim.get(*index),
				policy.apn.as_deref(),
			);
		}

		let gone: Vec<String> = self
			.chosen
			.keys()
			.filter(|name| !present.contains(name))
			.cloned()
			.collect();
		for name in gone {
			self.chosen.remove(&name);
			self.pending.remove(&name);
			let _ = std::fs::remove_file(path(run_dir, &name));
		}
	}

	/// Move a device to its next SIM source, if it has one.
	///
	/// Returns the source it moved to, or `None` when it is already on the
	/// last one -- 0152 stops there rather than wrapping, because a machine
	/// whose subscription has lapsed would otherwise reset its modem for ever
	/// and be permanently offline rather than offline until somebody looked.
	pub(crate) fn advance(
		&mut self,
		document: &Document,
		device: &str,
		run_dir: &Path,
	) -> Option<String> {
		let policy = modems(document)
			.find(|candidate| candidate.name == device)?
			.modem
			.as_ref()?;
		// One source is a list, not a special case, and it has nowhere to go.
		let index = self.chosen.entry(device.to_owned()).or_insert(0);
		if *index + 1 >= policy.sim.len() {
			return None;
		}
		*index += 1;
		let chosen = policy.sim.get(*index).cloned();
		self.pending.insert(device.to_owned());
		publish(run_dir, device, chosen.as_ref(), policy.apn.as_deref());
		chosen
	}

	/// Devices whose link has to be cycled for the new selection to take.
	pub(crate) fn pending(&self) -> Vec<String> {
		self.pending.iter().cloned().collect()
	}

	/// Every modem device, what it asks for and what is in force.
	///
	/// Joined here rather than by the client, because the two halves live
	/// apart: the order comes from the document and the choice from this
	/// module's own state. A client stitching them together would be a second
	/// copy of a rule that belongs to the daemon.
	pub(crate) fn status(&self, document: Option<&Document>) -> Vec<netcfgd_proto::ModemStatus> {
		let Some(document) = document else {
			return Vec::new();
		};
		modems(document)
			.map(|device| {
				let policy = device.modem.as_ref().expect("filtered on is_some");
				let index = self.chosen.get(&device.name).copied().unwrap_or(0);
				netcfgd_proto::ModemStatus {
					device: device.name.clone(),
					sim: policy.sim.clone(),
					selected: policy.sim.get(index).cloned(),
					apn: policy.apn.clone(),
					cycle_pending: self.pending.contains(&device.name),
				}
			})
			.collect()
	}

	/// Whether this device is waiting for its link to be cycled.
	pub(crate) fn is_pending(&self, device: &str) -> bool {
		self.pending.contains(device)
	}

	/// Forget the notes that a plan has now acted on.
	pub(crate) fn cycled(&mut self, devices: &[String]) {
		for device in devices {
			self.pending.remove(device);
		}
	}

	/// The source a device is on, for reporting.
	#[cfg(test)]
	pub(crate) fn current<'a>(&self, document: &'a Document, device: &str) -> Option<&'a str> {
		let policy = modems(document)
			.find(|candidate| candidate.name == device)?
			.modem
			.as_ref()?;
		policy
			.sim
			.get(self.chosen.get(device).copied().unwrap_or(0))
			.map(String::as_str)
	}
}

/// Write the selection where a `pre_up` hook can read it.
///
/// Written for every device with a `modem` block, including one that lists no
/// source at all, so a hook can read the file unconditionally rather than
/// having to tell "not written yet" from "this device has no modem policy".
///
/// Atomic through a temporary file, like every other thing netcfgd publishes
/// in `/run`: a hook reading a half-written selection would drive the mux to a
/// truncated source name.
fn publish(run_dir: &Path, device: &str, sim: Option<&String>, apn: Option<&str>) {
	let mut body = format!("# {device}, netcfgd's SIM selection\n");
	if let Some(sim) = sim {
		body.push_str(&format!("sim={sim}\n"));
	}
	if let Some(apn) = apn {
		body.push_str(&format!("apn={apn}\n"));
	}

	let target = path(run_dir, device);
	let Some(parent) = target.parent() else {
		return;
	};
	if std::fs::create_dir_all(parent).is_err() {
		return;
	}
	let temporary = target.with_extension("tmp");
	if std::fs::write(&temporary, body).is_ok() {
		let _ = std::fs::rename(&temporary, &target);
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use netcfgd_model::{Device, ModemPolicy, OnUnmanage};

	fn document(sim: &[&str], apn: Option<&str>) -> Document {
		let mut document = Document::default();
		document.devices.push(Device {
			name: "wwan0".to_owned(),
			r#match: None,
			managed: true,
			on_unmanage: OnUnmanage::Leave,
			wifi: None,
			modem: Some(ModemPolicy {
				sim: sim.iter().map(|s| (*s).to_owned()).collect(),
				apn: apn.map(str::to_owned),
			}),
		});
		document
	}

	fn read(run: &Path) -> String {
		std::fs::read_to_string(run.join("modem").join("wwan0")).expect("the selection")
	}

	#[test]
	fn the_first_source_is_chosen_and_published() {
		let run = tempdir();
		let document = document(&["esim", "socket"], Some("im.cxn"));
		let mut sims = Sims::default();
		sims.sync(&document, run.path());

		let body = read(run.path());
		assert!(body.contains("sim=esim"), "{body}");
		assert!(body.contains("apn=im.cxn"), "{body}");
	}

	/// The whole of 0152's second answer: the last source is where it stops.
	#[test]
	fn advancing_stops_at_the_last_source_rather_than_wrapping() {
		let run = tempdir();
		let document = document(&["esim", "socket"], None);
		let mut sims = Sims::default();
		sims.sync(&document, run.path());

		assert_eq!(
			sims.advance(&document, "wwan0", run.path()).as_deref(),
			Some("socket")
		);
		assert!(read(run.path()).contains("sim=socket"));
		// And again: nowhere to go, and it stays where it ended rather than
		// returning to `esim` and resetting the modem for ever.
		assert_eq!(sims.advance(&document, "wwan0", run.path()), None);
		assert_eq!(sims.current(&document, "wwan0"), Some("socket"));
	}

	/// A single source is a list of one, not a special case.
	#[test]
	fn one_source_has_nowhere_to_advance_to() {
		let run = tempdir();
		let document = document(&["socket"], None);
		let mut sims = Sims::default();
		sims.sync(&document, run.path());
		assert_eq!(sims.advance(&document, "wwan0", run.path()), None);
	}

	/// A reload must not take a machine back to the first source: that would
	/// be a SIM switch nobody asked for, triggered by an unrelated edit.
	#[test]
	fn a_reload_keeps_the_source_that_is_in_use() {
		let run = tempdir();
		let document = document(&["esim", "socket"], None);
		let mut sims = Sims::default();
		sims.sync(&document, run.path());
		sims.advance(&document, "wwan0", run.path());

		sims.sync(&document, run.path());
		assert_eq!(sims.current(&document, "wwan0"), Some("socket"));
		assert!(read(run.path()).contains("sim=socket"));
	}

	/// Shortening the list moves a device to the last source that still
	/// exists, rather than silently back to the first.
	#[test]
	fn a_shortened_list_clamps_rather_than_resetting() {
		let run = tempdir();
		let long = document(&["esim", "socket", "spare"], None);
		let mut sims = Sims::default();
		sims.sync(&long, run.path());
		sims.advance(&long, "wwan0", run.path());
		sims.advance(&long, "wwan0", run.path());
		assert_eq!(sims.current(&long, "wwan0"), Some("spare"));

		let short = document(&["esim", "socket"], None);
		sims.sync(&short, run.path());
		assert_eq!(sims.current(&short, "wwan0"), Some("socket"));
	}

	/// A device that loses its modem block takes its file with it. A stale
	/// selection is read as current by a hook that has no other source.
	#[test]
	fn a_device_that_leaves_the_document_loses_its_file() {
		let run = tempdir();
		let document = document(&["esim"], None);
		let mut sims = Sims::default();
		sims.sync(&document, run.path());
		assert!(run.path().join("modem").join("wwan0").exists());

		sims.sync(&Document::default(), run.path());
		assert!(!run.path().join("modem").join("wwan0").exists());
	}

	/// What the socket answers: the preference and the selection as separate
	/// facts.
	///
	/// Collapsing them into one "current SIM" would lose the question an
	/// operator actually has when a modem will not attach -- whether it is on
	/// the source they asked for, or has fallen through to a spare.
	#[test]
	fn the_status_reports_the_preference_and_the_choice_apart() {
		let run = tempdir();
		let document = document(&["esim", "socket"], Some("im.cxn"));
		let mut sims = Sims::default();
		sims.sync(&document, run.path());

		let before = sims.status(Some(&document));
		assert_eq!(before.len(), 1);
		assert_eq!(before[0].device, "wwan0");
		assert_eq!(before[0].sim, vec!["esim".to_owned(), "socket".to_owned()]);
		assert_eq!(before[0].selected.as_deref(), Some("esim"));
		assert_eq!(before[0].apn.as_deref(), Some("im.cxn"));
		assert!(!before[0].cycle_pending);

		sims.advance(&document, "wwan0", run.path());
		let after = sims.status(Some(&document));
		// The preference has not moved and must not: it is the operator's,
		// and constraint 1 is that netcfgd never rewrites it.
		assert_eq!(after[0].sim, vec!["esim".to_owned(), "socket".to_owned()]);
		assert_eq!(after[0].selected.as_deref(), Some("socket"));
		// Advanced but not yet cycled, which is "netcfgd wants the other SIM"
		// rather than "the machine is on it".
		assert!(after[0].cycle_pending);
	}

	/// A daemon that has not compiled a document yet answers with a list
	/// rather than an error: no configuration is a state.
	#[test]
	fn the_status_of_no_document_is_empty() {
		assert!(Sims::default().status(None).is_empty());
	}

	/// A modem block with no sources still publishes, so a hook can read the
	/// file unconditionally.
	#[test]
	fn a_modem_with_no_sources_still_publishes_its_apn() {
		let run = tempdir();
		let document = document(&[], Some("im.cxn"));
		let mut sims = Sims::default();
		sims.sync(&document, run.path());
		let body = read(run.path());
		assert!(body.contains("apn=im.cxn"), "{body}");
		assert!(!body.contains("sim="), "{body}");
	}

	struct TempDir(PathBuf);

	impl TempDir {
		fn path(&self) -> &Path {
			&self.0
		}
	}

	impl Drop for TempDir {
		fn drop(&mut self) {
			let _ = std::fs::remove_dir_all(&self.0);
		}
	}

	fn tempdir() -> TempDir {
		let base = std::env::temp_dir().join(format!(
			"netcfgd-sim-{}-{:?}",
			std::process::id(),
			std::thread::current().id()
		));
		let _ = std::fs::remove_dir_all(&base);
		std::fs::create_dir_all(&base).expect("a scratch directory");
		TempDir(base)
	}
}
