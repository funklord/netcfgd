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

use netcfgd_model::{Device, Document, ObservedReport};
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
	/// The card seen in each source, per device: `device -> source -> iccid`.
	///
	/// **Derived and disposable, like `chosen` above.** It is rebuilt as
	/// sources are used and gone after a reboot, which is right: a card can be
	/// swapped while the machine is off, and a remembered ICCID that outlived
	/// the card it named would be a confident wrong answer to the one question
	/// this exists to settle.
	///
	/// Filled in only for sources a helper has reported a card for. A source
	/// netcfgd has never been on has no entry, and that absence is the honest
	/// answer -- the mux shows the module one SIM at a time, so learning what
	/// is in the other socket costs a switch, a modem reset and the link.
	cards: HashMap<String, HashMap<String, String>>,
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
				// Ordered by the document's own list rather than by whatever
				// order the map iterates, so two runs on one machine print the
				// same thing and a source the operator put first reads first.
				let seen = self.cards.get(&device.name);
				let cards = policy
					.sim
					.iter()
					.filter_map(|source| {
						seen?.get(source).map(|iccid| netcfgd_proto::SimCard {
							source: source.clone(),
							iccid: iccid.clone(),
						})
					})
					.collect();
				netcfgd_proto::ModemStatus {
					device: device.name.clone(),
					sim: policy.sim.clone(),
					selected: policy.sim.get(index).cloned(),
					apn: policy.apn.clone(),
					cycle_pending: self.pending.contains(&device.name),
					cards,
				}
			})
			.collect()
	}

	/// Take note of the cards helpers have reported, so `status` can show them.
	///
	/// **The pairing comes from the report, not from `chosen`.** netcfgd
	/// publishes the source it wants and a helper reads the card some seconds
	/// later, across a modem reset -- so pairing the current selection with
	/// whatever ICCID last appeared would file one card under the other's name
	/// every time a source advanced. An advance publishes immediately while
	/// the module is still reading the old card, which is exactly the window
	/// where that mistake would be made and would then persist.
	///
	/// So a report without a `sim` key contributes nothing. It is not an
	/// error, and older helpers write exactly that: an ICCID with no idea
	/// which source it belongs to is a fact netcfgd cannot use, and guessing
	/// would be worse than not showing it.
	///
	/// A source is only accepted if the document lists it, so a stale report
	/// naming a source that has been edited out cannot resurrect it.
	pub(crate) fn observe(&mut self, document: Option<&Document>, reports: &[ObservedReport]) {
		let Some(document) = document else {
			return;
		};
		for device in modems(document) {
			let policy = device.modem.as_ref().expect("filtered on is_some");
			let Some(report) = reports
				.iter()
				.find(|report| report.interface == device.name)
			else {
				continue;
			};
			let (Some(iccid), Some(source)) = (&report.iccid, &report.sim) else {
				continue;
			};
			if !policy.sim.iter().any(|listed| listed == source) {
				continue;
			}
			self.cards
				.entry(device.name.clone())
				.or_default()
				.insert(source.clone(), iccid.clone());
		}
	}

	/// Whether this device is waiting for its link to be cycled.
	pub(crate) fn is_pending(&self, device: &str) -> bool {
		self.pending.contains(device)
	}

	/// Forget the notes that a plan has now acted on.
	///
	/// **A note is dropped only where its cycle actually happened.** Both call
	/// sites used to clear every note the moment `apply` returned, and `apply`
	/// returns a journal rather than a result -- so a `link.down` that failed
	/// forgot the note anyway, and nothing retried. The modem then sat on the
	/// source it had, with the new one published to `/run` and `pre_up` never
	/// fired, until something unrelated cycled the link. The comment at the
	/// call site already claimed this behaviour; the code did not have it.
	///
	/// The condition is per device rather than per plan, and that matters in
	/// both directions. Clearing on a whole-plan success would keep the note
	/// alive whenever anything else in the plan failed -- a wifi backend, an
	/// unrelated address -- and every apply after would take a working link
	/// down and up again, which is the flapping the call site's other comment
	/// records having just fixed.
	///
	/// A device with no records at all clears, and that is the right answer
	/// rather than an oversight: the planner emits a cycle only for a link
	/// that is *up*, because a link that is down runs `pre_up` on its way up
	/// regardless. No records means no cycle was needed.
	pub(crate) fn cycled(&mut self, devices: &[String], journal: &netcfgd_apply::Journal) {
		for device in devices {
			let happened = journal
				.records
				.iter()
				.filter(|record| record.interface.as_deref() == Some(device.as_str()))
				.all(|record| record.outcome == netcfgd_apply::journal::Outcome::Done);
			if happened {
				self.pending.remove(device);
			}
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
			mtu: None,
			mac: None,
			link_settings: None,
			kind: netcfgd_model::InterfaceKind::Physical,
			master: None,
			qdisc: None,
			ingress_redirect: None,
			bridge_vlans: Vec::new(),
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

	/// A report naming its source is what pairs a card with a SIM.
	///
	/// **And the pairing must not come from `chosen`.** netcfgd publishes a new
	/// source the instant it advances, while the module is still reading the
	/// old card -- so a `status` that paired its own current selection with
	/// whatever ICCID last appeared would file one card under the other's name
	/// at exactly the moment a source changed, which is the only moment anyone
	/// looks. This drives that window directly: advance to `socket`, then
	/// deliver a report that still says `esim`, and check the card lands on
	/// `esim`.
	#[test]
	fn a_card_is_filed_under_the_source_the_report_names() {
		let run = tempdir();
		let document = document(&["esim", "socket"], None);
		let mut sims = Sims::default();
		sims.sync(&document, run.path());

		sims.observe(
			Some(&document),
			&[report("wwan0", Some("8946000000000000001"), Some("esim"))],
		);

		// The advance happens, and the module has not caught up with it.
		sims.advance(&document, "wwan0", run.path());
		assert_eq!(sims.current(&document, "wwan0"), Some("socket"));
		sims.observe(
			Some(&document),
			&[report("wwan0", Some("8946000000000000001"), Some("esim"))],
		);

		let status = sims.status(Some(&document));
		let cards = &status[0].cards;
		assert_eq!(cards.len(), 1, "one card seen, not one per listed source");
		assert_eq!(cards[0].source, "esim", "the stale report named esim");
		assert_eq!(cards[0].iccid, "8946000000000000001");

		// And once the module does catch up, the second card joins the first
		// rather than replacing it: both are now known, which is the whole
		// point of remembering them.
		sims.observe(
			Some(&document),
			&[report("wwan0", Some("8946000000000000002"), Some("socket"))],
		);
		let status = sims.status(Some(&document));
		let cards = &status[0].cards;
		assert_eq!(cards.len(), 2);
		// In the document's order, so two runs print the same thing.
		assert_eq!(cards[0].source, "esim");
		assert_eq!(cards[1].source, "socket");
	}

	/// An unpaired card is not guessed at, and a source not in the document is
	/// not resurrected by a stale report.
	#[test]
	fn a_card_with_no_source_and_a_source_with_no_entry_are_both_ignored() {
		let run = tempdir();
		let document = document(&["esim", "socket"], None);
		let mut sims = Sims::default();
		sims.sync(&document, run.path());

		// An older helper reports the card and not the source. Nothing to do
		// with it: an ICCID with no idea which source it belongs to is a fact
		// netcfgd cannot use, and the current selection is not the answer.
		sims.observe(
			Some(&document),
			&[report("wwan0", Some("8946000000000000003"), None)],
		);
		assert!(sims.status(Some(&document))[0].cards.is_empty());

		// A source the document no longer lists, which is what a report left
		// behind by an earlier configuration looks like.
		sims.observe(
			Some(&document),
			&[report("wwan0", Some("8946000000000000004"), Some("spare"))],
		);
		assert!(sims.status(Some(&document))[0].cards.is_empty());

		// The control, from the other side: the same call with a source that
		// *is* listed does record, so the two refusals above are about the
		// input rather than about `observe` never working.
		sims.observe(
			Some(&document),
			&[report("wwan0", Some("8946000000000000005"), Some("socket"))],
		);
		assert_eq!(sims.status(Some(&document))[0].cards.len(), 1);
	}

	/// A report carrying only what a modem helper writes.
	fn report(interface: &str, iccid: Option<&str>, sim: Option<&str>) -> ObservedReport {
		ObservedReport {
			interface: interface.to_owned(),
			addresses: Vec::new(),
			gateways: Vec::new(),
			nameservers: Vec::new(),
			search: Vec::new(),
			routes: Vec::new(),
			iccid: iccid.map(str::to_owned),
			sim: sim.map(str::to_owned),
		}
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

	/// A journal holding one record for `wwan0` with the given outcome.
	fn journal(outcome: netcfgd_apply::journal::Outcome) -> netcfgd_apply::Journal {
		let mut journal = netcfgd_apply::Journal::default();
		journal.push(netcfgd_apply::journal::Record {
			id: 1,
			op: "link.down".to_owned(),
			interface: Some("wwan0".to_owned()),
			reason: netcfgd_plan::Reason::absent("wwan0", "modem.sim", "b"),
			outcome,
			error: None,
		});
		journal
	}

	/// A cycle that failed keeps its note, so the next apply tries again.
	///
	/// Both call sites cleared every note the moment `apply` returned, and
	/// `apply` returns a journal rather than a result -- so a `link.down` that
	/// failed forgot the note and nothing retried, leaving the modem on its old
	/// source with the new one published and `pre_up` never fired.
	#[test]
	fn a_cycle_that_failed_keeps_its_note() {
		let run = tempdir();
		let document = document(&["a", "b"], None);
		let mut sims = Sims::default();
		sims.sync(&document, run.path());
		assert_eq!(
			sims.advance(&document, "wwan0", run.path()).as_deref(),
			Some("b")
		);

		let waiting = sims.pending();
		sims.cycled(&waiting, &journal(netcfgd_apply::journal::Outcome::Failed));
		assert!(
			sims.is_pending("wwan0"),
			"a cycle whose link.down failed must still be waiting"
		);

		// And the note goes once the cycle really happened, or every later
		// apply would take a working link down and up again.
		sims.cycled(&waiting, &journal(netcfgd_apply::journal::Outcome::Done));
		assert!(
			!sims.is_pending("wwan0"),
			"a cycle that ran is finished with"
		);
	}

	/// An unrelated failure elsewhere in the plan does not hold the note.
	///
	/// The condition is per device rather than per plan: clearing on a
	/// whole-plan success would keep the note alive whenever a wifi backend or
	/// an unrelated address failed, and every apply after would flap a link
	/// that had already switched.
	#[test]
	fn a_failure_on_another_interface_does_not_hold_the_note() {
		let run = tempdir();
		let document = document(&["a", "b"], None);
		let mut sims = Sims::default();
		sims.sync(&document, run.path());
		sims.advance(&document, "wwan0", run.path());

		let mut mixed = journal(netcfgd_apply::journal::Outcome::Done);
		mixed.push(netcfgd_apply::journal::Record {
			id: 2,
			op: "backend.start".to_owned(),
			interface: Some("wlan0".to_owned()),
			reason: netcfgd_plan::Reason::absent("wlan0", "backend", "supplicant"),
			outcome: netcfgd_apply::journal::Outcome::Failed,
			error: Some("no supplicant".to_owned()),
		});
		let waiting = sims.pending();
		sims.cycled(&waiting, &mixed);
		assert!(
			!sims.is_pending("wwan0"),
			"another interface's failure is not this one's"
		);
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
