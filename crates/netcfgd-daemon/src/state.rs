//! The daemon's state, and every transition it can make.
//!
//! Deliberately free of threads, sockets and signals: everything here is a
//! method taking `&mut self` and returning what happened. The event loop in
//! `main` decides *when* these run and the tests decide *that* they behave,
//! which is the same seam that makes the planner testable without hardware.

use netcfgd_apply::{apply, Executor, Journal};
use netcfgd_host::{config, confirm, hooks::RunHooks, state as run_state};
use netcfgd_model::{Document, DriftPolicy, HookPhase, Observed};
use netcfgd_plan::{plan, Plan, PlanOptions};
use netcfgd_proto::{Event, Response};
use std::path::PathBuf;

/// Where the daemon reads and writes.
#[derive(Debug, Clone)]
pub(crate) struct Paths {
	/// The factory-default config directory, read before the writable one.
	pub(crate) factory: PathBuf,
	/// The writable config directory.
	pub(crate) config: PathBuf,
	/// The runtime state directory.
	pub(crate) run: PathBuf,
}

/// What the daemon knows.
pub(crate) struct State {
	/// Where it reads and writes.
	pub(crate) paths: Paths,
	/// The compiled desired state. `None` when the config does not compile.
	pub(crate) desired: Option<Document>,
	/// Why it does not compile, when it does not.
	pub(crate) diagnostics: Option<String>,
	/// What the kernel last reported.
	pub(crate) observed: Observed,
	/// The hash of a configuration a revert rejected, if there is one.
	///
	/// Compared against every recompile. Without it, anything that triggers a
	/// reload -- a spurious inotify event, an explicit request -- would adopt
	/// the config that just broke the machine and drift-reconcile the breakage
	/// straight back. A hash rather than a flag so that *fixing* the config
	/// clears it automatically: a different document is a different answer.
	pub(crate) rejected: Option<String>,
}

/// What a `reload` request answers, given the event that reload produced.
///
/// Here rather than at the socket because the event is the only complete
/// account of a reload, and reading anything else gets a different answer.
/// `State::diagnostics` is the tempting one and it is wrong twice over: a
/// configuration a revert rejected is refused without recording diagnostics at
/// all, and where an earlier reload failed to compile the field still holds
/// *that* failure's text. One reload, one answer, and the subscribers and the
/// asker are told the same thing.
pub(crate) fn reload_answer(event: &Event) -> Response {
	match event {
		Event::Reloaded {
			ok: false,
			diagnostics,
		} => Response::error(
			diagnostics
				.clone()
				.unwrap_or_else(|| "the configuration was not adopted".to_owned()),
		),
		_ => Response::Ok,
	}
}

impl State {
	/// Read the config and the kernel once.
	///
	/// A config that does not compile is not fatal. The daemon keeps running
	/// with no desired state, reports the diagnostics on the socket, and
	/// applies nothing -- design section 17 requires that a parse error leaves
	/// the last good state in effect rather than half-applying something.
	#[must_use]
	pub(crate) fn new(paths: Paths) -> Self {
		let mut state = Self {
			paths,
			desired: None,
			diagnostics: None,
			observed: Observed::default(),
			rejected: None,
		};
		state.reload();
		state.reobserve();
		state
	}

	/// Recompile the config directory.
	///
	/// Returns the event describing what happened, for subscribers.
	pub(crate) fn reload(&mut self) -> Event {
		let mut sink = RunHooks::new(&self.paths.run);
		let sources = match config::load_layered(&self.paths.factory, &self.paths.config) {
			Ok(sources) => sources,
			Err(error) => {
				self.diagnostics = Some(format!("{}: {error}", self.paths.config.display()));
				// The previous desired state is kept deliberately. Dropping it
				// would mean an unreadable directory silently disarms drift
				// detection, which is the moment it is most wanted.
				return Event::Reloaded {
					ok: false,
					diagnostics: self.diagnostics.clone(),
				};
			}
		};

		match netcfgd_compile::compile_with_provenance(&sources, &mut sink) {
			Ok((document, provenance)) => {
				let _ = run_state::write_provenance(&self.paths.run, &provenance);
				if self.rejected.as_deref() == Some(confirm::document_hash(&document).as_str()) {
					// The same configuration a revert already rejected. Adopting
					// it would undo the revert on the next drift check, which the
					// operator would watch happen and be unable to explain.
					return Event::Reloaded {
						ok: false,
						diagnostics: Some(
							"this configuration was reverted away from and has not \
							 changed since; edit it to try again"
								.to_owned(),
						),
					};
				}
				let _ = run_state::write_desired(&self.paths.run, &document);
				self.rejected = None;
				self.desired = Some(document);
				self.diagnostics = None;
				Event::Reloaded {
					ok: true,
					diagnostics: None,
				}
			}
			Err(found) => {
				self.diagnostics = Some(found.render(&sources));
				Event::Reloaded {
					ok: false,
					diagnostics: self.diagnostics.clone(),
				}
			}
		}
	}

	/// Re-read the kernel.
	pub(crate) fn reobserve(&mut self) {
		let prior = run_state::prior_state(&self.paths.run);
		// The document goes in so the observation can answer one question it
		// otherwise could not: whether a running access point still holds the
		// passphrase the secret store has (decision 0052). Only a boolean comes
		// back out.
		if let Ok(observed) =
			netcfgd_observe::current(&prior, &self.paths.run, self.desired.as_ref())
		{
			self.observed = observed;
			let _ = run_state::write_observed(&self.paths.run, &self.observed);
		}
	}

	/// What would change.
	#[must_use]
	pub(crate) fn plan(&self, options: &PlanOptions) -> Plan {
		self.desired.as_ref().map_or_else(Plan::default, |desired| {
			plan(desired, &self.observed, options)
		})
	}

	/// Make the observed state match the config.
	/// A kernel executor that knows about the current document.
	///
	/// The only way the daemon should make one. Three call sites used to
	/// construct it directly and exactly one remembered `with_context`, so an
	/// apply behaved differently depending on whether it arrived at startup,
	/// over the socket, or from drift -- DNS lost its scope flattening, a
	/// supplicant would be started with no networks, and the run directory
	/// reverted to the compiled-in default.
	///
	/// Nothing enforces that this is used instead of `KernelExecutor::new`.
	/// What it does is make the correct thing shorter than the incorrect one,
	/// which is the most a function can do about a mistake of omission.
	///
	/// # Errors
	///
	/// Returns a rendered message if a netlink socket cannot be opened.
	pub(crate) fn executor(&self) -> Result<netcfgd_apply::KernelExecutor, String> {
		let executor = netcfgd_apply::KernelExecutor::new()
			.map_err(|error| format!("cannot open a netlink socket: {error}"))?;
		Ok(match &self.desired {
			Some(document) => executor.with_context(&self.paths.run, document, &self.observed),
			None => executor,
		})
	}

	pub(crate) fn apply(
		&mut self,
		options: &PlanOptions,
		executor: &mut dyn Executor,
	) -> (Plan, Journal) {
		let plan = self.plan(options);
		let journal = apply(&plan, executor);
		let _ = run_state::write_journal(&self.paths.run, &journal);
		(plan, journal)
	}

	/// Look for drift, and do whatever the policy says.
	///
	/// Returns one event per drifting interface. An empty result is the normal
	/// case on a system nobody is fighting over.
	pub(crate) fn detect_drift(&self) -> Vec<Event> {
		let plan = self.plan(&PlanOptions::default());
		let mut events = Vec::new();
		let mut seen: Vec<&str> = Vec::new();

		for action in &plan.actions {
			let Some(interface) = action.op.interface() else {
				continue;
			};
			if seen.contains(&interface) {
				continue;
			}
			seen.push(interface);

			let policy = self.policy_for(interface);
			if policy == DriftPolicy::Ignore {
				continue;
			}
			events.push(Event::Drift {
				interface: interface.to_owned(),
				summary: format!(
					"{}: {} is {} but should be {}",
					action.op.name(),
					action.reason.field,
					action.reason.observed,
					action.reason.desired
				),
				action: match policy {
					DriftPolicy::Reconcile => "reconciling",
					_ => "reported only",
				}
				.to_owned(),
			});
		}

		// A guard refusing something is worth saying out loud too: it is
		// exactly the case where an operator is waiting for a change that is
		// never going to happen.
		for refusal in &plan.refusals {
			events.push(Event::Drift {
				interface: refusal.interface.clone(),
				summary: format!("{} refused: {} depends on it", refusal.op, refusal.guard),
				action: format!("blocked; {}", refusal.override_with),
			});
		}

		// And a credential nobody can revoke, for a stronger version of the
		// same reason: nothing is waiting on this one, which is exactly why it
		// would otherwise go unsaid until the hardware was gone.
		for stranded in &plan.stranded {
			events.push(Event::Drift {
				interface: stranded.interface.clone(),
				summary: format!("unmanaging it leaves {}", stranded.credential),
				action: format!(
					"undecided; {} or {}",
					stranded.remove_with, stranded.consent_with
				),
			});
		}

		events
	}

	/// Run the `drift` hooks for drift that has just been noticed.
	///
	/// **Not through the plan**, which every other phase goes through, and the
	/// reason is the phase's whole point. Drift under `report` produces no apply
	/// at all -- that is what `report` means -- so a `HookRun` action would be
	/// planned and never executed, and the one policy whose entire purpose is
	/// "tell me, do not touch it" would be the one where nothing told anybody.
	/// The hook *is* the telling.
	///
	/// Fires when drift **appears**, not while it persists. Under `report` the
	/// drift is still there on the next netlink event and the one after it, so
	/// firing on presence would run the script on every observation for as long
	/// as the operator left it alone -- 0079's restart storm in a different
	/// costume, and worse, because this one runs somebody else's code. The last
	/// summary a phase was told is already recorded per interface for the
	/// `carrier` and `lease` hooks, and the same record answers it here.
	///
	/// Never a veto. There is nothing to stop: the drift has happened, and
	/// whether netcfgd is about to reconcile it is not this script's to decide.
	pub(crate) fn run_drift_hooks(&self, events: &[Event]) -> Vec<(String, String)> {
		let Some(desired) = self.desired.as_ref() else {
			return Vec::new();
		};
		let mut told = Vec::new();

		for event in events {
			let Event::Drift {
				interface: name,
				summary,
				action,
			} = event
			else {
				continue;
			};
			let Some(interface) = desired.interfaces.iter().find(|i| &i.name == name) else {
				continue;
			};
			// What the script is told is what changed, not what netcfgd did
			// about it -- so a hook that has already seen this drift is quiet
			// even if the policy moved underneath it.
			if Self::last_told(&self.observed, name, HookPhase::Drift).as_deref()
				== Some(summary.as_str())
			{
				continue;
			}

			for hook in interface
				.hooks
				.iter()
				.filter(|hook| hook.phase == HookPhase::Drift)
			{
				let env = netcfgd_apply::hooks::HookEnv::for_interface(name)
					.because(summary.clone())
					.with("NCFG_ACTION", action.clone());
				match netcfgd_apply::hooks::run(hook, &env) {
					netcfgd_apply::hooks::Outcome::Ok => {}
					netcfgd_apply::hooks::Outcome::Vetoed(message)
					| netcfgd_apply::hooks::Outcome::Noted(message) => {
						eprintln!("netcfgd: {message}");
					}
				}
			}
			// Recorded whether or not the script succeeded, and whether or not
			// the interface declared one. A hook that failed and was retried on
			// every observation is the storm this exists to avoid (0064 made the
			// same call for `lease`), and recording it for an interface with no
			// hook costs one line in `/run` and keeps the answer to "has this
			// drift been seen" independent of whether anybody was listening.
			told.push((name.clone(), summary.clone()));
		}
		told
	}

	/// What a phase was last told about an interface.
	pub(crate) fn last_told(
		observed: &Observed,
		interface: &str,
		phase: HookPhase,
	) -> Option<String> {
		observed
			.hook_state
			.iter()
			.find(|record| record.interface == interface && record.phase == phase)
			.map(|record| record.value.clone())
	}

	/// The interfaces whose drift policy says to put things back.
	#[must_use]
	pub(crate) fn reconciling_interfaces(&self) -> Vec<String> {
		self.desired.as_ref().map_or_else(Vec::new, |desired| {
			desired
				.interfaces
				.iter()
				.filter(|interface| {
					// An interface with a preference is always reconciled,
					// whatever the drift policy says. Losing carrier is not
					// drift: drift is something else moving the system away
					// from the config, and this is the config's own meaning
					// changing, because a preferred interface's desired state
					// is a function of the document *and* its carrier.
					//
					// Treating it as drift meant the daemon reported the
					// switch instead of making it, and a laptop that announces
					// "your cable is out" while still routing down it is not
					// the feature anybody asked for.
					interface.preference.is_some()
						|| interface
							.on_drift
							.unwrap_or(desired.globals.on_drift_default)
							== DriftPolicy::Reconcile
				})
				.map(|interface| interface.name.clone())
				.collect()
		})
	}

	fn policy_for(&self, interface: &str) -> DriftPolicy {
		let Some(desired) = &self.desired else {
			return DriftPolicy::Report;
		};
		desired
			.interfaces
			.iter()
			.find(|candidate| candidate.name == interface)
			.and_then(|candidate| candidate.on_drift)
			.unwrap_or(desired.globals.on_drift_default)
	}
}

/// Keep only the actions belonging to these interfaces, and say what was
/// dropped.
///
/// Reconciling drift on one interface must not drag along a change to
/// another that the operator has set to `report`. Filtering an ordered DAG
/// can orphan a dependency, so an action whose `depends_on` is not also in
/// the set is dropped as well and named: applying it would run out of order,
/// and silently applying a subset that happens to work is how a reconciler
/// becomes unpredictable.
///
/// In practice dependencies stay within an interface -- create, mtu, up,
/// address, route -- so the orphan case is the master/member edge and little
/// else.
#[must_use]
pub(crate) fn restrict(plan: &Plan, interfaces: &[String]) -> (Plan, Vec<String>) {
	let mut kept = Plan {
		warnings: plan.warnings.clone(),
		refusals: plan.refusals.clone(),
		// Kept for the same reason the refusals are: restricting a plan to a
		// set of interfaces changes what will be *done*, not what is true about
		// the configuration. A key left on a device the operator did not ask
		// about is still a key left.
		stranded: plan.stranded.clone(),
		..Plan::default()
	};
	let mut dropped = Vec::new();
	let mut kept_ids: Vec<u32> = Vec::new();

	for action in &plan.actions {
		let wanted = action
			.op
			.interface()
			.is_some_and(|interface| interfaces.iter().any(|name| name == interface));
		if !wanted {
			continue;
		}
		if let Some(missing) = action.depends_on.iter().find(|id| !kept_ids.contains(id)) {
			dropped.push(format!(
				"{} on {} needs action {missing}, which belongs to another interface",
				action.op.name(),
				action.op.interface().unwrap_or("?")
			));
			continue;
		}
		kept_ids.push(action.id);
		kept.actions.push(action.clone());
	}

	(kept, dropped)
}

#[cfg(test)]
mod tests {
	use super::*;
	use netcfgd_plan::{Action, Op, Reason};
	use netcfgd_testdir::TestDir;
	use std::path::Path;

	/// A state over a config directory, without touching the kernel.
	///
	/// `State::new` also observes, which would make these tests depend on
	/// whatever interfaces the machine running them happens to have.
	fn state_over(config: &Path, run: &Path, text: &str) -> State {
		std::fs::write(config.join("netcfgd.conf"), text).expect("config written");
		State {
			paths: Paths {
				factory: config.to_path_buf(),
				config: config.to_path_buf(),
				run: run.to_path_buf(),
			},
			desired: None,
			diagnostics: None,
			observed: Observed::default(),
			rejected: None,
		}
	}

	/// The three ways a reload ends, and the one answer each gets.
	///
	/// Straightforward except for the middle one, which is the whole reason
	/// this function exists -- see below.
	#[test]
	fn a_reload_answers_what_its_event_said() {
		assert!(matches!(
			reload_answer(&Event::Reloaded {
				ok: true,
				diagnostics: None
			}),
			Response::Ok
		));
		let refused = reload_answer(&Event::Reloaded {
			ok: false,
			diagnostics: None,
		});
		assert!(
			matches!(refused, Response::Error { .. }),
			"a reload that did not happen must not answer ok: {refused:?}"
		);
		let broken = reload_answer(&Event::Reloaded {
			ok: false,
			diagnostics: Some("netcfgd.conf:3: unknown key".to_owned()),
		});
		match broken {
			Response::Error { message } => assert!(
				message.contains("netcfgd.conf:3"),
				"the daemon's diagnostics name a file and a line, and are \
				 passed through rather than summarised: {message}"
			),
			other => panic!("a config that does not compile must not answer ok: {other:?}"),
		}
	}

	/// A configuration a revert rejected is refused -- and the refusal lives
	/// **only** in the event.
	///
	/// This is what `reload_answer` exists for. The socket handler used to
	/// answer from `state.diagnostics`, which this leaves untouched, so an
	/// operator asking netcfgd to re-read a configuration it was refusing was
	/// told it had compiled. `ncfg reload` is the first shipped client that
	/// can send the request at all, so the wrong answer would have arrived
	/// with the command.
	#[test]
	fn a_rejected_configuration_refuses_without_setting_diagnostics() {
		let config = TestDir::new("reload-rejected-config");
		let run = TestDir::new("reload-rejected-run");
		let mut state = state_over(&config, &run, "interface eth0 { kind = \"dummy\" }\n");

		assert!(
			matches!(state.reload(), Event::Reloaded { ok: true, .. }),
			"the fixture has to compile, or the second half proves nothing"
		);

		// What a revert does, and the only thing about it that matters here.
		state.rejected = state.desired.as_ref().map(confirm::document_hash);

		let event = state.reload();
		assert!(
			matches!(event, Event::Reloaded { ok: false, .. }),
			"the same document a revert rejected must not be adopted: {event:?}"
		);
		assert!(
			state.diagnostics.is_none(),
			"the disagreement this test is here to pin: the refusal is in the \
			 event and nowhere else, so anything reading the state sees a \
			 daemon with nothing wrong"
		);
		assert!(
			matches!(reload_answer(&event), Response::Error { .. }),
			"so the answer has to come from the event"
		);
	}

	fn action(id: u32, interface: &str, depends_on: Vec<u32>) -> Action {
		Action {
			id,
			op: Op::LinkUp {
				name: interface.to_owned(),
			},
			reason: Reason::absent(interface, "enabled", "true"),
			depends_on,
			inverse: None,
		}
	}

	/// Reconciling drift on one interface must not drag along a change to
	/// another the operator set to `report`.
	#[test]
	fn restrict_keeps_only_the_named_interfaces() {
		let plan = Plan {
			actions: vec![
				action(0, "eth0", vec![]),
				action(1, "eth1", vec![]),
				action(2, "eth0", vec![0]),
			],
			..Plan::default()
		};

		let (kept, dropped) = restrict(&plan, &["eth0".to_owned()]);
		assert_eq!(kept.actions.len(), 2);
		assert!(kept
			.actions
			.iter()
			.all(|a| a.op.interface() == Some("eth0")));
		assert!(dropped.is_empty());
	}

	/// Filtering an ordered DAG can orphan a dependency. Applying an action
	/// whose prerequisite was filtered out would run it out of order, so it is
	/// dropped and named rather than attempted.
	#[test]
	fn an_action_orphaned_by_filtering_is_dropped_and_reported() {
		let plan = Plan {
			actions: vec![
				// The enslavement belongs to eth0 and gates the master.
				action(0, "eth0", vec![]),
				action(1, "br0", vec![0]),
			],
			..Plan::default()
		};

		let (kept, dropped) = restrict(&plan, &["br0".to_owned()]);
		assert!(kept.actions.is_empty());
		assert_eq!(dropped.len(), 1);
		assert!(
			dropped[0].contains("another interface"),
			"the note should say why: {}",
			dropped[0]
		);
	}

	/// Refusals and warnings survive restriction, because a guard blocking
	/// something is exactly what an operator waiting for a change needs to
	/// hear, whether or not that interface was being reconciled.
	#[test]
	fn restriction_keeps_the_refusals() {
		let plan = Plan {
			actions: vec![action(0, "eth0", vec![])],
			refusals: vec![netcfgd_plan::Refusal {
				interface: "eth1".to_owned(),
				op: "addr.del".to_owned(),
				guard: "nfs root".to_owned(),
				reason: Reason::unwanted("eth1", "addressing", "10.0.0.1/24"),
				override_with: "ncfg apply --allow-disruption eth1".to_owned(),
			}],
			..Plan::default()
		};

		let (kept, _) = restrict(&plan, &["eth0".to_owned()]);
		assert_eq!(kept.refusals.len(), 1);
	}

	/// Nothing to reconcile is the normal case and must not produce an empty
	/// apply, which would still open a netlink socket and write a journal.
	#[test]
	fn restricting_to_nothing_yields_nothing() {
		let plan = Plan {
			actions: vec![action(0, "eth0", vec![])],
			..Plan::default()
		};
		let (kept, dropped) = restrict(&plan, &[]);
		assert!(kept.actions.is_empty());
		assert!(dropped.is_empty());
	}
}
