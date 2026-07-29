//! The daemon's state, and every transition it can make.
//!
//! Deliberately free of threads, sockets and signals: everything here is a
//! method taking `&mut self` and returning what happened. The event loop in
//! `main` decides *when* these run and the tests decide *that* they behave,
//! which is the same seam that makes the planner testable without hardware.

use netcfgd_apply::{apply, Executor, Journal};
use netcfgd_host::{config, hooks::RunHooks, state as run_state};
use netcfgd_model::{Document, DriftPolicy, Observed};
use netcfgd_plan::{plan, Plan, PlanOptions};
use netcfgd_proto::Event;
use std::path::PathBuf;

/// Where the daemon reads and writes.
#[derive(Debug, Clone)]
pub(crate) struct Paths {
	/// The config directory.
	pub(crate) config_dir: PathBuf,
	/// The runtime state directory.
	pub(crate) run_dir: PathBuf,
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
		};
		state.reload();
		state.reobserve();
		state
	}

	/// Recompile the config directory.
	///
	/// Returns the event describing what happened, for subscribers.
	pub(crate) fn reload(&mut self) -> Event {
		let mut sink = RunHooks::new(&self.paths.run_dir);
		let sources = match config::load(&self.paths.config_dir) {
			Ok(sources) => sources,
			Err(error) => {
				self.diagnostics = Some(format!("{}: {error}", self.paths.config_dir.display()));
				// The previous desired state is kept deliberately. Dropping it
				// would mean an unreadable directory silently disarms drift
				// detection, which is the moment it is most wanted.
				return Event::Reloaded {
					ok: false,
					diagnostics: self.diagnostics.clone(),
				};
			}
		};

		match netcfgd_compile::compile(&sources, &mut sink) {
			Ok(document) => {
				let _ = run_state::write_desired(&self.paths.run_dir, &document);
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
		let prior = run_state::read_owned(&self.paths.run_dir).to_prior();
		if let Ok(observed) = netcfgd_observe::current(&prior) {
			self.observed = observed;
			let _ = run_state::write_observed(&self.paths.run_dir, &self.observed);
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
	pub(crate) fn apply(
		&mut self,
		options: &PlanOptions,
		executor: &mut dyn Executor,
	) -> (Plan, Journal) {
		let plan = self.plan(options);
		let journal = apply(&plan, executor);
		let _ = run_state::write_journal(&self.paths.run_dir, &journal);
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

		events
	}

	/// The interfaces whose drift policy says to put things back.
	#[must_use]
	pub(crate) fn reconciling_interfaces(&self) -> Vec<String> {
		self.desired.as_ref().map_or_else(Vec::new, |desired| {
			desired
				.interfaces
				.iter()
				.filter(|interface| {
					interface
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
