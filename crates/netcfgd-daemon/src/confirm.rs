//! The commit-confirm state machine.
//!
//! Design section 4.5: apply, start a timer, and revert to the last-good
//! desired state unless somebody confirms. The point is a machine you are
//! connected *through* -- if the change severs your session, the box comes
//! back on the old config by itself.
//!
//! Free of threads and sockets, like the rest of the daemon's state. `main`
//! decides when these run.

use crate::state::State;
use netcfgd_apply::{Executor, Journal, Outcome};
use netcfgd_host::{confirm, state as run_state};
use netcfgd_model::Document;
use netcfgd_plan::{Op, Plan, PlanOptions};
use netcfgd_proto::{Event, Response};

/// Why an arm request was refused.
pub(crate) enum ArmError {
	/// A window is already open.
	AlreadyArmed(u32),
	/// There is nothing to fall back to.
	NoLastGood,
}

impl ArmError {
	pub(crate) fn message(&self) -> String {
		match self {
			Self::AlreadyArmed(seconds) => format!(
				"a confirm window is already open with {seconds}s left; confirm or revert first"
			),
			Self::NoLastGood => "no last-good configuration to revert to; \
			                     apply once without a window first"
				.to_owned(),
		}
	}
}

/// Check that a window may be opened, and say what it would revert to.
///
/// Arming without a last-good document is refused rather than allowed with an
/// empty target. A window whose revert does nothing is worse than no window,
/// because the operator believes they have a safety net. The daemon applies on
/// start and records a last-good then, so in ordinary use one always exists by
/// the time anybody asks for a window.
pub(crate) fn may_arm(state: &State) -> Result<Document, ArmError> {
	if let Some(window) = confirm::read_window(&state.paths.run) {
		#[allow(clippy::cast_possible_truncation)]
		return Err(ArmError::AlreadyArmed(window.remaining().as_secs() as u32));
	}
	confirm::read_last_good(&state.paths.run).ok_or(ArmError::NoLastGood)
}

/// Open the window. Called after the apply has run.
pub(crate) fn arm(state: &State, window_seconds: u32, last_good: &Document) -> Event {
	let window = confirm::arm(window_seconds, confirm::document_hash(last_good));
	let _ = confirm::write_window(&state.paths.run, &window);
	Event::ConfirmArmed {
		seconds: window_seconds,
	}
}

/// The inverses of the actions that actually ran, in the order they ran.
///
/// Driven by the journal rather than by the plan alone, because an action
/// that failed or never ran has nothing to undo -- replaying its inverse
/// would be netcfgd removing an address it never added, or bringing down a
/// link somebody else owns. `Outcome::Done` is the only outcome that means
/// the machine changed.
///
/// An action with no declared inverse contributes nothing, which is what
/// `Plan::irreversible` warns about: those are the actions a revert cannot
/// take back, and the warning was true before this and stays true.
///
/// `commit.arm` is in the list and is deliberately left there. Its inverse is
/// `commit.revert`, and all three commit ops are no-ops in the executor --
/// the window is this module's bookkeeping, not the kernel's -- so replaying
/// it changes nothing and keeps the count the revert logs equal to the count
/// the apply reported.
pub(crate) fn undo_from(plan: &Plan, journal: &Journal) -> Vec<Op> {
	plan.actions
		.iter()
		.filter(|action| {
			journal
				.records
				.iter()
				.any(|record| record.id == action.id && record.outcome == Outcome::Done)
		})
		.filter_map(|action| action.inverse.clone())
		.collect()
}

/// Keep the change.
pub(crate) fn confirm_window(state: &mut State) -> (Response, Option<Event>) {
	if confirm::read_window(&state.paths.run).is_none() {
		return (Response::error("no confirm window is open"), None);
	}
	let _ = confirm::clear_window(&state.paths.run);
	// The change stood, so there is nothing to take back.
	state.undo.clear();
	// And it becomes what a future revert falls back to.
	if let Some(desired) = &state.desired {
		let _ = confirm::write_last_good(&state.paths.run, desired);
	}
	(
		Response::Ok,
		Some(Event::ConfirmResolved { confirmed: true }),
	)
}

/// Put the last-good configuration back.
///
/// **Two steps, and both are needed.** The declared inverses of what was
/// applied run first, newest first, because an action knows how to undo
/// itself in a way a re-plan cannot work out afterwards: a re-plan compares
/// the machine against a document, so it can only take back what that
/// document *disagrees* with. A setting the last-good document does not
/// mention is not a disagreement, and nothing plans it back.
///
/// Measured, with the document restore alone as the control. A window that
/// changed an address, a route and the MTU, then closed unconfirmed:
///
/// ```text
/// document restore only   addr restored   route restored   mtu 1400
/// declared inverses       addr restored   route restored   mtu 1500
/// ```
///
/// The MTU is the case, and it is the general shape rather than one field.
/// The last-good document states no MTU for that device, so 1400 agrees with
/// it as well as 1500 does and the re-plan has nothing to say -- while
/// `link.set_mtu` declared an inverse carrying the value it replaced. The
/// machine was left one revert away from the configuration the operator
/// thought they had gone back to.
///
/// Then the desired state becomes the last-good document and the plan runs
/// against it, which is what this function did on its own until now. It is
/// the safety net rather than a duplicate: it converges from wherever the
/// machine actually is -- including from a half-applied plan that stopped at
/// a failure, and from a restart, which loses the inverses entirely. If the
/// inverses were complete it finds nothing to do.
///
/// Nothing here needs the network: the inverses are in memory, the target
/// document is on disk and the current state comes from netlink.
pub(crate) fn revert(state: &mut State, reason: &str) -> (Response, Vec<Event>) {
	let Some(window) = confirm::read_window(&state.paths.run) else {
		return (Response::error("no confirm window is open"), Vec::new());
	};
	let Some(last_good) = confirm::read_last_good(&state.paths.run) else {
		let _ = confirm::clear_window(&state.paths.run);
		return (
			Response::error("the last-good configuration is unreadable; nothing reverted"),
			Vec::new(),
		);
	};

	eprintln!(
		"netcfgd: reverting to {} ({reason})",
		&window.last_good_hash[..window.last_good_hash.len().min(12)]
	);

	// The desired state becomes the last-good one *before* the revert is
	// planned, and stays that way afterwards. Without this the next drift
	// check would compare the machine against the config that just broke it
	// and put the breakage straight back -- a revert that undoes itself within
	// seconds is worse than none, because the operator watches it work and
	// then watches it fail.
	// Remember what was rejected by identity, so a reload of the *same*
	// configuration is refused and a genuinely edited one is not.
	state.rejected = state.desired.as_ref().map(confirm::document_hash);
	state.desired = Some(last_good);
	// /run/desired.json is what `cat` answers with, so it has to say what is
	// actually in effect rather than what is on disk.
	if let Some(desired) = &state.desired {
		let _ = run_state::write_desired(&state.paths.run, desired);
	}

	let mut events = Vec::new();
	// `state.desired` was set to the last-good document just above, so this
	// picks up the context of the configuration being reverted *to* -- which
	// is the point. A revert is the recovery path, and the worst place to
	// deliver a partial configuration is the one that runs after something has
	// already gone wrong.
	let Ok(mut executor) = state.executor() else {
		return (
			Response::error("cannot open a netlink socket to revert"),
			events,
		);
	};
	// Newest first: the inverses undo in the reverse of the order they were
	// applied, the way any stack of changes comes off. An address added after
	// a link was brought up has to go before the link goes down, or the
	// removal is aimed at something that is no longer there.
	let undo = std::mem::take(&mut state.undo);
	let mut undone = 0_usize;
	for op in undo.iter().rev() {
		match executor.execute(op) {
			Ok(()) => undone += 1,
			// Reported and stepped over rather than stopping the revert. The
			// remaining inverses are for other actions and are still worth
			// running, and the re-plan below is what covers whatever this one
			// failed to take back. Stopping here would leave a machine that is
			// neither the new configuration nor the old one, which is the one
			// outcome a revert exists to prevent.
			Err(error) => eprintln!("netcfgd: revert: undoing {} failed: {error}", op.name()),
		}
	}
	if !undo.is_empty() {
		eprintln!(
			"netcfgd: revert: undid {undone} of {} applied action(s)",
			undo.len()
		);
		// **The re-plan below has to see the machine the inverses left.**
		// Without this it plans against the observation taken before they ran
		// and re-issues work already done -- which the kernel then refuses,
		// because a route removed twice is gone the second time. Measured: a
		// revert that undid all five of its actions correctly went on to
		// report "revert incomplete: route.del failed: No such process", so a
		// clean revert announced itself as a broken one.
		state.reobserve();
	}

	let (_, journal) = state.apply(&PlanOptions::default(), &mut executor);
	let _ = run_state::update_owned(&state.paths.run, |owned| owned.absorb(&executor.effects));
	let _ = confirm::clear_window(&state.paths.run);
	state.reobserve();

	if let Some(failure) = journal.failure() {
		eprintln!(
			"netcfgd: revert incomplete: {} failed: {}",
			failure.op,
			failure.error.as_deref().unwrap_or("no detail")
		);
	}

	events.push(Event::ConfirmResolved { confirmed: false });
	(Response::Ok, events)
}

/// What to do about a window found at startup.
///
/// A daemon that died inside a window cannot have received a confirmation, so
/// the window is resolved by reverting whether or not the deadline has passed.
/// The alternative -- honouring the remaining time -- assumes the operator is
/// still there and still able to reach a socket that has been gone for however
/// long the daemon was down, which is exactly the assumption commit-confirm
/// exists because you cannot make.
pub(crate) fn resolve_on_startup(state: &mut State) -> Vec<Event> {
	if confirm::read_window(&state.paths.run).is_none() {
		return Vec::new();
	}
	eprintln!("netcfgd: a confirm window was open when this daemon started");
	let (_, events) = revert(state, "the daemon restarted inside the window");
	events
}

#[cfg(test)]
mod tests {
	use super::*;
	use netcfgd_apply::journal::Record;
	use netcfgd_plan::{Action, Reason};

	fn reason() -> Reason {
		Reason {
			interface: Some("e0".to_owned()),
			field: "mtu".to_owned(),
			desired: "1400".to_owned(),
			observed: "1500".to_owned(),
		}
	}

	fn action(id: u32, inverse: Option<Op>) -> Action {
		Action {
			id,
			op: Op::LinkSetMtu {
				name: "e0".to_owned(),
				mtu: 1400,
			},
			reason: reason(),
			depends_on: Vec::new(),
			inverse,
		}
	}

	fn mtu_inverse(mtu: u32) -> Op {
		Op::LinkSetMtu {
			name: "e0".to_owned(),
			mtu,
		}
	}

	fn record(id: u32, outcome: Outcome) -> Record {
		Record {
			id,
			op: "link.set_mtu".to_owned(),
			interface: Some("e0".to_owned()),
			reason: reason(),
			outcome,
			error: None,
		}
	}

	/// Only what reached the kernel, and only what declared an inverse.
	///
	/// The three rejections are the point rather than the acceptance. An
	/// action that failed or never ran has nothing to undo, and replaying its
	/// inverse would be netcfgd taking back a change it never made -- on a
	/// machine that is already in the state a revert exists to rescue.
	#[test]
	fn only_done_actions_with_an_inverse_are_undone() {
		let plan = Plan {
			actions: vec![
				action(0, Some(mtu_inverse(1500))),
				action(1, Some(mtu_inverse(1200))),
				action(2, Some(mtu_inverse(1100))),
				action(3, None),
			],
			..Plan::default()
		};
		let journal = Journal {
			records: vec![
				record(0, Outcome::Done),
				record(1, Outcome::Failed),
				record(2, Outcome::Skipped),
				record(3, Outcome::Done),
			],
		};

		// Action 0 alone: 1 failed, 2 never ran, 3 declares no inverse.
		assert_eq!(undo_from(&plan, &journal), vec![mtu_inverse(1500)]);
	}

	/// Plan order is preserved, because `revert` is what reverses it.
	///
	/// Asserted separately from the filtering above: a `undo_from` that
	/// happened to return its results reversed would leave `revert` applying
	/// them oldest-first, which is the wrong order and which no test of the
	/// filtering could see.
	#[test]
	fn the_list_is_in_plan_order() {
		let plan = Plan {
			actions: vec![
				action(0, Some(mtu_inverse(1500))),
				action(1, Some(mtu_inverse(1400))),
				action(2, Some(mtu_inverse(1300))),
			],
			..Plan::default()
		};
		let journal = Journal {
			records: vec![
				record(0, Outcome::Done),
				record(1, Outcome::Done),
				record(2, Outcome::Done),
			],
		};
		let undone: Vec<u32> = undo_from(&plan, &journal)
			.into_iter()
			.map(|op| match op {
				Op::LinkSetMtu { mtu, .. } => mtu,
				_ => 0,
			})
			.collect();
		assert_eq!(undone, vec![1500, 1400, 1300]);
	}
}
