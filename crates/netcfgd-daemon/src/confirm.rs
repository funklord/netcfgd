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
use netcfgd_host::{confirm, state as run_state};
use netcfgd_model::Document;
use netcfgd_plan::PlanOptions;
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

/// Keep the change.
pub(crate) fn confirm_window(state: &mut State) -> (Response, Option<Event>) {
	if confirm::read_window(&state.paths.run).is_none() {
		return (Response::error("no confirm window is open"), None);
	}
	let _ = confirm::clear_window(&state.paths.run);
	// The change stood, so it becomes what a future revert falls back to.
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
/// Reverting re-plans against the saved document rather than replaying the
/// inverses of what was applied. Design section 4.5 asks for "the last-good
/// desired state", and re-planning gets there from wherever the machine
/// actually is -- including from a half-applied plan that stopped at a
/// failure, which replaying inverses would not handle. Nothing here needs the
/// network: the target document is on disk and the current state comes from
/// netlink.
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
	let (_, journal) = state.apply(&PlanOptions::default(), &mut executor);
	let mut owned = run_state::read_owned(&state.paths.run);
	owned.absorb(&executor.effects);
	let _ = run_state::write_owned(&state.paths.run, &owned);
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
