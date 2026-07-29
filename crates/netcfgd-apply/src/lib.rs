#![forbid(unsafe_code)]

//! Executing a plan, and writing down what happened.
//!
//! Section 4's failure semantics, made concrete: execution stops at the first
//! failed action, progress is recorded with each action marked done, failed or
//! skipped, and the remainder is re-runnable. There is deliberately no
//! rollback on failure -- that is what commit-confirm is for, and conflating
//! the two produces behaviour nobody can predict from the outside.
//!
//! The [`Executor`] trait is what keeps this testable. The real one talks to
//! netlink; the one in the tests records calls and can be told to fail at a
//! chosen step, which is how the stop-and-resume behaviour is checked without
//! a network namespace.

pub mod hooks;
pub mod journal;
pub mod kernel;

pub use hooks::{HookEnv, Outcome as HookOutcome};
pub use journal::{Journal, Outcome, Record};
pub use kernel::KernelExecutor;

use netcfgd_plan::{Action, Op, Plan};

/// Something that can carry out one action.
///
/// Implemented by [`KernelExecutor`] against real netlink, and by a fake in
/// the tests. Everything about ordering, failure handling and journalling is
/// tested against the fake, so none of it needs privileges to exercise.
pub trait Executor {
	/// Carry out one action.
	///
	/// # Errors
	///
	/// Returns a human-readable message. It goes into the journal and in front
	/// of the operator, so it should name what failed rather than restating
	/// the action.
	fn execute(&mut self, op: &Op) -> Result<(), String>;
}

/// Run a plan.
///
/// Stops at the first failure. Every action after it is recorded as skipped
/// rather than dropped, because "what did not run" is the question an operator
/// asks next and a journal that omits it cannot answer.
pub fn apply(plan: &Plan, executor: &mut dyn Executor) -> Journal {
	let mut journal = Journal::default();
	let mut failed = false;

	for action in &plan.actions {
		if failed {
			journal.push(record(action, Outcome::Skipped, None));
			continue;
		}
		match executor.execute(&action.op) {
			Ok(()) => journal.push(record(action, Outcome::Done, None)),
			Err(message) => {
				failed = true;
				journal.push(record(action, Outcome::Failed, Some(message)));
			}
		}
	}

	journal
}

fn record(action: &Action, outcome: Outcome, error: Option<String>) -> Record {
	Record {
		id: action.id,
		op: action.op.name().to_owned(),
		interface: action.op.interface().map(ToOwned::to_owned),
		reason: action.reason.clone(),
		outcome,
		error,
	}
}
