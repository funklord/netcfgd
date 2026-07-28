//! Section 4's failure semantics, against a fake executor.
//!
//! None of this needs a kernel, privileges or a namespace, which is the point:
//! stop-at-first-failure and the journal are policy, and policy should be
//! testable without hardware.

use netcfgd_apply::{apply, Executor, Journal, Outcome};
use netcfgd_model::route::NETCFGD_PROTO;
use netcfgd_plan::{Action, Op, Plan, Reason};

/// Records what it was asked to do, and can be told to fail at one step.
#[derive(Default)]
struct FakeExecutor {
	seen: Vec<String>,
	fail_at: Option<usize>,
}

impl Executor for FakeExecutor {
	fn execute(&mut self, op: &Op) -> Result<(), String> {
		let index = self.seen.len();
		self.seen.push(op.name().to_owned());
		if self.fail_at == Some(index) {
			return Err(format!("{} refused by the kernel", op.name()));
		}
		Ok(())
	}
}

fn action(id: u32, op: Op) -> Action {
	Action {
		id,
		reason: Reason::absent("eth0", "test", "value"),
		op,
		depends_on: Vec::new(),
		inverse: None,
	}
}

fn sample_plan() -> Plan {
	Plan {
		actions: vec![
			action(
				0,
				Op::LinkUp {
					name: "eth0".to_owned(),
				},
			),
			action(
				1,
				Op::AddrAdd {
					iface: "eth0".to_owned(),
					addr: "10.0.0.1/24".to_owned(),
					preferred_lifetime: None,
					valid_lifetime: None,
				},
			),
			action(
				2,
				Op::RouteAdd {
					iface: "eth0".to_owned(),
					route: Box::new(netcfgd_model::Route {
						destination: "default".to_owned(),
						via: Some("10.0.0.254".parse().unwrap()),
						metric: None,
						table: None,
						src: None,
						scope: None,
						onlink: false,
						proto: Some(NETCFGD_PROTO),
					}),
				},
			),
		],
		warnings: Vec::new(),
	}
}

#[test]
fn a_plan_that_succeeds_records_every_action_done() {
	let mut executor = FakeExecutor::default();
	let journal = apply(&sample_plan(), &mut executor);

	assert!(journal.succeeded());
	assert_eq!(journal.done(), 3);
	assert_eq!(journal.skipped(), 0);
	assert_eq!(executor.seen, ["link.up", "addr.add", "route.add"]);
}

/// Execution stops at the first failure. Everything after it is recorded as
/// skipped rather than dropped, because "what did not run" is the next
/// question an operator asks and a journal that omits it cannot answer.
#[test]
fn execution_stops_at_the_first_failure_and_records_the_rest() {
	let mut executor = FakeExecutor {
		fail_at: Some(1),
		..FakeExecutor::default()
	};
	let journal = apply(&sample_plan(), &mut executor);

	assert!(!journal.succeeded());
	assert_eq!(journal.done(), 1);
	assert_eq!(journal.skipped(), 1);

	// The route was never attempted, not merely unrecorded.
	assert_eq!(executor.seen, ["link.up", "addr.add"]);

	let failure = journal.failure().expect("a failure is recorded");
	assert_eq!(failure.op, "addr.add");
	assert_eq!(failure.outcome, Outcome::Failed);
	assert!(failure
		.error
		.as_deref()
		.is_some_and(|message| message.contains("refused")));

	let last = journal.records.last().expect("three records");
	assert_eq!(last.op, "route.add");
	assert_eq!(last.outcome, Outcome::Skipped);
	assert!(last.error.is_none());
}

/// There is no rollback on failure. That is what commit-confirm is for, and
/// conflating the two produces behaviour nobody can predict from outside.
#[test]
fn a_failure_does_not_undo_what_already_succeeded() {
	let mut executor = FakeExecutor {
		fail_at: Some(1),
		..FakeExecutor::default()
	};
	apply(&sample_plan(), &mut executor);

	assert!(
		!executor
			.seen
			.iter()
			.any(|op| op.contains(".del") || op == "link.down" || op.contains(".stop")),
		"nothing should have been undone: {:?}",
		executor.seen
	);
}

/// An empty plan is the normal case on a correct system, and must not produce
/// a journal that looks like a failure.
#[test]
fn an_empty_plan_produces_an_empty_journal_that_counts_as_success() {
	let mut executor = FakeExecutor::default();
	let journal = apply(&Plan::default(), &mut executor);

	assert!(journal.succeeded());
	assert!(journal.records.is_empty());
	assert!(journal.failure().is_none());
	assert!(executor.seen.is_empty());
}

/// The journal carries the reason each action existed, not only its outcome.
/// After a failure an operator needs to know why the action was there.
#[test]
fn the_journal_keeps_the_reason_for_each_action() {
	let mut executor = FakeExecutor::default();
	let journal = apply(&sample_plan(), &mut executor);

	for record in &journal.records {
		assert_eq!(record.reason.field, "test");
		assert_eq!(record.interface.as_deref(), Some("eth0"));
	}
}

/// It round-trips through the form written to /run/netcfgd/plan.last.json.
#[test]
fn the_journal_round_trips_through_json() {
	let mut executor = FakeExecutor {
		fail_at: Some(2),
		..FakeExecutor::default()
	};
	let journal = apply(&sample_plan(), &mut executor);

	let text = journal.to_json().expect("serialises");
	let back: Journal = serde_json::from_str(&text).expect("parses");
	assert_eq!(journal, back);
	assert!(text.contains("\"outcome\": \"failed\""));
}
