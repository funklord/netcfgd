//! What happened, in a form somebody can read with `cat`.
//!
//! Written to `/run/netcfgd/plan.last.json`. This is the file that answers
//! "what did it actually do?" after an apply, and the reason it carries the
//! reason for each action as well as its outcome: an operator reading it after
//! a failure needs to know why the action existed, not only that it failed.

use netcfgd_plan::Reason;
use serde::{Deserialize, Serialize};

/// How one action ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
	/// It ran and the kernel accepted it.
	Done,
	/// It ran and failed. Execution stopped here.
	Failed,
	/// It never ran, because something before it failed.
	Skipped,
}

/// One line of the journal.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Record {
	/// The action's id in the plan.
	pub id: u32,
	/// Its op name, for example `addr.add`.
	pub op: String,
	/// Which interface it touched.
	#[serde(skip_serializing_if = "Option::is_none", default)]
	pub interface: Option<String>,
	/// Why the action existed.
	pub reason: Reason,
	/// How it ended.
	pub outcome: Outcome,
	/// What went wrong, for a failure.
	#[serde(skip_serializing_if = "Option::is_none", default)]
	pub error: Option<String>,
}

/// The record of one apply.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Journal {
	/// One entry per action in the plan, in plan order.
	pub records: Vec<Record>,
}

impl Journal {
	/// Append a record.
	pub fn push(&mut self, record: Record) {
		self.records.push(record);
	}

	/// Whether every action ran and succeeded.
	#[must_use]
	pub fn succeeded(&self) -> bool {
		self.records
			.iter()
			.all(|record| record.outcome == Outcome::Done)
	}

	/// The action that failed, if one did.
	#[must_use]
	pub fn failure(&self) -> Option<&Record> {
		self.records
			.iter()
			.find(|record| record.outcome == Outcome::Failed)
	}

	/// How many ran and succeeded.
	#[must_use]
	pub fn done(&self) -> usize {
		self.records
			.iter()
			.filter(|record| record.outcome == Outcome::Done)
			.count()
	}

	/// How many never ran.
	#[must_use]
	pub fn skipped(&self) -> usize {
		self.records
			.iter()
			.filter(|record| record.outcome == Outcome::Skipped)
			.count()
	}

	/// Render as JSON for `/run/netcfgd/plan.last.json`.
	///
	/// # Errors
	///
	/// Returns a serialisation error, which should not happen for these types
	/// and is reported rather than unwrapped so that a bug here cannot take
	/// down a daemon holding `CAP_NET_ADMIN`.
	pub fn to_json(&self) -> Result<String, String> {
		serde_json::to_string_pretty(self).map_err(|error| error.to_string())
	}
}
