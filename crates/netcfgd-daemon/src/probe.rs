//! Asking an uplink whether it actually carries traffic.
//!
//! [0119]: a probe is an *observation*. It runs a program the operator named,
//! takes its exit status as the answer, and the verdict joins observed state
//! beside carrier -- where the planner already knows what to do with a link
//! that is not carrying anything.
//!
//! **The verdict lives here and not in the observation**, because the observer
//! reads the kernel and no probe result comes from there. `reobserve` builds a
//! fresh `Observed` every time, so a verdict written into one would be gone on
//! the next tick; this keeps the tally across ticks and stamps it on.
//!
//! [0119]: ../../../docs/decisions/0119-a-probe-is-an-observation-and-a-failing-uplink-loses-its-routes.md

use netcfgd_model::{Document, Observed, ProbePolicy};
use std::collections::HashMap;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

/// What one interface's probe has been saying.
#[derive(Debug, Default)]
struct Tally {
	/// Consecutive results in the current direction.
	successes: u32,
	failures: u32,
	/// What netcfgd currently believes, once enough results agree.
	///
	/// `None` until the first run finishes, which is why an interface that has
	/// just been configured keeps its routes rather than losing them for the
	/// length of one interval.
	verdict: Option<bool>,
	/// When to run again.
	due: Option<Instant>,
}

/// Every interface's tally, across ticks.
#[derive(Debug, Default)]
pub(crate) struct Probes {
	tallies: HashMap<String, Tally>,
}

/// Run one probe and say whether it succeeded.
///
/// The timeout is enforced here rather than trusted to the program, because a
/// probe that hangs is the failure mode a probe is for: a `curl` against a
/// black hole does not exit, and a runner that waited would stop asking about
/// every other interface too.
fn succeeds(policy: &ProbePolicy) -> bool {
	// A probe that cannot be started is a probe that is not answering yes.
	// Treated as a failure rather than as an absence, because the alternative
	// is a typo in `command` quietly meaning "always up".
	let Ok(mut child) = Command::new(&policy.command)
		.args(&policy.args)
		.stdin(Stdio::null())
		.stdout(Stdio::null())
		.stderr(Stdio::null())
		.spawn()
	else {
		return false;
	};

	let deadline = Instant::now() + Duration::from_secs(u64::from(policy.timeout));
	loop {
		match child.try_wait() {
			Ok(Some(status)) => return status.success(),
			Ok(None) => {}
			Err(_) => return false,
		}
		if Instant::now() >= deadline {
			let _ = child.kill();
			let _ = child.wait();
			return false;
		}
		std::thread::sleep(Duration::from_millis(50));
	}
}

impl Probes {
	/// Run whatever is due, and say whether any verdict changed.
	///
	/// A changed verdict is what the caller needs, because it is the only
	/// reason to re-plan: a probe that agrees with itself for an hour should
	/// cost nothing but the program it runs.
	pub(crate) fn run_due(&mut self, desired: Option<&Document>) -> bool {
		let Some(document) = desired else {
			self.tallies.clear();
			return false;
		};

		let mut changed = false;
		let now = Instant::now();

		for interface in &document.interfaces {
			let Some(policy) = &interface.probe else {
				continue;
			};
			let tally = self.tallies.entry(interface.name.clone()).or_default();
			if tally.due.is_some_and(|due| now < due) {
				continue;
			}
			tally.due = Some(now + Duration::from_secs(u64::from(policy.interval)));

			// Counted as consecutive runs in one direction: a success resets
			// the failure run and the other way about. Hysteresis is the whole
			// feature, and a tally that let them accumulate independently
			// would flip on a link that alternated.
			if succeeds(policy) {
				tally.failures = 0;
				tally.successes = tally.successes.saturating_add(1);
				if tally.successes >= policy.up_after && tally.verdict != Some(true) {
					tally.verdict = Some(true);
					changed = true;
				}
			} else {
				tally.successes = 0;
				tally.failures = tally.failures.saturating_add(1);
				if tally.failures >= policy.down_after && tally.verdict != Some(false) {
					tally.verdict = Some(false);
					changed = true;
				}
			}
		}

		// An interface whose probe was removed from the config stops having a
		// verdict, rather than keeping the last one for ever.
		let configured: Vec<String> = document
			.interfaces
			.iter()
			.filter(|interface| interface.probe.is_some())
			.map(|interface| interface.name.clone())
			.collect();
		let before = self.tallies.len();
		self.tallies.retain(|name, _| configured.contains(name));
		changed || self.tallies.len() != before
	}

	/// Stamp the verdicts onto a fresh observation.
	///
	/// Only a decided verdict is written. A link with no probe, or one whose
	/// probe has not yet agreed with itself enough times, is left `None` --
	/// and the planner treats `None` as "nobody asked", which is what stops
	/// this taking the network away from a machine that configured no probes.
	pub(crate) fn apply(&self, observed: &mut Observed) {
		for link in &mut observed.links {
			if let Some(tally) = self.tallies.get(&link.name) {
				link.reachable = tally.verdict;
			}
		}
	}
}
