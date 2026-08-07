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
	/// The earliest the verdict may change again, where a dwell is configured.
	settled_until: Option<Instant>,
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

/// When a verdict that has just changed may change again.
fn dwell(policy: &ProbePolicy) -> Option<Instant> {
	(policy.hold_down > 0)
		.then(|| Instant::now() + Duration::from_secs(u64::from(policy.hold_down)))
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
			// A dwell suppresses the *change*, not the running: the program
			// keeps being asked, so the counts stay current and the moment the
			// dwell expires the verdict reflects what has been happening
			// rather than one stale result.
			let held = tally
				.settled_until
				.is_some_and(|until| Instant::now() < until);

			if succeeds(policy) {
				tally.failures = 0;
				tally.successes = tally.successes.saturating_add(1);
				if !held && tally.successes >= policy.up_after && tally.verdict != Some(true) {
					tally.verdict = Some(true);
					tally.settled_until = dwell(policy);
					changed = true;
				}
			} else {
				tally.successes = 0;
				tally.failures = tally.failures.saturating_add(1);
				if !held && tally.failures >= policy.down_after && tally.verdict != Some(false) {
					tally.verdict = Some(false);
					tally.settled_until = dwell(policy);
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

#[cfg(test)]
mod tests {
	use super::*;
	use netcfgd_testdir::TestDir;

	/// A probe that alternates: succeed, fail, succeed, fail.
	///
	/// A fixed `/bin/true` or `/bin/false` cannot exercise a dwell at all --
	/// the dwell only ever suppresses a *second* change, so a probe that never
	/// changes its mind would let a broken implementation pass. This is the
	/// flapping link the hold-down exists for, at the fastest period it can
	/// have.
	fn flapping(dir: &TestDir) -> String {
		let script = dir.join("flap.sh");
		std::fs::write(
			&script,
			"#!/bin/sh\nn=$(cat \"$0.n\" 2>/dev/null || echo 0)\n\
			 echo $((n + 1)) > \"$0.n\"\nexit $((n % 2))\n",
		)
		.unwrap();
		let mut mode = std::fs::metadata(&script).unwrap().permissions();
		std::os::unix::fs::PermissionsExt::set_mode(&mut mode, 0o755);
		std::fs::set_permissions(&script, mode).unwrap();
		script.to_str().unwrap().to_owned()
	}

	/// Built by compiling config text rather than by a struct literal, so the
	/// test also proves `hold_down` survives the lowering it was added to.
	fn document(command: &str, hold_down: u32) -> Document {
		let mut sources = netcfgd_compile::SourceMap::new();
		sources.add(
			"netcfgd.conf",
			format!(
				"interface eth0 {{\n\tpreference = 10\n\tprobe {{\n\
				 \t\tcommand = \"{command}\"\n\t\tinterval = 1\n\
				 \t\ttimeout = 5\n\t\tdown_after = 1\n\t\tup_after = 1\n\
				 \t\thold_down = {hold_down}\n\t}}\n}}\n"
			),
		);
		let document = netcfgd_compile::compile(&sources, &mut netcfgd_compile::NoHooks)
			.expect("the test config compiles");
		assert_eq!(
			document.interfaces[0]
				.probe
				.as_ref()
				.expect("the probe lowered")
				.hold_down,
			hold_down,
			"hold_down did not survive the compiler, so neither test below \
			 would be measuring a dwell"
		);
		document
	}

	/// Count how many times the verdict changes over six runs of a link that
	/// alternates on every single run.
	///
	/// Paced at the real interval rather than driven synthetically, because the
	/// compiler refuses `interval = 0` and a test that reached around it would
	/// be exercising a configuration nobody can write.
	fn changes(hold_down: u32) -> usize {
		let dir = TestDir::new("probe-dwell");
		let document = document(&flapping(&dir), hold_down);
		let mut probes = Probes::default();
		let mut changed = 0;
		for run in 0..6 {
			if run > 0 {
				std::thread::sleep(Duration::from_millis(1050));
			}
			if probes.run_due(Some(&document)) {
				changed += 1;
			}
		}
		changed
	}

	/// The counter-case, and the one that makes the other mean something: with
	/// no dwell this link moves the default route on every tick, which is
	/// precisely what 0119 left open.
	#[test]
	fn without_a_dwell_a_flapping_link_oscillates() {
		assert!(
			changes(0) >= 4,
			"a link alternating every run should change verdict nearly every \
			 run when no dwell is configured; if this stops being true the \
			 dwell test below is passing vacuously"
		);
	}

	/// And with one, it settles: the first verdict stands, and the rest of the
	/// flapping is absorbed.
	#[test]
	fn a_dwell_absorbs_the_flapping() {
		assert!(
			changes(60) <= 1,
			"a dwell longer than the test should let the verdict change once \
			 and then hold"
		);
	}
}
