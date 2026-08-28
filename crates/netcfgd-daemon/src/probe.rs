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
//! [0119]: ../../../doc/decision/0119-a-probe-is-an-observation-and-a-failing-uplink-loses-its-routes.md

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
	/// Consecutive failures to *start* the program.
	///
	/// Separate from `failures`, which counts a program that ran and said no.
	/// The two mean different things and only one of them is about the link.
	start_failures: u32,
	/// Set aside: the program could not be started enough times running that
	/// asking again is not going to help.
	blacklisted: bool,
	/// What the program last said, or why it was set aside.
	detail: Option<String>,
}

/// Every interface's tally, across ticks.
#[derive(Debug, Default)]
pub(crate) struct Probes {
	tallies: HashMap<String, Tally>,
}

/// How many consecutive failures to *start* a probe before it is set aside.
///
/// Only start failures count. A program that runs and exits non-zero is the
/// feature working -- that is a link that is down -- and no number of those
/// ever sets a probe aside.
const START_FAILURES_BEFORE_BLACKLIST: u32 = 5;

/// The most of a probe's standard error that is kept.
///
/// It crosses the socket to every client, and a script can write without end.
/// The tail rather than the head: a shell script's last words are the ones
/// about the thing that just failed.
const DETAIL_MAX: usize = 400;

/// What one run of a probe did.
struct Outcome {
	/// Whether the program ran and exited zero.
	ok: bool,
	/// Whether it ran at all. A program that could not be started says nothing
	/// about the link, which is a different fact from one that ran and failed.
	started: bool,
	/// Its standard error, tail-trimmed, or the reason it could not be run.
	detail: Option<String>,
}

/// Keep the last `DETAIL_MAX` bytes, on a character boundary, one line.
fn trim_detail(text: &str) -> Option<String> {
	let text = text.trim();
	if text.is_empty() {
		return None;
	}
	// The last non-empty line: a program that printed a banner and then an
	// error should report the error.
	let last = text.lines().rev().find(|line| !line.trim().is_empty())?;
	let last = last.trim();
	if last.len() <= DETAIL_MAX {
		return Some(last.to_owned());
	}
	let mut cut = last.len() - DETAIL_MAX;
	while cut < last.len() && !last.is_char_boundary(cut) {
		cut += 1;
	}
	Some(format!("...{}", &last[cut..]))
}

/// Run one probe and say what happened.
///
/// The timeout is enforced here rather than trusted to the program, because a
/// probe that hangs is the failure mode a probe is for: a `curl` against a
/// black hole does not exit, and a runner that waited would stop asking about
/// every other interface too.
///
/// **Standard error is kept, where it used to go to `/dev/null`.** An exit
/// status says the link does not work and nothing about why, so the one thing
/// the program had to say about it was being discarded -- and a probe nobody
/// can debug is one that gets deleted rather than fixed.
fn run(policy: &ProbePolicy) -> Outcome {
	// A probe that cannot be started is a probe that is not answering yes.
	// Treated as a failure rather than as an absence, because the alternative
	// is a typo in `command` quietly meaning "always up" -- but counted
	// separately, so a script that can never run is set aside rather than
	// withholding an interface's routes for ever on no information.
	let child = Command::new(&policy.command)
		.args(&policy.args)
		.stdin(Stdio::null())
		.stdout(Stdio::null())
		.stderr(Stdio::piped())
		.spawn();
	let mut child = match child {
		Ok(child) => child,
		Err(error) => {
			return Outcome {
				ok: false,
				started: false,
				detail: Some(format!("cannot run {}: {error}", policy.command)),
			};
		}
	};

	let deadline = Instant::now() + Duration::from_secs(u64::from(policy.timeout));
	loop {
		match child.try_wait() {
			Ok(Some(status)) => {
				let mut said = String::new();
				if let Some(mut pipe) = child.stderr.take() {
					use std::io::Read;
					let mut raw = Vec::new();
					let _ = pipe.read_to_end(&mut raw);
					said = String::from_utf8_lossy(&raw).into_owned();
				}
				return Outcome {
					ok: status.success(),
					started: true,
					detail: trim_detail(&said),
				};
			}
			Ok(None) => {}
			Err(error) => {
				return Outcome {
					ok: false,
					started: true,
					detail: Some(format!("cannot wait for the probe: {error}")),
				};
			}
		}
		if Instant::now() >= deadline {
			let _ = child.kill();
			let _ = child.wait();
			// A hanging probe is a failing link rather than a broken script:
			// it started, so it is answering, just not in time. Timing out for
			// ever must not set it aside -- that is exactly the black hole
			// 0119 is about.
			return Outcome {
				ok: false,
				started: true,
				detail: Some(format!(
					"no answer within {}s, so it was killed",
					policy.timeout
				)),
			};
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
			// Set aside stays set aside until the configuration changes, which
			// drops the tally entirely. Re-trying a command that does not
			// exist, every interval, for ever, is noise rather than
			// resilience.
			if tally.blacklisted {
				continue;
			}

			let held = tally
				.settled_until
				.is_some_and(|until| Instant::now() < until);

			let outcome = run(policy);
			tally.detail = outcome.detail;

			// **A program that cannot be started says nothing about the
			// link.** Counted apart, and after enough of them the probe is set
			// aside and its verdict cleared rather than left at `false`:
			// withholding an interface's routes for ever because of a typo in
			// `command` is how a probe takes a machine off the network and
			// keeps it there. The verdict going back to `None` means "nobody
			// asked", which is what a probe that never ran amounts to -- and
			// it is loud rather than quiet, which is the half the original
			// concern was really about.
			if !outcome.started {
				tally.start_failures = tally.start_failures.saturating_add(1);
				if tally.start_failures >= START_FAILURES_BEFORE_BLACKLIST {
					tally.blacklisted = true;
					tally.detail = Some(format!(
						"set aside after {} attempts: {}",
						tally.start_failures,
						tally.detail.as_deref().unwrap_or("it could not be started")
					));
					if tally.verdict.is_some() {
						tally.verdict = None;
						changed = true;
					}
				}
				continue;
			}
			tally.start_failures = 0;

			if outcome.ok {
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
				link.probe_detail = tally.detail.clone();
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

#[cfg(test)]
mod probe_detail_tests {
	use super::*;
	use netcfgd_testdir::TestDir;

	/// A link the way the model requires one.
	///
	/// `ObservedLink` has no `Default` and 31 fields, most of them answers
	/// rather than absences, so this spells out the ones that matter here and
	/// leaves the rest empty.
	fn link_named(name: &str) -> netcfgd_model::ObservedLink {
		netcfgd_model::ObservedLink {
			name: name.to_owned(),
			index: 2,
			kind: String::new(),
			wireless: false,
			up: true,
			carrier: true,
			reachable: None,
			probe_detail: None,
			mtu: 1500,
			mac: None,
			master: None,
			parent: None,
			offloads: Vec::new(),
			ipv6_token: None,
			qdisc: None,
			qdisc_bandwidth_bits: None,
			qdisc_ingress: false,
			ingress_redirect: None,
			forwarding: None,
			rfkill: None,
			privacy: None,
			accept_ra: None,
			ownership: netcfgd_model::Ownership::Foreign,
			private_key_loaded: false,
			bond: None,
			bridge: None,
			macvlan: None,
			vlan: None,
			tunnel: None,
			vxlan: None,
			wireguard: None,
		}
	}

	fn document_for(command: &str) -> Document {
		let mut sources = netcfgd_compile::SourceMap::new();
		sources.add(
			"netcfgd.conf",
			format!(
				"interface eth0 {{\n\tpreference = 10\n\tprobe {{\n\
				 \t\tcommand = \"{command}\"\n\t\tinterval = 1\n\
				 \t\ttimeout = 5\n\t\tdown_after = 1\n\t\tup_after = 1\n\t}}\n}}\n"
			),
		);
		netcfgd_compile::compile(&sources, &mut netcfgd_compile::NoHooks)
			.expect("the test config compiles")
	}

	/// **A failing probe says why, in the program's own words.**
	///
	/// The exit status says the link does not work and nothing about why not,
	/// and standard error used to go to `/dev/null` -- so the one thing the
	/// program had to say about it was discarded. A probe nobody can debug is
	/// one that gets deleted rather than fixed.
	#[test]
	fn a_failing_probe_reports_what_it_printed() {
		let dir = TestDir::new("probe-detail");
		let script = dir.join("noisy.sh");
		std::fs::write(
			&script,
			"#!/bin/sh\necho 'ping: connect: Network is unreachable' >&2\nexit 1\n",
		)
		.expect("write");
		let mut permissions = std::fs::metadata(&script).expect("stat").permissions();
		std::os::unix::fs::PermissionsExt::set_mode(&mut permissions, 0o755);
		std::fs::set_permissions(&script, permissions).expect("chmod");

		let document = document_for(&script.to_string_lossy());
		let mut probes = Probes::default();
		probes.run_due(Some(&document));

		let mut observed = Observed::default();
		observed.links.push(link_named("eth0"));
		probes.apply(&mut observed);

		assert_eq!(
			observed.links[0].reachable,
			Some(false),
			"it ran and said no"
		);
		assert_eq!(
			observed.links[0].probe_detail.as_deref(),
			Some("ping: connect: Network is unreachable"),
			"what it printed reaches the observation"
		);
	}

	/// **A program that cannot be started is set aside, not left withholding
	/// routes for ever.**
	///
	/// It says nothing about the link, so a verdict of `false` would be an
	/// answer to a question nobody managed to ask -- and a typo in `command`
	/// would take an interface off the network and keep it there. Loudly:
	/// `probe_detail` names the count and the reason, which is the half the
	/// original "a typo quietly meaning always up" concern was about.
	#[test]
	fn a_probe_that_cannot_run_is_set_aside_with_a_reason() {
		let document = document_for("/nonexistent/probe");
		let mut probes = Probes::default();

		// One short of the limit: still trying, and no verdict has been
		// reached because nothing ever ran.
		for _ in 0..(START_FAILURES_BEFORE_BLACKLIST - 1) {
			probes.run_due(Some(&document));
			std::thread::sleep(Duration::from_millis(1100));
		}
		let mut observed = Observed::default();
		observed.links.push(link_named("eth0"));
		probes.apply(&mut observed);
		assert!(
			observed.links[0]
				.probe_detail
				.as_deref()
				.is_some_and(|said| said.contains("cannot run")),
			"it says what went wrong before giving up: {:?}",
			observed.links[0].probe_detail
		);
		assert!(
			!observed.links[0]
				.probe_detail
				.as_deref()
				.is_some_and(|said| said.contains("set aside")),
			"and has not given up yet"
		);

		probes.run_due(Some(&document));
		let mut observed = Observed::default();
		observed.links.push(link_named("eth0"));
		probes.apply(&mut observed);
		assert_eq!(
			observed.links[0].reachable, None,
			"a probe that never ran leaves the link unjudged rather than down"
		);
		assert!(
			observed.links[0]
				.probe_detail
				.as_deref()
				.is_some_and(|said| said.contains("set aside")),
			"and says so: {:?}",
			observed.links[0].probe_detail
		);
	}
}
