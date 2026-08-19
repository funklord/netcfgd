//! Running hooks, with the contract design section 5.2 specifies.
//!
//! Three things it gets right that a naive `Command::new(path).status()` does
//! not: the environment is the documented one, the content hash is checked
//! before execution, and a failure means different things in different phases.

use netcfgd_model::{HookPhase, HookRef};
use std::collections::BTreeMap;
use std::process::Command;

/// What a hook is told.
///
/// Section 5.2 fixes these names, so they are a contract rather than an
/// implementation detail: a hook written against them keeps working.
#[derive(Debug, Clone, Default)]
pub struct HookEnv {
	/// Which interface.
	pub iface: String,
	/// Why it ran, for the event phases.
	pub reason: Option<String>,
	/// The address in play, where there is one.
	pub addr: Option<String>,
	/// The gateway, where there is one.
	pub gateway: Option<String>,
	/// Anything else, for phases that carry more.
	pub extra: BTreeMap<String, String>,
}

impl HookEnv {
	/// An environment for an interface.
	#[must_use]
	pub fn for_interface(iface: &str) -> Self {
		Self {
			iface: iface.to_owned(),
			..Self::default()
		}
	}

	/// Say why the hook is running.
	#[must_use]
	pub fn because(mut self, reason: impl Into<String>) -> Self {
		self.reason = Some(reason.into());
		self
	}

	/// One more variable, for a phase that carries more than a reason.
	///
	/// The named fields above are the ones several phases share. A phase with
	/// something of its own -- `drift` says what netcfgd is going to do about it,
	/// which no other phase has to answer -- puts it here rather than growing a
	/// field that every other phase would leave empty.
	#[must_use]
	pub fn with(mut self, key: &str, value: impl Into<String>) -> Self {
		self.extra.insert(key.to_owned(), value.into());
		self
	}
}

/// Whether a failure in this phase stops what is going on.
///
/// Section 5.2: "A non-zero exit from a `pre_*` hook **aborts** the
/// transition -- you can veto a bring-up. `post_*` and event hook failures are
/// logged, don't roll back."
///
/// That distinction is the whole reason this is a function rather than a
/// `status.success()` check at the call site. Treating a `post_up` failure as
/// fatal would stop a plan after the interface is already configured, leaving
/// the rest of the machine unconfigured because a logging script exited 1.
#[must_use]
pub fn is_veto_phase(phase: HookPhase) -> bool {
	matches!(
		phase,
		HookPhase::PreUp | HookPhase::PreDown | HookPhase::Up | HookPhase::Down
	)
}

/// What happened when a hook ran.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
	/// It ran and succeeded.
	Ok,
	/// It failed, and the phase says that vetoes the transition.
	Vetoed(String),
	/// It failed, and the phase says to carry on.
	Noted(String),
}

/// Run one hook.
///
/// # Errors
///
/// Never returns `Err`; the phase decides whether a failure is fatal, and the
/// caller decides what to do with an [`Outcome::Vetoed`].
#[must_use]
pub fn run(hook: &HookRef, env: &HookEnv) -> Outcome {
	// Section 2.2 records the content hash so drift detection can notice a
	// hook changing underneath the document that references it. Checking it
	// here makes that a control rather than a report: a hook file swapped
	// after the config was compiled does not run as root on the strength of
	// the old approval.
	match std::fs::read(&hook.path) {
		Ok(body) => {
			let actual = sha256_hex(&body);
			if actual != hook.sha256 {
				let message = format!(
					"{} has changed since the configuration was compiled \
					 (expected {}, found {}); not running it",
					hook.path,
					&hook.sha256[..hook.sha256.len().min(12)],
					&actual[..actual.len().min(12)]
				);
				return fail(hook.phase, message);
			}
		}
		Err(error) => return fail(hook.phase, format!("cannot read {}: {error}", hook.path)),
	}

	let mut command = Command::new(&hook.path);
	command
		.env("NCFG_IFACE", &env.iface)
		.env("NCFG_PHASE", hook.phase.name());
	if let Some(reason) = &env.reason {
		command.env("NCFG_REASON", reason);
	}
	if let Some(addr) = &env.addr {
		command.env("NCFG_ADDR", addr);
	}
	if let Some(gateway) = &env.gateway {
		command.env("NCFG_GW", gateway);
	}
	for (key, value) in &env.extra {
		command.env(key, value);
	}

	// Its own process group, so that killing it kills what it started. A hook
	// is a script: `sleep 300` in a `#!/bin/sh` file is a *grandchild*, and
	// signalling only the shell leaves it running and reparented to init.
	{
		use std::os::unix::process::CommandExt;
		command.process_group(0);
	}

	let mut child = match command.spawn() {
		Ok(child) => child,
		Err(error) => return fail(hook.phase, format!("could not run {}: {error}", hook.path)),
	};

	let limit = std::time::Duration::from_secs(u64::from(
		hook.timeout.unwrap_or(DEFAULT_TIMEOUT_SECONDS),
	));
	match wait_within(&mut child, limit) {
		Ended(Ok(status)) if status.success() => Outcome::Ok,
		Ended(Ok(status)) => fail(hook.phase, format!("{} exited with {status}", hook.path)),
		Ended(Err(error)) => fail(
			hook.phase,
			format!("could not wait for {}: {error}", hook.path),
		),
		TimedOut => fail(
			hook.phase,
			format!(
				"{} did not finish within {}s and was killed",
				hook.path,
				limit.as_secs()
			),
		),
	}
}

/// How long a hook may run when its own block does not say.
///
/// Sixty seconds because the honest slow cases are real: a `pre_up` that waits
/// for a peer, or a `post_up` bringing a tunnel to a far end, takes tens of
/// seconds and is not misbehaving. The number is a bound on damage rather than
/// a service-level target, and a hook that genuinely needs longer says so with
/// `timeout` in its own block rather than making every hook wait for it.
pub const DEFAULT_TIMEOUT_SECONDS: u32 = 60;

/// How long a killed hook gets between `SIGTERM` and `SIGKILL`.
const GRACE_SECONDS: u64 = 5;

/// How often the wait wakes to look. Small enough not to add meaningfully to a
/// hook's runtime, large enough not to spin.
const POLL: std::time::Duration = std::time::Duration::from_millis(20);

enum Waited {
	Ended(std::io::Result<std::process::ExitStatus>),
	TimedOut,
}
use Waited::{Ended, TimedOut};

/// Wait for a child, killing it if it outstays `limit`.
///
/// Polled rather than blocked on, because the wait has to be interruptible by
/// a clock and `std` offers no timed wait. The reconcile loop is single
/// threaded and calls this inline, so a hook that never exits used to stall
/// every request the daemon could otherwise answer -- `status` and `plan`
/// included, which is what an operator reaches for when the network stops.
///
/// `SIGTERM` first and `SIGKILL` only after a grace period, matching what
/// `netcfgd-sys::process::terminate` argues for everywhere else: a script that
/// traps `TERM` to tear down what it built deserves the chance to, and a
/// `SIGKILL` that arrives first is how a half-configured interface is left
/// behind.
fn wait_within(child: &mut std::process::Child, limit: std::time::Duration) -> Waited {
	if let Some(status) = poll_until(child, limit) {
		return status;
	}

	// `process_group(0)` made the child a group leader, so its pid is the
	// group id and the whole tree it started goes with it.
	let pgid = i32::try_from(child.id()).unwrap_or(-1);
	if pgid > 0 {
		let _ = netcfgd_sys::process::terminate_group(pgid);
	}
	if let Some(status) = poll_until(child, std::time::Duration::from_secs(GRACE_SECONDS)) {
		// The leader went on the TERM, which is the ordinary case. Still a
		// timeout as far as the caller is concerned: the hook did not finish
		// its work. The group is killed below regardless, because a leader
		// that exited says nothing about what it forked.
		let _ = status;
	}

	if pgid > 0 {
		let _ = netcfgd_sys::process::kill_group(pgid);
	}
	// Reaped so the child does not sit as a zombie for the life of the daemon.
	let _ = child.wait();
	TimedOut
}

/// Poll for exit until the deadline, or `None` if it is still running.
fn poll_until(child: &mut std::process::Child, limit: std::time::Duration) -> Option<Waited> {
	let deadline = std::time::Instant::now() + limit;
	loop {
		match child.try_wait() {
			Ok(Some(status)) => return Some(Ended(Ok(status))),
			Ok(None) => {}
			Err(error) => return Some(Ended(Err(error))),
		}
		if std::time::Instant::now() >= deadline {
			return None;
		}
		std::thread::sleep(POLL);
	}
}

fn fail(phase: HookPhase, message: String) -> Outcome {
	if is_veto_phase(phase) {
		Outcome::Vetoed(message)
	} else {
		Outcome::Noted(message)
	}
}

/// SHA-256, re-exported so callers need not reach past this crate.
pub use netcfgd_model::hash::sha256_hex;

#[cfg(test)]
mod tests {
	use super::*;
	use netcfgd_model::HookPhase;

	/// Write a hook script and the `HookRef` that names it.
	fn hook(dir: &netcfgd_testdir::TestDir, phase: HookPhase, body: &str, timeout: Option<u32>) -> HookRef {
		let path = dir.join("hook.sh");
		std::fs::write(&path, format!("#!/bin/sh\n{body}\n")).expect("written");
		#[cfg(unix)]
		{
			use std::os::unix::fs::PermissionsExt;
			std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700))
				.expect("made executable");
		}
		let body = std::fs::read(&path).expect("read back");
		HookRef {
			phase,
			path: path.display().to_string(),
			sha256: sha256_hex(&body),
			run_as: None,
			timeout,
		}
	}

	/// A hook that finishes inside its bound still succeeds.
	///
	/// The control for the two below: without it, a timeout that killed
	/// everything would look exactly like a timeout that worked.
	#[test]
	fn a_prompt_hook_still_succeeds() {
		let dir = netcfgd_testdir::TestDir::new("hook-prompt");
		let reference = hook(&dir, HookPhase::PostUp, "exit 0", Some(30));
		assert!(matches!(
			run(&reference, &HookEnv::for_interface("eth0")),
			Outcome::Ok
		));
	}

	/// A hook that never finishes is killed, and the phase decides what that
	/// means.
	///
	/// `pre_up` is a veto phase, so a hook that hangs stops the transition
	/// rather than letting it proceed unsupervised -- the same answer design
	/// section 5.2 gives for a non-zero exit, because a hook that never
	/// answered did not say yes.
	///
	/// The script traps nothing, so it dies on the `SIGTERM` and the grace
	/// period is never reached: this asserts the bound, not the `SIGKILL`.
	#[test]
	fn a_hook_that_hangs_is_killed_and_vetoes() {
		let dir = netcfgd_testdir::TestDir::new("hook-hangs");
		let reference = hook(&dir, HookPhase::PreUp, "sleep 300", Some(1));

		let started = std::time::Instant::now();
		let outcome = run(&reference, &HookEnv::for_interface("eth0"));
		let elapsed = started.elapsed();

		let Outcome::Vetoed(message) = outcome else {
			panic!("a hung pre_up hook must veto, got {outcome:?}");
		};
		assert!(
			message.contains("did not finish within 1s"),
			"the message must say what happened: {message}"
		);
		// Generous, because a loaded machine is slow; the point is that it
		// returned at all rather than waiting out the 300 second sleep.
		assert!(
			elapsed < std::time::Duration::from_secs(30),
			"the bound did not bind: waited {elapsed:?}"
		);
	}

	/// What the hook started dies with it.
	///
	/// This is the defect the first version of the timeout had, found by
	/// looking for orphans after a suite that reported success: a hook is a
	/// script, `sleep 300` inside it is a grandchild, and killing the shell
	/// left the sleep running and reparented to init. The daemon stopped
	/// waiting; the work it was waiting for carried on.
	///
	/// The child records its own child's pid, and this asserts that pid is
	/// gone afterwards -- by reading `/proc`, because `kill -0` calls a zombie
	/// alive and a reaped-by-init grandchild is exactly where that lies.
	#[test]
	fn a_hooks_own_children_are_killed_with_it() {
		let dir = netcfgd_testdir::TestDir::new("hook-grandchild");
		let pidfile = dir.join("child.pid");
		let reference = hook(
			&dir,
			HookPhase::PostUp,
			&format!("sleep 300 &\necho $! > {}\nwait", pidfile.display()),
			Some(1),
		);

		let outcome = run(&reference, &HookEnv::for_interface("eth0"));
		assert!(matches!(outcome, Outcome::Noted(_)), "expected a timeout");

		let recorded = std::fs::read_to_string(&pidfile).expect("the hook recorded its child");
		let pid: i32 = recorded.trim().parse().expect("a pid");

		// The group signal is delivered before `run` returns, but the kernel
		// reaping is not instantaneous. Poll briefly rather than assert once.
		let mut alive = true;
		for _ in 0..200 {
			let cmdline = std::fs::read(format!("/proc/{pid}/cmdline")).unwrap_or_default();
			if cmdline.is_empty() {
				alive = false;
				break;
			}
			std::thread::sleep(std::time::Duration::from_millis(10));
		}
		assert!(
			!alive,
			"the hook's child {pid} outlived the hook, so the bound freed the daemon and not the machine"
		);
	}

	/// The same hang in a non-veto phase is noted rather than fatal.
	///
	/// Section 5.2 again: a `post_up` failure is logged and does not roll back.
	/// A timeout is a failure, so it follows the phase like any other.
	#[test]
	fn a_hang_after_the_transition_is_noted_not_fatal() {
		let dir = netcfgd_testdir::TestDir::new("hook-hangs-post");
		let reference = hook(&dir, HookPhase::PostUp, "sleep 300", Some(1));
		assert!(matches!(
			run(&reference, &HookEnv::for_interface("eth0")),
			Outcome::Noted(_)
		));
	}
}
