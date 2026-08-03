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

	match command.status() {
		Ok(status) if status.success() => Outcome::Ok,
		Ok(status) => fail(hook.phase, format!("{} exited with {status}", hook.path)),
		Err(error) => fail(hook.phase, format!("could not run {}: {error}", hook.path)),
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
