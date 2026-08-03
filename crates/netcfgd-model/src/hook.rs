//! Hook references. The document never carries shell.

use serde::{Deserialize, Serialize};

/// When a hook runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HookPhase {
	/// Before the link comes up.
	///
	/// The interface is **down** when this runs, which is a constraint and not
	/// only an ordering: the kernel returns `EINVAL` for
	/// `/sys/class/net/*/carrier` on a down interface, so a hook here cannot
	/// discover whether a cable is plugged in. `mii-tool` and `ethtool` fail
	/// for the same reason.
	///
	/// This is where netcfgd differs from netifrc, which runs `up; preup; up`
	/// precisely so that its `preup` can check link. A netifrc `preup` that
	/// aborts on "no link" deadlocks here: it refuses the bring-up that would
	/// have produced the carrier it wanted. See `docs/decisions/0011`.
	///
	/// Use [`HookPhase::PostUp`] for anything needing an addressed device.
	///
	/// This comment used to send the reader to [`HookPhase::Up`] and
	/// [`HookPhase::Carrier`], neither of which this build runs. Four phases fire
	/// now -- `pre_up`, `post_up`, `down` and `post_down` -- and the other seven
	/// are recognised, materialised into `/run/netcfgd/hooks/` and hashed, and
	/// never executed; a plan says so per phase rather than leaving the script
	/// looking installed.
	///
	/// **The up phases fire only when netcfgd is bringing the interface up.** They
	/// used to be emitted unconditionally, which ran them on every apply of an
	/// already-correct interface and on the apply that took a disabled one *down*
	/// (0063).
	PreUp,
	/// As the link comes up.
	Up,
	/// After the last addressing action for the interface completes.
	PostUp,
	/// Before the link goes down. **Recognised and not run by this build**, unlike
	/// [`HookPhase::Down`], which is: the two would fire at the same point in a
	/// plan, and a phase whose only distinction is "before the addresses go" needs
	/// a teardown ordering netcfgd does not have yet. A plan says so (0063).
	PreDown,
	/// Immediately before the link goes down, while it still works.
	///
	/// Not "during", which is not a moment a plan has: this runs before the
	/// `link.down` or the `link.delete` it belongs to, and the interface still has
	/// its addresses and routes at that point -- teardown is the last thing in a
	/// plan. That is what lets a `down` hook unmount a share or stop a service
	/// that is using them.
	///
	/// A veto phase: a failure stops the apply, so the transition it brackets does
	/// not happen. A guard on the interface refuses this hook along with the
	/// transition, for the same reason -- a `down` script that runs when nothing
	/// goes down has already unmounted the share (0063).
	Down,
	/// After the link is down.
	///
	/// Runs whether or not anything else in the plan succeeds after it, and is not
	/// a veto phase: there is nothing left to stop.
	PostDown,
	/// Carrier gained or lost.
	///
	/// Where a link-state check belongs. Note that netcfgd does not currently
	/// gate addressing on carrier -- it brings a link up and addresses it
	/// whether or not a cable is present -- so this reports rather than
	/// defers (`docs/decisions/0011`).
	Carrier,
	/// A lease was acquired, renewed or lost.
	Lease,
	/// A wifi roam completed.
	Roam,
	/// A captive portal was detected.
	Portal,
	/// Observed state stopped matching desired state.
	Drift,
}

impl HookPhase {
	/// The name the config spells it with, and the value of `NCFG_PHASE`.
	///
	/// One table rather than the two this used to be -- `netcfgd-apply` needed it
	/// for the environment and `netcfgd-host` for the materialised filename, and
	/// each had its own copy. The names reach a script and a filename, so a
	/// spelling that drifted between the two would be an operator's hook that
	/// runs with an environment naming a phase their file is not named after.
	#[must_use]
	pub fn name(self) -> &'static str {
		match self {
			Self::PreUp => "pre_up",
			Self::Up => "up",
			Self::PostUp => "post_up",
			Self::PreDown => "pre_down",
			Self::Down => "down",
			Self::PostDown => "post_down",
			Self::Carrier => "carrier",
			Self::Lease => "lease",
			Self::Roam => "roam",
			Self::Portal => "portal",
			Self::Drift => "drift",
		}
	}
}

/// A reference to a hook script on disk.
///
/// The DSL lets an author write inline shell in a `post_up { ... }` block; the
/// compiler materialises those blocks into files under `/run/netcfgd/hooks/`
/// and the document carries only this reference. A document that could carry
/// shell would be remote code execution with extra steps, and this closes that
/// structurally rather than by policy.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HookRef {
	/// Which phase this runs in.
	pub phase: HookPhase,
	/// Absolute path to the script.
	pub path: String,
	/// Content hash at compile time, so drift detection can notice that a
	/// hook changed underneath the document that references it.
	pub sha256: String,
	/// User to run as. Absent means the global default.
	#[serde(skip_serializing_if = "Option::is_none", default)]
	pub run_as: Option<String>,
	/// Timeout in seconds.
	#[serde(skip_serializing_if = "Option::is_none", default)]
	pub timeout: Option<u32>,
}
