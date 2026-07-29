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
	/// Use [`HookPhase::Up`] for anything needing an initialised device, and
	/// [`HookPhase::Carrier`] for anything reacting to a cable.
	PreUp,
	/// As the link comes up.
	Up,
	/// After the last addressing action for the interface completes.
	PostUp,
	/// Before the link goes down.
	PreDown,
	/// As the link goes down.
	Down,
	/// After the link is down.
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
