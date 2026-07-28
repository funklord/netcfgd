//! Hook references. The document never carries shell.

use serde::{Deserialize, Serialize};

/// When a hook runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HookPhase {
	/// Before the link comes up.
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
