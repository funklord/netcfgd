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
	/// have produced the carrier it wanted. See `doc/decision/0011`.
	///
	/// Use [`HookPhase::Up`] for anything that needs the link live and the
	/// interface still bare, and [`HookPhase::PostUp`] for anything needing an
	/// addressed device.
	///
	/// **Which phases this build runs is one list, in `netcfgd-plan`**, and it is
	/// not repeated here. This comment carried a count and an enumeration twice,
	/// and both went stale within a release: it sent the reader to `Up` and
	/// `Carrier` when neither fired, and then said "four phases fire" after the
	/// number had changed. A phase that does not fire is named by the plan, per
	/// phase and per interface, which is where an operator will see it.
	///
	/// **The up phases fire only when netcfgd is bringing the interface up.** They
	/// used to be emitted unconditionally, which ran them on every apply of an
	/// already-correct interface and on the apply that took a disabled one *down*
	/// (0063).
	PreUp,
	/// After the link is up and before anything is addressed.
	///
	/// The one moment of the three where the interface is live and bare: the
	/// kernel will answer for it -- carrier, speed, an `ethtool` setting that
	/// needs an up device -- and no address or route netcfgd is about to install
	/// exists yet. `pre_up` cannot see any of that (0011) and `post_up` is after
	/// the fact.
	///
	/// The addressing waits for it, which is what makes "before anything is
	/// addressed" a fact rather than a claim: a script here that has to be in
	/// place first -- a firewall rule, a VLAN filter, a driver knob -- is in place
	/// first. That also means a slow one delays the addresses, which is the price
	/// of the guarantee and is worth knowing before writing one. Decision 0076.
	Up,
	/// After the last addressing action for the interface completes.
	PostUp,
	/// Before anything about the interface is taken away.
	///
	/// The interface still works here -- addresses, routes, all of it -- which
	/// makes this the phase for a script that needs the network on its way out:
	/// unmounting a share, telling a peer, deregistering from something.
	///
	/// **This is where `down` used to be.** Until 0096 teardown was a single
	/// `link.down` with nothing before it, so `down` fired while the addresses
	/// were still there and this phase had no moment of its own to occupy
	/// (0063). Now netcfgd removes what it installed first, and the two are
	/// different points: a `down` hook that needs the network belongs here.
	///
	/// A veto phase: a failure stops the apply, so the interface does not go
	/// down.
	PreDown,
	/// Immediately before the link goes down, once its addresses are gone.
	///
	/// Not "during", which is not a moment a plan has: this runs before the
	/// `link.down` or the `link.delete` it belongs to, and **after** netcfgd has
	/// removed the addresses and routes it installed (0096). So the link is
	/// still up and the driver still answers, and nothing can be reached over
	/// it any more.
	///
	/// A script that needs the network is [`HookPhase::PreDown`], which is
	/// where this phase used to sit: before 0096 there was nothing between the
	/// two, so `down` fired with the addresses still present and its
	/// documentation said so.
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
	/// defers (`doc/decision/0011`).
	Carrier,
	/// A lease was acquired, renewed or lost.
	Lease,
	/// A station moved to a different access point on the same network.
	///
	/// Not a plan action and not netcfgd's decision: `wpa_supplicant` picks the
	/// access point, and netcfgd hears about it on the supplicant's event
	/// socket -- a `CONNECTED` naming a different address than the last one
	/// (0091). The first association after netcfgd starts is not a roam; there
	/// is nothing to have moved from.
	///
	/// `NCFG_BSSID` is the access point now in use and `NCFG_REASON` says it
	/// moved there. Not de-duplicated the way `drift` is: drift is a condition
	/// that persists, a roam is a thing that happened, and a station that moved
	/// back and forth moved twice.
	///
	/// Not a veto phase: the move has already happened.
	Roam,
	/// A captive portal was detected.
	Portal,
	/// Observed state stopped matching desired state.
	///
	/// The one phase that is **not** a plan action, and deliberately (0084):
	/// drift under `on_drift = "report"` applies nothing, so a planned hook
	/// would never run and the policy that exists to say "tell me, do not touch
	/// it" would tell nobody. It fires from the daemon at detection, before any
	/// reconcile, so the script sees what drifted rather than what netcfgd has
	/// already put back.
	///
	/// Fires when a drift *appears*, not while it persists -- under `report` it
	/// persists indefinitely, and firing on presence runs the script on every
	/// netlink event the machine sees.
	///
	/// `NCFG_REASON` is what moved; `NCFG_ACTION` is what netcfgd is doing about
	/// it, which is the only thing that differs between the policies. Not a veto
	/// phase: the drift has already happened.
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
	/// User to run as, dropped to before the script is executed: uid, primary
	/// gid and supplementary groups, in the order that makes the drop complete.
	///
	/// **Absent means the daemon's own user**, which is root. It used to say
	/// "the global default"; there is no globals key for it and never was, so
	/// that sentence described a mechanism that did not exist. Design section 9
	/// wants hooks to "run as a configurable user, not blindly as root" -- the
	/// runner honours this now, and what is still missing is a way for an
	/// operator to set it, which needs config grammar and a materialiser that
	/// writes the script somewhere the target user can read.
	#[serde(skip_serializing_if = "Option::is_none", default)]
	pub run_as: Option<String>,
	/// Timeout in seconds.
	#[serde(skip_serializing_if = "Option::is_none", default)]
	pub timeout: Option<u32>,
}
