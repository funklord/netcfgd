//! Routes, and the protocol tag that marks one as ours.

use serde::{Deserialize, Serialize};
use std::net::IpAddr;

/// The `rtm_protocol` value netcfgd stamps on every route it installs, and the
/// `IFA_PROTO` value it stamps on every address.
///
/// 110 sits mid-gap in the 100..=185 run, the largest unallocated range in
/// `linux/rtnetlink.h`, which is the de facto registry. Anything not carrying
/// this tag is somebody else's object and is reported as foreign rather than
/// reconciled away (`docs/decisions/0002`).
///
/// Changing this orphans every route already installed, so it is not an
/// ordinary knob.
pub const NETCFGD_PROTO: u8 = 110;

/// The prefix on the alternative name netcfgd gives every link it creates.
///
/// A link has no protocol field, so [`NETCFGD_PROTO`] has nothing to stamp
/// and link ownership was the one kind that lived only in `/run` -- lost on
/// every restart, per decision 0136. An alternative name is the kernel-held
/// marker that field would have been.
///
/// **The full name is this prefix and the link's name at creation**, because
/// alternative names share the lookup namespace with real ones and a constant
/// would collide the moment netcfgd created a second link. Keeping the
/// original name in it also records what netcfgd made the link *as*, which
/// survives a later rename.
///
/// A colon, matching `@secret:` elsewhere in this project, and verified
/// against the kernel rather than assumed: `dev_valid_name` was expected to
/// reject one and does not.
pub const NETCFGD_ALTNAME_PREFIX: &str = "netcfgd:";

/// The alternative name netcfgd marks a link it creates with.
///
/// Returns `None` where the result would not fit `ALTIFNAMSIZ`, which cannot
/// happen for a name the kernel already accepted as an interface name -- 8
/// bytes of prefix and at most 15 of name against a limit of 128 -- but is
/// checked rather than reasoned about, because the caller treats a marker it
/// cannot write as non-fatal and should treat one it cannot build the same way.
#[must_use]
pub fn netcfgd_altname(link: &str) -> Option<String> {
	let name = format!("{NETCFGD_ALTNAME_PREFIX}{link}");
	(!link.is_empty() && name.len() < 128).then_some(name)
}

/// `RT_TABLE_MAIN`: the table a route goes into when the config names none.
///
/// The kernel always reports a table, so an absent `table` in the desired
/// state and a reported 254 in the observed state are the same table. Anything
/// comparing the two has to normalise through this constant or every
/// unqualified route looks absent and gets reinstalled on every run.
pub const MAIN_TABLE: u32 = 254;

/// Route scope.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RouteScope {
	/// Reachable beyond the link.
	Global,
	/// Reachable on the link only.
	Link,
	/// This host.
	Host,
}

/// A route netcfgd installs.
///
/// Ordered so that a sorted list of routes is stable across compiles: the
/// derived `Ord` follows field declaration order, and `destination` first is
/// what a reader expects to see grouped.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Route {
	/// CIDR, or `default`.
	pub destination: String,
	/// Next hop.
	#[serde(skip_serializing_if = "Option::is_none", default)]
	pub via: Option<IpAddr>,
	/// Metric. Where absent, the planner derives one from the position of the
	/// addressing source that produced this route.
	#[serde(skip_serializing_if = "Option::is_none", default)]
	pub metric: Option<u32>,
	/// Routing table id.
	#[serde(skip_serializing_if = "Option::is_none", default)]
	pub table: Option<u32>,
	/// Preferred source address.
	#[serde(skip_serializing_if = "Option::is_none", default)]
	pub src: Option<IpAddr>,
	/// Scope.
	#[serde(skip_serializing_if = "Option::is_none", default)]
	pub scope: Option<RouteScope>,
	/// Next hop is on-link even though no address covers it. Exempts this
	/// route from the ordering rule that puts `addr.add` before `route.add`.
	#[serde(default)]
	pub onlink: bool,
	/// Protocol tag. Absent means [`NETCFGD_PROTO`] is applied on install.
	#[serde(skip_serializing_if = "Option::is_none", default)]
	pub proto: Option<u8>,
}
