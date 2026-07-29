//! Policy routing rules: which routing table a packet is looked up in.
//!
//! A route says where a packet goes. A rule says which set of routes is
//! consulted in the first place, and that is a different question -- the one
//! that multi-homing, VPN split tunnelling and per-mark routing are all
//! answers to. netcfgd could not express it at all, which meant a machine
//! needing it had `ip rule` calls in a hook and netcfgd reporting no drift
//! while the actual forwarding decision came from somewhere it could not see.
//!
//! Rules are host-wide rather than per-interface. They are selected by
//! priority across the whole system, and two interfaces' rules interleave by
//! number, so attaching them to an interface would make the ordering
//! something you had to reconstruct by reading every block.

use serde::{Deserialize, Serialize};

/// What happens when a rule matches.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuleAction {
	/// Look the packet up in [`RoutingRule::table`].
	#[default]
	Lookup,
	/// Stop here: no route.
	Blackhole,
	/// Stop here, and tell the sender.
	Unreachable,
	/// Stop here, administratively.
	Prohibit,
}

impl RuleAction {
	/// The name as the config spells it.
	#[must_use]
	pub fn name(self) -> &'static str {
		match self {
			Self::Lookup => "lookup",
			Self::Blackhole => "blackhole",
			Self::Unreachable => "unreachable",
			Self::Prohibit => "prohibit",
		}
	}
}

/// Which address family a rule belongs to.
///
/// Explicit rather than inferred from the selectors, because a rule with no
/// address selector at all -- `from all fwmark 0x1 lookup 100`, the common
/// shape -- gives nothing to infer from, and guessing would silently install
/// it in one family only.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuleFamily {
	/// IPv4.
	#[default]
	Inet,
	/// IPv6.
	Inet6,
}

/// One policy routing rule.
///
/// The field set is deliberately the one `ip rule` exposes and no more.
/// Everything here maps to an `FRA_*` netlink attribute; anything that does
/// not have one is not expressible and should not look as though it is.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RoutingRule {
	/// A handle for this rule, from the block label.
	///
	/// Rules are the one thing here the kernel identifies purely by number,
	/// and a number is a poor thing to put in a diagnostic: "rule 100
	/// conflicts with rule 200" tells an operator nothing they did not already
	/// see. A name survives a renumbering, and `explain` can use it.
	pub id: String,
	/// Rule priority. Lower is consulted first.
	///
	/// Required, not defaulted. The kernel will assign one, but an unnumbered
	/// rule lands wherever the kernel puts it and two applies can produce
	/// different orders -- which makes the document stop describing the
	/// system. Making it mandatory is the cost of reconciliation being
	/// meaningful.
	pub priority: u32,
	/// Which family this rule is installed in.
	#[serde(default)]
	pub family: RuleFamily,
	/// Source prefix selector.
	#[serde(skip_serializing_if = "Option::is_none", default)]
	pub from: Option<String>,
	/// Destination prefix selector.
	#[serde(skip_serializing_if = "Option::is_none", default)]
	pub to: Option<String>,
	/// Incoming interface selector.
	#[serde(skip_serializing_if = "Option::is_none", default)]
	pub iif: Option<String>,
	/// Outgoing interface selector.
	#[serde(skip_serializing_if = "Option::is_none", default)]
	pub oif: Option<String>,
	/// Firewall mark selector.
	///
	/// netcfgd never sets a mark -- that is a firewall's job and constraint 2
	/// keeps it out of rulesets it does not own -- but routing on one somebody
	/// else set is exactly what this is for.
	#[serde(skip_serializing_if = "Option::is_none", default)]
	pub fwmark: Option<u32>,
	/// Mask applied to the mark before comparing.
	#[serde(skip_serializing_if = "Option::is_none", default)]
	pub fwmask: Option<u32>,
	/// Which table to look up, when the action is [`RuleAction::Lookup`].
	#[serde(skip_serializing_if = "Option::is_none", default)]
	pub table: Option<u32>,
	/// What to do on a match.
	#[serde(default)]
	pub action: RuleAction,
	/// Ignore routes whose prefix is shorter than this.
	///
	/// The `suppress_prefixlength 0` trick: consult the main table but skip
	/// its default route, so a more specific rule below can catch it.
	#[serde(skip_serializing_if = "Option::is_none", default)]
	pub suppress_prefixlength: Option<u32>,
	/// Match packets belonging to an l3mdev (VRF) master.
	#[serde(default)]
	pub l3mdev: bool,
	/// Keep going down the rule list after this one matches.
	#[serde(default)]
	pub invert: bool,
}

impl RoutingRule {
	/// A minimal lookup rule, for construction in tests and importers.
	#[must_use]
	pub fn lookup(id: impl Into<String>, priority: u32, table: u32) -> Self {
		Self {
			id: id.into(),
			priority,
			family: RuleFamily::Inet,
			from: None,
			to: None,
			iif: None,
			oif: None,
			fwmark: None,
			fwmask: None,
			table: Some(table),
			action: RuleAction::Lookup,
			suppress_prefixlength: None,
			l3mdev: false,
			invert: false,
		}
	}

	/// A one-line rendering, in `ip rule` order, for diagnostics and plans.
	///
	/// The name is not in it: this is the rule as the kernel holds it, so it
	/// can be compared against what `ip rule` shows. The name is netcfgd's and
	/// belongs in the sentence around this, not inside it.
	#[must_use]
	pub fn render(&self) -> String {
		let mut out = format!("{}:", self.priority);
		if self.family == RuleFamily::Inet6 {
			out.push_str(" -6");
		}
		out.push_str(" from ");
		out.push_str(self.from.as_deref().unwrap_or("all"));
		for (label, value) in [("to", &self.to), ("iif", &self.iif), ("oif", &self.oif)] {
			if let Some(value) = value {
				out.push_str(&format!(" {label} {value}"));
			}
		}
		if let Some(mark) = self.fwmark {
			out.push_str(&format!(" fwmark {mark:#x}"));
			if let Some(mask) = self.fwmask {
				out.push_str(&format!("/{mask:#x}"));
			}
		}
		if let Some(length) = self.suppress_prefixlength {
			out.push_str(&format!(" suppress_prefixlength {length}"));
		}
		if self.l3mdev {
			out.push_str(" l3mdev");
		}
		match self.action {
			RuleAction::Lookup => {
				out.push_str(&format!(
					" lookup {}",
					self.table.unwrap_or(crate::route::MAIN_TABLE)
				));
			}
			other => {
				out.push(' ');
				out.push_str(other.name());
			}
		}
		out
	}
}

/// Sorted by the order the kernel consults them, then by everything else so
/// that two rules at one priority still have one canonical order.
impl PartialOrd for RoutingRule {
	fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
		Some(self.cmp(other))
	}
}

impl Ord for RoutingRule {
	fn cmp(&self, other: &Self) -> std::cmp::Ordering {
		self.priority
			.cmp(&other.priority)
			.then_with(|| self.family.name().cmp(other.family.name()))
			.then_with(|| self.id.cmp(&other.id))
	}
}

impl RuleFamily {
	/// The name as the config spells it.
	#[must_use]
	pub fn name(self) -> &'static str {
		match self {
			Self::Inet => "inet",
			Self::Inet6 => "inet6",
		}
	}
}
