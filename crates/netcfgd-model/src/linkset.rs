//! A named set of links, one of which is used at a time.
//!
//! **Failover, said once, for links of any kind.** A laptop with a cable and
//! two saved wifi networks, a router with a fibre uplink and an LTE modem
//! behind it, a machine with a VPN it prefers when the VPN is up: all three are
//! the same sentence -- *these links can reach the same place, use the best one
//! that actually works* -- and netcfgd could not say it. What it had was
//! [`crate::Interface::preference`], which ranks interfaces by metric and
//! withholds the routes of one with no carrier or a failing probe. That is the
//! mechanism and not the idea: nothing named the group, nothing said only one
//! of them is in use, and a wifi network could not be in it at all, because a
//! `preference` lives on an interface and a network is not one.
//!
//! **A linkset is itself a link**, which is the property the shape is chosen
//! for rather than a curiosity: a set composes into another set, so an operator
//! can say "the office pair, or failing that the modem" without inventing a
//! second mechanism. It is not a kernel device -- it has no index, holds no
//! address and appears in no link table -- so what a set contributes to the
//! machine is entirely the member it picked.
//!
//! **`uplink` is the set with more assumptions**, and it is spelled as a name
//! rather than a flag: the set called `uplink` is the one that carries the
//! default route and is what [`crate::connectivity`] means by connected. There
//! is at most one because names are unique. Everything else about it is an
//! ordinary linkset.
//!
//! The rule for choosing is deliberately the one the tree already had:
//! **eligible members ranked by metric, lowest wins, ties broken by the order
//! the document lists them in.** A member is eligible when the link carrying it
//! is up, has carrier and has not failed a probe -- the same three facts
//! `preference` already acted on, now naming the group they act within.

use crate::observed::Observed;
use serde::{Deserialize, Serialize};

/// The set that carries the default route, by name.
///
/// A name rather than a `uplink = true` field, because a boolean would need a
/// rule saying what two of them mean and a name cannot be ambiguous: there is
/// one set called `uplink` for the same reason there is one interface called
/// `eth0`.
pub const UPLINK: &str = "uplink";

/// How deep a set may nest before netcfgd stops following it.
///
/// **A document that arrives over the socket or out of `/run` has not
/// necessarily been through the compiler**, and the compiler is where a cycle
/// is diagnosed. This is the model refusing to hang on one anyway: a set naming
/// itself, directly or through a chain, stops here and reports no active
/// member rather than recursing until the stack runs out.
const MAX_DEPTH: usize = 8;

/// A named set of links, one of which is used at a time.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Linkset {
	/// What the set is called. [`UPLINK`] is the special one.
	pub name: String,
	/// The links in it, best first where they cannot be told apart by metric.
	///
	/// **A ranked list, not a set**, which is why nothing sorts it -- a bond's
	/// members are interchangeable and get sorted into canonical order, and
	/// these are not: the order is the operator saying which of two equally
	/// ranked links they would rather be on.
	///
	/// A member is an `interface` block's name, a `network` block's id, or
	/// another linkset's name.
	pub members: Vec<String>,
}

/// Why a member cannot be used right now.
///
/// **Named rather than counted**, because every one of these is a different
/// thing to do about it: a cable to plug in, a network out of range, a set
/// whose own members are all down.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Ineligible {
	/// Nothing on this machine answers to the name.
	///
	/// A member the document names and neither the kernel nor the document has:
	/// an interface whose card is out, a `network` block that was deleted, a
	/// typo the compiler would have caught in a document it compiled.
	Absent,
	/// A configured network no radio is associated with.
	///
	/// Separate from [`Ineligible::Absent`] because the network exists and is
	/// perfectly fine -- nothing is on it. That is the ordinary state of every
	/// saved network but one.
	Unjoined,
	/// The cable is not in, or the radio is not associated.
	///
	/// **A link that is down reads as this too**, and there is deliberately no
	/// separate answer for it: `up` is netcfgd's own setting and a plan is
	/// usually in the middle of applying it, so a set that called a down link
	/// unusable would withhold every route on the first pass and install them
	/// on the second -- a machine that needs two applies to come up. Carrier is
	/// the fact about the world, and a link the operator disabled loses it as
	/// soon as it goes down.
	NoCarrier,
	/// The probe says it is not reaching anything.
	///
	/// Only an explicit refusal. A link nobody probed keeps its standing, which
	/// is the rule [`crate::observed::ObservedLink::reachable`] states and the
	/// one [0119] applies to a ranked interface's routes.
	///
	/// [0119]: ../../../doc/decision/0119-a-probe-is-an-observation-and-a-failing-uplink-loses-its-routes.md
	Probe,
	/// A nested set with no usable member of its own.
	Empty,
	/// A set that names itself, directly or through a chain.
	///
	/// Reported rather than followed. The compiler refuses such a document; a
	/// document that did not come through the compiler gets this instead of a
	/// stack overflow.
	Cycle,
}

impl Ineligible {
	/// The word a status line or a column uses.
	#[must_use]
	pub fn name(self) -> &'static str {
		match self {
			Self::Absent => "absent",
			Self::Unjoined => "unjoined",
			Self::NoCarrier => "no carrier",
			Self::Probe => "probe failed",
			Self::Empty => "empty",
			Self::Cycle => "cycle",
		}
	}
}

/// Where one member of a set stands.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Standing {
	/// The member, as the document names it.
	pub name: String,
	/// The interface carrying it, where one is.
	///
	/// A member's own name for an interface; the radio for a network; the
	/// nested set's own answer for a set. `None` when nothing carries it, which
	/// is also when it is ineligible.
	#[serde(skip_serializing_if = "Option::is_none", default)]
	pub interface: Option<String>,
	/// How it ranks. Lower wins; absent reads as 0, the kernel's own default
	/// and the strongest, exactly as an unnumbered route does.
	#[serde(skip_serializing_if = "Option::is_none", default)]
	pub metric: Option<u32>,
	/// Why it cannot be used, or `None` when it can.
	#[serde(skip_serializing_if = "Option::is_none", default)]
	pub ineligible: Option<Ineligible>,
}

impl Standing {
	/// Whether this member could be the active one.
	#[must_use]
	pub fn eligible(&self) -> bool {
		self.ineligible.is_none()
	}
}

/// What a set decided, and what it decided it from.
///
/// The whole standing rather than the winner alone, because "why am I on the
/// modem" is answered by the members that lost and not by the one that won.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Chosen {
	/// The set this is about.
	pub name: String,
	/// The member in use, where one can be.
	#[serde(skip_serializing_if = "Option::is_none", default)]
	pub active: Option<String>,
	/// The interface that member is running on.
	///
	/// Carried beside [`Chosen::active`] rather than looked up again, because
	/// for a network member they are different strings and every caller needs
	/// the second one: the routes, the metric and the probe all live on the
	/// interface.
	#[serde(skip_serializing_if = "Option::is_none", default)]
	pub interface: Option<String>,
	/// Every member, in the order the document lists them.
	pub members: Vec<Standing>,
}

/// The set by this name, if the document has one.
#[must_use]
pub fn find<'a>(document: &'a crate::Document, name: &str) -> Option<&'a Linkset> {
	document.linksets.iter().find(|set| set.name == name)
}

/// Work out which member of a set is in use.
///
/// `None` when the document has no set by that name. A set whose members are
/// all unusable answers with `active: None` and every member's reason, which is
/// the answer an operator needs when nothing works.
#[must_use]
pub fn choose(document: &crate::Document, observed: &Observed, name: &str) -> Option<Chosen> {
	// **The set being asked about counts as in progress**, or a set naming
	// itself directly is reported as empty rather than as the cycle it is --
	// the inner call refuses it correctly and the outer one only sees that
	// nothing came back.
	choose_within(document, observed, name, &mut vec![name.to_owned()])
}

/// [`choose`], carrying the names already being resolved.
///
/// The visited list is the cycle guard, and it is a list rather than a depth
/// count because the two answers differ: a chain eight sets deep is legal and
/// rare, a set that names itself is a mistake, and only naming the sets already
/// in progress can tell them apart.
fn choose_within(
	document: &crate::Document,
	observed: &Observed,
	name: &str,
	within: &mut Vec<String>,
) -> Option<Chosen> {
	let set = find(document, name)?;
	let mut members = Vec::with_capacity(set.members.len());
	for member in &set.members {
		members.push(stand(document, observed, member, within));
	}

	// Lowest metric wins, ties going to whichever the document listed first.
	// `enumerate` supplies that second key rather than relying on a stable
	// sort of the whole list, because the list is not sorted at all -- the
	// winner is picked out of it and the list keeps its declared order for the
	// caller to display.
	let active = members
		.iter()
		.enumerate()
		.filter(|(_, member)| member.eligible())
		.min_by_key(|(position, member)| (member.metric.unwrap_or(0), *position))
		.map(|(_, member)| member.clone());

	Some(Chosen {
		name: set.name.clone(),
		active: active.as_ref().map(|member| member.name.clone()),
		interface: active.and_then(|member| member.interface),
		members,
	})
}

/// Where one member stands, whatever kind of thing it is.
fn stand(
	document: &crate::Document,
	observed: &Observed,
	member: &str,
	within: &mut Vec<String>,
) -> Standing {
	// A nested set first, because a set and an interface could in principle
	// share a name and the set is the more specific thing to have written.
	if find(document, member).is_some() {
		return stand_on_set(document, observed, member, within);
	}
	if document.networks.iter().any(|network| network.id == member) {
		return stand_on_network(document, observed, member);
	}
	stand_on_interface(document, observed, member)
}

/// A member that is another set: it stands wherever its own choice does.
fn stand_on_set(
	document: &crate::Document,
	observed: &Observed,
	member: &str,
	within: &mut Vec<String>,
) -> Standing {
	if within.iter().any(|seen| seen == member) {
		return Standing {
			name: member.to_owned(),
			interface: None,
			metric: None,
			ineligible: Some(Ineligible::Cycle),
		};
	}
	if within.len() >= MAX_DEPTH {
		return Standing {
			name: member.to_owned(),
			interface: None,
			metric: None,
			ineligible: Some(Ineligible::Cycle),
		};
	}

	within.push(member.to_owned());
	let inner = choose_within(document, observed, member, within);
	within.pop();

	let Some(inner) = inner else {
		return Standing {
			name: member.to_owned(),
			interface: None,
			metric: None,
			ineligible: Some(Ineligible::Absent),
		};
	};
	// **The nested set's metric is its winner's**, not one of its own. A set
	// has no metric to have: what it contributes to an outer set is whichever
	// link it settled on, and that link's ranking is the one that should
	// compete outside.
	let winner = inner
		.active
		.as_ref()
		.and_then(|active| inner.members.iter().find(|member| &member.name == active));
	Standing {
		name: member.to_owned(),
		interface: inner.interface,
		metric: winner.and_then(|member| member.metric),
		ineligible: if winner.is_some() {
			None
		} else {
			Some(Ineligible::Empty)
		},
	}
}

/// A member that is a `network` block: it stands on the radio that joined it.
fn stand_on_network(document: &crate::Document, observed: &Observed, member: &str) -> Standing {
	let metric = document
		.networks
		.iter()
		.find(|network| network.id == member)
		.and_then(|network| network.metric);
	let Some(link) = observed
		.links
		.iter()
		.find(|link| link.network.as_deref() == Some(member))
	else {
		// Configured, nothing on it. The ordinary state of every saved network
		// but one, and not a fault.
		return Standing {
			name: member.to_owned(),
			interface: None,
			metric,
			ineligible: Some(Ineligible::Unjoined),
		};
	};
	Standing {
		name: member.to_owned(),
		interface: Some(link.name.clone()),
		metric,
		ineligible: usable(observed, &link.name),
	}
}

/// A member that is an interface: it stands on itself.
fn stand_on_interface(document: &crate::Document, observed: &Observed, member: &str) -> Standing {
	let metric = document
		.interfaces
		.iter()
		.find(|interface| interface.name == member)
		.and_then(|interface| interface.preference);
	if observed.link(member).is_none() {
		return Standing {
			name: member.to_owned(),
			interface: None,
			metric,
			ineligible: Some(Ineligible::Absent),
		};
	}
	Standing {
		name: member.to_owned(),
		interface: Some(member.to_owned()),
		metric,
		ineligible: usable(observed, member),
	}
}

/// Whether a link can carry traffic, and what stops it where it cannot.
///
/// The same three facts `preference` already acted on, in one place so that a
/// set and a ranked interface cannot come to disagree about what "working"
/// means.
fn usable(observed: &Observed, interface: &str) -> Option<Ineligible> {
	let link = observed.link(interface)?;
	if !link.carrier {
		return Some(Ineligible::NoCarrier);
	}
	// Only an explicit refusal. `None` is "nobody asked" or "no answer yet",
	// and treating that as unreachable would empty every set on a machine that
	// configured no probes.
	if link.reachable == Some(false) {
		return Some(Ineligible::Probe);
	}
	None
}

/// Every set a link is a member of, by the name the document used for it.
///
/// Both spellings, because a wifi member is named by its `network` block and
/// carried by a radio: asking with either the network's id or the radio's name
/// answers the same set. That is what a caller has -- the planner holds an
/// interface, a list holds a row -- and making each of them join the two lists
/// itself is how two callers come to disagree.
#[must_use]
pub fn sets_containing(document: &crate::Document, observed: &Observed, link: &str) -> Vec<String> {
	let mut names = Vec::new();
	for set in &document.linksets {
		let member = set.members.iter().any(|member| {
			member == link
				|| observed
					.links
					.iter()
					.any(|seen| seen.name == link && seen.network.as_deref() == Some(member))
		});
		if member {
			names.push(set.name.clone());
		}
	}
	names
}

#[cfg(test)]
mod tests {
	use super::{choose, sets_containing, Ineligible, Linkset, UPLINK};
	use crate::observed::{Observed, ObservedLink};
	use crate::{Document, Interface};

	/// A link, built from JSON rather than a literal: the idiom this tree uses
	/// where a struct has no `Default`, so a new field does not silently change
	/// what every test asserts.
	fn link(name: &str, up: bool, carrier: bool, network: Option<&str>) -> ObservedLink {
		serde_json::from_value(serde_json::json!({
			"name": name,
			"index": 1,
			"kind": "",
			"wireless": network.is_some(),
			"up": up,
			"carrier": carrier,
			"mtu": 1500,
			"forwarding": false,
			"qdisc_ingress": false,
			"privacy": false,
			"ownership": "unknown",
			"private_key_loaded": false,
			"network": network,
		}))
		.expect("a link")
	}

	/// The same idiom for the document's own blocks: the fields this test
	/// cares about, and whatever the schema says for the rest.
	fn network(id: &str, metric: Option<u32>) -> crate::WifiNetwork {
		serde_json::from_value(serde_json::json!({
			"id": id,
			"security": {"type": "open"},
			"metric": metric,
		}))
		.expect("a network")
	}

	fn interface(name: &str, preference: Option<u32>) -> Interface {
		serde_json::from_value(serde_json::json!({
			"name": name,
			"preference": preference,
		}))
		.expect("an interface")
	}

	fn set(name: &str, members: &[&str]) -> Linkset {
		Linkset {
			name: name.to_owned(),
			members: members.iter().map(|member| (*member).to_owned()).collect(),
		}
	}

	/// The whole point, in one assertion: two links that work, one in use.
	#[test]
	fn the_best_working_member_is_the_one_in_use() {
		let mut document = Document::default();
		document.interfaces.push(interface("eth0", Some(100)));
		document.interfaces.push(interface("wwan0", Some(700)));
		document.linksets.push(set(UPLINK, &["eth0", "wwan0"]));

		let mut observed = Observed::default();
		observed.links.push(link("eth0", true, true, None));
		observed.links.push(link("wwan0", true, true, None));

		let chosen = choose(&document, &observed, UPLINK).expect("the set");
		assert_eq!(chosen.active.as_deref(), Some("eth0"));
		assert_eq!(chosen.interface.as_deref(), Some("eth0"));
		assert!(chosen.members.iter().all(super::Standing::eligible));

		// The cable comes out and the modem takes over, with no configuration
		// change at all. This is the sentence the whole thing exists to say.
		observed.links[0] = link("eth0", true, false, None);
		let chosen = choose(&document, &observed, UPLINK).expect("the set");
		assert_eq!(chosen.active.as_deref(), Some("wwan0"));
		assert_eq!(
			chosen.members[0].ineligible,
			Some(Ineligible::NoCarrier),
			"and it says why the cable lost"
		);
	}

	/// A wifi network is a member like any other, which `preference` could not
	/// express: it lives on an interface and a network is not one.
	#[test]
	fn a_network_is_a_member_and_stands_on_its_radio() {
		let mut document = Document::default();
		document.interfaces.push(interface("eth0", Some(100)));
		document.networks.push(network("office", Some(50)));
		document.linksets.push(set(UPLINK, &["eth0", "office"]));

		let mut observed = Observed::default();
		observed.links.push(link("eth0", true, true, None));
		observed
			.links
			.push(link("wlan0", true, true, Some("office")));

		let chosen = choose(&document, &observed, UPLINK).expect("the set");
		// The network wins on metric, and what carries it is the radio.
		assert_eq!(chosen.active.as_deref(), Some("office"));
		assert_eq!(chosen.interface.as_deref(), Some("wlan0"));

		// A saved network nothing is on is unjoined rather than absent: the
		// network is fine, there is simply no radio on it.
		observed.links.pop();
		let chosen = choose(&document, &observed, UPLINK).expect("the set");
		assert_eq!(chosen.active.as_deref(), Some("eth0"));
		assert_eq!(chosen.members[1].ineligible, Some(Ineligible::Unjoined));
		assert_eq!(chosen.members[1].interface, None);
	}

	/// Ties go to the document's order, which is why nothing sorts the list.
	#[test]
	fn members_that_cannot_be_told_apart_go_in_the_order_written() {
		let mut document = Document::default();
		document.interfaces.push(interface("eth0", None));
		document.interfaces.push(interface("eth1", None));
		document.linksets.push(set("office", &["eth1", "eth0"]));

		let mut observed = Observed::default();
		observed.links.push(link("eth0", true, true, None));
		observed.links.push(link("eth1", true, true, None));

		let chosen = choose(&document, &observed, "office").expect("the set");
		assert_eq!(
			chosen.active.as_deref(),
			Some("eth1"),
			"written first, so preferred"
		);

		// **An absent metric reads as 0, which is the strongest**, so writing a
		// metric on one member and not the other demotes the one that was
		// written. That looks backwards and is the only answer that keeps the
		// set and the kernel agreeing: an unnumbered route goes in at metric 0
		// too, so a set that ranked the unnumbered member last would pick one
		// link while the routing table used the other.
		document.interfaces[1].preference = Some(10);
		let chosen = choose(&document, &observed, "office").expect("the set");
		assert_eq!(chosen.active.as_deref(), Some("eth0"));
	}

	/// A set is a link, so a set can be a member of a set.
	#[test]
	fn a_set_composes_into_another_set() {
		let mut document = Document::default();
		document.interfaces.push(interface("eth0", Some(100)));
		document.interfaces.push(interface("eth1", Some(200)));
		document.interfaces.push(interface("wwan0", Some(700)));
		document.linksets.push(set("office", &["eth0", "eth1"]));
		document.linksets.push(set(UPLINK, &["office", "wwan0"]));

		let mut observed = Observed::default();
		observed.links.push(link("eth0", true, false, None));
		observed.links.push(link("eth1", true, true, None));
		observed.links.push(link("wwan0", true, true, None));

		let chosen = choose(&document, &observed, UPLINK).expect("the set");
		assert_eq!(chosen.active.as_deref(), Some("office"));
		assert_eq!(
			chosen.interface.as_deref(),
			Some("eth1"),
			"the inner set's own answer is what carries the outer one"
		);
		assert_eq!(
			chosen.members[0].metric,
			Some(200),
			"and it competes on its winner's metric, not on one of its own"
		);

		// The inner set empties, and the outer one says so rather than
		// pretending it is absent.
		observed.links[1] = link("eth1", true, false, None);
		let chosen = choose(&document, &observed, UPLINK).expect("the set");
		assert_eq!(chosen.active.as_deref(), Some("wwan0"));
		assert_eq!(chosen.members[0].ineligible, Some(Ineligible::Empty));
	}

	/// A document the compiler never saw can name a cycle. The model reports
	/// one instead of recursing until the stack runs out.
	#[test]
	fn a_set_that_names_itself_is_reported_and_not_followed() {
		let mut document = Document::default();
		document.interfaces.push(interface("eth0", None));
		document.linksets.push(set("a", &["b"]));
		document.linksets.push(set("b", &["a", "eth0"]));

		let mut observed = Observed::default();
		observed.links.push(link("eth0", true, true, None));

		let chosen = choose(&document, &observed, "a").expect("the set");
		// `b` is reachable through `a`, and inside it `a` is refused -- so the
		// cycle costs the machine nothing: `eth0` still wins.
		assert_eq!(chosen.active.as_deref(), Some("b"));
		assert_eq!(chosen.interface.as_deref(), Some("eth0"));

		let mut naming_itself = Document::default();
		naming_itself.linksets.push(set("a", &["a"]));
		let chosen = choose(&naming_itself, &Observed::default(), "a").expect("the set");
		assert_eq!(chosen.active, None);
		assert_eq!(chosen.members[0].ineligible, Some(Ineligible::Cycle));
	}

	/// The states a member can be in that are not "working", told apart.
	#[test]
	fn a_member_that_cannot_be_used_says_which_kind_of_cannot() {
		let mut document = Document::default();
		document.interfaces.push(interface("down0", None));
		document.interfaces.push(interface("cut0", None));
		document.interfaces.push(interface("dark0", None));
		document
			.linksets
			.push(set("s", &["down0", "cut0", "dark0", "gone0"]));

		let mut observed = Observed::default();
		observed.links.push(link("down0", false, false, None));
		observed.links.push(link("cut0", true, false, None));
		let mut dark = link("dark0", true, true, None);
		dark.reachable = Some(false);
		observed.links.push(dark);

		let chosen = choose(&document, &observed, "s").expect("the set");
		assert_eq!(chosen.active, None, "nothing here works");
		// Down and cut both read as no carrier, deliberately: see
		// `Ineligible::NoCarrier` for why a set does not act on `up`.
		assert_eq!(chosen.members[0].ineligible, Some(Ineligible::NoCarrier));
		assert_eq!(chosen.members[1].ineligible, Some(Ineligible::NoCarrier));
		assert_eq!(chosen.members[2].ineligible, Some(Ineligible::Probe));
		assert_eq!(chosen.members[3].ineligible, Some(Ineligible::Absent));

		// A link nobody probed keeps its standing, which is the other half of
		// the probe rule and the half that breaks every machine when it is got
		// wrong: `None` is not `Some(false)`.
		observed.links[2].reachable = None;
		let chosen = choose(&document, &observed, "s").expect("the set");
		assert_eq!(chosen.active.as_deref(), Some("dark0"));

		// **A link that is down but has carrier is usable**, and it is first in
		// the list so it takes over from `dark0` here. That is the state every
		// interface is in between netcfgd deciding to bring it up and having
		// done so, and a set that refused it would plan no routes at all on the
		// first pass and every route on the second.
		observed.links[0].carrier = true;
		let chosen = choose(&document, &observed, "s").expect("the set");
		assert_eq!(chosen.active.as_deref(), Some("down0"));
	}

	/// Asked with either name -- the network's or the radio's -- a link says
	/// which sets it is in.
	#[test]
	fn a_link_says_which_sets_it_belongs_to_under_either_name() {
		let mut document = Document::default();
		document.networks.push(network("office", None));
		document.interfaces.push(interface("eth0", None));
		document.linksets.push(set(UPLINK, &["eth0", "office"]));

		let mut observed = Observed::default();
		observed.links.push(link("eth0", true, true, None));
		observed
			.links
			.push(link("wlan0", true, true, Some("office")));

		assert_eq!(sets_containing(&document, &observed, "eth0"), ["uplink"]);
		assert_eq!(sets_containing(&document, &observed, "office"), ["uplink"]);
		assert_eq!(
			sets_containing(&document, &observed, "wlan0"),
			["uplink"],
			"the radio carrying a member network is in the set too"
		);
		assert!(sets_containing(&document, &observed, "docker0").is_empty());
	}

	/// A document with no sets answers nothing, rather than inventing one.
	#[test]
	fn a_document_with_no_set_by_that_name_has_no_answer() {
		assert!(choose(&Document::default(), &Observed::default(), UPLINK).is_none());
	}
}
