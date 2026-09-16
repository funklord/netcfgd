//! What kind of thing a link is, decided once.
//!
//! **A filter cannot be built from `kind`, and that is why this exists.** The
//! kernel reports an empty kind for every real network card -- wired, wireless
//! and loopback alike -- so "show me only the ethernet devices" is not a field
//! lookup. It is a small rule over three sources: the kernel's kind where there
//! is one, the `wireless` flag, the name for loopback, and the *document* for a
//! modem, which is marked on a device's policy and nowhere on the link.
//!
//! Measured on the reporting machine, which is why the rule looks the way it
//! does:
//!
//! ```text
//! enp0s31f6   kind=""           wireless=false
//! wlp0s20f3   kind=""           wireless=true
//! lo          kind=""           wireless=false
//! docker0     kind="bridge"     wireless=false
//! wg-test     kind="wireguard"  wireless=false
//! ```
//!
//! Three of those five are indistinguishable by `kind`.
//!
//! **Here rather than in a client, before there are four of them.** No client
//! classifies links today, so unlike [`crate::wifi::network_for`] and
//! [`crate::connectivity`] this is not a consolidation -- it is the same
//! mistake declined in advance. A dropdown in the Qt window, a filter in the
//! text interface and a column in the TDE module would otherwise be three
//! rules, and the one that is wrong would be wrong quietly: a link in no
//! category is a row that simply does not appear.

use crate::observed::{Observed, ObservedLink};
use serde::{Deserialize, Serialize};

/// What kind of thing a link is, for choosing an icon or filtering a list.
///
/// **Coarser than the kernel's kind, deliberately.** This answers "which of
/// these rows do I want to look at", so `gre`, `sit`, `ipip` and `vxlan` are
/// one answer and not four -- an operator filtering a list is not asking which
/// encapsulation is in use, and the exact kind is still in the row beside it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Category {
	/// The machine talking to itself.
	Loopback,
	/// A wired network card.
	Ethernet,
	/// A radio.
	Wifi,
	/// A link whose device the document gives a modem policy.
	///
	/// **The only category that needs the document.** Nothing on the link says
	/// modem: `sim.rs` puts it exactly one place -- a device with a `modem`
	/// block -- and the link it produces looks like an ordinary one to the
	/// kernel. A machine with no document classifies such a link by whatever
	/// else it looks like, which is the honest answer rather than a guess.
	Modem,
	/// A bridge.
	Bridge,
	/// A bond.
	Bond,
	/// A VLAN, or a macvlan.
	Vlan,
	/// `WireGuard`.
	///
	/// Its own category rather than folded into [`Category::Tunnel`], because
	/// it is the tunnel people have, and a list that hides it among five
	/// encapsulations nobody configured is a list nobody filters.
	Wireguard,
	/// Something carrying traffic inside something else: `gre`, `sit`, `ipip`,
	/// `vxlan`, `tun`, `tap`, a PPP session, an `OpenVPN` interface.
	Tunnel,
	/// A link that exists to be plumbing: `veth`, `dummy`, `ifb`, `vrf`.
	Virtual,
	/// A kind netcfgd has no word for.
	///
	/// **Not an error and not empty.** A kernel gains link kinds faster than
	/// this list does, and a row in no category at all is a row that vanishes
	/// from every filtered list -- which is the quiet failure this whole module
	/// is arranged to avoid.
	Other,
}

impl Category {
	/// The word a document, a filter or a column header uses.
	#[must_use]
	pub fn name(self) -> &'static str {
		match self {
			Self::Loopback => "loopback",
			Self::Ethernet => "ethernet",
			Self::Wifi => "wifi",
			Self::Modem => "modem",
			Self::Bridge => "bridge",
			Self::Bond => "bond",
			Self::Vlan => "vlan",
			Self::Wireguard => "wireguard",
			Self::Tunnel => "tunnel",
			Self::Virtual => "virtual",
			Self::Other => "other",
		}
	}
}

/// Whether a link is there, with a third answer for when nobody can say.
///
/// **Not a boolean, and the third value is the point.** A hidden network, or
/// any network on a radio that is not allowed to probe actively, cannot be
/// found by looking: a hidden access point beacons with an empty name, so its
/// *address* is observable and the name-to-address mapping is not.
/// `scan_ssid=1` sends the directed probe that would resolve it, and on a
/// `no IR` channel -- 5180 and 5260 among them, see [`crate::device`] -- that
/// probe is forbidden. The only evidence left is an attempt to associate.
///
/// This tree already states the convention twice, on
/// [`crate::observed::ObservedLink::reachable`] and on
/// `ObservedBackend::networks_match`: `None` is not `Some(false)`, and a thing
/// nobody could ask about keeps its standing. 0245.
///
/// **The rendering rule follows and is the reason this is an enum rather than
/// an `Option<bool>`:** unknown must never be drawn as absent. A hidden network
/// shown as "not present" looks permanently gone, and the operator's correct
/// response -- try it -- is the one thing that display argues against.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Presence {
	/// Seen.
	Present,
	/// Looked for, with a method that would have found it, and not there.
	Absent,
	/// No method available that could have found it.
	Unknown,
}

impl Presence {
	/// The word a column or a status line uses.
	#[must_use]
	pub fn name(self) -> &'static str {
		match self {
			Self::Present => "present",
			Self::Absent => "absent",
			Self::Unknown => "unknown",
		}
	}
}

/// Whether an interface named by the document is there.
///
/// **Two-valued, unlike a network's, and that asymmetry is the whole rule.**
/// The kernel's link table is complete: netcfgd has seen every interface there
/// is, so one it cannot find is one that does not exist. There is no third
/// answer here because there is no question netcfgd was unable to ask.
#[must_use]
pub fn presence_of_interface(name: &str, observed: &Observed) -> Presence {
	if observed.link(name).is_some() {
		Presence::Present
	} else {
		Presence::Absent
	}
}

/// Whether a configured wifi network is within reach.
///
/// `associated` is whether some radio is on it now, which settles the question
/// outright. `seen` is what a scan said: `Some(true)` found it, `Some(false)`
/// looked and did not, `None` means no scan has been read.
///
/// **A hidden network is `Unknown` even when a scan has been read**, and that
/// is the case this function exists for. A scan cannot name a hidden access
/// point -- `pick_ssid` refuses for exactly this reason -- so "not in the scan"
/// is not evidence of absence for one. Treating it as evidence would report a
/// network that is right there as gone.
#[must_use]
pub fn presence_of_network(hidden: bool, associated: bool, seen: Option<bool>) -> Presence {
	if associated {
		// The strongest evidence there is, and it outranks a stale scan.
		return Presence::Present;
	}
	if hidden {
		return Presence::Unknown;
	}
	match seen {
		Some(true) => Presence::Present,
		Some(false) => Presence::Absent,
		// Nobody looked. Not the same as looking and finding nothing, which is
		// the distinction every `Option<bool>` in this tree is about.
		None => Presence::Unknown,
	}
}

/// The loopback, which no `kind` distinguishes from a wired card.
const LOOPBACK: &str = "lo";

/// Which category a link falls into.
///
/// `document` supplies the one thing the observation cannot: whether the
/// device behind this link is a modem. `None` where there is no document, which
/// classifies such a link by its kernel kind instead of guessing.
#[must_use]
pub fn category_of(link: &ObservedLink, document: Option<&crate::Document>) -> Category {
	// **The document first, because it knows something the link does not.** A
	// modem's link is an ordinary one to the kernel -- often `ppp` or a plain
	// card -- so asking `kind` first would classify it as something else and
	// never reach here.
	if document.is_some_and(|document| is_modem(link, document)) {
		return Category::Modem;
	}
	if link.name == LOOPBACK {
		return Category::Loopback;
	}
	// Before the kind check: a radio reports an empty kind like every other
	// real card, so the flag is the only thing that separates them.
	if link.wireless {
		return Category::Wifi;
	}
	match link.kind.as_str() {
		// An empty kind is what the kernel reports for a real network card,
		// and by here it is not loopback and not a radio.
		"" | "ether" => Category::Ethernet,
		"bridge" => Category::Bridge,
		"bond" => Category::Bond,
		"vlan" | "macvlan" | "macvtap" => Category::Vlan,
		"wireguard" => Category::Wireguard,
		"gre" | "gretap" | "ip6gre" | "ip6tnl" | "ipip" | "sit" | "vxlan" | "tun" | "tap"
		| "ppp" | "vti" | "vti6" => Category::Tunnel,
		"veth" | "dummy" | "ifb" | "vrf" => Category::Virtual,
		_ => Category::Other,
	}
}

/// Whether this link is a radio carrying a network the document describes.
///
/// Split out because it decides whether a row exists at all, which is worth
/// being able to read on its own. `link.network` is the `network` block's id
/// the observation resolved -- empty for a radio joined to something the
/// document does not describe, which is the case that keeps its own row.
fn carries_a_configured_network(link: &ObservedLink, document: Option<&crate::Document>) -> bool {
	let Some(id) = link.network.as_deref() else {
		return false;
	};
	document.is_some_and(|document| document.networks.iter().any(|network| network.id == id))
}

/// Whether the document gives this link's device a modem policy.
fn is_modem(link: &ObservedLink, document: &crate::Document) -> bool {
	document
		.devices
		.iter()
		.any(|device| device.name == link.name && device.modem.is_some())
}

/// Which of the document's two link-shaped things a row is.
///
/// **A row has to know, because acting on it differs.** Configuring an
/// interface and configuring a wifi network are different dialogs against
/// different blocks, and a list that mixed them without saying which is which
/// sent one to the other -- selecting a network opened an interface dialog for
/// an interface that does not exist. 0247.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Subject {
	/// An `interface` block, or a link the kernel has that no block names.
	Interface,
	/// A `network` block.
	Network,
}

impl Subject {
	/// The word a column or a client uses.
	#[must_use]
	pub fn name(self) -> &'static str {
		match self {
			Self::Interface => "interface",
			Self::Network => "network",
		}
	}
}

/// One row of the link list: what netcfgd knows about one link.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Entry {
	/// What to call it.
	///
	/// An interface's name, or a `network` block's id for a wifi network --
	/// which is the identity a wifi link has, since the operator names every
	/// block and one name can cover a whole set of access points (0245).
	pub name: String,
	/// What kind of thing it is.
	pub category: Category,
	/// Whether it is there.
	pub presence: Presence,
	/// Whether the document names it.
	///
	/// False for a link the machine has and nobody configured -- a container
	/// bridge, a card another manager owns. Those are in the list because
	/// hiding something demonstrably on the machine is worse than showing
	/// something netcfgd does not manage.
	pub configured: bool,
	/// Which kind of thing this row is, and so what acting on it means.
	pub subject: Subject,
	/// The interface carrying this link right now, where that is not itself.
	///
	/// **Only a wifi network has one**, and it is the radio it is associated
	/// with. A network is not hardware: it runs on whichever radio joined it,
	/// and which one that is belongs in the row rather than being inferred by
	/// whoever is reading.
	///
	/// `None` for an interface, which carries itself, and for a network that
	/// nothing is on.
	#[serde(skip_serializing_if = "Option::is_none", default)]
	pub carrier: Option<String>,
}

/// Every link this machine has or has been told about.
///
/// **A union of two sets that do not coincide**, which is why neither half
/// alone will do. Three provenances (0245):
///
/// * configured and present -- the ordinary case;
/// * configured and not present -- a saved network out of range, an
///   `interface` whose card is not plugged in. These have no kernel link at
///   all, so an observation-only list cannot show them;
/// * present and not configured -- `docker0`, a card another manager owns. A
///   document-only list would hide something demonstrably on the machine.
///
/// Sorted by name, so two calls on one machine compare equal and a list does
/// not reorder itself under somebody reading it.
///
/// **Wifi presence is `Unknown` here unless a radio is on the network**, and
/// that is honest rather than lazy: narrowing it to `Absent` needs a scan, the
/// observation carries none, and for a hidden network no scan could settle it
/// anyway. A caller holding scan results can ask
/// [`presence_of_network`] directly.
#[must_use]
pub fn inventory(document: Option<&crate::Document>, observed: &Observed) -> Vec<Entry> {
	let mut entries: Vec<Entry> = Vec::new();

	for link in &observed.links {
		// **A radio carrying a configured network does not get a row of its
		// own**, because the network's row is that connection: it holds the
		// state, the addresses and the lease, and naming the same thing twice
		// put all the detail on one row and all the meaning on the other.
		//
		// Only when the network is one the document describes. A radio joined
		// to something nobody configured still appears as itself, since there
		// is no other row for it to hide behind.
		if carries_a_configured_network(link, document) {
			continue;
		}
		let configured = document.is_some_and(|document| {
			document
				.interfaces
				.iter()
				.any(|interface| interface.name == link.name)
		});
		entries.push(Entry {
			name: link.name.clone(),
			// The link's own category where the observation has worked one
			// out, and the rule again where it has not -- a bare netlink
			// snapshot has no category, and a row with no kind is a row that
			// falls out of every filter.
			category: link.category.unwrap_or_else(|| category_of(link, document)),
			presence: Presence::Present,
			configured,
			subject: Subject::Interface,
			// An interface carries itself; there is nothing else to name.
			carrier: None,
		});
	}

	let Some(document) = document else {
		entries.sort_by(|left, right| left.name.cmp(&right.name));
		return entries;
	};

	// An interface the document names and the kernel does not have.
	for interface in &document.interfaces {
		if observed.link(&interface.name).is_some() {
			continue;
		}
		entries.push(Entry {
			name: interface.name.clone(),
			// Nothing to read a kind from: the link does not exist, so there
			// is no kernel kind and no `wireless` flag. `Other` rather than a
			// guess from the name, which is the convention `eth0` is not a
			// fact.
			category: Category::Other,
			presence: presence_of_interface(&interface.name, observed),
			configured: true,
			subject: Subject::Interface,
			carrier: None,
		});
	}

	// Every configured network, which is a link whether or not a radio is on
	// it. Where a radio is on one, the radio's own row was skipped above and
	// this is the only row for the pair: the network is the thing an operator
	// configured, the thing a linkset would hold, and -- through `carrier` --
	// the thing that says which hardware is carrying it.
	for network in &document.networks {
		// The radio it is on, which is also what decides whether it is there.
		let carrier = observed
			.links
			.iter()
			.find(|link| link.network.as_deref() == Some(network.id.as_str()))
			.map(|link| link.name.clone());
		entries.push(Entry {
			name: network.id.clone(),
			category: Category::Wifi,
			presence: presence_of_network(network.hidden, carrier.is_some(), None),
			configured: true,
			subject: Subject::Network,
			carrier,
		});
	}

	entries.sort_by(|left, right| left.name.cmp(&right.name));
	entries
}

#[cfg(test)]
mod tests {
	use super::{category_of, Category};
	use crate::observed::ObservedLink;

	/// A link, built from JSON: `ObservedLink` has no `Default`, and a literal
	/// would have to be edited every time it gains a field.
	fn link(name: &str, kind: &str, wireless: bool) -> ObservedLink {
		serde_json::from_value(serde_json::json!({
			"name": name,
			"index": 1,
			"kind": kind,
			"wireless": wireless,
			"up": true,
			"carrier": true,
			"mtu": 1500,
			"forwarding": false,
			"qdisc_ingress": false,
			"privacy": false,
			"ownership": "unknown",
			"private_key_loaded": false,
		}))
		.expect("a link")
	}

	/// The three the kernel cannot tell apart.
	///
	/// **This is the whole reason the module exists.** `enp0s31f6`,
	/// `wlp0s20f3` and `lo` all report an empty `kind` on the reporting
	/// machine, so a filter built on `kind` puts a wired card, a radio and the
	/// loopback in one bucket -- and a dropdown offering "ethernet" would show
	/// the radio.
	#[test]
	fn an_empty_kind_is_three_different_things() {
		assert_eq!(
			category_of(&link("enp0s31f6", "", false), None),
			Category::Ethernet
		);
		assert_eq!(
			category_of(&link("wlp0s20f3", "", true), None),
			Category::Wifi
		);
		assert_eq!(
			category_of(&link("lo", "", false), None),
			Category::Loopback
		);
	}

	/// Everything else comes from the kernel's kind, coarsened.
	#[test]
	fn the_kernels_kinds_map_onto_words_an_operator_filters_by() {
		for (kind, wanted) in [
			("bridge", Category::Bridge),
			("bond", Category::Bond),
			("vlan", Category::Vlan),
			("macvlan", Category::Vlan),
			("wireguard", Category::Wireguard),
			("gre", Category::Tunnel),
			("sit", Category::Tunnel),
			("vxlan", Category::Tunnel),
			("tun", Category::Tunnel),
			("ppp", Category::Tunnel),
			("veth", Category::Virtual),
			("dummy", Category::Virtual),
		] {
			assert_eq!(
				category_of(&link("x0", kind, false), None),
				wanted,
				"kind {kind}"
			);
		}

		// **A kind this list has never heard of is `Other`, not nothing.** A
		// kernel gains link kinds faster than this does, and a row in no
		// category vanishes from every filtered list -- which is the failure
		// that would be hardest to notice.
		assert_eq!(
			category_of(&link("x0", "a-kind-from-2031", false), None),
			Category::Other
		);
	}

	/// The whole reason presence is not a boolean.
	///
	/// A hidden network is `Unknown` even when a scan has been read and did
	/// not find it, because a scan *cannot* find one: a hidden access point
	/// beacons with an empty name, which is what `pick_ssid` refuses over. A
	/// network that is right there would otherwise be reported gone.
	#[test]
	fn a_hidden_network_is_unknown_and_not_absent() {
		use super::{presence_of_network, Presence};

		// Looked, with a method that would have worked, and it was not there.
		assert_eq!(
			presence_of_network(false, false, Some(false)),
			Presence::Absent
		);
		// The same evidence about a hidden network is not evidence at all.
		assert_eq!(
			presence_of_network(true, false, Some(false)),
			Presence::Unknown
		);

		// Nobody looked. Not the same as looking and finding nothing, which is
		// what every `Option<bool>` in this tree is about.
		assert_eq!(presence_of_network(false, false, None), Presence::Unknown);

		// Association settles it either way, and outranks a stale scan that
		// disagrees.
		assert_eq!(presence_of_network(false, true, None), Presence::Present);
		assert_eq!(
			presence_of_network(true, true, Some(false)),
			Presence::Present
		);
		assert_eq!(
			presence_of_network(false, false, Some(true)),
			Presence::Present
		);
	}

	/// An interface has no third answer, and that asymmetry is deliberate.
	#[test]
	fn an_interface_is_present_or_absent_and_never_unknown() {
		use super::{presence_of_interface, Presence};

		let mut observed = crate::observed::Observed::default();
		observed.links.push(link("eth0", "", false));

		assert_eq!(presence_of_interface("eth0", &observed), Presence::Present);
		// The kernel's link table is complete: an interface netcfgd cannot
		// find is one that does not exist, so there is no question it was
		// unable to ask.
		assert_eq!(presence_of_interface("eth1", &observed), Presence::Absent);
	}

	/// The row set is a union, and each of its three provenances appears.
	#[test]
	fn the_inventory_is_a_union_of_two_sets_that_do_not_coincide() {
		use super::{inventory, Presence};

		let mut observed = crate::observed::Observed::default();
		observed.links.push(link("eth0", "", false));
		// Present and not configured: hiding something demonstrably on the
		// machine is worse than showing something netcfgd does not manage.
		observed.links.push(link("docker0", "bridge", false));

		let mut document = crate::Document::default();
		document.interfaces.push(
			serde_json::from_value(serde_json::json!({ "name": "eth0" })).expect("an interface"),
		);
		// Configured and not present: no kernel link exists for it at all, so
		// an observation-only list could not show this row.
		document.interfaces.push(
			serde_json::from_value(serde_json::json!({ "name": "eth1" })).expect("an interface"),
		);
		document.networks.push(
			serde_json::from_value(serde_json::json!({
				"id": "office",
				"ssid": "6f6666696365",
				"security": { "type": "open" },
				"hidden": true,
			}))
			.expect("a network"),
		);

		let rows = inventory(Some(&document), &observed);
		let find = |name: &str| {
			rows.iter()
				.find(|entry| entry.name == name)
				.unwrap_or_else(|| panic!("no row for {name}"))
		};

		assert_eq!(find("eth0").presence, Presence::Present);
		assert!(find("eth0").configured);

		assert_eq!(find("docker0").presence, Presence::Present);
		assert!(!find("docker0").configured, "nobody configured docker0");

		assert_eq!(find("eth1").presence, Presence::Absent);
		assert!(find("eth1").configured);

		// A configured network is a link whether or not a radio is on it, and
		// this one is hidden, so no scan could settle it.
		assert_eq!(find("office").presence, Presence::Unknown);
		assert_eq!(find("office").category, super::Category::Wifi);

		// Sorted, so a list does not reorder itself under somebody reading it.
		let mut sorted = rows.clone();
		sorted.sort_by(|left, right| left.name.cmp(&right.name));
		assert_eq!(rows, sorted);

		// And with no document the union is just what the machine has.
		let bare = inventory(None, &observed);
		assert_eq!(bare.len(), 2);
		assert!(bare.iter().all(|entry| !entry.configured));
	}

	/// One connection is one row, and it is the network's.
	///
	/// **A radio and the network it is on were two rows, and neither was
	/// complete**: the radio held the addresses, the state and the lease while
	/// the network held only its name. All the detail on one, all the meaning
	/// on the other. The network is the link -- the radio is the hardware it
	/// runs on -- so the network's row is the one that survives, naming its
	/// carrier.
	#[test]
	fn a_radio_carrying_a_configured_network_does_not_get_its_own_row() {
		use super::{inventory, Presence, Subject};

		let mut observed = crate::observed::Observed::default();
		let mut radio = link("wlan0", "", true);
		radio.network = Some("office".to_owned());
		observed.links.push(radio);

		let mut document = crate::Document::default();
		document.interfaces.push(
			serde_json::from_value(serde_json::json!({ "name": "wlan0" })).expect("an interface"),
		);
		document.networks.push(
			serde_json::from_value(serde_json::json!({
				"id": "office",
				"ssid": "6f6666696365",
				"security": { "type": "open" },
			}))
			.expect("a network"),
		);

		let rows = inventory(Some(&document), &observed);
		assert_eq!(rows.len(), 1, "one connection is one row: {rows:?}");
		assert_eq!(rows[0].name, "office");
		assert_eq!(rows[0].subject, Subject::Network);
		assert_eq!(rows[0].presence, Presence::Present);
		// The hardware it is running on, in the row rather than inferred by
		// whoever is reading it.
		assert_eq!(rows[0].carrier.as_deref(), Some("wlan0"));

		// **A radio joined to something nobody configured keeps its own row**,
		// because there is no other row for it to hide behind -- and that is
		// a real state: an operator may associate by hand.
		observed.links[0].network = Some("somewhere-else".to_owned());
		let rows = inventory(Some(&document), &observed);
		let names: Vec<&str> = rows.iter().map(|entry| entry.name.as_str()).collect();
		assert!(
			names.contains(&"wlan0"),
			"the radio keeps its row: {names:?}"
		);
		// And the configured network is now nowhere, which is honest: nothing
		// is on it and no scan has looked.
		let office = rows
			.iter()
			.find(|entry| entry.name == "office")
			.expect("office");
		assert_eq!(office.presence, Presence::Unknown);
		assert_eq!(office.carrier, None);

		// An idle radio keeps its row too, for the same reason.
		observed.links[0].network = None;
		let names: Vec<String> = inventory(Some(&document), &observed)
			.into_iter()
			.map(|entry| entry.name)
			.collect();
		assert!(names.contains(&"wlan0".to_owned()), "{names:?}");
	}

	/// An interface row and a network row are told apart, because acting on
	/// them differs.
	///
	/// Selecting a network and pressing configure opened an *interface* dialog
	/// for an interface that does not exist, which is what happens when a list
	/// mixes two kinds of thing without saying which is which.
	#[test]
	fn a_row_says_which_kind_of_block_it_is() {
		use super::{inventory, Subject};

		let mut observed = crate::observed::Observed::default();
		observed.links.push(link("eth0", "", false));

		let mut document = crate::Document::default();
		document.networks.push(
			serde_json::from_value(serde_json::json!({
				"id": "office",
				"ssid": "6f6666696365",
				"security": { "type": "open" },
			}))
			.expect("a network"),
		);

		let rows = inventory(Some(&document), &observed);
		let find = |name: &str| {
			rows.iter()
				.find(|entry| entry.name == name)
				.unwrap_or_else(|| panic!("no row for {name}"))
		};
		assert_eq!(find("eth0").subject, Subject::Interface);
		assert_eq!(find("office").subject, Subject::Network);
	}

	/// A modem is the one category the link cannot answer for itself.
	#[test]
	fn a_modem_is_known_from_the_document_and_nowhere_else() {
		// The document built from its own default and one device, rather than
		// spelled out: a literal whole document here would have to be edited
		// every time `Document` gains a required field.
		let mut modem = crate::Document::default();
		modem.devices.push(
			serde_json::from_value(serde_json::json!({
				"name": "wwan0",
				"modem": { "sim": [] },
			}))
			.expect("a device"),
		);

		// Without the document it is whatever it looks like, which is an
		// honest answer rather than a guess.
		assert_eq!(
			category_of(&link("wwan0", "", false), None),
			Category::Ethernet
		);
		// With it, the document wins -- and it has to be asked first, since a
		// modem's link looks ordinary to the kernel.
		assert_eq!(
			category_of(&link("wwan0", "", false), Some(&modem)),
			Category::Modem
		);
		// And a device with no modem block is not made one by the document
		// merely existing.
		assert_eq!(
			category_of(&link("enp0s31f6", "", false), Some(&modem)),
			Category::Ethernet
		);
	}
}
