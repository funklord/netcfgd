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

use crate::observed::ObservedLink;
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

/// Whether the document gives this link's device a modem policy.
fn is_modem(link: &ObservedLink, document: &crate::Document) -> bool {
	document
		.devices
		.iter()
		.any(|device| device.name == link.name && device.modem.is_some())
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
