//! One answer to "is this machine on the network, and on what".
//!
//! **Four clients were deriving this and no two agreed.** The Qt tray computed
//! `routed`/`local`/`offline` from the links; the TDE tray transcribed the same
//! rule into `TQt3`, comments and all; the `NetworkManager` shim answered a coarser
//! `CONNECTED_GLOBAL`/`DISCONNECTED`; and the text interface had no notion of it
//! at all. `Request::Status` hands back the raw observation, so every client had
//! to invent a verdict, and each invented a slightly different one.
//!
//! That is the argument [`crate::wifi::network_for`] already makes for living in
//! the model -- "here rather than in either caller, because there are two" --
//! with four callers and three languages instead of two callers and one.
//!
//! **The rule is not obvious, which is why copying it was expensive.**
//! Associating is not addressing and addressing is not routing, and the middle
//! rung exists because the icon used to lie: a machine holding an address with
//! nothing to route through was drawn as connected, and it fails every request
//! while looking configured.

use crate::observed::{Observed, ObservedLink};
use serde::{Deserialize, Serialize};

/// The loopback interface, which is never what anybody means by connected.
///
/// Not in [`Policy::ignore`] and not overridable, because it is not a policy
/// question: a machine talking to itself is the definition of not being on a
/// network, on every machine there has ever been.
const LOOPBACK: &str = "lo";

/// Interfaces that are somebody else's by default.
///
/// **The default group is "every link except the absurd ones", and this is the
/// absurd ones.** A container bridge, a veth pair's end, a libvirt bridge: each
/// holds an address, none is how this machine reaches the network, and a
/// machine with nothing else would otherwise report itself locally connected
/// and name one. Measured on the reporting machine, where `docker0` holds
/// `172.17.0.1/16`.
///
/// **A trailing `*` is a prefix**, because these are named by pattern --
/// `br-1a2b3c` is docker's, and nobody can list them. No other wildcard: this
/// is a short list of families, not a matching language.
///
/// **What is deliberately absent is as important as what is here.** A
/// `WireGuard` interface, a `tun` or a `tap` is often exactly the link an
/// operator means -- a laptop whose real uplink is a VPN is ordinary -- so
/// excluding them by default would be netcfgd deciding somebody's network for
/// them. A document that wants them out says so.
///
/// Writing `ignore` in a document **replaces** this list rather than adding to
/// it, so an operator who needs one of these counted can have it.
pub const DEFAULT_IGNORE: &[&str] = &["docker*", "br-*", "veth*", "virbr*", "vnet*"];

/// How far towards carrying traffic this machine has actually got.
///
/// Ordered, and comparable: each rung implies the ones below it. A client that
/// wants a plain yes or no asks [`Connectivity::connected`] rather than
/// collapsing these itself, which is how the middle rung got lost the first
/// time.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Rung {
	/// Nothing to work with: no interface that counts holds an address.
	Offline,
	/// Addressed, and nothing to route through.
	///
	/// **The rung that exists because it was once reported as connected.** A
	/// machine here reaches its own subnet and fails everything else, which
	/// looks like a working configuration to anybody reading an icon.
	Local,
	/// A default route exists, so traffic has somewhere to go.
	///
	/// This is as far as netcfgd can tell without asking: a route is a claim
	/// about where packets are sent, not about what happens to them. A captive
	/// portal looks exactly like this.
	Routed,
	/// A probe has confirmed traffic actually reaches somewhere.
	///
	/// Only reachable where the document configures a probe. Absent one, a
	/// machine stops at [`Rung::Routed`] and that is the honest answer rather
	/// than a pessimistic one.
	Online,
}

/// What this machine is mainly connected through.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Primary {
	/// The interface carrying it.
	pub interface: String,
	/// What to call it, for somebody reading a tray or a status line.
	///
	/// The `network` block's id where the link is a radio associated with one,
	/// which is the name an operator recognises, and the interface's own name
	/// otherwise. Never empty.
	pub label: String,
	/// Whether it is a radio, so a client can pick an icon without guessing
	/// from the name.
	pub wireless: bool,
}

/// The whole answer: how far this machine got, and through what.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Connectivity {
	/// How far towards carrying traffic.
	pub rung: Rung,
	/// The link it got there through, where one can be named.
	///
	/// `None` at [`Rung::Offline`], and also where the machine is addressed on
	/// something but has no default route to rank -- there is no *main* link
	/// when nothing is carrying anything.
	#[serde(skip_serializing_if = "Option::is_none", default)]
	pub primary: Option<Primary>,
}

impl Connectivity {
	/// The plain yes or no, for a client that wants one.
	///
	/// True from [`Rung::Routed`] up. Derived here rather than left to each
	/// caller so that "connected" means one thing across the tray, the shim and
	/// the text interface -- which is the whole reason this module exists.
	#[must_use]
	pub fn connected(&self) -> bool {
		self.rung >= Rung::Routed
	}
}

/// What the document says should count as connected.
///
/// Defaults to the answer that needs no configuration and no probe.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Requires {
	/// A default route. The default, and what a machine with no probe can know.
	#[default]
	Route,
	/// A probe that has actually answered.
	///
	/// For a machine behind a captive portal or a filtering gateway, where a
	/// route proves nothing. Only meaningful where a probe is configured; a
	/// document asking for this on a machine with none gets
	/// [`Rung::Routed`] and never [`Rung::Online`], which is the honest
	/// outcome rather than a permanent red icon.
	Probe,
	/// An address is enough.
	///
	/// For a machine whose job is its own subnet -- a lab gateway, an
	/// appliance -- where a default route is not expected and its absence is
	/// not a fault.
	Address,
}

/// Which links count, and what counts as connected.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Policy {
	/// What the operator means by connected.
	#[serde(default)]
	pub requires: Requires,
	/// Interfaces that never count, whatever they are holding.
	///
	/// **`docker0` is why this exists.** It is down and holds `172.17.0.1/16`
	/// on any machine with docker installed, and both trays counted any
	/// addressed interface that was not `lo` -- so a wired-only machine with no
	/// network at all reported itself locally connected, naming a bridge to
	/// nowhere. Expressed rather than hardcoded: which interfaces are somebody
	/// else's business is a property of the machine, not of netcfgd.
	#[serde(default = "default_ignore")]
	pub ignore: Vec<String>,
}

impl Default for Policy {
	fn default() -> Self {
		Self {
			requires: Requires::Route,
			ignore: default_ignore(),
		}
	}
}

/// [`DEFAULT_IGNORE`] as a document would have written it.
fn default_ignore() -> Vec<String> {
	DEFAULT_IGNORE
		.iter()
		.map(|name| (*name).to_owned())
		.collect()
}

/// Whether a name is covered by one pattern, where a trailing `*` is a prefix.
fn matches(pattern: &str, name: &str) -> bool {
	pattern.strip_suffix('*').map_or_else(
		|| pattern == name,
		|prefix| {
			// A bare `*` would match everything, including the link the machine
			// is actually on. Refused rather than honoured: a document that
			// ignores every link is asking for a verdict that cannot be
			// computed, and silently answering "offline" for ever is the worst
			// way to tell it so.
			!prefix.is_empty() && name.starts_with(prefix)
		},
	)
}

impl Policy {
	/// Whether a link counts towards the verdict at all.
	///
	/// **Down links do not, and that is separate from the ignore list.** The
	/// list is for interfaces that are up and still not the operator's network;
	/// an interface that is administratively down is not carrying anything for
	/// anybody, and no document should have to say so.
	fn counts(&self, link: &ObservedLink) -> bool {
		link.name != LOOPBACK
			&& link.up
			&& !self
				.ignore
				.iter()
				.any(|pattern| matches(pattern, &link.name))
	}
}

/// Work out how far this machine has got, and through what.
///
/// **One function, four callers.** See the module documentation for what each
/// of them used to do instead.
#[must_use]
pub fn overall(observed: &Observed, policy: &Policy) -> Connectivity {
	// **Where the document declares an `uplink` set, that set is the answer.**
	// A machine whose operator said which links carry its traffic has said what
	// "connected" means on it, and a verdict assembled from every other link
	// would contradict the thing they wrote down. Absent such a set the rule is
	// unchanged: every link the policy counts, best default route wins.
	if let Some(uplink) = observed
		.linksets
		.iter()
		.find(|set| set.name == crate::linkset::UPLINK)
	{
		return through(observed, policy, uplink);
	}

	let counts = |name: &str| {
		observed
			.links
			.iter()
			.find(|link| link.name == name)
			.is_some_and(|link| policy.counts(link))
	};

	// The best default route on a link that counts, where best is the lowest
	// metric -- which is what the kernel means by it and what `network.metric`
	// is expressed in. A route with no metric reads as 0, the kernel's own
	// default and the strongest.
	let best = observed
		.routes
		.iter()
		.filter(|route| route.destination == "default" && counts(&route.interface))
		.min_by_key(|route| (route.metric.unwrap_or(0), route.interface.clone()));

	let addressed = observed
		.addresses
		.iter()
		.any(|address| counts(&address.interface));

	let Some(route) = best else {
		// Nothing is carrying traffic, so there is no main link to name even
		// where something holds an address.
		return Connectivity {
			rung: if addressed && policy.requires == Requires::Address {
				Rung::Routed
			} else if addressed {
				Rung::Local
			} else {
				Rung::Offline
			},
			primary: None,
		};
	};

	let link = observed.links.iter().find(|l| l.name == route.interface);
	// **`Some(false)` and `None` are different answers**, which is the rule
	// `ObservedLink::reachable` states: a link nobody probed keeps its
	// standing, and only an explicit refusal takes it away.
	let probe = link.and_then(|l| l.reachable);
	let rung = match (policy.requires, probe) {
		(Requires::Probe, Some(true)) => Rung::Online,
		(Requires::Probe, Some(false)) => Rung::Local,
		// Asked for a probe and there is none, or did not ask: a route is as
		// far as anybody can honestly say.
		_ => Rung::Routed,
	};

	Connectivity {
		rung,
		primary: link.map(|link| Primary {
			interface: link.name.clone(),
			// The `network` block's id where the radio is on one, because that
			// is the name an operator recognises and the same string
			// `ncfg wifi status` prints.
			label: link.network.clone().unwrap_or_else(|| link.name.clone()),
			wireless: link.wireless,
		}),
	}
}

/// The verdict as the `uplink` set sees it.
///
/// The same ladder as [`overall`], asked about one link instead of about the
/// machine: the set has already decided which link that is, and asking again
/// here would be the fifth copy of a rule this module exists to have one of.
fn through(observed: &Observed, policy: &Policy, uplink: &crate::linkset::Chosen) -> Connectivity {
	let Some(interface) = uplink.interface.as_deref() else {
		// The set has nothing usable. **Not "offline" by definition**: a
		// member may still hold an address -- a cable into a switch with no
		// uplink of its own does -- and the middle rung is exactly the state
		// where a machine is configured and reaching nothing.
		let addressed = uplink.members.iter().any(|member| {
			member.interface.as_deref().is_some_and(|interface| {
				observed
					.addresses
					.iter()
					.any(|address| address.interface == interface)
			})
		});
		return Connectivity {
			rung: if addressed {
				Rung::Local
			} else {
				Rung::Offline
			},
			primary: None,
		};
	};

	let routed = observed
		.routes
		.iter()
		.any(|route| route.destination == "default" && route.interface == interface);
	let link = observed.links.iter().find(|link| link.name == interface);
	let addressed = observed
		.addresses
		.iter()
		.any(|address| address.interface == interface);
	// `Some(false)` and `None` are different answers, which is the rule
	// `ObservedLink::reachable` states and the one the set itself applies when
	// deciding whether this member was eligible at all.
	let probe = link.and_then(|link| link.reachable);

	let rung = if routed || (addressed && policy.requires == Requires::Address) {
		match (policy.requires, probe) {
			(Requires::Probe, Some(true)) => Rung::Online,
			(Requires::Probe, Some(false)) => Rung::Local,
			_ => Rung::Routed,
		}
	} else if addressed {
		Rung::Local
	} else {
		Rung::Offline
	};

	Connectivity {
		rung,
		primary: (rung > Rung::Offline).then(|| Primary {
			interface: interface.to_owned(),
			// **The set's own word for the member**: a `network` block's id
			// where the member is a wifi network, an interface's name where it
			// is an interface, and the inner set's name where it is a nested
			// set -- which is the name the operator wrote in the set and so the
			// one they will recognise in a tray.
			label: uplink
				.active
				.clone()
				.unwrap_or_else(|| interface.to_owned()),
			wireless: link.is_some_and(|link| link.wireless),
		}),
	}
}

#[cfg(test)]
mod tests {
	use super::{overall, Policy, Requires, Rung};
	use crate::observed::{Observed, ObservedLink};

	/// A link, built from JSON rather than a literal.
	///
	/// The idiom this tree already uses where a struct has no `Default`: a
	/// literal here would have to be edited every time `ObservedLink` gains a
	/// field, which is how a test comes to assert a shape nobody meant.
	fn link(name: &str, up: bool, wireless: bool) -> ObservedLink {
		serde_json::from_value(serde_json::json!({
			"name": name,
			"index": 1,
			"kind": "",
			"wireless": wireless,
			"up": up,
			"carrier": up,
			"mtu": 1500,
			"forwarding": false,
			"qdisc_ingress": false,
			"privacy": false,
			"ownership": "unknown",
			"private_key_loaded": false,
		}))
		.expect("a link")
	}

	fn addressed(observed: &mut Observed, interface: &str, address: &str) {
		observed.addresses.push(
			serde_json::from_value(serde_json::json!({
				"interface": interface,
				"address": address,
				"ownership": "foreign",
			}))
			.expect("an address"),
		);
	}

	fn default_route(observed: &mut Observed, interface: &str, metric: Option<u32>) {
		observed.routes.push(
			serde_json::from_value(serde_json::json!({
				"interface": interface,
				"destination": "default",
				"metric": metric,
				"ownership": "foreign",
			}))
			.expect("a route"),
		);
	}

	/// The set the operator declared decides, and the rest of the machine does
	/// not get a vote.
	///
	/// **This is the sentence "connected" has needed all along.** The rule
	/// without a set is "the best default route on any link that counts", which
	/// is a guess about which link matters assembled from the routing table. A
	/// machine that says which links carry its traffic has answered that
	/// question itself, and a verdict naming some other link would contradict
	/// the thing its operator wrote down.
	#[test]
	fn where_an_uplink_set_is_declared_it_is_the_answer() {
		let mut observed = Observed::default();
		observed.links.push(link("eth0", true, false));
		observed.links.push(link("wlan0", true, true));
		addressed(&mut observed, "eth0", "10.0.0.2/24");
		addressed(&mut observed, "wlan0", "192.168.1.5/24");
		// The radio holds the better route, so the ruleless answer is the
		// radio. The set says the cable.
		default_route(&mut observed, "wlan0", Some(600));
		default_route(&mut observed, "eth0", Some(100));

		let answer = overall(&observed, &Policy::default());
		assert_eq!(
			answer
				.primary
				.as_ref()
				.map(|primary| primary.interface.clone()),
			Some("eth0".to_owned()),
			"with no set, the best metric wins"
		);

		observed.linksets.push(crate::linkset::Chosen {
			name: crate::linkset::UPLINK.to_owned(),
			active: Some("office".to_owned()),
			interface: Some("wlan0".to_owned()),
			members: Vec::new(),
		});
		let answer = overall(&observed, &Policy::default());
		let primary = answer.primary.expect("a primary");
		assert_eq!(primary.interface, "wlan0");
		assert!(primary.wireless);
		assert_eq!(
			primary.label, "office",
			"named as the set names it, which is what an operator recognises"
		);
		assert_eq!(answer.rung, Rung::Routed);
	}

	/// A set with nothing usable in it is not connected -- and is not
	/// automatically offline either.
	#[test]
	fn a_set_with_no_usable_member_stops_at_what_it_is_holding() {
		let mut observed = Observed::default();
		observed.links.push(link("eth0", true, false));
		addressed(&mut observed, "eth0", "10.0.0.2/24");
		// Something else entirely is routing. It is not in the set, so it is
		// not this machine's uplink and does not make it connected.
		observed.links.push(link("wg0", true, false));
		addressed(&mut observed, "wg0", "10.9.0.2/32");
		default_route(&mut observed, "wg0", Some(50));

		let member = |name: &str, interface: Option<&str>| crate::linkset::Standing {
			name: name.to_owned(),
			interface: interface.map(std::borrow::ToOwned::to_owned),
			metric: None,
			ineligible: Some(crate::linkset::Ineligible::NoCarrier),
		};
		observed.linksets.push(crate::linkset::Chosen {
			name: crate::linkset::UPLINK.to_owned(),
			active: None,
			interface: None,
			members: vec![member("eth0", Some("eth0"))],
		});

		let answer = overall(&observed, &Policy::default());
		assert_eq!(
			answer.rung,
			Rung::Local,
			"the cable is plugged into something and reaching nothing"
		);
		assert!(!answer.connected());
		assert_eq!(answer.primary, None, "nothing to name");

		// And with nothing held anywhere in the set, offline.
		observed
			.addresses
			.retain(|address| address.interface != "eth0");
		assert_eq!(overall(&observed, &Policy::default()).rung, Rung::Offline);
	}

	/// A machine with nothing but a bridge to nowhere is offline.
	///
	/// **`docker0` is why this test exists.** It is administratively down and
	/// holds `172.17.0.1/16` on any machine with docker installed, and both
	/// trays counted every addressed interface that was not `lo` -- so a
	/// wired-only machine with no network at all drew the amber "locally
	/// connected" icon and named a bridge. Measured on the reporting machine,
	/// where `docker0` is exactly that.
	#[test]
	fn a_down_interface_holding_an_address_is_not_a_connection() {
		let mut observed = Observed::default();
		observed.links.push(link("lo", true, false));
		observed.links.push(link("docker0", false, false));
		addressed(&mut observed, "lo", "127.0.0.1/8");
		addressed(&mut observed, "docker0", "172.17.0.1/16");

		let answer = overall(&observed, &Policy::default());
		assert_eq!(answer.rung, Rung::Offline);
		assert!(!answer.connected());
		assert_eq!(answer.primary, None);

		// **A name the ignore list says nothing about, so this is the `up`
		// check and only the `up` check.** The assertion above stopped being
		// one when `docker*` joined the default list: `docker0` was then
		// excluded by name whether it was up or down, and a sabotage removing
		// the `up` test passed. A down wired NIC that kept a stale address is
		// the case that would have reported a machine locally connected.
		observed.links.push(link("eth1", false, false));
		addressed(&mut observed, "eth1", "192.0.2.9/24");
		assert_eq!(overall(&observed, &Policy::default()).rung, Rung::Offline);
		observed.links[2].up = true;
		assert_eq!(overall(&observed, &Policy::default()).rung, Rung::Local);
		observed.links[2].up = false;

		// And bringing it up changes nothing, because the default group is
		// "every link except the absurd ones" and a container bridge is one of
		// them. `docker0` matches `docker*`.
		observed.links[1].up = true;
		assert_eq!(overall(&observed, &Policy::default()).rung, Rung::Offline);

		// A document that wants it counted says so, and `ignore` replaces the
		// default rather than adding to it -- otherwise an operator whose real
		// uplink is one of these families could never get it back.
		let policy = Policy {
			ignore: Vec::new(),
			..Policy::default()
		};
		assert_eq!(overall(&observed, &policy).rung, Rung::Local);
	}

	/// The default group is every link but the absurd ones, by pattern.
	#[test]
	fn the_default_group_excludes_the_families_that_are_never_an_uplink() {
		let mut observed = Observed::default();
		for name in ["docker0", "br-1a2b3c", "veth9f2", "virbr0", "vnet7"] {
			observed.links.push(link(name, true, false));
			addressed(&mut observed, name, "172.17.0.1/16");
		}
		assert_eq!(overall(&observed, &Policy::default()).rung, Rung::Offline);

		// **Not in the list, deliberately.** A laptop whose real uplink is a
		// VPN is ordinary, so excluding these by default would be netcfgd
		// deciding somebody's network for them.
		for name in ["wg0", "tun0", "tap0"] {
			observed.links.push(link(name, true, false));
			addressed(&mut observed, name, "10.9.0.2/24");
		}
		assert_eq!(overall(&observed, &Policy::default()).rung, Rung::Local);

		// A bare `*` would ignore every link, including the one the machine is
		// on, and answer offline for ever. Refused rather than honoured.
		let policy = Policy {
			ignore: vec!["*".to_owned()],
			..Policy::default()
		};
		assert_eq!(overall(&observed, &policy).rung, Rung::Local);

		// An exact name still means an exact name.
		let policy = Policy {
			ignore: vec!["wg0".to_owned()],
			..Policy::default()
		};
		assert_eq!(overall(&observed, &policy).rung, Rung::Local);
	}

	/// Addressed with nothing to route through is not connected.
	///
	/// The rung that exists because it was once reported as connected: a
	/// machine here reaches its own subnet and fails everything else.
	#[test]
	fn an_address_without_a_route_is_not_connected() {
		let mut observed = Observed::default();
		observed.links.push(link("eth0", true, false));
		addressed(&mut observed, "eth0", "192.168.1.10/24");

		let answer = overall(&observed, &Policy::default());
		assert_eq!(answer.rung, Rung::Local);
		assert!(!answer.connected());
		// Nothing is carrying traffic, so there is no main link to name.
		assert_eq!(answer.primary, None);

		// Unless the document says an address is what it means, which is the
		// appliance on its own subnet.
		let policy = Policy {
			requires: Requires::Address,
			..Policy::default()
		};
		assert!(overall(&observed, &policy).connected());
	}

	/// The main link is the one with the best default route, and it is named.
	#[test]
	fn the_primary_is_the_best_route_and_carries_the_networks_name() {
		let mut observed = Observed::default();
		observed.links.push(link("eth0", true, false));
		let mut radio = link("wlan0", true, true);
		radio.network = Some("EMP-XYLEM".to_owned());
		observed.links.push(radio);
		addressed(&mut observed, "eth0", "192.168.1.10/24");
		addressed(&mut observed, "wlan0", "10.78.60.134/22");
		default_route(&mut observed, "eth0", Some(400));
		default_route(&mut observed, "wlan0", Some(200));

		let answer = overall(&observed, &Policy::default());
		assert_eq!(answer.rung, Rung::Routed);
		assert!(answer.connected());
		let primary = answer.primary.expect("something is carrying traffic");
		// Lower wins, which is what a metric means and what `network.metric`
		// is expressed in (0154).
		assert_eq!(primary.interface, "wlan0");
		assert!(primary.wireless);
		// The name an operator recognises, not the interface.
		assert_eq!(primary.label, "EMP-XYLEM");

		// Give the wire the better metric and the answer moves with it.
		observed.routes[0].metric = Some(100);
		let primary = overall(&observed, &Policy::default())
			.primary
			.expect("something is carrying traffic");
		assert_eq!(primary.interface, "eth0");
		assert!(!primary.wireless);
		// A wired link has no network block, so it is called what it is.
		assert_eq!(primary.label, "eth0");
	}

	/// A route is a claim about where packets are sent, not about what happens.
	#[test]
	fn a_probe_separates_a_route_from_a_connection() {
		let mut observed = Observed::default();
		observed.links.push(link("wlan0", true, true));
		addressed(&mut observed, "wlan0", "10.0.0.5/24");
		default_route(&mut observed, "wlan0", Some(200));
		let policy = Policy {
			requires: Requires::Probe,
			..Policy::default()
		};

		// No probe has answered. Asking for one does not invent a refusal:
		// a machine with none stops at `Routed`, which is a working icon and
		// not a permanent red one.
		assert_eq!(overall(&observed, &policy).rung, Rung::Routed);
		assert!(overall(&observed, &policy).connected());

		// One that answered yes is the only way to reach the top rung.
		observed.links[0].reachable = Some(true);
		assert_eq!(overall(&observed, &policy).rung, Rung::Online);

		// And one that answered no is the captive portal: a default route,
		// and nothing at the other end of it.
		observed.links[0].reachable = Some(false);
		assert_eq!(overall(&observed, &policy).rung, Rung::Local);
		assert!(!overall(&observed, &policy).connected());

		// A document that did not ask for a probe is not overruled by one.
		// `Some(false)` withholding a route from a machine that never asked is
		// the mistake `ObservedLink::reachable` warns about.
		assert_eq!(overall(&observed, &Policy::default()).rung, Rung::Routed);
	}
}
