#![forbid(unsafe_code)]

//! Kernel dumps plus recorded prior state, turned into the observed model.
//!
//! Where decision 0002 becomes code. Two questions get answered here and
//! nowhere else:
//!
//! - **Is this object ours?** A route carrying `rtm_protocol` 110 is;
//!   an address carrying `IFA_PROTO` 110 is, on a kernel new enough to report
//!   it. Everything else is foreign or unknown, and neither may be removed.
//! - **Which source produced it?** Decision 0006 rule 7 needs that to tell a
//!   missing static address from an expired lease, and the kernel does not
//!   know, so it comes from [`PriorState`].
//!
//! [`build`] is a pure function of its inputs, so the whole tagging policy is
//! testable against synthetic dumps with no kernel present. [`current`] is the
//! thin wrapper that fetches real ones.

pub mod host;

use netcfgd_model::route::NETCFGD_PROTO;
use netcfgd_model::ObservedRule;
use netcfgd_model::{
	Observed, ObservedAddress, ObservedBackend, ObservedLink, ObservedRoute, Origin, Ownership,
};
use netcfgd_sys::Snapshot;
use std::io;

/// What netcfgd recorded about its own past actions.
///
/// Read from `/run/netcfgd/`. Three things the kernel cannot tell us live
/// here: which links we created, which source produced each address and route,
/// and which backends we started.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PriorState {
	/// Names of links netcfgd created.
	pub created_links: Vec<String>,
	/// `(interface, cidr, origin)` for each address netcfgd installed.
	pub address_origins: Vec<(String, String, Origin)>,
	/// `(interface, destination, origin)` for each route netcfgd installed.
	pub route_origins: Vec<(String, String, Origin)>,
	/// Backends netcfgd believes it started.
	pub backends: Vec<ObservedBackend>,
	/// DNS scopes netcfgd has delivered.
	pub dns: Vec<netcfgd_model::AppliedDns>,
	/// Interfaces netcfgd turned IP forwarding on for.
	pub forwarding: Vec<String>,
	/// Interfaces netcfgd set the root qdisc on.
	pub qdisc: Vec<String>,
	/// Interfaces netcfgd installed an ingress redirect on.
	pub ingress: Vec<String>,
	/// Prefixes a `DHCPv6` client reported, read from `/run`.
	///
	/// Prior state rather than a kernel read because a delegated prefix is not
	/// kernel state: nothing in the kernel knows the machine was given a /56
	/// until an address is derived from it. The client is the only source, and
	/// netcfgd does not implement the client (decision 0004).
	pub delegations: Vec<netcfgd_model::Delegation>,
	/// What helpers and daemons reported about interfaces, read from `/run`.
	///
	/// Prior state for the same reason a delegation is: the configuration a
	/// cellular bearer or a tunnel comes up with is known to whatever negotiated
	/// it, and netcfgd negotiates neither (decisions 0044, 0045 and 0047). The
	/// contract is `docs/interface-report.md`.
	pub reports: Vec<netcfgd_model::ObservedReport>,
}

impl PriorState {
	fn address_origin(&self, interface: &str, cidr: &str) -> Option<Origin> {
		self.address_origins
			.iter()
			.find(|(iface, address, _)| iface == interface && address == cidr)
			.map(|(_, _, origin)| *origin)
	}

	fn route_origin(&self, interface: &str, destination: &str) -> Option<Origin> {
		self.route_origins
			.iter()
			.find(|(iface, dst, _)| iface == interface && dst == destination)
			.map(|(_, _, origin)| *origin)
	}
}

/// One rule, with ownership decided the way a route's is.
///
/// `FRA_PROTOCOL` round-trips through the kernel, so unlike a link this needs
/// no recorded state: a rule carrying 110 is netcfgd's and nothing else is.
/// A kernel too old for the attribute reports 0 on everything, which reads as
/// foreign -- so netcfgd installs and never removes, which is the safe way to
/// be wrong.
fn observed_rule(record: &netcfgd_sys::rule::RuleRecord) -> ObservedRule {
	let cidr = |selector: Option<(std::net::IpAddr, u8)>| {
		selector.map(|(address, prefix)| format!("{address}/{prefix}"))
	};
	ObservedRule {
		priority: record.priority,
		// `AF_INET6`. Named here rather than pulled from libc, which this
		// crate does not depend on and should not start to for one constant.
		family: if record.family == 10 {
			netcfgd_model::RuleFamily::Inet6
		} else {
			netcfgd_model::RuleFamily::Inet
		},
		from: cidr(record.from),
		to: cidr(record.to),
		iif: record.iif.clone(),
		oif: record.oif.clone(),
		fwmark: record.fwmark,
		fwmask: record.fwmask,
		// Zero is `RT_TABLE_UNSPEC`, which for an action other than a lookup
		// is simply "no table" rather than "table zero".
		table: (record.table != 0).then_some(record.table),
		action: match record.action {
			netcfgd_sys::rule::FR_ACT_BLACKHOLE => netcfgd_model::RuleAction::Blackhole,
			netcfgd_sys::rule::FR_ACT_UNREACHABLE => netcfgd_model::RuleAction::Unreachable,
			netcfgd_sys::rule::FR_ACT_PROHIBIT => netcfgd_model::RuleAction::Prohibit,
			_ => netcfgd_model::RuleAction::Lookup,
		},
		suppress_prefixlength: record.suppress_prefixlength,
		l3mdev: record.l3mdev,
		invert: record.invert,
		ownership: if record.protocol == NETCFGD_PROTO {
			Ownership::Ours
		} else {
			Ownership::Foreign
		},
	}
}

/// The name of a link, by index.
fn link_name(snapshot: &Snapshot, index: u32) -> Option<&str> {
	snapshot
		.links
		.iter()
		.find(|link| link.index == index)
		.map(|link| link.name.as_str())
}

/// One link, with everything the dumps and the recorded state say about it.
fn observed_link(
	link: &netcfgd_sys::LinkRecord,
	snapshot: &Snapshot,
	prior: &PriorState,
) -> ObservedLink {
	ObservedLink {
		name: link.name.clone(),
		index: link.index,
		kind: link.kind.clone(),
		up: link.up,
		carrier: link.carrier,
		mtu: link.mtu,
		mac: link.mac.clone(),
		master: link
			.master
			.and_then(|index| link_name(snapshot, index).map(ToOwned::to_owned)),
		// The kernel has no protocol field for links, so this can only
		// come from what netcfgd wrote down. A link nobody recorded is
		// never deleted, which is the conservative direction.
		// Filled in by `host::augment`, which is where the impure reads are.
		offloads: Vec::new(),
		ipv6_token: link.ipv6_token.map(|address| address.to_string()),
		qdisc: root_qdisc(snapshot, link.index).map(|record| record.kind.clone()),
		qdisc_ingress: root_qdisc(snapshot, link.index).is_some_and(|record| record.ingress),
		ingress_redirect: snapshot
			.redirects
			.iter()
			.find(|(index, _)| *index == link.index)
			.and_then(|(_, target)| link_name(snapshot, *target).map(ToOwned::to_owned)),
		qdisc_bandwidth_bits: root_qdisc(snapshot, link.index)
			.and_then(|record| record.bandwidth_bits),
		// Not in the netlink snapshot; filled in by `host::augment`,
		// which is why `build` can stay pure.
		forwarding: None,
		ownership: if prior.created_links.contains(&link.name) {
			Ownership::Ours
		} else {
			Ownership::Unknown
		},
		// Generic netlink rather than the link dump, so this is filled in by
		// `host::augment` for the same reason `forwarding` and `offloads` are.
		private_key_loaded: false,
	}
}

/// The root qdisc on one link, from the dump.
fn root_qdisc(snapshot: &Snapshot, index: u32) -> Option<&netcfgd_sys::qdisc::QdiscRecord> {
	snapshot
		.qdiscs
		.roots
		.iter()
		.find(|record| record.index == index)
}

/// Turn a kernel snapshot plus recorded state into the observed model.
///
/// Pure, so the ownership policy that decides whether netcfgd may delete
/// somebody's address is testable without a kernel, without privileges and
/// without a network namespace.
#[must_use]
pub fn build(snapshot: &Snapshot, prior: &PriorState) -> Observed {
	let name_of = |index: u32| -> Option<&str> {
		snapshot
			.links
			.iter()
			.find(|link| link.index == index)
			.map(|link| link.name.as_str())
	};

	let links = snapshot
		.links
		.iter()
		.map(|link| observed_link(link, snapshot, prior))
		.collect();

	let addresses = snapshot
		.addresses
		.iter()
		.filter_map(|address| {
			let interface = name_of(address.index)?.to_owned();
			let cidr = address.cidr();
			Some(ObservedAddress {
				ownership: address_ownership(
					address.proto,
					snapshot.address_proto_supported,
					prior.address_origin(&interface, &cidr).is_some(),
				),
				origin: prior.address_origin(&interface, &cidr),
				interface,
				address: cidr,
				proto: address.proto,
			})
		})
		.collect();

	let routes = snapshot
		.routes
		.iter()
		.filter_map(|route| {
			let interface = name_of(route.index?)?.to_owned();
			let destination = route.destination_text();
			Some(ObservedRoute {
				// A route's protocol comes straight from the kernel on every
				// supported version, so this needs no fallback and no
				// recorded state -- which is exactly why decision 0002 picked
				// a field the kernel round-trips.
				ownership: if route.protocol == NETCFGD_PROTO {
					Ownership::Ours
				} else {
					Ownership::Foreign
				},
				origin: prior.route_origin(&interface, &destination),
				destination,
				via: route.gateway,
				metric: route.metric,
				table: Some(route.table),
				src: route.prefsrc,
				scope: None,
				proto: Some(route.protocol),
				interface,
			})
		})
		.collect();

	let mut observed = Observed {
		rules: snapshot.rules.iter().map(observed_rule).collect(),
		nat: Vec::new(),
		nat_conflicts: Vec::new(),
		forwarding_applied: prior.forwarding.clone(),
		ingress_applied: prior.ingress.clone(),
		qdisc_applied: prior.qdisc.clone(),
		links,
		addresses,
		routes,
		backends: prior.backends.clone(),
		dns: prior.dns.clone(),
		bridge_vlans: snapshot
			.bridge_vlans
			.iter()
			.map(|vlan| netcfgd_model::ObservedBridgeVlan {
				index: vlan.index,
				vid: vlan.vid,
				pvid: vlan.pvid,
				untagged: vlan.untagged,
			})
			.collect(),
		delegations: prior.delegations.clone(),
		reports: prior.reports.clone(),
		address_proto_supported: snapshot.address_proto_supported,
	};
	observed.canonicalize();
	observed
}

/// Decide whether an address is ours.
///
/// Split out and given its own name because it is the one judgement in this
/// crate that can lose a user their address, and it should be reviewable on
/// its own.
fn address_ownership(proto: Option<u8>, proto_supported: bool, recorded: bool) -> Ownership {
	if proto_supported {
		// The kernel is authoritative here. An address with somebody else's
		// tag, or none, is theirs whatever netcfgd wrote down -- a stale
		// record must not be able to claim an address back.
		return match proto {
			Some(NETCFGD_PROTO) => Ownership::Ours,
			_ => Ownership::Foreign,
		};
	}
	// Pre-5.18: no tag to read, so recorded state is all there is. It cannot
	// distinguish our address from an identical one added by hand, so a match
	// is `Unknown` rather than `Ours` and nothing gets removed on the strength
	// of it. Decision 0002 says the fallback is weaker; this is how much.
	if recorded {
		Ownership::Unknown
	} else {
		Ownership::Foreign
	}
}

/// Take a live observation.
///
/// `run_dir` is netcfgd's own `/run` directory, which the impure half needs:
/// an access point's control socket and the record of the policy it was started
/// with both live under it.
///
/// `desired` is the document, where the caller has one, and is needed for
/// exactly one question: whether a running daemon still holds the secret the
/// store has. That comparison cannot happen anywhere else -- the planner is
/// pure and the secret is in neither the document nor the observation
/// (decision 0052) -- so it happens here and only a boolean comes out. `None`
/// is an ordinary answer: `ncfg status` on a machine whose config does not
/// compile still observes the kernel.
///
/// # Errors
///
/// Returns the underlying `io::Error` from the netlink socket.
pub fn current(
	prior: &PriorState,
	run_dir: &std::path::Path,
	desired: Option<&netcfgd_model::Document>,
) -> io::Result<Observed> {
	let snapshot = netcfgd_sys::snapshot()?;
	let mut observed = build(&snapshot, prior);
	host::augment(&mut observed, run_dir, desired);
	Ok(observed)
}

#[cfg(test)]
mod tests {
	use super::*;
	use netcfgd_sys::{AddressRecord, LinkRecord, RouteRecord};

	fn link(index: u32, name: &str) -> LinkRecord {
		LinkRecord {
			index,
			name: name.to_owned(),
			kind: String::new(),
			up: true,
			carrier: true,
			mtu: 1500,
			mac: None,
			master: None,
			ipv6_token: None,
		}
	}

	fn address(index: u32, text: &str, prefix_len: u8, proto: Option<u8>) -> AddressRecord {
		AddressRecord {
			index,
			address: text.parse().expect("test address"),
			prefix_len,
			proto,
		}
	}

	/// The constant is duplicated in `netcfgd-sys`, which cannot depend on
	/// the model. If the two ever disagree, every route netcfgd installed
	/// becomes foreign to it and drift detection silently stops working.
	#[test]
	fn the_two_copies_of_the_protocol_constant_agree() {
		assert_eq!(NETCFGD_PROTO, netcfgd_sys::wire::netcfgd_proto());
		assert_eq!(
			netcfgd_model::route::MAIN_TABLE,
			netcfgd_sys::ops::RT_TABLE_MAIN
		);
	}

	#[test]
	fn our_tag_makes_an_address_ours_on_a_modern_kernel() {
		assert_eq!(
			address_ownership(Some(NETCFGD_PROTO), true, false),
			Ownership::Ours
		);
	}

	#[test]
	fn another_tag_is_foreign_even_if_we_recorded_it() {
		// A stale record must not be able to claim back an address that the
		// kernel says belongs to somebody else.
		assert_eq!(address_ownership(Some(4), true, true), Ownership::Foreign);
	}

	#[test]
	fn an_untagged_address_is_foreign_on_a_modern_kernel() {
		assert_eq!(address_ownership(None, true, true), Ownership::Foreign);
	}

	/// The flag is a lower bound: a live 6.12 kernel reports no `IFA_PROTO` on
	/// any address until netcfgd installs one, so a fresh system starts in the
	/// weak mode and calibrates into the strong one. Checked against a real
	/// kernel, not assumed.
	#[test]
	fn ownership_calibrates_once_we_own_an_address() {
		let fresh = Snapshot {
			links: vec![link(1, "lo")],
			addresses: vec![address(1, "127.0.0.1", 8, None)],
			address_proto_supported: false,
			..Snapshot::default()
		};
		let prior = PriorState {
			address_origins: vec![("lo".to_owned(), "127.0.0.1/8".to_owned(), Origin::Static)],
			..PriorState::default()
		};
		// Recorded, but the kernel offered no tag: Unknown, and not removable.
		assert_eq!(
			build(&fresh, &prior).addresses[0].ownership,
			Ownership::Unknown
		);

		// Once one address comes back tagged, the whole snapshot is in the
		// strong mode and the same address resolves to Ours.
		let calibrated = Snapshot {
			addresses: vec![address(1, "127.0.0.1", 8, Some(NETCFGD_PROTO))],
			address_proto_supported: true,
			..fresh
		};
		assert_eq!(
			build(&calibrated, &prior).addresses[0].ownership,
			Ownership::Ours
		);
	}

	#[test]
	fn the_fallback_never_reaches_ours() {
		// The whole point of decision 0002's fallback being weaker: on a
		// pre-5.18 kernel a recorded address is Unknown, and Unknown cannot be
		// removed. Under-claiming costs convenience; over-claiming deletes an
		// address somebody typed.
		assert_eq!(address_ownership(None, false, true), Ownership::Unknown);
		assert_eq!(address_ownership(None, false, false), Ownership::Foreign);
		assert!(!Ownership::Unknown.may_remove());
	}

	#[test]
	fn a_snapshot_becomes_a_model_with_names_resolved() {
		let snapshot = Snapshot {
			qdiscs: netcfgd_sys::qdisc::QdiscDump::default(),
			redirects: Vec::new(),
			rules: Vec::new(),
			bridge_vlans: Vec::new(),
			links: vec![link(2, "eth0"), link(3, "br0")],
			addresses: vec![
				address(2, "192.168.1.10", 24, Some(NETCFGD_PROTO)),
				address(3, "10.0.0.1", 24, Some(4)),
			],
			routes: vec![RouteRecord {
				index: Some(2),
				destination: None,
				dst_len: 0,
				gateway: Some("192.168.1.1".parse().unwrap()),
				metric: Some(100),
				table: 254,
				prefsrc: None,
				protocol: NETCFGD_PROTO,
				scope: 0,
			}],
			address_proto_supported: true,
		};
		let prior = PriorState {
			address_origins: vec![(
				"eth0".to_owned(),
				"192.168.1.10/24".to_owned(),
				Origin::Static,
			)],
			..PriorState::default()
		};

		let observed = build(&snapshot, &prior);

		assert_eq!(observed.links.len(), 2);
		let ours = observed
			.addresses
			.iter()
			.find(|a| a.address == "192.168.1.10/24")
			.expect("present");
		assert_eq!(ours.interface, "eth0");
		assert_eq!(ours.ownership, Ownership::Ours);
		assert_eq!(ours.origin, Some(Origin::Static));

		let theirs = observed
			.addresses
			.iter()
			.find(|a| a.address == "10.0.0.1/24")
			.expect("present");
		assert_eq!(theirs.ownership, Ownership::Foreign);
		assert_eq!(theirs.origin, None);

		assert_eq!(observed.routes[0].interface, "eth0");
		assert_eq!(observed.routes[0].ownership, Ownership::Ours);
		assert_eq!(observed.routes[0].destination, "default");
	}

	/// A master is reported by index; the model wants a name. An unresolvable
	/// index means the master is in another namespace, which is not a crash.
	#[test]
	fn a_master_index_becomes_a_name_or_nothing() {
		let mut member = link(2, "eth0");
		member.master = Some(3);
		let mut orphan = link(4, "eth1");
		orphan.master = Some(99);

		let snapshot = Snapshot {
			qdiscs: netcfgd_sys::qdisc::QdiscDump::default(),
			redirects: Vec::new(),
			rules: Vec::new(),
			bridge_vlans: Vec::new(),
			links: vec![member, link(3, "br0"), orphan],
			..Snapshot::default()
		};
		let observed = build(&snapshot, &PriorState::default());

		let eth0 = observed.link("eth0").expect("present");
		assert_eq!(eth0.master.as_deref(), Some("br0"));
		let eth1 = observed.link("eth1").expect("present");
		assert_eq!(eth1.master, None);
	}

	/// An address on an interface the link dump did not mention is dropped
	/// rather than attributed to the wrong interface.
	#[test]
	fn an_address_with_no_matching_link_is_dropped() {
		let snapshot = Snapshot {
			qdiscs: netcfgd_sys::qdisc::QdiscDump::default(),
			redirects: Vec::new(),
			rules: Vec::new(),
			bridge_vlans: Vec::new(),
			links: vec![link(2, "eth0")],
			addresses: vec![address(77, "10.0.0.1", 24, None)],
			..Snapshot::default()
		};
		let observed = build(&snapshot, &PriorState::default());
		assert!(observed.addresses.is_empty());
	}

	/// Only links netcfgd recorded creating are ours, because the kernel has
	/// no protocol field for links to read back.
	#[test]
	fn only_recorded_links_are_ours() {
		let snapshot = Snapshot {
			qdiscs: netcfgd_sys::qdisc::QdiscDump::default(),
			redirects: Vec::new(),
			rules: Vec::new(),
			bridge_vlans: Vec::new(),
			links: vec![link(2, "eth0"), link(3, "br0")],
			..Snapshot::default()
		};
		let prior = PriorState {
			created_links: vec!["br0".to_owned()],
			..PriorState::default()
		};
		let observed = build(&snapshot, &prior);

		assert_eq!(observed.link("br0").unwrap().ownership, Ownership::Ours);
		assert_eq!(observed.link("eth0").unwrap().ownership, Ownership::Unknown);
	}
}
