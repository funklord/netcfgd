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
	/// `(kind, interface, count)` -- starts of a backend that did not stay up.
	pub backend_restarts: Vec<(netcfgd_model::BackendKind, String, u32)>,
	/// Interfaces netcfgd turned temporary addresses on for.
	pub privacy: Vec<String>,
	/// Interfaces netcfgd wrote the `accept_ra` sysctl for.
	pub accept_ra: Vec<String>,
	/// What each event hook was last told, per interface and phase.
	pub hook_state: Vec<netcfgd_model::ObservedHookState>,
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
		// The same predicate `start_supplicant` uses to choose a driver and
		// `ncfg wifi add` uses to pick a radio, shared rather than repeated:
		// three copies of one fact is how they end up disagreeing.
		wireless: netcfgd_sys::radio::is_wireless(&netcfgd_sys::radio::class_net(), &link.name),
		up: link.up,
		carrier: link.carrier,
		// The observer reads the kernel, and no probe result comes from
		// there. The daemon runs probes and fills this in; leaving it None
		// here is what makes an unprobed link keep its routes.
		reachable: None,
		mtu: link.mtu,
		mac: link.mac.clone(),
		master: link
			.master
			.and_then(|index| link_name(snapshot, index).map(ToOwned::to_owned)),
		// A name rather than an index, for the reason a master is a name: the
		// document names interfaces and an index is a number the kernel handed
		// out. An index with no name in this snapshot is a device in another
		// namespace, which reads as "no parent netcfgd can talk about".
		parent: link
			.parent
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
		privacy: None,
		accept_ra: None,
		// `/sys`, so `host::augment` again -- and the one thing in the observation
		// that is not netlink, a sysctl or a file netcfgd wrote itself.
		rfkill: None,
		ownership: link_ownership(&link.altnames, prior.created_links.contains(&link.name)),
		// Generic netlink rather than the link dump, so these are filled in by
		// `host::augment` for the same reason `forwarding` and `offloads` are.
		private_key_loaded: false,
		wireguard: None,
		// The mode arrives as a number and is compared as a name, so the
		// translation happens here -- once, where every other kernel-to-model
		// conversion in this function is.
		bond: link.bond.map(|bond| netcfgd_model::ObservedBond {
			mode: bond
				.mode
				.and_then(netcfgd_model::BondMode::from_number)
				.map(|mode| mode.name().to_owned()),
			miimon: bond.miimon,
		}),
		// Hundredths of a second on the wire, seconds in the model. The
		// conversion is here, once, beside nothing else that converts -- the
		// writer's half is in `netcfgd-sys`, and links.sh exists partly because
		// a bridge once came up with a 40ms forward delay instead of 4s.
		bridge: link.bridge.map(|bridge| netcfgd_model::ObservedBridge {
			stp: bridge.stp,
			forward_delay: bridge.forward_delay.map(|value| value / 100),
			hello_time: bridge.hello_time.map(|value| value / 100),
			ageing_time: bridge.ageing_time.map(|value| value / 100),
			priority: bridge.priority,
			vlan_filtering: bridge.vlan_filtering,
		}),
		// A mode number to a mode name, in the one place the bond's is done, and
		// for the same reason: the planner compares what the document says
		// against a word rather than against 4.
		macvlan: link.macvlan.map(|macvlan| netcfgd_model::ObservedMacvlan {
			mode: macvlan
				.mode
				.and_then(netcfgd_model::MacvlanMode::from_number)
				.map(|mode| mode.name().to_owned()),
		}),
		// An ethertype to the name the config uses, in the one place every other
		// kernel-to-model translation in this function happens.
		vlan: link.vlan.map(|vlan| netcfgd_model::ObservedVlan {
			id: vlan.id,
			protocol: vlan
				.protocol
				.and_then(netcfgd_model::VlanProtocol::from_ethertype)
				.map(|protocol| protocol.name().to_owned()),
		}),
		tunnel: link.tunnel.map(|tunnel| netcfgd_model::ObservedTunnel {
			local: tunnel.local,
			remote: tunnel.remote,
			ttl: tunnel.ttl,
			key: tunnel.key,
		}),
		vxlan: link.vxlan.map(|vxlan| netcfgd_model::ObservedVxlan {
			id: vxlan.id,
			local: vxlan.local,
			remote: vxlan.remote,
			port: vxlan.port,
		}),
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
				origin: prior
					.address_origin(&interface, &cidr)
					.or_else(|| tagged_origin(address.proto)),
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
				origin: prior
					.route_origin(&interface, &destination)
					.or_else(|| tagged_origin(Some(route.protocol))),
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
		privacy_applied: prior.privacy.clone(),
		accept_ra_applied: prior.accept_ra.clone(),
		backend_restarts: prior.backend_restarts.clone(),
		hook_state: prior.hook_state.clone(),
		// Read in `host::augment` beside the sysctls, for the reason they are:
		// `build` stays a pure function of a netlink snapshot.
		hostname: None,
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
/// Whether a link is netcfgd's, from the kernel first and the record second.
///
/// **A link has no protocol field**, so decision 0002's tag had nothing to
/// stamp and link ownership lived only in `/run` -- which a restart deletes.
/// 0136 gives every link netcfgd creates an alternative name instead, and this
/// reads it back.
///
/// The marker is matched by its prefix rather than by the whole name, because
/// the name carries what the link was *called* when netcfgd made it and a link
/// can be renamed afterwards. Matching the whole string would make a rename
/// look like a change of owner.
///
/// **A recorded link with no marker is still ours**, which is what keeps this
/// additive: a link created by an older netcfgd carries no alternative name,
/// and a kernel that refused `RTM_NEWLINKPROP` left one unmarked on purpose.
/// Neither should stop being netcfgd's on the day this ships.
///
/// **An unmarked, unrecorded link is `Unknown` rather than `Foreign`**, the
/// same as before. netcfgd did not make `eth0`, and saying so positively would
/// claim to know something about every physical device on the machine.
fn link_ownership(altnames: &[String], recorded: bool) -> Ownership {
	if altnames
		.iter()
		.any(|name| name.starts_with(netcfgd_model::route::NETCFGD_ALTNAME_PREFIX))
	{
		return Ownership::Ours;
	}
	if recorded {
		return Ownership::Ours;
	}
	Ownership::Unknown
}

/// The origin an object's kernel tag implies, when nothing was recorded.
///
/// **netcfgd's tag has exactly one producer, and that is what makes this
/// sound.** `Op::AddrAdd` is the only call site of `add_address`, and
/// `Op::RouteAdd` the only call site of `add_route`; both stamp
/// [`NETCFGD_PROTO`] and both record [`Origin::Static`]. So an object wearing
/// the tag was put there by netcfgd from config, and there is no other way for
/// it to be wearing it. A lease's address belongs to the DHCP client, which
/// installs it itself under its own protocol number and never under this one.
///
/// **Why it is needed.** Ownership survives the loss of `/run` because the
/// kernel carries the tag, but *origin* did not, and every teardown path gates
/// on `origin == Static` before it gates on anything else. So a netcfgd that
/// lost its record kept the tag, read the address as `Ours`, and then declined
/// to touch it because the origin was `None` -- it could tell the address was
/// its own and not that it was allowed to remove it. Measured: with the record
/// intact a stale address and route are removed; with the record deleted both
/// are held.
///
/// **The record still wins where it exists**, which is what keeps this a
/// fallback rather than a replacement: a pre-5.18 kernel has no `IFA_PROTO` to
/// read, and a DHCP address recorded as `Dhcp4` must stay `Dhcp4` even though
/// netcfgd's own tag is absent from it.
///
/// The uniqueness this rests on is asserted by `tools/tag_producer_gate.py`,
/// because it is a property of the tree rather than of this function, and a
/// second producer added later would make the inference wrong here without
/// changing a line of it.
fn tagged_origin(proto: Option<u8>) -> Option<Origin> {
	(proto == Some(NETCFGD_PROTO)).then_some(Origin::Static)
}

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
			// Unmarked: the fixture stands for a link netcfgd did not create,
			// and the tests that want one of netcfgd's say so explicitly.
			altnames: Vec::new(),
			bond: None,
			bridge: None,
			macvlan: None,
			vlan: None,
			tunnel: None,
			vxlan: None,
			index,
			name: name.to_owned(),
			kind: String::new(),
			up: true,
			carrier: true,
			mtu: 1500,
			mac: None,
			master: None,
			parent: None,
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
	fn a_link_wearing_our_alternative_name_is_ours_with_no_record() {
		// The whole point: a restart deletes the record, and this must not
		// change the answer.
		assert_eq!(
			link_ownership(&["netcfgd:br0".to_owned()], false),
			Ownership::Ours
		);
	}

	#[test]
	fn a_renamed_link_is_still_ours() {
		// The mark carries the name the link had when netcfgd created it, and
		// a link can be renamed afterwards -- so the two disagree and the
		// answer must not. Written with a suffix that matches nothing, since
		// the property is that the suffix is not consulted at all.
		assert_eq!(
			link_ownership(&["netcfgd:whatever-it-was-called".to_owned()], false),
			Ownership::Ours
		);
	}

	#[test]
	fn a_recorded_link_with_no_mark_is_still_ours() {
		// Additive: a link an older netcfgd created carries no alternative
		// name, and must not stop being netcfgd's on the day this ships.
		assert_eq!(link_ownership(&[], true), Ownership::Ours);
	}

	#[test]
	fn somebody_elses_alternative_name_does_not_make_a_link_ours() {
		assert_eq!(
			link_ownership(&["prettyname".to_owned(), "enp0s1".to_owned()], false),
			Ownership::Unknown
		);
	}

	#[test]
	fn an_unmarked_unrecorded_link_is_unknown_rather_than_foreign() {
		// netcfgd did not make eth0, and saying so positively would be a claim
		// about every physical device on the machine.
		assert_eq!(link_ownership(&[], false), Ownership::Unknown);
	}

	#[test]
	fn the_mark_is_built_from_the_prefix_and_the_name() {
		use netcfgd_model::route::netcfgd_altname;
		assert_eq!(netcfgd_altname("br0").as_deref(), Some("netcfgd:br0"));
		assert_eq!(netcfgd_altname(""), None);
		// Longer than ALTIFNAMSIZ once the prefix is on it.
		assert_eq!(netcfgd_altname(&"x".repeat(200)), None);
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
