//! The other half of the freeze: what netcfgd says it can see.
//!
//! `docs/schema/document.json` pins the desired state and
//! `docs/schema/socket.json` pins the request and response envelopes. Between
//! them sat a hole: a `Status` response carries an `Observed`, the socket
//! witness says so and adds that it is "pinned by their own crates", and no
//! crate pinned it. A field could be added, renamed or dropped from the
//! observed schema and no gate anywhere moved.
//!
//! Found by adding `ObservedReport::routes` and noticing that nothing asked to
//! be blessed. That is the shape project.md section 9 keeps writing down: a
//! gate that cannot see part of the tree enforces nothing there, and a comment
//! claiming coverage is not coverage.
//!
//! The observed schema is a public surface for the same reasons the document
//! is. It goes over the control socket to `ncfg`, the TUI and the NM shim; it
//! is written to `/run/netcfgd/observed/`; and `ncfg status --json` is the
//! thing scripts read. Any of those breaks silently when a field moves.
//!
//! Same mechanism, same discipline: populated by hand, regenerated deliberately
//! with `make schema-bless`, and the diff is the review.

use netcfgd_model::observed::{
	AppliedDns, BackendKind, Delegation, Observed, ObservedAccessControl, ObservedAddress,
	ObservedBackend, ObservedBridgeVlan, ObservedLink, ObservedPolicy, ObservedReport,
	ObservedRoute, ObservedRule, Origin, Ownership, ReportedRoute,
};
use netcfgd_model::{AclPolicy, DnsMode, DnsPolicy, DnsServer, RuleAction, RuleFamily};
use std::path::PathBuf;

fn witness_path() -> PathBuf {
	PathBuf::from(env!("CARGO_MANIFEST_DIR"))
		.join("../..")
		.join("docs/schema/observed.json")
}

/// Every ownership, so none can be renamed unnoticed.
///
/// The two-check pattern the document witness arrived at. The match is a
/// *compile* error when a variant appears, which is the half that catches an
/// addition; the assertion catches a sample that went away or a name that moved.
/// Never a `_` arm -- the wildcard is what would take the first half away.
/// `crates/netcfgd-plan/tests/frozen.rs` is exact about what neither half
/// catches.
fn every_ownership() -> Vec<Ownership> {
	let all = vec![Ownership::Ours, Ownership::Foreign, Ownership::Unknown];
	let name = |ownership: &Ownership| match ownership {
		Ownership::Ours => "ours",
		Ownership::Foreign => "foreign",
		Ownership::Unknown => "unknown",
	};
	let mut present: Vec<&str> = all.iter().map(name).collect();
	present.sort_unstable();
	assert_eq!(
		present,
		["foreign", "ours", "unknown"],
		"the witness is missing an ownership, so the frozen surface would not \
		 move when that ownership changed"
	);
	all
}

/// Every origin, on the same terms.
fn every_origin() -> Vec<Origin> {
	let all = vec![
		Origin::Static,
		Origin::Dhcp4,
		Origin::Dhcp6,
		Origin::Slaac,
		Origin::LinkLocal,
		Origin::Delegated,
	];
	let name = |origin: &Origin| match origin {
		Origin::Static => "static",
		Origin::Dhcp4 => "dhcp4",
		Origin::Dhcp6 => "dhcp6",
		Origin::Slaac => "slaac",
		Origin::LinkLocal => "link_local",
		Origin::Delegated => "delegated",
	};
	let mut present: Vec<&str> = all.iter().map(name).collect();
	present.sort_unstable();
	assert_eq!(
		present,
		[
			"delegated",
			"dhcp4",
			"dhcp6",
			"link_local",
			"slaac",
			"static"
		],
		"the witness is missing an origin, so the frozen surface would not move \
		 when that origin changed"
	);
	all
}

/// Every backend kind, on the same terms.
fn every_backend_kind() -> Vec<BackendKind> {
	let all = vec![
		BackendKind::Dhcp4,
		BackendKind::Dhcp6,
		BackendKind::Supplicant,
		BackendKind::AccessPoint,
		BackendKind::WireGuard,
		BackendKind::Pppoe,
		BackendKind::OpenVpn,
		BackendKind::Dns,
		BackendKind::RouterAdvert,
	];
	let name = |kind: &BackendKind| match kind {
		BackendKind::Dhcp4 => "dhcp4",
		BackendKind::Dhcp6 => "dhcp6",
		BackendKind::Supplicant => "supplicant",
		BackendKind::AccessPoint => "access_point",
		BackendKind::WireGuard => "wire_guard",
		BackendKind::Pppoe => "pppoe",
		BackendKind::OpenVpn => "open_vpn",
		BackendKind::Dns => "dns",
		BackendKind::RouterAdvert => "router_advert",
	};
	let mut present: Vec<&str> = all.iter().map(name).collect();
	present.sort_unstable();
	assert_eq!(
		present,
		[
			"access_point",
			"dhcp4",
			"dhcp6",
			"dns",
			"open_vpn",
			"pppoe",
			"router_advert",
			"supplicant",
			"wire_guard"
		],
		"the witness is missing a backend kind, so the frozen surface would not \
		 move when that kind changed"
	);
	all
}

/// Every access-point policy an observation can carry, including both of the
/// ones inside `Set`.
fn every_observed_policy() -> Vec<ObservedPolicy> {
	let all = vec![
		ObservedPolicy::Unset,
		ObservedPolicy::Set(AclPolicy::Deny),
		ObservedPolicy::Set(AclPolicy::Allow),
		ObservedPolicy::Unknown,
	];
	let name = |policy: &ObservedPolicy| match policy {
		ObservedPolicy::Unset => "unset",
		ObservedPolicy::Set(AclPolicy::Deny) => "set:deny",
		ObservedPolicy::Set(AclPolicy::Allow) => "set:allow",
		ObservedPolicy::Unknown => "unknown",
	};
	let mut present: Vec<&str> = all.iter().map(name).collect();
	present.sort_unstable();
	assert_eq!(
		present,
		["set:allow", "set:deny", "unknown", "unset"],
		"the witness is missing an observed access-point policy"
	);
	all
}

/// A link with every field set, so that none of them can go quiet.
fn maximal_link(name: &str, ownership: Ownership) -> ObservedLink {
	ObservedLink {
		name: name.to_owned(),
		index: 7,
		kind: "veth".to_owned(),
		up: true,
		carrier: true,
		mtu: 1500,
		mac: Some("02:00:00:00:00:01".to_owned()),
		master: Some("br0".to_owned()),
		parent: Some("eth0".to_owned()),
		offloads: vec![
			"rx-checksum".to_owned(),
			"tx-checksum-ip-generic".to_owned(),
		],
		ipv6_token: Some("::5".to_owned()),
		qdisc: Some("cake".to_owned()),
		qdisc_bandwidth_bits: Some(20_000_000),
		qdisc_ingress: true,
		ingress_redirect: Some("ifb-eth0".to_owned()),
		forwarding: Some(true),
		privacy: Some(true),
		accept_ra: Some(netcfgd_model::ObservedAcceptRa {
			value: 2,
			effective: true,
		}),
		rfkill: Some(netcfgd_model::ObservedRfkill {
			switch: "phy0".to_owned(),
			soft: true,
			hard: false,
		}),
		ownership,
		private_key_loaded: true,
		// Every field of the WireGuard state as well, for the reason this
		// function exists: a field with no sample is a field the witness cannot
		// notice changing, which is how three socket messages went unpinned for
		// a whole milestone.
		// Every field again, for the reason the WireGuard block below carries
		// every one of its own.
		bond: Some(netcfgd_model::ObservedBond {
			mode: Some("active-backup".to_owned()),
			miimon: Some(100),
		}),
		bridge: Some(netcfgd_model::ObservedBridge {
			stp: true,
			forward_delay: Some(4),
			hello_time: Some(2),
			ageing_time: Some(300),
			priority: Some(32_768),
			vlan_filtering: true,
		}),
		macvlan: Some(netcfgd_model::ObservedMacvlan {
			mode: Some("bridge".to_owned()),
		}),
		vlan: Some(netcfgd_model::ObservedVlan {
			id: Some(42),
			protocol: Some("dot1ad".to_owned()),
		}),
		tunnel: Some(netcfgd_model::ObservedTunnel {
			local: Some("192.0.2.1".parse().expect("an address")),
			remote: Some("192.0.2.2".parse().expect("an address")),
			ttl: Some(64),
			key: Some(42),
		}),
		vxlan: Some(netcfgd_model::ObservedVxlan {
			id: Some(100),
			local: Some("192.0.2.1".parse().expect("an address")),
			remote: Some("192.0.2.3".parse().expect("an address")),
			port: Some(4789),
		}),
		wireguard: Some(netcfgd_model::ObservedWireGuard {
			public_key: Some(key(0x11)),
			listen_port: Some(51820),
			key_matches: Some(true),
			fwmark: Some(0x6e),
			peers: vec![netcfgd_model::ObservedWgPeer {
				public_key: key(0x22),
				preshared_key: true,
				preshared_matches: Some(false),
				endpoint: Some("198.51.100.7:51820".to_owned()),
				allowed_ips: vec!["10.0.0.0/24".to_owned(), "fd00::/64".to_owned()],
				keepalive: Some(25),
			}],
		}),
	}
}

/// A key with every octet the same, which is enough to be a distinct sample.
fn key(seed: u8) -> netcfgd_model::Key {
	netcfgd_model::Key::from_bytes([seed; 32])
}

/// The one DNS scope netcfgd records having delivered.
fn applied_dns() -> AppliedDns {
	AppliedDns {
		scope: "globals".to_owned(),
		policy: DnsPolicy {
			mode: DnsMode::WriteResolvConf,
			servers: vec![DnsServer {
				addr: "9.9.9.9".parse().expect("an address"),
				port: Some(853),
				sni: Some("dns.quad9.net".to_owned()),
			}],
			search: vec!["example.com".to_owned()],
			domains: Vec::new(),
			options: vec!["edns0".to_owned()],
			dnssec: None,
			transport: None,
		},
	}
}

/// A rule with every selector set, so none of them can go quiet.
fn maximal_rule() -> ObservedRule {
	ObservedRule {
		priority: 100,
		family: RuleFamily::Inet,
		from: Some("192.168.0.0/24".to_owned()),
		to: Some("10.0.0.0/8".to_owned()),
		iif: Some("eth0".to_owned()),
		oif: Some("eth1".to_owned()),
		fwmark: Some(3),
		fwmask: Some(0xffff),
		table: Some(200),
		action: RuleAction::Lookup,
		suppress_prefixlength: Some(0),
		l3mdev: true,
		invert: true,
		ownership: Ownership::Ours,
	}
}

/// A report with every key a writer may use, including both shapes of route.
fn maximal_report() -> ObservedReport {
	ObservedReport {
		interface: "vpn0".to_owned(),
		addresses: vec!["10.8.0.2/24".to_owned()],
		gateways: vec!["10.8.0.1".to_owned()],
		nameservers: vec!["10.0.0.53".to_owned()],
		search: vec!["corp.example".to_owned()],
		routes: vec![
			ReportedRoute {
				destination: "10.0.0.0/8".to_owned(),
				via: Some("10.8.0.1".to_owned()),
			},
			ReportedRoute {
				destination: "192.168.44.0/24".to_owned(),
				via: None,
			},
		],
	}
}

/// One address per origin and one per ownership, plus a route per ownership and
/// the default route the kernel spells with no destination at all -- which is
/// the spelling a reported route has to match.
fn addresses_and_routes(observed: &mut Observed) {
	for (index, origin) in every_origin().into_iter().enumerate() {
		observed.addresses.push(ObservedAddress {
			interface: "eth0".to_owned(),
			address: format!("192.168.{index}.1/24"),
			proto: Some(110),
			ownership: Ownership::Ours,
			origin: Some(origin),
		});
	}
	// The optional fields absent as well, because an absent field cannot pin
	// the variant it would have carried.
	for (index, ownership) in every_ownership().into_iter().enumerate() {
		observed.addresses.push(ObservedAddress {
			interface: "eth1".to_owned(),
			address: format!("172.16.{index}.1/24"),
			proto: None,
			ownership,
			origin: None,
		});
		observed.routes.push(ObservedRoute {
			interface: "eth1".to_owned(),
			destination: format!("10.{index}.0.0/16"),
			via: Some("10.0.0.1".parse().expect("an address")),
			metric: Some(700),
			table: Some(254),
			src: Some("10.0.0.9".parse().expect("an address")),
			scope: Some(netcfgd_model::RouteScope::Global),
			proto: Some(110),
			ownership,
			origin: Some(Origin::Static),
		});
	}
	observed.routes.push(ObservedRoute {
		interface: "eth0".to_owned(),
		destination: "default".to_owned(),
		via: Some("192.168.0.254".parse().expect("an address")),
		metric: None,
		table: None,
		src: None,
		scope: None,
		proto: None,
		ownership: Ownership::Foreign,
		origin: None,
	});
}

/// One backend per kind, and the access-control block on the one kind that
/// carries it -- plus every policy that block can report.
fn backends(observed: &mut Observed) {
	for kind in every_backend_kind() {
		observed.backends.push(ObservedBackend {
			kind,
			interface: "eth0".to_owned(),
			running: true,
			answering: None,
			access_control: None,
			started_with: None,
			secret_matches: None,
			config_matches: None,
			advertised: Vec::new(),
		});
	}
	for (index, policy) in every_observed_policy().into_iter().enumerate() {
		observed.backends.push(ObservedBackend {
			kind: BackendKind::AccessPoint,
			interface: format!("wlan{index}"),
			running: true,
			// The kind the field is real for: the ACL read below is the round
			// trip that answers it, so a sample with a list and no verdict
			// would pin a shape netcfgd never produces.
			answering: Some(true),
			access_control: Some(ObservedAccessControl {
				policy,
				denied: vec!["02:00:00:00:00:aa".to_owned()],
				accepted: vec!["02:00:00:00:00:bb".to_owned()],
			}),
			started_with: None,
			secret_matches: None,
			config_matches: None,
			advertised: Vec::new(),
		});
	}
	// The shape 0085 is about: the process is there and it is not answering.
	// `access_control` is `None` beside it on purpose -- the failed round trip
	// is *why* there is no list, and a sample carrying both a verdict of `false`
	// and a list would pin a combination netcfgd cannot produce.
	observed.backends.push(ObservedBackend {
		kind: BackendKind::AccessPoint,
		interface: "wedged0".to_owned(),
		running: true,
		answering: Some(false),
		access_control: None,
		started_with: None,
		secret_matches: None,
		config_matches: None,
		advertised: Vec::new(),
	});
	// The one backend that carries what it was last given, which is how a
	// renumbered delegation is noticed at all.
	observed.backends.push(ObservedBackend {
		kind: BackendKind::RouterAdvert,
		interface: "lan0".to_owned(),
		running: true,
		answering: None,
		access_control: None,
		started_with: None,
		secret_matches: None,
		config_matches: None,
		advertised: vec!["2001:db8:1234::/64".to_owned()],
	});
	// And the identity an access point was started with, which is the other
	// half of the same question (decision 0052). Sampled on its own backend
	// rather than beside the ACL, because the two are read from different
	// places -- one from a control socket, one from the file netcfgd wrote.
	// A tunnel, carrying the other boolean: whether the `.ovpn` it was started
	// from is still that file (decision 0053).
	observed.backends.push(ObservedBackend {
		kind: BackendKind::OpenVpn,
		interface: "vpn0".to_owned(),
		running: true,
		answering: None,
		access_control: None,
		started_with: None,
		secret_matches: None,
		config_matches: Some(false),
		advertised: Vec::new(),
	});
	observed.backends.push(ObservedBackend {
		kind: BackendKind::AccessPoint,
		interface: "wlan9".to_owned(),
		running: true,
		answering: None,
		access_control: None,
		started_with: Some(netcfgd_model::ObservedAccessPoint {
			ssid: netcfgd_model::Ssid::new(b"home".to_vec()).expect("an ssid"),
			band: Some("2.4".to_owned()),
			channel: Some(6),
		}),
		// The answer to a question about a secret, which is the only form a
		// secret takes in an observation (decision 0052).
		secret_matches: Some(true),
		config_matches: None,
		advertised: Vec::new(),
	});
}

/// The whole observed surface, in one value.
fn witness() -> Observed {
	let mut observed = Observed {
		links: every_ownership()
			.into_iter()
			.enumerate()
			.map(|(index, ownership)| maximal_link(&format!("eth{index}"), ownership))
			.collect(),
		addresses: Vec::new(),
		routes: Vec::new(),
		backends: Vec::new(),
		dns: vec![applied_dns()],
		rules: vec![maximal_rule()],
		bridge_vlans: vec![ObservedBridgeVlan {
			index: 7,
			vid: 10,
			pvid: true,
			untagged: true,
		}],
		delegations: vec![Delegation {
			interface: "wan0".to_owned(),
			prefixes: vec!["2001:db8:1234::/56".to_owned()],
		}],
		reports: vec![maximal_report()],
		qdisc_applied: vec!["eth0".to_owned()],
		ingress_applied: vec!["eth0".to_owned()],
		forwarding_applied: vec!["eth0".to_owned()],
		privacy_applied: vec!["eth0".to_owned()],
		accept_ra_applied: vec!["eth0".to_owned()],
		backend_restarts: vec![(BackendKind::OpenVpn, "vpn0".to_owned(), 2)],
		// Both phases that have a memory, so the witness carries a sample of each --
		// one value that is an address and one that is a word.
		hook_state: vec![
			netcfgd_model::ObservedHookState {
				interface: "eth0".to_owned(),
				phase: netcfgd_model::HookPhase::Lease,
				value: "192.168.1.50/24".to_owned(),
			},
			netcfgd_model::ObservedHookState {
				interface: "eth0".to_owned(),
				phase: netcfgd_model::HookPhase::Carrier,
				value: "up".to_owned(),
			},
		],
		hostname: Some("host.example".to_owned()),
		nat: vec!["eth0".to_owned()],
		nat_conflicts: vec!["somebody-elses-table".to_owned()],
		address_proto_supported: true,
	};

	addresses_and_routes(&mut observed);
	backends(&mut observed);
	observed
}

/// The frozen surface, byte for byte.
#[test]
fn the_observed_schema_matches_its_witness() {
	let observed = witness();
	let rendered = serde_json::to_string_pretty(&observed).expect("the witness serialises");

	if std::env::var_os("NCFG_BLESS").is_some() {
		let path = witness_path();
		std::fs::create_dir_all(path.parent().expect("a parent")).expect("mkdir");
		std::fs::write(&path, &rendered).expect("write the witness");
		println!("blessed {}", path.display());
		return;
	}

	let expected = std::fs::read_to_string(witness_path()).unwrap_or_else(|error| {
		panic!(
			"cannot read the observed witness ({error}). If this is a new \
			 checkout something is missing; otherwise run `make schema-bless`."
		)
	});

	if rendered != expected {
		// One line, not the whole file. `assert_eq!` on two JSON documents
		// prints both of them escaped onto one line, which is unreadable and
		// buries the thing that changed -- the document witness learned that
		// first and this is the same answer.
		let (line, before, after) = first_difference(&expected, &rendered);
		panic!(
			"the observed schema has changed.\n\
			 \n\
			 first difference at line {line}:\n\
			 \x20 was: {before}\n\
			 \x20 now: {after}\n\
			 \n\
			 It goes over the control socket to `ncfg`, the TUI and the NM shim,\n\
			 into /run/netcfgd/observed/, and out of `ncfg status --json`, so a\n\
			 field that moves here moves under somebody. Run `make schema-bless`\n\
			 and say in the commit what moved and why."
		);
	}
}

fn first_difference(expected: &str, actual: &str) -> (usize, String, String) {
	for (index, (left, right)) in expected.lines().zip(actual.lines()).enumerate() {
		if left != right {
			return (index + 1, left.trim().to_owned(), right.trim().to_owned());
		}
	}
	let line = expected.lines().count().min(actual.lines().count()) + 1;
	(
		line,
		expected.lines().nth(line - 1).unwrap_or("<end>").to_owned(),
		actual.lines().nth(line - 1).unwrap_or("<end>").to_owned(),
	)
}

/// The witness has to survive a round trip, or it is pinning a format nothing
/// can read.
///
/// `Observed` denies unknown fields, so this also catches a field that
/// serialises under one name and deserialises under another.
#[test]
fn the_observed_witness_round_trips() {
	let observed = witness();
	let rendered = serde_json::to_string_pretty(&observed).expect("serialises");
	let parsed: Observed = serde_json::from_str(&rendered).expect("parses");
	assert_eq!(parsed, observed);
}
