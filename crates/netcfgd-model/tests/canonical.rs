//! The invariants project.md section 2 states, as tests rather than as prose.

use netcfgd_model::address::{Delegated, Dhcp4Backend, Static};
use netcfgd_model::dns::{DnsMode, RoutingDomain};
use netcfgd_model::interface::{BridgeConfig, RaPolicy};
use netcfgd_model::security::{PskConfig, PskProto};
use netcfgd_model::{
	AddressSource, Device, Dhcp4, DnsPolicy, DnsServer, Document, Error, HookPhase, HookRef,
	Interface, InterfaceKind, PrefixRef, Route, SecretRef, Security, Ssid, Version, WifiNetwork,
	SCHEMA_VERSION,
};
use std::net::IpAddr;

fn dev(name: &str) -> Device {
	Device {
		name: name.to_owned(),
		r#match: None,
		managed: true,
		on_unmanage: netcfgd_model::OnUnmanage::Leave,
		wifi: None,
		modem: None,
		mtu: None,
		mac: None,
		link_settings: None,
		kind: netcfgd_model::InterfaceKind::Physical,
		master: None,
		qdisc: None,
		ingress_redirect: None,
		bridge_vlans: Vec::new(),
	}
}

fn iface(name: &str) -> Interface {
	Interface {
		name: name.to_owned(),
		enabled: true,
		addressing: Vec::new(),
		routes: Vec::new(),
		dns: None,
		hooks: Vec::new(),
		on_drift: None,
		dot1x: None,
		advertise: None,
		forwarding: None,
		nat: None,
		guard: None,
		ipv6_token: None,
		preference: None,
		probe: None,
	}
}

fn route(destination: &str) -> Route {
	Route {
		destination: destination.to_owned(),
		via: None,
		metric: None,
		table: None,
		src: None,
		scope: None,
		onlink: false,
		proto: None,
	}
}

fn server(addr: &str) -> DnsServer {
	DnsServer {
		addr: addr.parse::<IpAddr>().expect("test address parses"),
		port: None,
		sni: None,
	}
}

fn wifi(id: &str) -> WifiNetwork {
	WifiNetwork {
		id: id.to_owned(),
		ssid: Some(Ssid::new(id.as_bytes().to_vec()).expect("short enough")),
		hidden: false,
		security: Security::Psk(PskConfig {
			passphrase: SecretRef {
				provider: netcfgd_model::SecretProvider::File,
				name: format!("{id}-psk"),
			},
			proto: PskProto::Wpa2Wpa3,
		}),
		metric: None,
		autoconnect: true,
		metered: false,
		bssid: Vec::new(),
		roam: None,
		addressing: Vec::new(),
		routes: Vec::new(),
		dns: None,
		hooks: Vec::new(),
	}
}

/// Encoding is a function: the same document twice is the same bytes.
#[test]
fn encoding_is_stable_across_runs() {
	let mut doc = Document::default();
	doc.interfaces.push(iface("eth0"));

	let first = doc.to_json_canonical().expect("valid");
	let second = doc.to_json_canonical().expect("valid");
	assert_eq!(first, second);
}

/// And Bluetooth devices sort with everything else.
///
/// Left out of `canonicalize` for as long as the field existed, and invisible
/// while `Document`'s equality also omitted it: with neither walk covering
/// `bluetooth`, order could not produce a spurious difference because no
/// difference was visible at all. Fixing equality made this reachable, so the
/// two belong to one repair rather than two.
#[test]
fn bluetooth_devices_sort_with_everything_else() {
	let device = |id: &str| netcfgd_model::bluetooth::BluetoothDevice {
		id: id.to_owned(),
		address: "11:22:33:44:55:66".to_owned(),
		profile: netcfgd_model::bluetooth::BluetoothProfile::Pan,
		autoconnect: true,
	};
	let mut forward = Document::default();
	forward.bluetooth.push(device("alpha"));
	forward.bluetooth.push(device("beta"));
	let mut backward = Document::default();
	backward.bluetooth.push(device("beta"));
	backward.bluetooth.push(device("alpha"));

	assert_ne!(
		forward, backward,
		"unsorted, the two orders are different states"
	);
	forward.canonicalize();
	backward.canonicalize();
	assert_eq!(forward, backward, "canonicalised, the order is gone");
}

/// The property that makes plan diffs trustworthy: two documents describing
/// the same state encode identically however their parts were ordered. This is
/// the case that actually arises, since drop-in files are read in filename
/// order and say nothing about interface order.
#[test]
fn insertion_order_does_not_survive_canonicalisation() {
	let mut forward = Document::default();
	forward.interfaces.push(iface("eth0"));
	forward.interfaces.push(iface("eth1"));
	forward.interfaces.push(iface("wlan0"));
	forward.networks.push(wifi("alpha"));
	forward.networks.push(wifi("beta"));
	forward.devices.push(Device {
		kind: netcfgd_model::InterfaceKind::Physical,
		master: None,
		qdisc: None,
		ingress_redirect: None,
		bridge_vlans: Vec::new(),
		name: "eth0".to_owned(),
		r#match: None,
		managed: true,
		mtu: None,
		mac: None,
		link_settings: None,
		on_unmanage: netcfgd_model::OnUnmanage::Leave,
		wifi: None,
		modem: None,
	});

	let mut backward = Document::default();
	backward.interfaces.push(iface("wlan0"));
	backward.interfaces.push(iface("eth1"));
	backward.interfaces.push(iface("eth0"));
	backward.networks.push(wifi("beta"));
	backward.networks.push(wifi("alpha"));
	backward.devices.push(Device {
		kind: netcfgd_model::InterfaceKind::Physical,
		master: None,
		qdisc: None,
		ingress_redirect: None,
		bridge_vlans: Vec::new(),
		name: "eth0".to_owned(),
		r#match: None,
		managed: true,
		mtu: None,
		mac: None,
		link_settings: None,
		on_unmanage: netcfgd_model::OnUnmanage::Leave,
		wifi: None,
		modem: None,
	});

	assert_eq!(
		forward.to_json_canonical().expect("valid"),
		backward.to_json_canonical().expect("valid")
	);

	// Equality alone would also hold if canonicalize() did nothing and both
	// documents happened to be built the same way, so assert the ordering
	// directly. Without this the test above cannot fail.
	backward.canonicalize();
	let names: Vec<&str> = backward
		.interfaces
		.iter()
		.map(|i| i.name.as_str())
		.collect();
	assert_eq!(names, ["eth0", "eth1", "wlan0"]);
	let ids: Vec<&str> = backward.networks.iter().map(|n| n.id.as_str()).collect();
	assert_eq!(ids, ["alpha", "beta"]);
}

/// Sorting reaches into nested lists too, not just the top level.
#[test]
fn nested_lists_sort_as_well() {
	let mut a = Document::default();
	let mut eth0 = iface("eth0");
	eth0.routes.push(route("10.0.0.0/8"));
	eth0.routes.push(route("default"));
	let mut br = dev("eth0");
	br.kind = InterfaceKind::Bridge(BridgeConfig {
		members: vec!["eth2".to_owned(), "eth1".to_owned()],
		stp: false,
		forward_delay: None,
		hello_time: None,
		ageing_time: None,
		priority: None,
		vlan_filtering: false,
	});
	a.interfaces.push(eth0);
	a.devices.push(br);

	let mut b = Document::default();
	let mut eth0 = iface("eth0");
	eth0.routes.push(route("default"));
	eth0.routes.push(route("10.0.0.0/8"));
	let mut br = dev("eth0");
	br.kind = InterfaceKind::Bridge(BridgeConfig {
		members: vec!["eth1".to_owned(), "eth2".to_owned()],
		stp: false,
		forward_delay: None,
		hello_time: None,
		ageing_time: None,
		priority: None,
		vlan_filtering: false,
	});
	b.interfaces.push(eth0);
	b.devices.push(br);

	assert_eq!(
		a.to_json_canonical().expect("valid"),
		b.to_json_canonical().expect("valid")
	);
}

/// Search order is semantic. Sorting it would change what the config means
/// rather than normalise how it was written, so canonicalisation leaves it be.
#[test]
fn search_order_is_preserved_because_it_is_semantic() {
	let mut doc = Document::default();
	doc.globals.dns.search = vec!["b.example".to_owned(), "a.example".to_owned()];

	let json = doc.to_json_canonical().expect("valid");
	let back = Document::from_json(&json).expect("round trips");
	assert_eq!(back.globals.dns.search, vec!["b.example", "a.example"]);
}

/// A document survives a round trip through its own encoding.
#[test]
fn round_trip_preserves_the_document() {
	let mut doc = Document::default();
	let mut eth0 = iface("eth0");
	eth0.addressing.push(AddressSource::Static(Static {
		address: "192.168.1.10/24".to_owned(),
		peer: None,
		preferred_lifetime: None,
		valid_lifetime: None,
	}));
	eth0.addressing.push(AddressSource::Dhcp4(Dhcp4 {
		backend: Dhcp4Backend::Dhcpcd,
		..Dhcp4::default()
	}));
	eth0.hooks.push(HookRef {
		phase: HookPhase::PostUp,
		path: "/etc/netcfgd/hooks/notify".to_owned(),
		sha256: "0".repeat(64),
		run_as: None,
		timeout: Some(30),
	});
	doc.interfaces.push(eth0);
	doc.networks.push(wifi("home"));

	let json = doc.to_json_canonical().expect("valid");
	let back = Document::from_json(&json).expect("round trips");
	assert_eq!(doc, back);
}

/// Static and DHCP on one interface is a composition, not a conflict. Decision
/// 0006 turns on this being legal.
#[test]
fn static_and_dhcp_compose() {
	let mut doc = Document::default();
	let mut eth0 = iface("eth0");
	eth0.addressing.push(AddressSource::Static(Static {
		address: "192.168.1.10/24".to_owned(),
		peer: None,
		preferred_lifetime: None,
		valid_lifetime: None,
	}));
	eth0.addressing.push(AddressSource::Dhcp4(Dhcp4::default()));
	doc.interfaces.push(eth0);

	assert!(doc.validate().is_ok());
}

/// Two DHCP clients on one link is always a bug, so it fails to compile rather
/// than racing at runtime.
#[test]
fn two_dhcp4_sources_are_refused() {
	let mut doc = Document::default();
	let mut eth0 = iface("eth0");
	eth0.addressing.push(AddressSource::Dhcp4(Dhcp4::default()));
	eth0.addressing.push(AddressSource::Dhcp4(Dhcp4 {
		backend: Dhcp4Backend::Udhcpc,
		..Dhcp4::default()
	}));
	doc.interfaces.push(eth0);

	assert_eq!(
		doc.validate(),
		Err(Error::RepeatedAddressSource {
			interface: "eth0".to_owned(),
			source: "dhcp4",
		})
	);
}

/// Several static addresses on one interface stay legal; only the singleton
/// sources are limited.
#[test]
fn many_static_addresses_are_fine() {
	let mut doc = Document::default();
	let mut eth0 = iface("eth0");
	for addr in ["10.0.0.1/24", "10.0.1.1/24", "10.0.2.1/24"] {
		eth0.addressing.push(AddressSource::Static(Static {
			address: addr.to_owned(),
			peer: None,
			preferred_lifetime: None,
			valid_lifetime: None,
		}));
	}
	doc.interfaces.push(eth0);

	assert!(doc.validate().is_ok());
}

/// The heart of decision 0007: a flat mode asked for routing domains is an
/// error, because silently flattening sends internal queries to a public
/// resolver.
#[test]
fn a_flat_dns_mode_refuses_routing_domains() {
	let mut doc = Document::default();
	let mut vpn = iface("wg0");
	vpn.dns = Some(DnsPolicy {
		mode: DnsMode::WriteResolvConf,
		servers: vec![server("10.0.0.53")],
		domains: vec![RoutingDomain {
			suffix: "corp.example".to_owned(),
			exclusive: true,
		}],
		..DnsPolicy::default()
	});
	doc.interfaces.push(vpn);

	assert_eq!(
		doc.validate(),
		Err(Error::DnsModeCannotRoute {
			scope: "wg0".to_owned(),
			mode: "write_resolv_conf",
		})
	);
}

/// The same policy under a scope-capable mode is accepted.
#[test]
fn a_scope_capable_dns_mode_accepts_routing_domains() {
	let mut doc = Document::default();
	let mut vpn = iface("wg0");
	vpn.dns = Some(DnsPolicy {
		mode: DnsMode::Openresolv,
		servers: vec![server("10.0.0.53")],
		domains: vec![RoutingDomain {
			suffix: "corp.example".to_owned(),
			exclusive: true,
		}],
		..DnsPolicy::default()
	});
	doc.interfaces.push(vpn);

	assert!(doc.validate().is_ok());
}

/// A scope that states no mode of its own is checked against the host's.
///
/// The mode is not a per-interface choice -- a scope states one only to
/// override -- so a scope with routing domains and no mode is checked against
/// the mode that will actually deliver it. This used to be refused as "mode
/// none cannot express routing domains", naming a mode nobody wrote, for the
/// config that is the recommended way to split DNS down a tunnel.
#[test]
fn a_scope_with_no_mode_inherits_the_hosts_before_being_checked() {
	let mut doc = Document::default();
	doc.globals.dns = DnsPolicy {
		mode: DnsMode::Dnsmasq,
		..DnsPolicy::default()
	};
	let mut vpn = iface("vpn0");
	vpn.dns = Some(DnsPolicy {
		domains: vec![RoutingDomain {
			suffix: "corp.example".to_owned(),
			exclusive: true,
		}],
		..DnsPolicy::default()
	});
	doc.interfaces.push(vpn);

	assert_eq!(doc.validate(), Ok(()));
}

/// And refused when the host's mode cannot route either -- with that mode
/// named, rather than the `none` the scope happened to hold.
#[test]
fn a_scope_with_no_mode_is_refused_by_the_hosts_mode_and_names_it() {
	let mut doc = Document::default();
	doc.globals.dns = DnsPolicy {
		mode: DnsMode::WriteResolvConf,
		..DnsPolicy::default()
	};
	let mut vpn = iface("vpn0");
	vpn.dns = Some(DnsPolicy {
		domains: vec![RoutingDomain {
			suffix: "corp.example".to_owned(),
			exclusive: true,
		}],
		..DnsPolicy::default()
	});
	doc.interfaces.push(vpn);

	assert_eq!(
		doc.validate(),
		Err(Error::DnsModeCannotRoute {
			scope: "vpn0".to_owned(),
			mode: "write_resolv_conf",
		})
	);
}

/// A flat mode with no routing domains is not an error. The check is about
/// what the config asks for, not about which mode was chosen.
#[test]
fn a_flat_dns_mode_without_domains_is_fine() {
	let mut doc = Document::default();
	doc.globals.dns = DnsPolicy {
		mode: DnsMode::WriteResolvConf,
		servers: vec![server("192.168.1.1")],
		search: vec!["example".to_owned()],
		..DnsPolicy::default()
	};

	assert!(doc.validate().is_ok());
}

/// section 2: a consumer rejects any document containing a field it does not
/// recognise. Silently dropping one would mean acting on a subset of what the
/// author wrote.
#[test]
fn an_unknown_field_is_refused() {
	let json = r#"{
		"schema_version": {"major": 1, "minor": 0},
		"globals": {},
		"devices": [],
		"interfaces": [],
		"networks": [],
		"unknown_future_field": true
	}"#;

	let err = Document::from_json(json).expect_err("must refuse");
	match err {
		Error::Syntax(msg) => assert!(
			msg.contains("unknown_future_field"),
			"the diagnostic should name the field, got: {msg}"
		),
		other => panic!("expected a syntax error, got {other:?}"),
	}
}

/// An unknown field nested inside an interface is refused too, not just one at
/// the top level.
#[test]
fn an_unknown_nested_field_is_refused() {
	let json = r#"{
		"schema_version": {"major": 1, "minor": 0},
		"globals": {},
		"devices": [],
		"interfaces": [{"name": "eth0", "kind": "physical", "speculative": 1}],
		"networks": []
	}"#;

	assert!(matches!(Document::from_json(json), Err(Error::Syntax(_))));
}

/// A differing major version is a hard refusal.
#[test]
fn a_future_major_version_is_refused() {
	let doc = Document {
		schema_version: Version {
			major: SCHEMA_VERSION.major + 1,
			minor: 0,
		},
		..Document::default()
	};

	assert_eq!(
		doc.validate(),
		Err(Error::SchemaMajor {
			found: doc.schema_version,
			expected: SCHEMA_VERSION,
		})
	);
}

/// Provenance is not state. A document from a different build describes the
/// same desired state, and the reconciler must not see a change.
#[test]
fn generated_by_is_excluded_from_equality() {
	let a = Document {
		generated_by: Some("netcfgd 0.1.0".to_owned()),
		..Document::default()
	};
	let b = Document {
		generated_by: Some("netcfgd 0.2.0".to_owned()),
		..Document::default()
	};

	assert_eq!(a, b);
}

/// Everything else IS state, and `bluetooth` was the one that got left out.
///
/// `Document`'s equality is hand-written so that `generated_by` can be
/// excluded, and for as long as the `bluetooth` field existed it was omitted
/// too -- so two documents differing only in a Bluetooth device compared
/// equal. The reconciler saw no change to apply, and `ncfg profile save`
/// accepted a snapshot with a wrong address as reproducing the machine.
///
/// The real guard is that `eq` destructures `Self`, which makes the next
/// added field a compile error. This asserts the case that was broken, since
/// a compile-time guard leaves no failing test behind to show it was ever
/// alive.
#[test]
fn a_bluetooth_device_is_part_of_a_document_s_identity() {
	let device = |address: &str| netcfgd_model::bluetooth::BluetoothDevice {
		id: "phone".to_owned(),
		address: address.to_owned(),
		profile: netcfgd_model::bluetooth::BluetoothProfile::Pan,
		autoconnect: true,
	};
	let a = Document {
		bluetooth: vec![device("11:22:33:44:55:66")],
		..Document::default()
	};
	let b = Document {
		bluetooth: vec![device("99:99:99:99:99:99")],
		..Document::default()
	};

	assert_ne!(
		a, b,
		"two documents differing only in Bluetooth are not the same state"
	);
	assert_ne!(
		a,
		Document::default(),
		"a device present is not the same as none"
	);
}

/// An SSID is octets, not text. This one is not valid UTF-8 and must survive
/// the encoding unchanged.
#[test]
fn a_non_utf8_ssid_round_trips() {
	let raw = vec![0xff, 0x00, 0x41, 0xc3];
	let ssid = Ssid::new(raw.clone()).expect("within 32 octets");
	assert_eq!(ssid.to_hex(), "ff0041c3");

	let mut doc = Document::default();
	let mut network = wifi("odd");
	network.ssid = Some(ssid);
	doc.networks.push(network);

	let json = doc.to_json_canonical().expect("valid");
	let back = Document::from_json(&json).expect("round trips");
	assert_eq!(
		back.networks[0]
			.ssid
			.as_ref()
			.expect("a stated ssid")
			.as_bytes(),
		raw.as_slice()
	);
}

/// Two spellings of one SSID would break the byte-identical guarantee, so
/// uppercase hex is refused rather than accepted.
#[test]
fn uppercase_ssid_hex_is_refused() {
	assert_eq!(Ssid::from_hex("FF00"), Err(Error::SsidNotHex));
	assert_eq!(Ssid::from_hex("ff0"), Err(Error::SsidNotHex));
	assert_eq!(Ssid::from_hex("zz"), Err(Error::SsidNotHex));
}

/// 802.11 caps an SSID at 32 octets.
#[test]
fn an_oversized_ssid_is_refused() {
	assert_eq!(
		Ssid::new(vec![b'a'; 33]),
		Err(Error::SsidTooLong { len: 33 })
	);
	assert!(Ssid::new(vec![b'a'; 32]).is_ok());
}

/// A hook path has to be absolute; a relative one would resolve against
/// whatever directory the daemon happened to be in.
#[test]
fn a_relative_hook_path_is_refused() {
	let mut doc = Document::default();
	let mut eth0 = iface("eth0");
	eth0.hooks.push(HookRef {
		phase: HookPhase::PreUp,
		path: "hooks/relative".to_owned(),
		sha256: "0".repeat(64),
		run_as: None,
		timeout: None,
	});
	doc.interfaces.push(eth0);

	assert_eq!(
		doc.validate(),
		Err(Error::HookPathNotAbsolute {
			path: "hooks/relative".to_owned(),
		})
	);
}

/// Two interfaces of one name is a config that cannot mean anything.
#[test]
fn duplicate_interface_names_are_refused() {
	let mut doc = Document::default();
	doc.interfaces.push(iface("eth0"));
	doc.interfaces.push(iface("eth0"));

	assert_eq!(
		doc.validate(),
		Err(Error::DuplicateKey {
			collection: "interface",
			key: "eth0".to_owned(),
		})
	);
}

/// A delegated prefix reaches the document as a reference and never as a
/// value, which is what keeps the document a pure function of the config.
#[test]
fn a_delegated_address_carries_a_reference_not_a_prefix() {
	let mut doc = Document::default();
	let mut lan = iface("br-lan");
	lan.addressing.push(AddressSource::Delegated(Delegated {
		prefix: PrefixRef {
			source: "wan0".to_owned(),
			index: 0,
			subnet: 1,
		},
		suffix: "::1/64".to_owned(),
	}));
	lan.advertise = Some(RaPolicy {
		prefixes: vec![PrefixRef {
			source: "wan0".to_owned(),
			index: 0,
			subnet: 1,
		}],
		..RaPolicy::default()
	});
	doc.interfaces.push(lan);

	let json = doc.to_json_canonical().expect("valid");
	assert!(json.contains("\"source\": \"wan0\""));
	// Nothing resembling an actual prefix should be in here.
	assert!(!json.contains("::/"));

	let back = Document::from_json(&json).expect("round trips");
	assert_eq!(doc, back);
}

/// The encoding carries no floats anywhere. Every number in the schema is an
/// integer, and a float would make byte-identical output impossible to
/// guarantee across platforms.
#[test]
fn the_encoding_contains_no_floats() {
	let mut doc = Document::default();
	let mut eth0 = iface("eth0");
	eth0.addressing.push(AddressSource::Dhcp4(Dhcp4 {
		metric: Some(100),
		request_options: vec![121, 249],
		..Dhcp4::default()
	}));
	doc.interfaces.push(eth0);
	// The MTU is on the device since 0155 pass 1a, and it is one of the five
	// numbers the count below insists on -- so it moves here rather than
	// leaving the guard to fail for the wrong reason.
	doc.devices.push(netcfgd_model::Device {
		kind: netcfgd_model::InterfaceKind::Physical,
		master: None,
		qdisc: None,
		ingress_redirect: None,
		bridge_vlans: Vec::new(),
		name: "eth0".to_owned(),
		r#match: None,
		managed: true,
		mtu: Some(1500),
		mac: None,
		link_settings: None,
		on_unmanage: netcfgd_model::OnUnmanage::Leave,
		wifi: None,
		modem: None,
	});
	doc.globals.confirm_default = Some(120);

	let json = doc.to_json_canonical().expect("valid");
	let mut numbers_checked = 0;
	for (index, line) in json.lines().enumerate() {
		let Some((_, value)) = line.split_once(':') else {
			continue;
		};
		let value = value.trim().trim_end_matches(',');
		if value.is_empty() || !value.starts_with(|c: char| c.is_ascii_digit() || c == '-') {
			continue;
		}
		numbers_checked += 1;
		assert!(
			!value.contains('.'),
			"line {index} looks like a float: {line}"
		);
	}
	// Without this the loop could match nothing and pass regardless: 1500,
	// 100, 120 and the two request options are all in there.
	assert!(
		numbers_checked >= 5,
		"expected to inspect several numbers, saw {numbers_checked}"
	);
}
