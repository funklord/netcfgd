//! The third thing the socket sends, and the last one nothing was pinning.
//!
//! `docs/schema/document.json` pins the desired state, `observed.json` pins
//! what netcfgd can see, and `socket.json` pins the envelopes. A `Status`
//! response carries a `Plan` too, and the socket witness said so while pinning
//! only the envelope -- so an `Op` variant could be renamed, or gain a field,
//! and nothing anywhere would move.
//!
//! That matters more here than the shape of the type suggests. `ncfg plan
//! --json` is what a script reads before deciding whether to apply, the TUI's
//! plan pane is built from it, and `/run/netcfgd/plan.last.json` is how an
//! interrupted apply says which actions ran. An op renamed in a refactor
//! changes all three silently.
//!
//! Same mechanism and same discipline as the other two: populated by hand,
//! regenerated deliberately with `make schema-bless`, and the diff is the
//! review.

use netcfgd_model::hook::HookPhase;
use netcfgd_model::{
	AclPolicy, BackendKind, DnsMode, DnsPolicy, DnsServer, InterfaceKind, Key, Route, RouteScope,
	RoutingRule, RuleAction, RuleFamily, WgPeer,
};
use netcfgd_plan::{Action, Op, Plan, Reason, Refusal, Stranded, Warning};
use std::path::PathBuf;

fn witness_path() -> PathBuf {
	PathBuf::from(env!("CARGO_MANIFEST_DIR"))
		.join("../..")
		.join("docs/schema/plan.json")
}

fn route() -> Route {
	Route {
		destination: "10.0.0.0/8".to_owned(),
		via: Some("192.168.1.1".parse().expect("an address")),
		metric: Some(700),
		table: Some(254),
		src: Some("192.168.1.10".parse().expect("an address")),
		scope: Some(RouteScope::Global),
		onlink: true,
		proto: Some(110),
	}
}

fn rule() -> RoutingRule {
	RoutingRule {
		id: "from-lan".to_owned(),
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
	}
}

/// Every op, so that none can be renamed, reshaped or added unnoticed.
///
/// Three checks, and it is worth being exact about which one does what, because
/// the older witnesses claim more for the second than it delivers:
///
/// - **The match is a compile error when a variant appears.** No `_` arm, ever:
///   a wildcard here is the whole gate. This is the half that catches an
///   addition, and it catches it by stopping the build in a file whose only
///   purpose is samples.
/// - **The assertion catches a sample that went away**, or a name that moved.
///   It does *not* catch an arm written with no sample beside it -- neither list
///   would mention the new name, and they would agree. Nothing in Rust can
///   enumerate a variant without a value of it, so that case is left to the
///   compile error above and is stated here rather than assumed away.
/// - **The last loop checks the crate's own `Op::name` against this one**, so a
///   rename in the crate that nobody mirrored here fails rather than pinning a
///   spelling nothing renders.
#[allow(clippy::too_many_lines)]
fn every_op() -> Vec<Op> {
	// Two lists of forty-odd names, which is what an exhaustive check of forty
	// ops looks like. Splitting it to please a line count would put the match
	// and the names it is checked against in different places, which is the one
	// thing this function must not do.
	let all = every_op_sample();

	let name = |op: &Op| match op {
		Op::LinkCreate { .. } => "link.create",
		Op::LinkDelete { .. } => "link.delete",
		Op::LinkSetMtu { .. } => "link.set_mtu",
		Op::LinkSetMac { .. } => "link.set_mac",
		Op::LinkSetMaster { .. } => "link.set_master",
		Op::LinkUnsetMaster { .. } => "link.unset_master",
		Op::LinkUp { .. } => "link.up",
		Op::LinkDown { .. } => "link.down",
		Op::AddrAdd { .. } => "addr.add",
		Op::AddrDel { .. } => "addr.del",
		Op::RouteAdd { .. } => "route.add",
		Op::RouteDel { .. } => "route.del",
		Op::BackendStart { .. } => "backend.start",
		Op::BackendStop { .. } => "backend.stop",
		Op::BackendReload { .. } => "backend.reload",
		Op::BridgeVlanAdd { .. } => "bridge.vlan.add",
		Op::BridgeVlanDel { .. } => "bridge.vlan.del",
		Op::WifiSetProfiles { .. } => "wifi.set_profiles",
		Op::WifiAssociate { .. } => "wifi.associate",
		Op::WifiDisassociate { .. } => "wifi.disassociate",
		Op::WifiSetRegdom { .. } => "wifi.set_regdom",
		Op::AccessControlAdd { .. } => "access_control.add",
		Op::AccessControlDel { .. } => "access_control.del",
		Op::LinkSetBond { .. } => "link.set_bond",
		Op::LinkSetBridge { .. } => "link.set_bridge",
		Op::LinkSetMacvlan { .. } => "link.set_macvlan",
		Op::LinkSetTunnel { .. } => "link.set_tunnel",
		Op::LinkSetVxlan { .. } => "link.set_vxlan",
		Op::WgSetDevice { .. } => "wg.set_device",
		Op::WgSetPeers { .. } => "wg.set_peers",
		Op::DnsApply { .. } => "dns.apply",
		Op::LinkSetOffloads { .. } => "link.set_offloads",
		Op::LinkSetIpv6Token { .. } => "link.set_ipv6_token",
		Op::RuleAdd { .. } => "rule.add",
		Op::RuleDel { .. } => "rule.del",
		Op::QdiscSet { .. } => "qdisc.set",
		Op::QdiscReset { .. } => "qdisc.reset",
		Op::IngressRedirect { .. } => "ingress.redirect",
		Op::IngressRedirectClear { .. } => "ingress.redirect.clear",
		Op::SysctlSetForwarding { .. } => "sysctl.set_forwarding",
		Op::NatReplace { .. } => "nat.replace",
		Op::HookRun { .. } => "hook.run",
		Op::CommitArm { .. } => "commit.arm",
		Op::CommitConfirm => "commit.confirm",
		Op::CommitRevert { .. } => "commit.revert",
	};

	let mut present: Vec<&str> = all.iter().map(name).collect();
	present.sort_unstable();
	present.dedup();
	let mut expected = [
		"access_control.add",
		"access_control.del",
		"addr.add",
		"addr.del",
		"backend.reload",
		"backend.start",
		"backend.stop",
		"bridge.vlan.add",
		"bridge.vlan.del",
		"commit.arm",
		"commit.confirm",
		"commit.revert",
		"dns.apply",
		"hook.run",
		"ingress.redirect",
		"ingress.redirect.clear",
		"link.create",
		"link.delete",
		"link.down",
		"link.set_bond",
		"link.set_bridge",
		"link.set_ipv6_token",
		"link.set_mac",
		"link.set_macvlan",
		"link.set_master",
		"link.set_mtu",
		"link.set_offloads",
		"link.set_tunnel",
		"link.set_vxlan",
		"link.unset_master",
		"link.up",
		"nat.replace",
		"qdisc.reset",
		"qdisc.set",
		"route.add",
		"route.del",
		"rule.add",
		"rule.del",
		"sysctl.set_forwarding",
		"wg.set_device",
		"wg.set_peers",
		"wifi.associate",
		"wifi.disassociate",
		"wifi.set_profiles",
		"wifi.set_regdom",
	];
	expected.sort_unstable();
	assert_eq!(
		present, expected,
		"the witness is missing a sample for an op, so the frozen surface would \
		 not move when that op changed"
	);

	// The names in the witness are the names the crate itself renders, or the
	// witness is pinning a spelling nothing uses.
	for op in &all {
		assert_eq!(op.name(), name(op), "{op:?}");
	}
	all
}

#[allow(clippy::too_many_lines)]
fn every_op_sample() -> Vec<Op> {
	vec![
		Op::LinkCreate {
			name: "br0".to_owned(),
			kind: Box::new(InterfaceKind::Dummy),
		},
		Op::LinkDelete {
			name: "br0".to_owned(),
		},
		Op::LinkSetMtu {
			name: "eth0".to_owned(),
			mtu: 9000,
		},
		Op::LinkSetMac {
			name: "eth0".to_owned(),
			mac: "02:00:00:00:00:01".to_owned(),
		},
		Op::LinkSetMaster {
			name: "eth0".to_owned(),
			master: "br0".to_owned(),
		},
		Op::LinkUnsetMaster {
			name: "eth0".to_owned(),
		},
		Op::LinkUp {
			name: "eth0".to_owned(),
		},
		Op::LinkDown {
			name: "eth0".to_owned(),
		},
		Op::AddrAdd {
			iface: "eth0".to_owned(),
			addr: "192.168.1.10/24".to_owned(),
			preferred_lifetime: Some(3600),
			valid_lifetime: Some(7200),
		},
		Op::AddrDel {
			iface: "eth0".to_owned(),
			addr: "192.168.1.10/24".to_owned(),
		},
		Op::RouteAdd {
			iface: "eth0".to_owned(),
			route: Box::new(route()),
		},
		Op::RouteDel {
			iface: "eth0".to_owned(),
			route: Box::new(route()),
		},
		Op::BackendStart {
			kind: BackendKind::Dhcp4,
			iface: "eth0".to_owned(),
		},
		Op::BackendStop {
			kind: BackendKind::OpenVpn,
			iface: "vpn0".to_owned(),
		},
		Op::BackendReload {
			kind: BackendKind::Supplicant,
			iface: "wlan0".to_owned(),
		},
		Op::BridgeVlanAdd {
			iface: "eth0".to_owned(),
			vid: 10,
			pvid: true,
			untagged: true,
			on_self: false,
		},
		Op::BridgeVlanDel {
			iface: "eth0".to_owned(),
			vid: 10,
			on_self: true,
		},
		Op::WifiSetProfiles {
			device: "wlan0".to_owned(),
			profiles: vec!["home".to_owned()],
		},
		Op::WifiAssociate {
			device: "wlan0".to_owned(),
			network_id: "home".to_owned(),
		},
		Op::WifiDisassociate {
			device: "wlan0".to_owned(),
		},
		Op::WifiSetRegdom {
			device: "wlan0".to_owned(),
			country: "SE".to_owned(),
		},
		Op::AccessControlAdd {
			iface: "wlan0".to_owned(),
			list: AclPolicy::Deny,
			station: "02:00:00:00:00:aa".to_owned(),
		},
		Op::AccessControlDel {
			iface: "wlan0".to_owned(),
			list: AclPolicy::Allow,
			station: "02:00:00:00:00:bb".to_owned(),
		},
		Op::LinkSetBond {
			name: "bond0".to_owned(),
			mode: true,
		},
		Op::LinkSetBridge {
			name: "br0".to_owned(),
		},
		Op::LinkSetMacvlan {
			name: "mv0".to_owned(),
		},
		Op::LinkSetTunnel {
			name: "tun-office".to_owned(),
		},
		Op::LinkSetVxlan {
			name: "vx0".to_owned(),
		},
		Op::WgSetDevice {
			iface: "wg0".to_owned(),
			// A reference, never a key. The whole point of `SecretRef`, and the
			// one thing in this witness worth checking by eye every time it
			// moves: a plan goes to `/run` and over the socket.
			private_key_ref: "@secret:wg0".to_owned(),
			listen_port: Some(51820),
			fwmark: Some(1),
		},
		Op::WgSetPeers {
			iface: "wg0".to_owned(),
			peers: vec![WgPeer {
				name: "office".to_owned(),
				public_key: Key::from_bytes([7; 32]),
				preshared_key: None,
				endpoint: Some("vpn.example:51820".to_owned()),
				allowed_ips: vec!["10.0.0.0/24".to_owned()],
				keepalive: Some(25),
			}],
		},
		Op::DnsApply {
			scope: "globals".to_owned(),
			policy: Box::new(DnsPolicy {
				mode: DnsMode::WriteResolvConf,
				servers: vec![DnsServer {
					addr: "9.9.9.9".parse().expect("an address"),
					port: None,
					sni: None,
				}],
				search: vec!["example.com".to_owned()],
				..DnsPolicy::default()
			}),
		},
		Op::LinkSetOffloads {
			name: "eth0".to_owned(),
			features: vec![("rx-checksum".to_owned(), true)],
		},
		Op::LinkSetIpv6Token {
			name: "eth0".to_owned(),
			token: "::5".to_owned(),
		},
		Op::RuleAdd {
			rule: Box::new(rule()),
		},
		Op::RuleDel {
			rule: Box::new(rule()),
		},
		Op::QdiscSet {
			iface: "eth0".to_owned(),
			kind: "cake".to_owned(),
			bandwidth_bits: Some(20_000_000),
			ingress: true,
		},
		Op::QdiscReset {
			iface: "eth0".to_owned(),
		},
		Op::IngressRedirect {
			iface: "eth0".to_owned(),
			target: "ifb-eth0".to_owned(),
		},
		Op::IngressRedirectClear {
			iface: "eth0".to_owned(),
		},
		Op::SysctlSetForwarding {
			iface: "eth0".to_owned(),
			enabled: true,
		},
		Op::NatReplace {
			uplinks: vec!["eth0".to_owned()],
		},
		Op::HookRun {
			iface: "eth0".to_owned(),
			phase: HookPhase::PostUp,
			path: "/run/netcfgd/hooks/eth0-post_up".to_owned(),
		},
		Op::CommitArm { window_seconds: 90 },
		Op::CommitConfirm,
		Op::CommitRevert {
			to_document_hash: "0000000000000000000000000000000000000000000000000000000000000000"
				.to_owned(),
		},
	]
}

/// The whole plan surface, in one value.
fn witness() -> Plan {
	let actions: Vec<Action> = every_op()
		.into_iter()
		.enumerate()
		.map(|(index, op)| Action {
			id: u32::try_from(index).expect("a small index"),
			// The inverse on every action rather than one: it is an `Option`,
			// and a field that is absent in the sample pins nothing.
			inverse: Some(op.clone()),
			op,
			reason: Reason {
				interface: Some("eth0".to_owned()),
				field: "addressing[0]".to_owned(),
				desired: "192.168.1.10/24".to_owned(),
				observed: "<absent>".to_owned(),
			},
			depends_on: vec![0],
		})
		.collect();

	Plan {
		actions,
		warnings: vec![Warning {
			message: "slaac is accepted but not yet applied by this build".to_owned(),
			interface: Some("eth0".to_owned()),
		}],
		refusals: vec![Refusal {
			interface: "eth0".to_owned(),
			op: "link.down".to_owned(),
			guard: "the office runs on this".to_owned(),
			reason: Reason {
				interface: Some("eth0".to_owned()),
				field: "enabled".to_owned(),
				desired: "false".to_owned(),
				observed: "true".to_owned(),
			},
			override_with: "ncfg apply --allow-disruption eth0".to_owned(),
		}],
		stranded: vec![Stranded {
			interface: "wg0".to_owned(),
			credential: "the WireGuard private key".to_owned(),
			irrevocable: "only every peer's administrator can revoke it".to_owned(),
			remove_with: "on_unmanage = \"clear\"".to_owned(),
			consent_with: "ncfg apply --strand-credentials wg0".to_owned(),
		}],
	}
}

/// The frozen surface, byte for byte.
#[test]
fn the_plan_schema_matches_its_witness() {
	let plan = witness();
	let rendered = serde_json::to_string_pretty(&plan).expect("the witness serialises");

	if std::env::var_os("NCFG_BLESS").is_some() {
		let path = witness_path();
		std::fs::create_dir_all(path.parent().expect("a parent")).expect("mkdir");
		std::fs::write(&path, &rendered).expect("write the witness");
		println!("blessed {}", path.display());
		return;
	}

	let expected = std::fs::read_to_string(witness_path()).unwrap_or_else(|error| {
		panic!(
			"cannot read the plan witness ({error}). If this is a new checkout \
			 something is missing; otherwise run `make schema-bless`."
		)
	});

	if rendered != expected {
		let (line, before, after) = first_difference(&expected, &rendered);
		panic!(
			"the plan schema has changed.\n\
			 \n\
			 first difference at line {line}:\n\
			 \x20 was: {before}\n\
			 \x20 now: {after}\n\
			 \n\
			 A plan goes over the control socket, into /run/netcfgd/plan.last.json\n\
			 and out of `ncfg plan --json`, so an op renamed here is renamed under\n\
			 whatever reads those. Run `make schema-bless` and say in the commit\n\
			 what moved and why."
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
#[test]
fn the_plan_witness_round_trips() {
	let plan = witness();
	let rendered = serde_json::to_string_pretty(&plan).expect("serialises");
	let parsed: Plan = serde_json::from_str(&rendered).expect("parses");
	assert_eq!(parsed, plan);
}

/// A plan carries references to secrets and never secrets.
///
/// Constraint 5 holds for `/run` and the wire as well as for the document, and
/// a plan is both. Cheap to state here, where the whole surface is in one
/// value, and it fails the day somebody resolves a `SecretRef` one step too
/// early.
#[test]
fn no_secret_material_reaches_a_plan() {
	let rendered = serde_json::to_string(&witness()).expect("serialises");
	assert!(
		rendered.contains("@secret:wg0"),
		"the witness should carry a reference to check"
	);
	for suspicious in ["-----BEGIN", "PRIVATE KEY", "passphrase", "password"] {
		assert!(
			!rendered.contains(suspicious),
			"a plan carrying `{suspicious}` is carrying a secret"
		);
	}
}
