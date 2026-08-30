//! The schema freeze, as a test.
//!
//! M4 freezes the document schema, and the freeze is about *this* codebase
//! rather than about anybody else's. Project.md section 8: "the model freezes
//! before any adapter exists, so no adapter can shape it." The NM shim and the
//! TUI arrive later and will both want a field bent their way; the point is
//! that bending one has to be a decision rather than a diff.
//!
//! Nothing consumes the format yet, so a change to it breaks nothing. What the
//! witness buys is visibility: a field renamed in a refactor, a variant
//! reordered, a `skip_serializing_if` added -- none of them looks like a
//! schema change in a diff, and all of them are one.
//!
//! So the frozen surface is written down as a *witness*: one document with
//! every field populated and every variant present, serialised and checked in
//! at `doc/schema/document.json`. Any change to the schema changes those
//! bytes, and the diff is the review.
//!
//! Regenerate deliberately with `make schema-bless`, and say why in the commit.
//! That is the whole mechanism -- the same shape as `size-budget.txt`, for the
//! same reason: a limit that moves silently is not a limit.
//!
//! Populated by hand rather than derived. Writing it out is what forces
//! somebody adding a field to look at every other one, and a generated witness
//! would drift in step with the thing it is meant to pin.

use netcfgd_model::address::{
	Delegated, Dhcp4Backend, Dhcp6Mode, HostnameMode, PdRequest, PrefixRef, Slaac, SlaacPrivacy,
	Static,
};
use netcfgd_model::device::{
	AccessControl, AccessPoint, AclPolicy, Device, DeviceMatch, MacPolicy, Powersave, WifiBackend,
	WifiDevicePolicy,
};
use netcfgd_model::dns::{DnsMode, DnsPolicy, DnsServer, DnsTransport, Dnssec, RoutingDomain};
use netcfgd_model::hook::{HookPhase, HookRef};
use netcfgd_model::interface::{
	BondConfig, BondMode, BridgeConfig, BridgeVlan, Guard, LinkSettings, MacvlanConfig,
	MacvlanMode, PppoeConfig, RaBackend, RaPolicy, Toggle, TunConfig, TunMode, TunnelConfig,
	TunnelKind, VethConfig, VlanConfig, VlanProtocol, VrfConfig, VxlanConfig, WgPeer,
	WireGuardConfig,
};
use netcfgd_model::route::{Route, RouteScope};
use netcfgd_model::rule::{RoutingRule, RuleAction, RuleFamily};
use netcfgd_model::security::{EapConfig, EapMethod, PskConfig, PskProto, Security};
use netcfgd_model::{
	AddressSource, CertSource, Control, Dhcp4, Dhcp6, Document, DriftPolicy, Globals,
	HostnamePolicy, Interface, InterfaceKind, Key, Principal, QdiscKind, QdiscPolicy, RemotePolicy,
	SecretProvider, SecretRef, Ssid, WifiNetwork,
};
use std::path::PathBuf;

fn witness_path() -> PathBuf {
	PathBuf::from(env!("CARGO_MANIFEST_DIR"))
		.join("../..")
		.join("doc/schema/document.json")
}

fn secret(name: &str, provider: SecretProvider) -> SecretRef {
	SecretRef {
		provider,
		name: name.to_owned(),
	}
}

fn key(seed: u8) -> Key {
	Key::from_bytes([seed; 32])
}

/// Every addressing source, so none can be renamed unnoticed.
///
/// **And so none can be *added* unnoticed**, which this list did not manage on
/// its own: `AddressSource::Reported` was added and the witness did not move,
/// because a witness is a sample document and a sample cannot notice a variant
/// nobody put in it. The gate said "every variant present" and nothing checked
/// it -- the same shape as every other gate this project has caught passing on
/// an incomplete input set.
///
/// So there are now two checks below, and it is worth being exact about which
/// one does what -- this comment used to claim more for the second than it
/// delivers. **The exhaustive match is what catches an addition**: it stops this
/// file compiling, in a file whose only purpose is samples. The assertion
/// catches a sample that went away or a name that moved. It does *not* catch an
/// arm written with no sample beside it, because neither list would mention the
/// new name and they would agree; nothing in Rust can enumerate a variant
/// without a value of it. `crates/netcfgd-plan/tests/frozen.rs` says the same
/// thing at greater length.
fn every_address_source() -> Vec<AddressSource> {
	let sources = every_address_source_sample();

	// Two checks, and the first one is a *compile* error rather than a failing
	// assertion. That is the point: adding a variant to `AddressSource` stops
	// this file building until somebody writes an arm, and writing the arm is
	// what reminds them to add the sample below. Never a `_` arm -- a wildcard
	// here restores exactly the hole this closes.
	let name = |source: &AddressSource| match source {
		AddressSource::Static(_) => "static",
		AddressSource::Dhcp4(_) => "dhcp4",
		AddressSource::Dhcp6(_) => "dhcp6",
		AddressSource::Slaac(_) => "slaac",
		AddressSource::Delegated(_) => "delegated",
		AddressSource::LinkLocal => "link_local",
		AddressSource::Reported(_) => "reported",
	};

	// And this one fails at runtime for a sample that went away or a name that
	// moved -- *not* for an arm written above with no sample added below, which
	// this comment claimed until the claim was tried: neither list would mention
	// the new name and the two would agree. Sorted and compared as a set, so it
	// says which one is missing rather than that a count is wrong.
	let mut present: Vec<&str> = sources.iter().map(name).collect();
	present.sort_unstable();
	present.dedup();
	assert_eq!(
		present,
		[
			"delegated",
			"dhcp4",
			"dhcp6",
			"link_local",
			"reported",
			"slaac",
			"static"
		],
		"the witness is missing a sample for an addressing source, so the frozen \
		 surface would not move when that source changed"
	);
	sources
}

fn every_address_source_sample() -> Vec<AddressSource> {
	vec![
		AddressSource::Static(Static {
			address: "192.0.2.1/24".to_owned(),
			peer: Some("192.0.2.2".to_owned()),
			preferred_lifetime: Some(3600),
			valid_lifetime: Some(7200),
		}),
		AddressSource::Dhcp4(Dhcp4 {
			hostname_mode: HostnameMode::SendFqdn,
			client_id: Some("01:02".to_owned()),
			metric: Some(100),
			request_options: vec![121],
			backend: Dhcp4Backend::Dhcpcd,
		}),
		AddressSource::Dhcp6(Dhcp6 {
			mode: Dhcp6Mode::Managed,
			rapid_commit: true,
			prefix_delegation: Some(PdRequest {
				hint: Some("2001:db8::/56".to_owned()),
				length: Some(56),
			}),
		}),
		AddressSource::Slaac(Slaac {
			privacy: SlaacPrivacy::PreferTemporary,
		}),
		AddressSource::Delegated(Delegated {
			prefix: PrefixRef {
				source: "wan0".to_owned(),
				index: 0,
				subnet: 1,
			},
			suffix: "::1/64".to_owned(),
		}),
		AddressSource::LinkLocal,
		AddressSource::Reported(netcfgd_model::Reported::default()),
	]
}

fn every_dns_mode() -> Vec<DnsMode> {
	vec![
		DnsMode::None,
		DnsMode::WriteResolvConf,
		DnsMode::Resolvconf,
		DnsMode::Openresolv,
		DnsMode::Resolved,
		DnsMode::Dnsmasq,
		DnsMode::Unbound,
		DnsMode::Exec("/usr/local/bin/dns".to_owned()),
	]
}

fn dns_policy(mode: DnsMode) -> DnsPolicy {
	// Routing domains only where the mode can carry them. The model refuses
	// the combination at canonicalisation (decision 0007), so a witness that
	// set them unconditionally would not serialise -- which is the validation
	// working, and worth leaving in force rather than reaching around.
	let domains = if mode.can_route() {
		vec![RoutingDomain {
			suffix: "corp.example".to_owned(),
			exclusive: true,
		}]
	} else {
		Vec::new()
	};
	DnsPolicy {
		mode,
		servers: vec![DnsServer {
			addr: "192.0.2.53".parse().expect("an address"),
			port: Some(853),
			sni: Some("dns.example".to_owned()),
		}],
		search: vec!["example".to_owned()],
		domains,
		options: vec!["ndots:2".to_owned()],
		dnssec: Some(Dnssec::Yes),
		transport: Some(DnsTransport::Tls),
	}
}

/// An interface with every optional field set, so `skip_serializing_if` cannot
/// hide one.
fn maximal_interface(name: &str, kind: InterfaceKind) -> Interface {
	Interface {
		name: name.to_owned(),
		kind,
		enabled: true,
		mtu: Some(1400),
		mac: Some("02:00:00:00:00:01".to_owned()),
		addressing: every_address_source(),
		routes: vec![Route {
			destination: "198.51.100.0/24".to_owned(),
			via: Some("192.0.2.254".parse().expect("an address")),
			metric: Some(200),
			table: Some(254),
			src: Some("192.0.2.1".parse().expect("an address")),
			scope: Some(RouteScope::Link),
			onlink: true,
			proto: Some(110),
		}],
		dns: Some(dns_policy(DnsMode::Openresolv)),
		hooks: vec![HookRef {
			phase: HookPhase::PostUp,
			path: "/run/netcfgd/hooks/eth0.0".to_owned(),
			sha256: "0".repeat(64),
			run_as: Some("nobody".to_owned()),
			timeout: Some(30),
		}],
		on_drift: Some(DriftPolicy::Reconcile),
		master: Some("br0".to_owned()),
		dot1x: Some(EapConfig {
			method: EapMethod::Peap,
			identity: "dave".to_owned(),
			anonymous_identity: Some("anonymous".to_owned()),
			password: Some(secret("dot1x", SecretProvider::File)),
			ca_cert: Some(CertSource::Path("/etc/ssl/ca.pem".to_owned())),
			client_cert: Some(CertSource::Path("/etc/ssl/client.pem".to_owned())),
			private_key: Some(CertSource::Stored(secret("key", SecretProvider::Exec))),
			phase2: Some("auth=MSCHAPV2".to_owned()),
		}),
		advertise: Some(RaPolicy {
			backend: RaBackend::Odhcpd,
			prefixes: vec![PrefixRef {
				source: "wan0".to_owned(),
				index: 0,
				subnet: 0,
			}],
			managed: true,
			other_config: true,
			dns: true,
			lifetime: Some(1800),
		}),
		forwarding: Some(true),
		nat: Some(true),
		qdisc: Some(QdiscPolicy {
			kind: QdiscKind::Cake,
			bandwidth_bits: Some(100_000_000),
			ingress_bandwidth_bits: Some(50_000_000),
			ingress: true,
		}),
		ingress_redirect: Some("ifb-eth0".to_owned()),
		guard: Some(Guard {
			reason: "nfs".to_owned(),
		}),
		ipv6_token: Some("::5".to_owned()),
		preference: Some(100),
		// Filled rather than left None, because `probe` is
		// skip_serializing_if: a sample without it pins only the absent form,
		// and the bytes the daemon sends for a probed uplink would be pinned
		// by nothing. The same gap the scan report had.
		probe: Some(netcfgd_model::ProbePolicy {
			command: "/bin/ping".to_owned(),
			args: vec!["-c1".to_owned(), "-W1".to_owned(), "192.0.2.1".to_owned()],
			interval: 30,
			timeout: 5,
			down_after: 3,
			up_after: 2,
			// Non-zero, so the present form is pinned and not only the
			// default: `hold_down` is skip_serializing_if too.
			hold_down: 120,
		}),
		bridge_vlans: vec![
			BridgeVlan {
				vid: 10,
				pvid: true,
				untagged: true,
			},
			BridgeVlan {
				vid: 20,
				pvid: false,
				untagged: false,
			},
		],
		link_settings: Some(LinkSettings {
			autoneg: Toggle::Off,
			speed: Some(1000),
			duplex: Some("full".to_owned()),
			wol: Some("g".to_owned()),
			rx_ring: Some(4096),
			tx_ring: Some(4096),
			gro: Toggle::Off,
			gso: Toggle::On,
			tso: Toggle::Off,
			rx_checksum: Toggle::On,
			tx_checksum: Toggle::Unmanaged,
		}),
	}
}

/// The kinds whose configuration is plain parameters.
fn plain_kinds() -> Vec<(&'static str, InterfaceKind)> {
	vec![
		("physical", InterfaceKind::Physical),
		(
			"bridge",
			InterfaceKind::Bridge(BridgeConfig {
				members: vec!["eth0".to_owned()],
				stp: true,
				forward_delay: Some(4),
				hello_time: Some(2),
				ageing_time: Some(300),
				priority: Some(4096),
				vlan_filtering: true,
			}),
		),
		(
			"bond",
			InterfaceKind::Bond(BondConfig {
				members: vec!["eth1".to_owned()],
				mode: BondMode::Ieee8023ad,
				miimon: Some(100),
			}),
		),
		(
			"vlan",
			InterfaceKind::Vlan(VlanConfig {
				parent: "eth0".to_owned(),
				id: 42,
				protocol: VlanProtocol::Dot1ad,
			}),
		),
		(
			"vxlan",
			InterfaceKind::Vxlan(VxlanConfig {
				id: 100,
				parent: Some("eth0".to_owned()),
				local: Some("192.0.2.1".parse().expect("an address")),
				remote: Some("192.0.2.2".parse().expect("an address")),
				port: Some(4789),
			}),
		),
	]
}

/// The kinds that carry a credential, kept apart only because one list of
/// thirteen was longer than the style allows.
fn credentialled_kinds() -> Vec<(&'static str, InterfaceKind)> {
	vec![
		(
			"wireguard",
			InterfaceKind::WireGuard(WireGuardConfig {
				private_key: secret("wg", SecretProvider::Keyring),
				listen_port: Some(51820),
				fwmark: Some(42),
				peers: vec![WgPeer {
					name: "hub".to_owned(),
					public_key: key(1),
					preshared_key: Some(secret("psk", SecretProvider::Pass)),
					endpoint: Some("vpn.example:51820".to_owned()),
					allowed_ips: vec!["10.0.0.0/24".to_owned()],
					keepalive: Some(25),
				}],
			}),
		),
		(
			"pppoe",
			InterfaceKind::Pppoe(PppoeConfig {
				parent: "eth0".to_owned(),
				username: "alice".to_owned(),
				password: secret("dsl", SecretProvider::File),
				service: Some("internet".to_owned()),
				ac: Some("BRAS-01".to_owned()),
			}),
		),
		("dummy", InterfaceKind::Dummy),
		(
			"veth",
			InterfaceKind::Veth(VethConfig {
				peer: "veth-b".to_owned(),
			}),
		),
		("vrf", InterfaceKind::Vrf(VrfConfig { table: 100 })),
		(
			"macvlan",
			InterfaceKind::Macvlan(MacvlanConfig {
				parent: "eth0".to_owned(),
				mode: MacvlanMode::Passthru,
			}),
		),
		(
			"tunnel",
			InterfaceKind::Tunnel(TunnelConfig {
				mode: TunnelKind::Gretap,
				local: Some("192.0.2.1".parse().expect("an address")),
				remote: Some("192.0.2.2".parse().expect("an address")),
				parent: Some("eth0".to_owned()),
				ttl: Some(64),
				key: Some(7),
			}),
		),
		(
			"tun",
			InterfaceKind::Tun(TunConfig {
				mode: TunMode::Tap,
				owner: Some("qemu".to_owned()),
				group: Some("kvm".to_owned()),
			}),
		),
		// Never written by hand -- the compiler synthesises one per interface
		// that shapes arriving traffic -- but it is in the document, and the
		// witness covers the document rather than the config.
		("ifb", InterfaceKind::Ifb),
		(
			"openvpn",
			InterfaceKind::OpenVpn(netcfgd_model::OpenVpnConfig {
				config: "/etc/openvpn/work.ovpn".to_owned(),
				username: Some("vpn-user".to_owned()),
				password: Some(secret("vpn", SecretProvider::File)),
			}),
		),
	]
}

/// Every interface kind, one interface each.
///
/// **Guarded the same way `every_address_source` is, and for the same reason it
/// needed guarding twice.** That fix was made for `AddressSource` alone and this
/// list kept the hole: `InterfaceKind::OpenVpn` was added, the frozen surface
/// did not move, and the gate stayed green. A witness is a sample document and
/// a sample cannot notice a variant nobody put in it, so *every* list of
/// variants in this file needs the check, not only the one caught first.
fn every_kind() -> Vec<Interface> {
	// Exhaustive, never a wildcard: adding a variant stops this file compiling
	// until somebody writes an arm, and writing the arm is what reminds them to
	// add the sample. That reminder is the whole mechanism -- the assertion
	// underneath does *not* back it up, because an arm with no sample leaves
	// both lists unchanged and agreeing. What the assertion catches is a sample
	// that went away or a name that moved.
	fn name(kind: &InterfaceKind) -> &'static str {
		match kind {
			InterfaceKind::Physical => "physical",
			InterfaceKind::Bridge(_) => "bridge",
			InterfaceKind::Bond(_) => "bond",
			InterfaceKind::Vlan(_) => "vlan",
			InterfaceKind::Vxlan(_) => "vxlan",
			InterfaceKind::WireGuard(_) => "wireguard",
			InterfaceKind::Pppoe(_) => "pppoe",
			InterfaceKind::OpenVpn(_) => "openvpn",
			InterfaceKind::Dummy => "dummy",
			InterfaceKind::Veth(_) => "veth",
			InterfaceKind::Vrf(_) => "vrf",
			InterfaceKind::Macvlan(_) => "macvlan",
			InterfaceKind::Tunnel(_) => "tunnel",
			InterfaceKind::Tun(_) => "tun",
			InterfaceKind::Ifb => "ifb",
		}
	}

	let all: Vec<(&'static str, InterfaceKind)> = plain_kinds()
		.into_iter()
		.chain(credentialled_kinds())
		.collect();
	let mut present: Vec<&str> = all.iter().map(|(_, kind)| name(kind)).collect();
	present.sort_unstable();
	present.dedup();
	assert_eq!(
		present,
		[
			"bond",
			"bridge",
			"dummy",
			"ifb",
			"macvlan",
			"openvpn",
			"physical",
			"pppoe",
			"tun",
			"tunnel",
			"veth",
			"vlan",
			"vrf",
			"vxlan",
			"wireguard"
		],
		"the witness is missing a sample for an interface kind, so the frozen \
		 surface would not move when that kind changed"
	);

	all.into_iter()
		.map(|(name, kind)| maximal_interface(&format!("k-{name}"), kind))
		.collect()
}

/// Every tunnel kind, which the single interface above cannot cover.
fn every_tunnel_kind() -> Vec<Interface> {
	[
		TunnelKind::Gre,
		TunnelKind::Gretap,
		TunnelKind::Ip6gre,
		TunnelKind::Ipip,
		TunnelKind::Sit,
		TunnelKind::Ip6tnl,
		TunnelKind::Geneve,
	]
	.into_iter()
	.map(|kind| Interface {
		name: format!("t-{}", kind.name()),
		kind: InterfaceKind::Tunnel(TunnelConfig {
			mode: kind,
			local: None,
			remote: None,
			parent: None,
			ttl: None,
			key: None,
		}),
		..maximal_interface("t", InterfaceKind::Physical)
	})
	.collect()
}

/// Every wifi security shape.
fn every_network() -> Vec<WifiNetwork> {
	let securities = vec![
		("open", Security::Open),
		(
			"psk",
			Security::Psk(PskConfig {
				passphrase: secret("psk", SecretProvider::File),
				proto: PskProto::Wpa2Wpa3,
			}),
		),
		(
			"eap",
			Security::Eap(EapConfig {
				method: EapMethod::Tls,
				identity: "dave".to_owned(),
				anonymous_identity: None,
				password: None,
				ca_cert: None,
				client_cert: None,
				private_key: Some(CertSource::Stored(secret("k", SecretProvider::File))),
				phase2: None,
			}),
		),
		("owe", Security::Owe),
	];

	let mut networks: Vec<WifiNetwork> = securities
		.into_iter()
		.map(|(name, security)| WifiNetwork {
			id: format!("n-{name}"),
			ssid: Some(Ssid::new(name.as_bytes().to_vec()).expect("an ssid")),
			hidden: true,
			security,
			priority: 30,
			autoconnect: true,
			metered: true,
			bssid: vec!["00:11:22:33:44:55".to_owned()],
			roam: None,
			addressing: every_address_source(),
			routes: Vec::new(),
			dns: Some(dns_policy(DnsMode::Resolved)),
			hooks: Vec::new(),
		})
		.collect();

	// One that roams, on its own network rather than beside a pin: the two are
	// mutually exclusive to the compiler -- an access point to stay on and a
	// better one to move to are different requests -- so a sample carrying both
	// would pin a document nothing can produce.
	networks.push(WifiNetwork {
		id: "n-roaming".to_owned(),
		ssid: Some(Ssid::new(b"roaming".to_vec()).expect("an ssid")),
		hidden: false,
		security: Security::Owe,
		priority: 10,
		autoconnect: true,
		metered: false,
		bssid: Vec::new(),
		roam: Some(netcfgd_model::RoamPolicy {
			signal: -68,
			interval: 20,
			slow_interval: 240,
		}),
		addressing: Vec::new(),
		routes: Vec::new(),
		dns: None,
		hooks: Vec::new(),
	});
	networks
}

/// A document exercising every type, field and variant in the schema.
fn witness() -> Document {
	let mut document = Document {
		schema_version: netcfgd_model::SCHEMA_VERSION,
		// One device, because a witness pins a shape and an empty list would
		// pin nothing about this one.
		bluetooth: vec![netcfgd_model::bluetooth::BluetoothDevice {
			id: "headphones".to_owned(),
			address: "AA:BB:CC:DD:EE:FF".to_owned(),
			profile: netcfgd_model::bluetooth::BluetoothProfile::A2dpSink,
			autoconnect: true,
		}],
		// Excluded from equality and from the hash, and present here so the
		// field itself cannot vanish unnoticed.
		generated_by: Some("witness".to_owned()),
		globals: Globals {
			dns: dns_policy(DnsMode::Dnsmasq),
			on_drift_default: DriftPolicy::Report,
			confirm_default: Some(90),
			hostname_policy: HostnamePolicy::Static("host.example".to_owned()),
			control: Control {
				observe: Principal::Any,
				wifi: Principal::Group("netdev".to_owned()),
				admin: Principal::User("root".to_owned()),
			},
			// Not the default, and mixed rather than uniform: a witness that
			// pinned three falses would serialise the same whether the field
			// carried a policy or a placeholder.
			remote: RemotePolicy {
				observe: true,
				wifi: true,
				admin: false,
			},
		},
		devices: vec![Device {
			name: "wlan0".to_owned(),
			r#match: Some(DeviceMatch {
				mac: Some("02:00:00:00:00:02".to_owned()),
				path: Some("pci-0000:03:00.0".to_owned()),
				driver: Some("iwlwifi".to_owned()),
				name_glob: Some("wl*".to_owned()),
			}),
			managed: true,
			// The witness carries the non-default so a spelling change moves
			// the bytes: a field that is always at its default serialises to
			// nothing and is pinned by nothing.
			on_unmanage: netcfgd_model::OnUnmanage::Clear,
			wifi: Some(WifiDevicePolicy {
				backend: WifiBackend::WpaSupplicant,
				autoconnect: true,
				portal_check: Some("http://example.com/generate_204".to_owned()),
				regdom: Some("SE".to_owned()),
				powersave: Powersave::Off,
				mac_policy: MacPolicy::PerNetwork,
				scan_randomization: true,
			}),
		}],
		interfaces: every_kind(),
		networks: every_network(),
		rules: vec![RoutingRule {
			id: "vpn".to_owned(),
			priority: 100,
			family: RuleFamily::Inet6,
			from: Some("2001:db8::/32".to_owned()),
			to: Some("2001:db8:1::/48".to_owned()),
			iif: Some("eth0".to_owned()),
			oif: Some("eth1".to_owned()),
			fwmark: Some(1),
			fwmask: Some(255),
			table: Some(42),
			action: RuleAction::Prohibit,
			suppress_prefixlength: Some(0),
			l3mdev: true,
			invert: true,
		}],
		access_points: vec![AccessPoint {
			id: "guest".to_owned(),
			ssid: Ssid::new(b"guest".to_vec()).expect("an ssid"),
			device: "wlan0".to_owned(),
			security: Security::Owe,
			channel: Some(6),
			band: Some("2.4".to_owned()),
			hidden: true,
			regdom: Some("SE".to_owned()),
			access_control: Some(AccessControl {
				policy: AclPolicy::Deny,
				stations: vec!["aa:bb:cc:dd:ee:ff".to_owned()],
			}),
		}],
	};
	document.interfaces.extend(every_tunnel_kind());

	// Every remaining enum variant that the shapes above did not reach. A
	// variant with no witness is a variant that can be renamed silently.
	for (index, mode) in every_dns_mode().into_iter().enumerate() {
		let mut interface = maximal_interface(&format!("d-{index}"), InterfaceKind::Physical);
		interface.dns = Some(dns_policy(mode));
		document.interfaces.push(interface);
	}
	for (index, drift) in [
		DriftPolicy::Report,
		DriftPolicy::Reconcile,
		DriftPolicy::Ignore,
	]
	.into_iter()
	.enumerate()
	{
		let mut interface = maximal_interface(&format!("p-{index}"), InterfaceKind::Physical);
		interface.on_drift = Some(drift);
		document.interfaces.push(interface);
	}

	document.canonicalize();
	document
}

/// The frozen surface, byte for byte.
///
/// If this fails and the change was intended, `make schema-bless` rewrites the
/// witness and the commit says why. Nothing reads the format yet, so that is
/// the whole cost -- the gate exists to make the change visible, not to make
/// it expensive.
#[test]
fn the_schema_matches_its_witness() {
	let document = witness();
	let rendered = document
		.to_json_canonical()
		.expect("the witness serialises");

	if std::env::var_os("NCFG_BLESS").is_some() {
		let path = witness_path();
		std::fs::create_dir_all(path.parent().expect("a parent")).expect("mkdir");
		std::fs::write(&path, &rendered).expect("write the witness");
		println!("blessed {}", path.display());
		return;
	}

	let expected = std::fs::read_to_string(witness_path()).unwrap_or_else(|error| {
		panic!(
			"cannot read the schema witness ({error}). If this is a new checkout \
			 something is missing; otherwise run `make schema-bless`."
		)
	});

	if rendered != expected {
		// The diff itself is left to git: printing two thousand lines here
		// would bury the one that changed.
		let (line, before, after) = first_difference(&expected, &rendered);
		panic!(
			"the document schema has changed.\n\
			 \n\
			 first difference at line {line}:\n\
			 \x20 was: {before}\n\
			 \x20 now: {after}\n\
			 \n\
			 Nothing reads this format yet, so the change breaks nothing and is\n\
			 cheap. The gate is here to make it visible: run `make schema-bless`\n\
			 and say in the commit what moved and why.\n\
			 \n\
			 The one thing to weigh is whose idea the change was. M4 froze the\n\
			 model so that a later adapter -- the NM shim, the TUI -- cannot\n\
			 quietly reshape it to suit itself (project.md section 8). A change\n\
			 that comes from the network is ordinary; one that comes from a\n\
			 consumer's convenience is the thing the freeze is for."
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
fn the_witness_round_trips() {
	let document = witness();
	let rendered = document.to_json_canonical().expect("serialises");
	let parsed = Document::from_json(&rendered).expect("parses");
	assert_eq!(parsed, document);
	assert_eq!(parsed.to_json_canonical().expect("re-serialises"), rendered);
}

/// A document from a future major is refused rather than half-read.
///
/// The mechanism, not the ceremony. There is nothing to be compatible with
/// yet, so the version number is not doing work and this does not assert what
/// it is -- what matters is that `from_json` still declines a document it
/// cannot claim to understand, which is the behaviour a rolling upgrade will
/// need whenever there is finally something to roll.
#[test]
fn a_document_from_a_future_major_is_refused() {
	// Patched in the text rather than the struct: the *serialiser* validates
	// the major too, so a future-major document cannot be produced by this
	// build at all. Which is itself the right behaviour -- and means the only
	// way to test the reader is to hand it bytes this build would not write.
	let text = witness().to_json_canonical().expect("serialises").replacen(
		"\"major\": 1",
		"\"major\": 2",
		1,
	);

	let error = Document::from_json(&text).expect_err("a future major must be refused");
	assert!(
		matches!(error, netcfgd_model::Error::SchemaMajor { .. }),
		"got {error:?}"
	);
}
