//! The language, exercised from fixtures with no filesystem in sight.

use netcfgd_compile::{compile, Diagnostics, HookSink, NoHooks, SourceMap};
use netcfgd_model::dns::DnsMode;
use netcfgd_model::{AclPolicy, AddressSource, Document, HookPhase, HookRef, InterfaceKind};

/// A hook sink that records instead of writing.
///
/// The compiler needs `{phase, path, sha256}` and cannot produce them without
/// touching a filesystem, so the caller supplies this. Tests supply a fake and
/// keep the whole front end pure.
#[derive(Debug, Default)]
struct FakeHooks {
	seen: Vec<(HookPhase, String, String)>,
}

impl HookSink for FakeHooks {
	fn materialise(
		&mut self,
		phase: HookPhase,
		owner: &str,
		body: &str,
	) -> Result<HookRef, String> {
		let index = self.seen.len();
		self.seen.push((phase, owner.to_owned(), body.to_owned()));
		Ok(HookRef {
			phase,
			path: format!("/run/netcfgd/hooks/{owner}.{index}"),
			sha256: format!("{index:064}"),
			run_as: None,
			timeout: None,
		})
	}
}

fn build(text: &str) -> Result<Document, Diagnostics> {
	let mut sources = SourceMap::new();
	sources.add("netcfgd.conf", text);
	compile(&sources, &mut NoHooks)
}

fn build_ok(text: &str) -> Document {
	let mut sources = SourceMap::new();
	sources.add("netcfgd.conf", text);
	match compile(&sources, &mut NoHooks) {
		Ok(document) => document,
		Err(diagnostics) => panic!("expected success, got:\n{}", diagnostics.render(&sources)),
	}
}

fn errors(text: &str) -> String {
	let mut sources = SourceMap::new();
	sources.add("netcfgd.conf", text);
	match compile(&sources, &mut NoHooks) {
		Ok(_) => panic!("expected failure, but it compiled"),
		Err(diagnostics) => diagnostics.render(&sources),
	}
}

/// The worked example from design section 3.2, which is the shape a netifrc
/// user will type first.
#[test]
fn a_static_ethernet_interface_compiles() {
	let document = build_ok(
		r#"
		device eth0 { mtu = 1500 }
		interface eth0 {
			config = "192.168.1.10/24"
			routes = "default via 192.168.1.1"
			dns    = "192.168.1.1 1.1.1.1"
		}
		"#,
	);

	assert_eq!(document.interfaces.len(), 1);
	let eth0 = &document.interfaces[0];
	assert_eq!(eth0.name, "eth0");
	assert_eq!(document.devices[0].mtu, Some(1500));
	assert_eq!(eth0.kind, InterfaceKind::Physical);

	match &eth0.addressing[0] {
		AddressSource::Static(address) => assert_eq!(address.address, "192.168.1.10/24"),
		other => panic!("expected a static address, got {other:?}"),
	}
	assert_eq!(eth0.routes[0].destination, "default");
	assert_eq!(
		eth0.routes[0].via,
		Some("192.168.1.1".parse().expect("parses"))
	);

	let dns = eth0.dns.as_ref().expect("dns was set");
	assert_eq!(dns.servers.len(), 2);
}

/// `config = "dhcp"` is the netifrc spelling and the most common line in any
/// real config.
#[test]
fn dhcp_is_spelled_as_a_config_value() {
	let document = build_ok("interface eth0 { config = \"dhcp\" }");
	assert!(matches!(
		document.interfaces[0].addressing[0],
		AddressSource::Dhcp4(_)
	));
}

/// Decision 0006: sources compose. Both spellings, one string with newlines or
/// a list, mean the same thing.
#[test]
fn several_sources_compose_in_either_spelling() {
	let from_string = build_ok("interface eth0 {\n\tconfig = \"192.168.1.10/24\ndhcp\nslaac\"\n}");
	let from_list =
		build_ok("interface eth0 { config = [\"192.168.1.10/24\", \"dhcp\", \"slaac\"] }");

	assert_eq!(from_string.interfaces[0].addressing.len(), 3);
	assert_eq!(from_string, from_list);
}

/// A list may span lines, since a long one is unreadable otherwise.
#[test]
fn a_list_may_span_lines() {
	let document = build_ok(
		r#"
		interface eth0 {
			config = [
				"10.0.0.1/24",
				"10.0.1.1/24",
			]
		}
		"#,
	);
	assert_eq!(document.interfaces[0].addressing.len(), 2);
}

/// Comments and semicolon terminators, both of which the grammar allows and
/// people use.
#[test]
fn comments_and_semicolons_are_accepted() {
	let document = build_ok(
		r#"
		# the uplink
		device eth0 { mtu = 9000 } # jumbo
		interface eth0 { config = "dhcp" }
		"#,
	);
	assert_eq!(document.devices[0].mtu, Some(9000));
}

/// Drop-in precedence: later files win for scalar keys.
#[test]
fn a_later_drop_in_wins_for_a_scalar() {
	let mut sources = SourceMap::new();
	sources.add("netcfgd.conf", "hostname = \"first\"");
	sources.add("conf.d/10-name.conf", "hostname = \"second\"");

	let document = compile(&sources, &mut NoHooks).expect("compiles");
	assert_eq!(
		document.globals.hostname_policy,
		netcfgd_model::HostnamePolicy::Static("second".to_owned())
	);
}

/// The rule that keeps layering predictable: redefining a block is an error,
/// not a silent last-wins.
#[test]
fn redefining_a_block_without_override_is_an_error() {
	let mut sources = SourceMap::new();
	sources.add("netcfgd.conf", "interface eth0 { config = \"dhcp\" }");
	sources.add(
		"conf.d/10-lan.conf",
		"interface eth0 { config = \"10.0.0.1/24\" }",
	);

	let diagnostics = compile(&sources, &mut NoHooks).expect_err("must refuse");
	let rendered = diagnostics.render(&sources);
	assert!(
		rendered.contains("conf.d/10-lan.conf"),
		"the diagnostic should name the later file: {rendered}"
	);
	assert!(
		rendered.contains("already defined") && rendered.contains("override"),
		"and should say how to fix it: {rendered}"
	);
}

/// With `override` the same pair is accepted, and replaces wholesale.
#[test]
fn override_replaces_a_block_entirely() {
	let mut sources = SourceMap::new();
	sources.add(
		"netcfgd.conf",
		"interface eth0 { config = \"dhcp\"\nenabled = false }",
	);
	sources.add(
		"conf.d/10-lan.conf",
		"override interface eth0 { config = \"10.0.0.1/24\" }",
	);

	let document = compile(&sources, &mut NoHooks).expect("compiles");
	assert_eq!(document.interfaces.len(), 1);
	// Wholesale, not merged: `enabled = false` from the first definition is
	// gone. A merge would make the result depend on which keys the earlier
	// block happened to set.
	assert!(document.interfaces[0].enabled);
	assert!(matches!(
		document.interfaces[0].addressing[0],
		AddressSource::Static(_)
	));
}

/// Overriding something that does not exist is a typo with a confident tone.
#[test]
fn override_with_nothing_to_override_is_an_error() {
	let rendered = errors("override interface eth0 { config = \"dhcp\" }");
	assert!(rendered.contains("nothing to override"), "got: {rendered}");
}

/// The irregular production: a hook body ends at the first line that is only a
/// closing brace, whatever braces the shell contains.
#[test]
fn a_hook_body_survives_braces_in_the_shell() {
	let text = "interface eth0 {\n\
		\tconfig = \"dhcp\"\n\
		\tpost_up {\n\
		if [ -n \"$NCFG_ADDR\" ]; then\n\
		\techo \"up ${NCFG_IFACE}\" | logger\n\
		fi\n\
		}\n\
		}\n";

	let mut sources = SourceMap::new();
	sources.add("netcfgd.conf", text);
	let mut hooks = FakeHooks::default();
	let document = match compile(&sources, &mut hooks) {
		Ok(document) => document,
		Err(diagnostics) => panic!("expected success, got:\n{}", diagnostics.render(&sources)),
	};

	assert_eq!(hooks.seen.len(), 1);
	let (phase, owner, body) = &hooks.seen[0];
	assert_eq!(*phase, HookPhase::PostUp);
	assert_eq!(owner, "eth0");
	// Every brace-bearing line survived, and the closing line did not.
	assert!(body.contains("${NCFG_IFACE}"), "body was: {body:?}");
	assert!(body.contains("fi\n"), "body was: {body:?}");
	assert!(!body.contains("\n}\n"), "the close line leaked: {body:?}");

	assert_eq!(document.interfaces[0].hooks.len(), 1);
	assert_eq!(document.interfaces[0].hooks[0].phase, HookPhase::PostUp);
}

/// `on <event>` reaches the phases with no keyword of their own.
#[test]
fn on_names_the_remaining_phases() {
	let text = "interface eth0 {\n\
		\tconfig = \"dhcp\"\n\
		\ton lease {\n\
		echo leased\n\
		}\n\
		}\n";

	let mut sources = SourceMap::new();
	sources.add("netcfgd.conf", text);
	let mut hooks = FakeHooks::default();
	compile(&sources, &mut hooks).expect("compiles");
	assert_eq!(hooks.seen[0].0, HookPhase::Lease);
}

/// A caller with nowhere to put hooks refuses them rather than dropping them,
/// which would produce a document describing a system nobody asked for.
#[test]
fn a_sink_that_cannot_materialise_refuses_loudly() {
	let text = "interface eth0 {\n\tpost_up {\necho hi\n}\n}\n";
	let rendered = errors(text);
	assert!(
		rendered.contains("cannot materialise hooks"),
		"got: {rendered}"
	);
}

/// Decision 0007, through the language: routing domains under a flat mode are
/// refused, and the model's validation is what refuses them.
#[test]
fn routing_domains_under_a_flat_mode_are_refused() {
	let rendered = errors(
		r#"
		interface wg0 {
			config      = "10.9.0.2/24"
			dns         = "10.9.0.1"
			dns_mode    = "write_resolv_conf"
			dns_domains = "~corp.example"
		}
		"#,
	);
	assert!(rendered.contains("routing domains"), "got: {rendered}");
}

/// The same config under openresolv compiles, and the `~` sigil becomes the
/// exclusive flag rather than being kept as part of the suffix.
#[test]
fn routing_domains_under_openresolv_compile() {
	let document = build_ok(
		r#"
		interface wg0 {
			config      = "10.9.0.2/24"
			dns         = "10.9.0.1"
			dns_mode    = "openresolv"
			dns_domains = "~corp.example example.test"
		}
		"#,
	);

	let dns = document.interfaces[0].dns.as_ref().expect("dns was set");
	assert_eq!(dns.mode, DnsMode::Openresolv);
	assert_eq!(dns.domains.len(), 2);
	let corp = dns
		.domains
		.iter()
		.find(|d| d.suffix == "corp.example")
		.expect("suffix has no sigil");
	assert!(corp.exclusive);
	let plain = dns
		.domains
		.iter()
		.find(|d| d.suffix == "example.test")
		.expect("present");
	assert!(!plain.exclusive);
}

/// A delegated prefix is written as an indirection in the language too, so the
/// document never holds a prefix that a lease has not produced yet.
#[test]
fn a_delegated_prefix_is_a_reference() {
	let document = build_ok(
		r#"
		interface br-lan {
			config = "@pd:wan0/1=::1/64"
		}
		"#,
	);

	match &document.interfaces[0].addressing[0] {
		AddressSource::Delegated(delegated) => {
			assert_eq!(delegated.prefix.source, "wan0");
			assert_eq!(delegated.prefix.subnet, 1);
			assert_eq!(delegated.suffix, "::1/64");
		}
		other => panic!("expected a delegated address, got {other:?}"),
	}
}

/// Nested link-type blocks set the interface kind.
#[test]
fn a_vlan_block_sets_the_kind() {
	let document = build_ok(
		r#"
		interface lan-10 {
			vlan { parent = "eth0"; id = 10 }
			config = "10.0.10.1/24"
		}
		"#,
	);

	match &document.interfaces[0].kind {
		InterfaceKind::Vlan(vlan) => {
			assert_eq!(vlan.parent, "eth0");
			assert_eq!(vlan.id, 10);
		}
		other => panic!("expected a vlan, got {other:?}"),
	}
}

/// Compilation is deterministic: the same text is the same document, and the
/// same bytes.
#[test]
fn compiling_twice_gives_identical_bytes() {
	let text = r#"
	interface eth1 { config = "dhcp" }
	interface eth0 { config = "10.0.0.1/24" }
	global { on_drift = "reconcile" }
	"#;

	let first = build_ok(text).to_json_canonical().expect("valid");
	let second = build_ok(text).to_json_canonical().expect("valid");
	assert_eq!(first, second);

	// And the interfaces come out sorted regardless of the order written.
	let document = build_ok(text);
	let names: Vec<&str> = document
		.interfaces
		.iter()
		.map(|i| i.name.as_str())
		.collect();
	assert_eq!(names, ["eth0", "eth1"]);
}

/// A diagnostic names the file, the line and the column. Design section 17
/// requires it, and a parse error without a position sends the reader hunting
/// through a directory of drop-ins.
#[test]
fn a_diagnostic_names_file_line_and_column() {
	let mut sources = SourceMap::new();
	sources.add("netcfgd.conf", "device eth0 {\n\tmtu = \"big\"\n}\n");

	let diagnostics = compile(&sources, &mut NoHooks).expect_err("must refuse");
	let rendered = diagnostics.render(&sources);
	assert!(
		rendered.starts_with("netcfgd.conf:2:"),
		"expected file:line:col, got: {rendered}"
	);
	assert!(rendered.contains("expected a number"), "got: {rendered}");
}

/// Four mistakes should take one edit round, not four.
#[test]
fn every_error_is_reported_not_only_the_first() {
	let mut sources = SourceMap::new();
	sources.add(
		"netcfgd.conf",
		"device eth0 {\n\
		 \tmtu = \"big\"\n\
		 }\n\
		 interface eth0 {\n\
		 \tnonsense = 1\n\
		 \tconfig = \"999.999.999.999/24\"\n\
		 }\n",
	);

	let diagnostics = compile(&sources, &mut NoHooks).expect_err("must refuse");
	assert!(
		diagnostics.len() >= 3,
		"expected several diagnostics, got {}:\n{}",
		diagnostics.len(),
		diagnostics.render(&sources)
	);
}

/// Section 2 forbids floats. The lexer says so in those words rather than
/// letting the `.` surface as an unexpected character.
#[test]
fn a_float_is_refused_by_name() {
	let rendered = errors("device eth0 { mtu = 15.5 }");
	assert!(rendered.contains("integers"), "got: {rendered}");
}

/// An address without a prefix length is caught at compile time rather than
/// half way through configuring the interface.
#[test]
fn an_address_without_a_prefix_length_is_refused() {
	let rendered = errors("interface eth0 { config = \"192.168.1.10\" }");
	assert!(rendered.contains("not an address"), "got: {rendered}");
}

/// And one whose prefix length is impossible.
#[test]
fn an_impossible_prefix_length_is_refused() {
	let rendered = errors("interface eth0 { config = \"192.168.1.10/64\" }");
	assert!(rendered.contains("between 0 and 32"), "got: {rendered}");
}

/// There is nothing left for the compiler to defer.
///
/// This test used to assert that a feature in the model but not in the build
/// named its milestone. It has been repointed four times -- `network` blocks,
/// then wireguard, then pppoe -- and now every block the language accepts is
/// implemented. What remains unimplemented is recognised at compile time by
/// design (decision 0018) and reported by `ncfg plan`, which
/// `recognised_but_unimplemented_features_are_named_in_the_plan` covers.
///
/// So the claim this file can still make is the narrower one: a block the
/// language does not know is an error rather than something quietly dropped.
#[test]
fn an_unknown_block_is_an_error_rather_than_ignored() {
	let rendered = errors("interface eth0 {\n\tsorcery { level = 9 }\n}");
	assert!(
		rendered.contains("not valid inside `interface`"),
		"got: {rendered}"
	);

	let rendered = errors("wizardry \"x\" { }");
	assert!(
		rendered.contains("unknown top-level block"),
		"got: {rendered}"
	);
}

/// Unterminated constructs are named rather than producing a cascade.
#[test]
fn an_unclosed_block_is_reported() {
	let rendered = errors("interface eth0 {\n\tconfig = \"dhcp\"\n");
	assert!(rendered.contains("unclosed block"), "got: {rendered}");
}

/// An unterminated hook body cannot be recovered from, and says so.
#[test]
fn an_unterminated_hook_body_is_reported() {
	let rendered = errors("interface eth0 {\n\tpost_up {\necho hi\n");
	assert!(
		rendered.contains("unterminated hook body"),
		"got: {rendered}"
	);
}

/// A string may span lines, which the grammar requires because the netifrc
/// spelling puts several entries in one value. The cost is that a missing
/// closing quote swallows the rest of the file, so the diagnostic has to point
/// at the opening quote -- reporting where the lexer gave up would send the
/// reader to a line that is not the mistake.
#[test]
fn a_runaway_string_points_at_its_opening_quote() {
	let mut sources = SourceMap::new();
	sources.add(
		"netcfgd.conf",
		"interface eth0 {\n\tconfig = \"dhcp\n\tmtu = 1500\n}\n",
	);

	let diagnostics = compile(&sources, &mut NoHooks).expect_err("must refuse");
	let rendered = diagnostics.render(&sources);
	assert!(
		rendered.contains("netcfgd.conf:2:11"),
		"expected the opening quote's position, got: {rendered}"
	);
	assert!(rendered.contains("unterminated string"), "got: {rendered}");
}

/// The compiler opens no files, so an unresolved include is an error rather
/// than a silent omission.
#[test]
fn an_unresolved_include_is_an_error() {
	let rendered = errors("include \"conf.d/extra.conf\"");
	assert!(rendered.contains("not resolved"), "got: {rendered}");
}

/// The parser must not panic on anything, since a config file is input the
/// daemon reads with privileges. This is the cheap deterministic stand-in for
/// the fuzz target section 6 requires; it is not a replacement for it.
#[test]
fn adversarial_input_never_panics() {
	let seeds = [
		"",
		"\0",
		"{",
		"}",
		"[",
		"\"",
		"\"\\",
		"interface",
		"interface {",
		"interface eth0 { config = }",
		"= = =",
		"a = [[[[[[[[",
		"a = 99999999999999999999999999",
		"a = -",
		"post_up {",
		"on {",
		"override",
		"override override override",
		"include",
		"\u{feff}interface eth0 {}",
		"interface \u{1f600} {}",
		"a = \"\\q\"",
		"# comment with no newline",
		"interface eth0 { dns = 1 }",
	];

	for seed in seeds {
		// Any outcome is acceptable except a panic.
		let _ = build(seed);
	}

	// And the same seeds concatenated, which reaches states no single seed
	// does.
	let combined = seeds.join("\n");
	let _ = build(&combined);
}

/// netifrc's primary spelling for several addresses is space-separated, not
/// newline-separated. Splitting on newlines alone treated the whole line as
/// one malformed address, which is a real config failing to compile.
#[test]
fn several_addresses_on_one_line_are_separate_entries() {
	let document =
		build_ok(r#"interface eth0 { config = "192.168.0.2/24 192.168.0.3/24 192.168.0.4/24" }"#);
	assert_eq!(document.interfaces[0].addressing.len(), 3);
}

/// And mixed: spaces within a line, newlines between lines.
#[test]
fn spaces_and_newlines_both_separate_entries() {
	let document = build_ok(
		"interface eth0 {\n\tconfig = \"192.168.0.2/24 192.168.0.3/24\n4321:0:1:2:3:4:567:89ab/64\"\n}",
	);
	assert_eq!(document.interfaces[0].addressing.len(), 3);
}

/// The reason the split needs a modifier table: a netmask is itself
/// address-shaped, so a naive whitespace split makes two addresses out of one.
#[test]
fn a_netmask_does_not_start_a_second_address() {
	let document = build_ok(r#"interface eth0 { config = "192.168.0.2 netmask 255.255.255.0" }"#);
	assert_eq!(document.interfaces[0].addressing.len(), 1);
	match &document.interfaces[0].addressing[0] {
		AddressSource::Static(address) => assert_eq!(address.address, "192.168.0.2/24"),
		other => panic!("expected a static address, got {other:?}"),
	}
}

/// A netmask with a hole in it is not a netmask.
#[test]
fn a_non_contiguous_netmask_is_refused() {
	let rendered = errors(r#"interface eth0 { config = "192.168.0.2 netmask 255.0.255.0" }"#);
	assert!(rendered.contains("contiguous"), "got: {rendered}");
}

/// Two spellings of the same thing in one entry is a mistake, not a merge.
#[test]
fn a_prefix_and_a_netmask_together_are_refused() {
	let rendered = errors(r#"interface eth0 { config = "192.168.0.2/24 netmask 255.255.255.0" }"#);
	assert!(rendered.contains("not both"), "got: {rendered}");
}

/// Lifetimes and peers are carried through, including netifrc's `forever`.
#[test]
fn supported_modifiers_reach_the_model() {
	let document = build_ok(
		r#"interface eth0 { config = "192.168.0.2/24 peer 192.168.0.1 preferred_lft 0 valid_lft forever" }"#,
	);
	match &document.interfaces[0].addressing[0] {
		AddressSource::Static(address) => {
			assert_eq!(address.peer.as_deref(), Some("192.168.0.1"));
			assert_eq!(address.preferred_lifetime, Some(0));
			assert_eq!(address.valid_lifetime, None);
		}
		other => panic!("expected a static address, got {other:?}"),
	}
}

/// A modifier this build cannot honour is named rather than dropped. Acting on
/// a subset of what the author wrote is the failure mode section 2 exists to
/// prevent, and it applies to the language as well as to the document.
#[test]
fn an_unsupported_modifier_is_named_not_ignored() {
	let rendered = errors(r#"interface eth0 { config = "192.168.0.2/24 scope host" }"#);
	assert!(rendered.contains("`scope`"), "got: {rendered}");
	assert!(rendered.contains("not supported"), "got: {rendered}");
}

/// netifrc's `null` means "no address", used on bridge members. An empty
/// addressing list is already legal, so it contributes nothing.
#[test]
fn null_yields_no_addressing_at_all() {
	let document = build_ok(r#"interface eth0 { config = "null" }"#);
	assert!(document.interfaces[0].addressing.is_empty());
}

/// `noop` means "keep whatever is there", which a reconciler cannot express:
/// there is no state to converge on.
#[test]
fn noop_is_refused_with_an_explanation() {
	let rendered = errors(r#"interface eth0 { config = "noop 192.168.0.2/24" }"#);
	assert!(rendered.contains("reconciled model"), "got: {rendered}");
}

/// A stray word is caught rather than swallowed.
#[test]
fn a_word_that_is_neither_address_nor_keyword_is_refused() {
	let rendered = errors(r#"interface eth0 { config = "192.168.0.2/24 wibble" }"#);
	assert!(rendered.contains("wibble"), "got: {rendered}");
}

/// The wifi example from design section 3.2, which is what a laptop config
/// actually looks like.
#[test]
fn the_wifi_example_compiles() {
	let document = build_ok(
		r#"
device wlan0 {
	wifi {
		backend      = "wpa_supplicant"
		autoconnect  = true
		portal_check = "http://example.com/generate_204"
		regdom       = "SE"
		powersave    = "off"
	}
}

network "HomeFiber" {
	metric = 30
	wifi   { psk = "@secret:HomeFiber" }
	config = "dhcp"
}

network "Office" {
	wifi {
		eap      = "peap"
		identity = "dave"
		password = "@secret:Office"
		ca_cert  = "/etc/ssl/certs/office.pem"
	}
	metric = 60
	config = "dhcp"
}

network "Phone Hotspot" {
	wifi    { psk = "@secret:Hotspot" }
	metric  = 600
	config  = "dhcp"
	metered = true
}
"#,
	);

	let radio = document.devices[0].wifi.as_ref().expect("a wifi policy");
	assert_eq!(
		radio.backend,
		netcfgd_model::device::WifiBackend::WpaSupplicant
	);
	assert_eq!(radio.regdom.as_deref(), Some("SE"));
	assert_eq!(radio.powersave, netcfgd_model::device::Powersave::Off);

	// Sorted by id, per the schema.
	let ids: Vec<&str> = document
		.networks
		.iter()
		.map(|network| network.id.as_str())
		.collect();
	assert_eq!(ids, ["HomeFiber", "Office", "Phone Hotspot"]);

	let home = &document.networks[0];
	assert_eq!(
		home.ssid.as_ref().expect("a stated ssid").as_bytes(),
		b"HomeFiber"
	);
	// The ordering the old `priority` expressed, inverted rather than copied:
	// HomeFiber was the most preferred at 30 where higher won, so it is the
	// most preferred at 30 where lower wins -- and the other two moved past
	// it rather than this one moving (0154).
	assert_eq!(home.metric, Some(30));
	assert_eq!(document.networks[1].metric, Some(60));
	assert_eq!(document.networks[2].metric, Some(600));
	assert!(matches!(home.security, netcfgd_model::Security::Psk(_)));

	// A space in an SSID is ordinary and must survive being a block label.
	assert_eq!(
		document.networks[2]
			.ssid
			.as_ref()
			.expect("a stated ssid")
			.as_bytes(),
		b"Phone Hotspot"
	);
	assert!(document.networks[2].metered);
}

/// A passphrase written into the config would make "config files are safe to
/// commit" a convention rather than a property. The first person to paste one
/// in has to be told, not accommodated.
#[test]
fn an_inline_passphrase_is_refused() {
	let message = errors(r#"network "Home" { wifi { psk = "hunter2hunter2" } }"#);
	assert!(message.contains("secret reference"), "got: {message}");
	assert!(message.contains("@secret:"), "got: {message}");
	assert!(
		!message.contains("hunter2hunter2"),
		"a diagnostic must not echo the passphrase: {message}"
	);
}

/// Two kinds of security means guessing which was meant, and the wrong guess
/// is either a network that will not join or one joined with less protection
/// than was asked for.
#[test]
fn a_network_has_one_kind_of_security() {
	let message =
		errors(r#"network "Home" { wifi { psk = "@secret:home"; eap = "peap"; identity = "d" } }"#);
	assert!(message.contains("one kind of security"), "got: {message}");
}

/// An open network is a real thing and almost never what somebody meant to
/// write. Silence here is how a laptop joins anything using the same name.
#[test]
fn a_network_with_no_security_block_must_say_so() {
	let message = errors(r#"network "Cafe" { config = "dhcp" }"#);
	assert!(message.contains("open network"), "got: {message}");
	assert!(message.contains("open = true"), "got: {message}");

	// And saying so compiles.
	let document = build_ok(r#"network "Cafe" { wifi { open = true }; config = "dhcp" }"#);
	assert_eq!(document.networks[0].security, netcfgd_model::Security::Open);
}

/// An EAP network with no CA certificate **compiles**.
///
/// It authenticates to any server that answers, which is worth saying and is
/// said -- as a plan warning, by `netcfgd-plan` (0087). It used to be said here,
/// by pushing a `Diagnostic`, and the only severity this compiler has is fatal:
/// so a network that pins nothing did not compile, which is precisely what 0017
/// rejected. The comment above the code even said "not an error".
///
/// Plenty of real deployments pin nothing. A tool that refuses one on security
/// grounds nobody asked it for is replaced by a tool that works, and then it
/// protects nothing at all.
#[test]
fn eap_without_a_ca_certificate_still_compiles() {
	let document = build_ok(
		r#"network "Corp" { wifi { eap = "ttls"; identity = "d"; password = "@secret:c" } }"#,
	);
	let netcfgd_model::Security::Eap(eap) = &document.networks[0].security else {
		panic!("expected an eap network");
	};
	assert!(eap.ca_cert.is_none());
}

/// WPA3 has to be expressible, and the default has to be the transitional mode
/// that works against both -- picking WPA2 by default would quietly cap a WPA3
/// network's security at WPA2.
#[test]
fn the_wpa_generation_defaults_to_transitional() {
	use netcfgd_model::security::PskProto;

	let default = build_ok(r#"network "H" { wifi { psk = "@secret:h" } }"#);
	let netcfgd_model::Security::Psk(config) = &default.networks[0].security else {
		panic!("expected a psk network");
	};
	assert_eq!(config.proto, PskProto::Wpa2Wpa3);

	let wpa3 = build_ok(r#"network "H" { wifi { psk = "@secret:h"; proto = "wpa3" } }"#);
	let netcfgd_model::Security::Psk(config) = &wpa3.networks[0].security else {
		panic!("expected a psk network");
	};
	assert_eq!(config.proto, PskProto::Wpa3);
}

/// An SSID is 32 arbitrary octets, so a name that is not text needs a way in.
#[test]
fn a_non_text_ssid_can_be_given_as_hex() {
	let document = build_ok(r#"network "the odd one" { ssid = "ff0080"; wifi { open = true } }"#);
	assert_eq!(
		document.networks[0]
			.ssid
			.as_ref()
			.expect("a stated ssid")
			.as_bytes(),
		&[0xff, 0x00, 0x80]
	);
	// The label stays the handle, so the network still has one readable name.
	assert_eq!(document.networks[0].id, "the odd one");
}

/// iwd compiles and is refused at use, so the diagnostic can explain why
/// rather than reading as a typo (decision 0014).
#[test]
fn the_iwd_backend_compiles_so_it_can_be_refused_by_name() {
	let document = build_ok(r#"device wlan0 { wifi { backend = "iwd" } }"#);
	assert_eq!(
		document.devices[0].wifi.as_ref().expect("policy").backend,
		netcfgd_model::device::WifiBackend::Iwd
	);
}

/// A regulatory domain the kernel ignores is a radio quietly using the
/// world-roaming defaults, which is not a thing anybody notices.
#[test]
fn a_malformed_regulatory_domain_is_refused() {
	for bad in ["se", "SWE", "S"] {
		let message = errors(&format!(
			r#"device wlan0 {{ wifi {{ regdom = "{bad}" }} }}"#
		));
		assert!(
			message.contains("regulatory domain"),
			"`{bad}` should be refused: {message}"
		);
	}
}

/// Decision 0008: 802.1X lives on the interface, because port-based access
/// control predates radios and is ordinary on wired campus networks. Nesting
/// it under an SSID made the wired case inexpressible.
#[test]
fn a_wired_port_can_carry_dot1x() {
	let document = build_ok(
		r#"
interface eth0 {
	dot1x {
		eap      = "peap"
		identity = "dave@corp.example"
		password = "@secret:corp"
		ca_cert  = "/etc/ssl/certs/corp.pem"
		phase2   = "auth=MSCHAPV2"
	}
	config = "dhcp"
}
"#,
	);
	let eap = document.interfaces[0]
		.dot1x
		.as_ref()
		.expect("a dot1x config");
	assert_eq!(eap.method, netcfgd_model::EapMethod::Peap);
	assert_eq!(eap.identity, "dave@corp.example");
	assert_eq!(eap.phase2.as_deref(), Some("auth=MSCHAPV2"));
}

/// A wired port has no passphrase, no band and no priority. Accepting those
/// keys and ignoring them would let somebody write a config that says
/// something the system does not do.
#[test]
fn wireless_only_keys_are_refused_on_a_wired_port() {
	for key in ["psk = \"@secret:x\"", "priority = 3", "owe = true"] {
		let message = errors(&format!("interface eth0 {{ dot1x {{ {key} }} }}"));
		assert!(
			message.contains("means nothing on a wired port"),
			"`{key}` should be refused: {message}"
		);
	}
}

/// A `dot1x` block with no method is a port that would authenticate with
/// nothing, which is not a thing to guess at.
#[test]
fn dot1x_without_a_method_is_refused() {
	let message = errors(r#"interface eth0 { dot1x { identity = "dave" } }"#);
	assert!(message.contains("needs an `eap` method"), "got: {message}");
}

/// Policy routing: which table a packet is looked up in, which is a different
/// question from where it goes. Without it a machine that needs it has `ip
/// rule` in a hook and netcfgd reporting no drift.
#[test]
fn policy_routing_rules_compile() {
	let document = build_ok(
		r#"
rule work    { priority = 100; from = "192.168.8.0/24"; lookup = 42 }
rule marked  { priority = 200; fwmark = 1; fwmask = 255; lookup = 43; family = "inet6" }
rule dropped { priority = 50;  to = "10.0.0.0/8"; action = "blackhole" }
rule nodefault { priority = 90; lookup = 254; suppress_prefixlength = 0 }
"#,
	);

	// Sorted by priority, because that is the order the kernel consults them
	// and any other order would misrepresent what the config does.
	let priorities: Vec<u32> = document.rules.iter().map(|rule| rule.priority).collect();
	assert_eq!(priorities, [50, 90, 100, 200]);

	assert_eq!(
		document.rules[0].action,
		netcfgd_model::RuleAction::Blackhole
	);
	assert_eq!(document.rules[1].suppress_prefixlength, Some(0));
	assert_eq!(document.rules[2].from.as_deref(), Some("192.168.8.0/24"));
	assert_eq!(document.rules[3].family, netcfgd_model::RuleFamily::Inet6);
	assert_eq!(document.rules[3].fwmark, Some(1));

	// The name is the handle a diagnostic can use; the rendering is the rule
	// as the kernel holds it, so it can be compared against `ip rule`.
	assert_eq!(document.rules[0].id, "dropped");
	assert_eq!(
		document.rules[2].render(),
		"100: from 192.168.8.0/24 lookup 42"
	);
}

/// The priority is mandatory even though the kernel would assign one: an
/// unnumbered rule lands wherever the kernel puts it, two applies can order
/// them differently, and then the document has stopped describing the system.
#[test]
fn a_rule_without_a_priority_is_refused() {
	let message = errors("rule vpn { lookup = 42 }");
	assert!(message.contains("no `priority`"), "got: {message}");
	assert!(message.contains("two applies"), "got: {message}");
}

/// A rule that looks up no table and names no action does nothing, and reads
/// as though it does something. The likeliest cause is a `lookup` somebody
/// meant to write.
#[test]
fn a_rule_that_does_nothing_is_refused() {
	let message = errors(r#"rule vpn { priority = 100; from = "10.0.0.0/8" }"#);
	assert!(message.contains("looks up no table"), "got: {message}");
	assert!(message.contains("add `lookup = N`"), "got: {message}");
}

/// A mask with no mark matches nothing in particular while looking as though
/// it narrows something.
#[test]
fn a_mask_without_a_mark_is_refused() {
	let message = errors("rule vpn { priority = 100; fwmask = 255; lookup = 42 }");
	assert!(message.contains("no `fwmark`"), "got: {message}");
}

/// An IPv6 token is the host half only. The kernel accepts a full address and
/// silently uses the bottom 64 bits, so a config that looks like it pins an
/// address would quietly pin half of one.
#[test]
fn an_ipv6_token_must_be_host_bits_only() {
	let document = build_ok(r#"interface eth0 { ipv6_token = "::5"; config = "dhcp" }"#);
	assert_eq!(document.interfaces[0].ipv6_token.as_deref(), Some("::5"));

	let message = errors(r#"interface eth0 { ipv6_token = "2001:db8::5"; config = "dhcp" }"#);
	assert!(message.contains("prefix half"), "got: {message}");
	assert!(
		message.contains("::5"),
		"the help shows the right shape: {message}"
	);

	assert!(errors(r#"interface eth0 { ipv6_token = "10.0.0.1" }"#).contains("not an IPv6"));
}

/// MAC randomization: a client that always uses its permanent address is
/// trackable across every network it has joined by anyone who has seen it
/// twice. The default stays permanent, because some networks admit by address.
#[test]
fn mac_policy_compiles_and_defaults_to_permanent() {
	use netcfgd_model::MacPolicy;

	let default = build_ok(r#"device wlan0 { wifi { backend = "auto" } }"#);
	let policy = default.devices[0].wifi.as_ref().expect("policy");
	assert_eq!(policy.mac_policy, MacPolicy::Permanent);
	assert!(!policy.scan_randomization);

	let chosen = build_ok(
		r#"device wlan0 { wifi { mac_policy = "per_network"; scan_randomization = true } }"#,
	);
	let policy = chosen.devices[0].wifi.as_ref().expect("policy");
	assert_eq!(policy.mac_policy, MacPolicy::PerNetwork);
	assert!(policy.scan_randomization);

	assert!(
		errors(r#"device wlan0 { wifi { mac_policy = "sometimes" } }"#)
			.contains("not a MAC policy")
	);
}

/// ethtool settings are in the schema and not in the build. They still have to
/// compile, or a config that will work in a later release is a config that has
/// to be rewritten to upgrade.
#[test]
fn ethtool_settings_compile_even_though_nothing_applies_them() {
	use netcfgd_model::Toggle;

	let document = build_ok(
		r#"
device eth0 {
	ethtool { gro = "off"; tso = "off"; rx_ring = 4096; wol = "g" }
}
interface eth0 { config = "dhcp" }
"#,
	);
	let settings = document.devices[0]
		.link_settings
		.as_ref()
		.expect("link settings");
	assert_eq!(settings.gro, Toggle::Off);
	assert_eq!(settings.tso, Toggle::Off);
	assert_eq!(settings.rx_ring, Some(4096));
	assert_eq!(settings.wol.as_deref(), Some("g"));
	// Unmanaged is a third state, not a synonym for off: "netcfgd does not
	// touch this" and "netcfgd requires this off" are different instructions.
	assert_eq!(settings.gso, Toggle::Unmanaged);

	assert!(errors(r#"device eth0 { ethtool { duplex = "sideways" } }"#)
		.contains("not a duplex setting"));
}

/// An empty `ethtool` block asks for nothing, and must not produce a settings
/// object -- an action that changes nothing does not belong in a plan.
#[test]
fn an_empty_ethtool_block_produces_nothing() {
	let document = build_ok(
		r#"device eth0 { ethtool { } }
interface eth0 { config = "dhcp" }"#,
	);
	assert!(document.devices[0].link_settings.is_none());
}

/// An access point is bound to one radio, unlike a `network`, which
/// deliberately is not.
/// The policy for what happens on the way out of being managed.
#[test]
fn a_device_can_say_what_to_do_when_it_stops_being_managed() {
	let document = build_ok(r#"device wlan0 { managed = false; on_unmanage = "clear" }"#);
	assert_eq!(
		document.devices[0].on_unmanage,
		netcfgd_model::OnUnmanage::Clear
	);

	// The default is to walk away, which is what a device that says nothing
	// gets -- and what decision 0035 settled on.
	let quiet = build_ok(r"device wlan0 { managed = false }");
	assert_eq!(
		quiet.devices[0].on_unmanage,
		netcfgd_model::OnUnmanage::Leave
	);

	// A policy nobody implements is refused by name rather than ignored, and
	// the help says which one to reach for.
	let message = errors(r#"device wlan0 { on_unmanage = "burn" }"#);
	assert!(
		message.contains("`burn` is not an `on_unmanage` policy"),
		"{message}"
	);
	assert!(message.contains("leaving your hands"), "{message}");
}

#[test]
fn an_access_point_compiles_and_names_its_radio() {
	let document = build_ok(
		r#"
access_point "guest" {
	device  = "wlan0"
	channel = 6
	wifi    { psk = "@secret:guest"; proto = "wpa2" }
}
"#,
	);
	assert_eq!(document.access_points[0].device, "wlan0");
	assert_eq!(document.access_points[0].channel, Some(6));
	assert_eq!(document.access_points[0].ssid.as_bytes(), b"guest");

	let message = errors(r#"access_point "guest" { wifi { open = true } }"#);
	assert!(message.contains("which radio runs it"), "got: {message}");
}

/// The single-host half of Ubiquiti-style roaming (decision 0036): a station is
/// kept off every access point except the one meant to serve it.
#[test]
fn an_access_control_block_carries_one_station_list() {
	let document = build_ok(
		r#"
access_point "guest" {
	device = "wlan0"
	wifi   { open = true }
	access_control { deny = ["AA-BB-CC-DD-EE-FF", "00:11:22:33:44:55"] }
}
"#,
	);
	let acl = document.access_points[0]
		.access_control
		.as_ref()
		.expect("the block compiles");
	assert_eq!(acl.policy, AclPolicy::Deny);
	// Normalised to hostapd's spelling and sorted, so that the same two
	// stations written either way give the same document.
	assert_eq!(acl.stations, ["00:11:22:33:44:55", "aa:bb:cc:dd:ee:ff"]);

	let allow = build_ok(
		r#"
access_point "guest" {
	device = "wlan0"
	wifi   { open = true }
	access_control { allow = "aa:bb:cc:dd:ee:ff" }
}
"#,
	);
	let acl = allow.access_points[0]
		.access_control
		.as_ref()
		.expect("a bare string is a one-element list");
	assert_eq!(acl.policy, AclPolicy::Allow);
	assert_eq!(acl.stations, ["aa:bb:cc:dd:ee:ff"]);
}

#[test]
fn an_access_point_has_one_station_list_rather_than_two() {
	// hostapd reads the accept list or the deny list, never both, so a
	// configuration naming both would have half of it silently ignored.
	let message = errors(
		r#"
access_point "guest" {
	device = "wlan0"
	wifi   { open = true }
	access_control { deny = "aa:bb:cc:dd:ee:ff"; allow = "00:11:22:33:44:55" }
}
"#,
	);
	assert!(message.contains("one station list"), "got: {message}");

	// And what is not an address is refused where it was written, rather than
	// handed to hostapd to fail on later.
	let message = errors(
		r#"
access_point "guest" {
	device = "wlan0"
	wifi   { open = true }
	access_control { deny = "aabbccddeeff" }
}
"#,
	);
	assert!(
		message.contains("six colon-separated octets"),
		"got: {message}"
	);
}

/// A VLAN interface is conventionally named `eth0.42`, and design section 3.2
/// uses exactly that spelling. Without a dot in identifiers the standard name
/// for the commonest virtual interface does not parse.
#[test]
fn an_interface_name_may_contain_a_dot() {
	let document = build_ok(
		r#"interface eth0.42 { vlan { parent = "eth0"; id = 42 }; config = "10.42.0.2/24" }"#,
	);
	assert!(document
		.interfaces
		.iter()
		.any(|interface| interface.name == "eth0.42"));

	// But a bare dot still is not a name, and a float is still refused.
	assert!(build(".42 { }").is_err());
}

/// Membership can be written from either end. The model holds only `master`,
/// because that is the direction the kernel works in -- so the list has to be
/// expanded, and before it was it was accepted and ignored: the bridge came up
/// empty and the apply reported success.
#[test]
fn bridge_members_become_masters() {
	let document = build_ok(
		r#"
interface br0 { bridge { members = "eth0 eth1" }; config = "dhcp" }
interface eth0 { config = "null" }
"#,
	);

	let master_of = |name: &str| {
		document
			.interfaces
			.iter()
			.find(|interface| interface.name == name)
			.unwrap_or_else(|| panic!("no {name}"))
			.master
			.clone()
	};
	// One had a block of its own; the other did not, and gets one. Otherwise
	// `bridge { members = ... }` only works when every member is also spelled
	// out, which is not the shape anybody writes.
	assert_eq!(master_of("eth0").as_deref(), Some("br0"));
	assert_eq!(master_of("eth1").as_deref(), Some("br0"));
}

/// Said twice consistently is fine -- drop-ins do that. Said twice differently
/// is one of them being wrong, and guessing puts an interface in the wrong
/// bridge.
#[test]
fn a_contradictory_membership_is_refused() {
	let agreed = build_ok(
		r#"
interface br0 { bridge { members = "eth0" }; config = "dhcp" }
interface eth0 { master = "br0"; config = "null" }
"#,
	);
	assert_eq!(agreed.interfaces.len(), 2);

	let message = errors(
		r#"
interface br0 { bridge { members = "eth0" }; config = "dhcp" }
interface br1 { bridge { members = "eth0" }; config = "dhcp" }
interface eth0 { config = "null" }
"#,
	);
	assert!(message.contains("is listed as a member"), "got: {message}");
	assert!(message.contains("one master"), "got: {message}");
}

/// A bonding mode a string could hold but the kernel rejects is a config that
/// compiles, plans cleanly, and fails with the interface half-built.
#[test]
fn a_bonding_mode_is_checked_at_compile_time() {
	use netcfgd_model::BondMode;

	let document = build_ok(
		r#"interface bond0 { bond { members = "eth0"; mode = "802.3ad" }; config = "dhcp" }"#,
	);
	let netcfgd_model::InterfaceKind::Bond(bond) = &document.interfaces[0].kind else {
		panic!("expected a bond");
	};
	assert_eq!(bond.mode, BondMode::Ieee8023ad);
	assert_eq!(bond.mode.number(), 4);

	let message = errors(r#"interface bond0 { bond { mode = "active_backup" } }"#);
	assert!(message.contains("not a bonding mode"), "got: {message}");
	assert!(
		message.contains("active-backup"),
		"the help spells it: {message}"
	);
}

/// VXLAN, which had no lowering at all: `interface vx0 { vxlan { ... } }` was
/// an unknown block.
#[test]
fn vxlan_compiles() {
	let document = build_ok(
		r#"
interface vx100 {
	vxlan { id = 100; parent = "eth0"; local = "10.0.0.1"; remote = "10.0.0.2"; port = 4789 }
	config = "null"
}
"#,
	);
	let netcfgd_model::InterfaceKind::Vxlan(vxlan) = &document.interfaces[0].kind else {
		panic!("expected a vxlan");
	};
	assert_eq!(vxlan.id, 100);
	assert_eq!(vxlan.parent.as_deref(), Some("eth0"));
	assert_eq!(vxlan.port, Some(4789));

	// A VNI over 24 bits is silently truncated by the kernel, so two tunnels
	// that look distinct in the config become one.
	assert!(errors("interface vx0 { vxlan { id = 16777216 } }").contains("24 bits"));
	// Mixing families produces a kernel error that names neither end.
	assert!(errors(
		r#"interface vx0 { vxlan { id = 1; local = "10.0.0.1"; remote = "fd00::1" } }"#
	)
	.contains("same address family"));
	assert!(errors(r#"interface vx0 { vxlan { parent = "eth0" } }"#).contains("needs an `id`"));
}

/// A veth is a pair and both ends are named at creation.
#[test]
fn veth_compiles() {
	let document = build_ok(r#"interface veth-a { veth { peer = "veth-b" }; config = "null" }"#);
	let netcfgd_model::InterfaceKind::Veth(veth) = &document.interfaces[0].kind else {
		panic!("expected a veth");
	};
	assert_eq!(veth.peer, "veth-b");
	assert!(errors("interface veth-a { veth { } }").contains("needs a `peer`"));
}

/// `WireGuard`, which had been refused with "lands in M4" since M1.
#[test]
fn wireguard_compiles() {
	let document = build_ok(
		r#"
interface wg0 {
	wireguard {
		private_key = "@secret:wg0"
		listen_port = 51820
		peer hub {
			public_key  = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
			endpoint    = "vpn.example.com:51820"
			allowed_ips = "10.0.0.0/24 fd00::/64"
			keepalive   = 25
		}
	}
	config = "10.0.0.5/32"
}
"#,
	);
	let netcfgd_model::InterfaceKind::WireGuard(wg) = &document.interfaces[0].kind else {
		panic!("expected a wireguard interface");
	};
	assert_eq!(wg.listen_port, Some(51820));
	assert_eq!(wg.peers.len(), 1);
	assert_eq!(wg.peers[0].allowed_ips.len(), 2);
	assert_eq!(wg.peers[0].keepalive, Some(25));
}

/// A public key that is not 32 octets of base64 fails here rather than after
/// the interface has been created and the tunnel is half-built.
#[test]
fn a_malformed_public_key_is_refused_at_compile_time() {
	let message = errors(
		r#"
interface wg0 {
	wireguard {
		private_key = "@secret:wg0"
		peer hub { public_key = "not-a-key"; allowed_ips = "10.0.0.0/24" }
	}
}
"#,
	);
	assert!(message.contains("not a public key"), "got: {message}");
	assert!(message.contains("44 characters"), "got: {message}");
}

/// A private key written into the config would be a private key in version
/// control. It is a secret reference like every other credential.
#[test]
fn a_wireguard_private_key_must_be_a_secret() {
	let message = errors(
		r#"interface wg0 { wireguard { private_key = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=" } }"#,
	);
	assert!(message.contains("secret reference"), "got: {message}");

	let missing = errors(r"interface wg0 { wireguard { listen_port = 51820 } }");
	assert!(missing.contains("needs a `private_key`"), "got: {missing}");
}

/// A peer with no allowed IPs is legal to the kernel, receives nothing, is
/// routed nothing, and is never what anybody meant.
#[test]
fn a_peer_with_no_allowed_ips_is_refused() {
	let message = errors(
		r#"
interface wg0 {
	wireguard {
		private_key = "@secret:wg0"
		peer hub { public_key = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=" }
	}
}
"#,
	);
	assert!(
		message.contains("nothing would route to it"),
		"got: {message}"
	);
}

/// A public key is a peer's identity, so two peers sharing one is two halves
/// of one entry -- the kernel would keep the last and the other's allowed IPs
/// would silently vanish.
#[test]
fn two_peers_may_not_share_a_public_key() {
	let message = errors(
		r#"
interface wg0 {
	wireguard {
		private_key = "@secret:wg0"
		peer a { public_key = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="; allowed_ips = "10.0.0.0/24" }
		peer b { public_key = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="; allowed_ips = "10.0.1.0/24" }
	}
}
"#,
	);
	assert!(message.contains("share the public key"), "got: {message}");
}

/// The link kinds the pre-freeze format audit turned up. Each is expressible
/// in netifrc or networkd and was not expressible here.
#[test]
fn the_audit_kinds_compile() {
	use netcfgd_model::{InterfaceKind, MacvlanMode, TunnelKind};

	let document = build_ok(
		r#"
interface mgmt-vrf { vrf { table = 100 }; config = "null" }
interface base0    { kind = "dummy"; config = "10.7.0.1/24" }
interface mv0      { macvlan { parent = "base0"; mode = "bridge" }; config = "null" }
interface gre1     { tunnel { mode = "gre"; local = "10.7.0.1"; remote = "10.7.0.2" }; config = "null" }
interface tap0     { tap { owner = "qemu" }; config = "null" }
"#,
	);

	let kind = |name: &str| {
		document
			.interfaces
			.iter()
			.find(|interface| interface.name == name)
			.unwrap_or_else(|| panic!("no {name}"))
			.kind
			.clone()
	};

	let InterfaceKind::Vrf(vrf) = kind("mgmt-vrf") else {
		panic!("expected a vrf");
	};
	assert_eq!(vrf.table, 100);

	// A dummy was creatable by the executor and unsayable in the config until
	// the audit noticed -- the gap was in netcfgd's own coverage, not against
	// a foreign format.
	assert!(matches!(kind("base0"), InterfaceKind::Dummy));

	let InterfaceKind::Macvlan(macvlan) = kind("mv0") else {
		panic!("expected a macvlan");
	};
	assert_eq!(macvlan.mode, MacvlanMode::Bridge);

	let InterfaceKind::Tunnel(tunnel) = kind("gre1") else {
		panic!("expected a tunnel");
	};
	assert_eq!(tunnel.mode, TunnelKind::Gre);

	let InterfaceKind::Tun(tun) = kind("tap0") else {
		panic!("expected a tap");
	};
	assert_eq!(tun.mode, netcfgd_model::TunMode::Tap);
}

/// A VRF with no table isolates traffic into nowhere.
#[test]
fn a_vrf_needs_a_table() {
	let message = errors("interface v { vrf { } }");
	assert!(message.contains("needs a `table`"), "got: {message}");
}

/// A hostname is checked here, because the kernel's refusal names nothing.
///
/// A write to `/proc/sys/kernel/hostname` fails with `EINVAL` for a name with a
/// space in it, which arrives at apply time with no line number and no key.
#[test]
fn a_hostname_is_a_hostname() {
	let document = build_ok(r#"global { hostname = "laptop.example" }"#);
	assert!(matches!(
		document.globals.hostname_policy,
		netcfgd_model::HostnamePolicy::Static(ref name) if name == "laptop.example"
	));

	// The one overloaded word, which stays what it has always meant.
	let document = build_ok(r#"global { hostname = "dhcp" }"#);
	assert!(matches!(
		document.globals.hostname_policy,
		netcfgd_model::HostnamePolicy::FromDhcp
	));

	for bad in ["a name", "-leading", "trailing-", "two..dots", ""] {
		let message = errors(&format!(r#"global {{ hostname = "{bad}" }}"#));
		assert!(
			message.contains("is not a hostname"),
			"`{bad}` was accepted: {message}"
		);
	}
}

/// `slaac` takes a privacy setting, which had no spelling until decision 0061.
///
/// The model has carried `SlaacPrivacy` since M1 and the config language had no
/// way to reach it, so a reader of the schema would have thought RFC 4941
/// temporary addresses worked. They now do.
#[test]
fn slaac_takes_a_privacy_setting() {
	let document = build_ok(r#"interface eth0 { config = "slaac privacy prefer_temporary" }"#);
	assert!(matches!(
		document.interfaces[0].addressing[0],
		netcfgd_model::AddressSource::Slaac(netcfgd_model::Slaac {
			privacy: netcfgd_model::SlaacPrivacy::PreferTemporary
		})
	));

	// The default is off, and saying so explicitly is allowed.
	let document = build_ok(r#"interface eth0 { config = "slaac" }"#);
	assert!(matches!(
		document.interfaces[0].addressing[0],
		netcfgd_model::AddressSource::Slaac(netcfgd_model::Slaac {
			privacy: netcfgd_model::SlaacPrivacy::None
		})
	));
	build_ok(r#"interface eth0 { config = "slaac privacy none" }"#);

	// And a value nobody can act on is refused rather than ignored.
	let message = errors(r#"interface eth0 { config = "slaac privacy yes" }"#);
	assert!(message.contains("not a privacy setting"), "got: {message}");
	let message = errors(r#"interface eth0 { config = "slaac privacy" }"#);
	assert!(message.contains("needs a value"), "got: {message}");
}

/// A geneve tunnel has no underlay interface, so a `parent` could only be dropped.
///
/// There is no attribute for one in geneve's netlink family and `ip` offers no
/// `dev` for it either -- asked, rather than assumed, after the same value turned
/// out to be going to the wrong place for a VXLAN and for every other tunnel
/// kind (0060). Refused here because this is the layer that can still name the
/// line it was written on.
#[test]
fn a_geneve_tunnel_has_no_parent() {
	let message = errors(r#"interface g { tunnel { mode = "geneve"; vni = 1; parent = "eth0" } }"#);
	assert!(message.contains("no underlay interface"), "got: {message}");

	// And the kinds that do have one still take it.
	let document =
		build_ok(r#"interface t { tunnel { mode = "gre"; parent = "eth0" }; config = "null" }"#);
	let netcfgd_model::InterfaceKind::Tunnel(tunnel) = &document.interfaces[0].kind else {
		panic!("expected a tunnel");
	};
	assert_eq!(tunnel.parent.as_deref(), Some("eth0"));
}

/// A v6 endpoint on a v4 encapsulation produces a link the kernel refuses to
/// build, with an error naming neither the interface nor the field.
#[test]
fn a_tunnel_endpoint_must_match_its_encapsulation() {
	let message = errors(r#"interface t { tunnel { mode = "ipip"; remote = "fd00::1" } }"#);
	assert!(message.contains("IPv4 outer header"), "got: {message}");
	assert!(message.contains("`remote` is IPv6"), "got: {message}");

	// And the v6 kinds want v6 endpoints.
	let message = errors(r#"interface t { tunnel { mode = "ip6tnl"; local = "10.0.0.1" } }"#);
	assert!(message.contains("IPv6 outer header"), "got: {message}");
}

/// tun and tap are in the schema and cannot be created, because they come from
/// an ioctl rather than netlink. The config compiles so the schema is settled
/// before the freeze; the refusal happens where the attempt would.
#[test]
fn a_tun_device_compiles_and_says_it_cannot_be_created() {
	let document = build_ok(r#"interface tun0 { tun { }; config = "null" }"#);
	assert!(matches!(
		document.interfaces[0].kind,
		netcfgd_model::InterfaceKind::Tun(_)
	));
}

/// The bridge parameters netifrc sets and netcfgd could not.
#[test]
fn the_remaining_bridge_parameters_compile() {
	let document = build_ok(
		r#"interface br0 { bridge { hello_time = 3; ageing_time = 60; priority = 4096; vlan_filtering = true }; config = "null" }"#,
	);
	let netcfgd_model::InterfaceKind::Bridge(bridge) = &document.interfaces[0].kind else {
		panic!("expected a bridge");
	};
	assert_eq!(bridge.hello_time, Some(3));
	assert_eq!(bridge.ageing_time, Some(60));
	assert_eq!(bridge.priority, Some(4096));
	assert!(bridge.vlan_filtering);
	// Off unless asked: a bridge quietly becoming VLAN-aware drops untagged
	// traffic that used to pass.
	let plain = build_ok(r#"interface br1 { bridge { }; config = "null" }"#);
	let netcfgd_model::InterfaceKind::Bridge(bridge) = &plain.interfaces[0].kind else {
		panic!("expected a bridge");
	};
	assert!(!bridge.vlan_filtering);
}

/// `PPPoE`, which for a DSL line is not a nicety -- it is the only way onto the
/// network at all.
#[test]
fn pppoe_compiles() {
	let document = build_ok(
		r#"
interface ppp0 {
	pppoe {
		parent   = "eth0"
		username = "alice@isp.example"
		password = "@secret:dsl"
		service  = "internet"
	}
	routes = "default"
}
"#,
	);
	let netcfgd_model::InterfaceKind::Pppoe(pppoe) = &document.interfaces[0].kind else {
		panic!("expected a pppoe interface");
	};
	assert_eq!(pppoe.parent, "eth0");
	assert_eq!(pppoe.username, "alice@isp.example");
	assert_eq!(pppoe.service.as_deref(), Some("internet"));

	// The route a DSL user actually needs: a point-to-point link has no
	// gateway, so `default` with no `via` is a device route netcfgd owns --
	// rather than one pppd installs behind its back.
	assert_eq!(document.interfaces[0].routes.len(), 1);
	assert_eq!(document.interfaces[0].routes[0].destination, "default");
	assert!(document.interfaces[0].routes[0].via.is_none());
}

/// A DSL password inline would put it in version control, like every other
/// credential here.
#[test]
fn a_pppoe_password_must_be_a_secret() {
	let message = errors(
		r#"interface ppp0 { pppoe { parent = "eth0"; username = "a"; password = "hunter2" } }"#,
	);
	assert!(message.contains("secret reference"), "got: {message}");

	let missing = errors(r#"interface ppp0 { pppoe { parent = "eth0" } }"#);
	assert!(missing.contains("needs a `username`"), "got: {missing}");

	let parentless = errors(r#"interface ppp0 { pppoe { username = "a" } }"#);
	assert!(parentless.contains("needs a `parent`"), "got: {parentless}");
}

/// Per-port VLAN membership: how a switch is provisioned on any current
/// kernel, since DSA presents switch ports as ordinary interfaces.
#[test]
fn bridge_vlans_compile() {
	let document = build_ok(
		r#"
interface br0  { bridge { vlan_filtering = true }; vlans = "10"; config = "null" }
interface lan1 {
	master = "br0"
	vlans  = "
		10 pvid untagged
		20
		30-32
	"
	config = "null"
}
"#,
	);
	let vlans = |name: &str| {
		document
			.interfaces
			.iter()
			.find(|interface| interface.name == name)
			.unwrap_or_else(|| panic!("no {name}"))
			.bridge_vlans
			.clone()
	};

	assert_eq!(vlans("br0").len(), 1);
	// The range is expanded here, so nothing downstream has to know ranges
	// exist -- the kernel compresses them again on the way out.
	let ids: Vec<u16> = vlans("lan1").iter().map(|vlan| vlan.vid).collect();
	assert_eq!(ids, [10, 20, 30, 31, 32]);
	assert!(vlans("lan1")[0].pvid && vlans("lan1")[0].untagged);
	assert!(!vlans("lan1")[1].pvid && !vlans("lan1")[1].untagged);
}

/// 0 is not a VLAN and 4095 is reserved. The kernel refuses both with an errno
/// rather than a name.
#[test]
fn an_impossible_vlan_id_is_refused() {
	assert!(errors(r#"interface p { vlans = "0" }"#).contains("not a VLAN id"));
	assert!(errors(r#"interface p { vlans = "4095" }"#).contains("not a VLAN id"));
	assert!(errors(r#"interface p { vlans = "20-10" }"#).contains("counts backwards"));
	assert!(errors(r#"interface p { vlans = "10 sideways" }"#).contains("not a vlan option"));
}

/// A PVID is where untagged ingress lands, so a range of them would be several
/// answers to one question.
#[test]
fn a_range_cannot_be_the_pvid() {
	let message = errors(r#"interface p { vlans = "10-20 pvid" }"#);
	assert!(message.contains("cannot be the pvid"), "got: {message}");
}

/// Rates are written the way `tc` writes them and stored the way the model
/// wants them: decimal multipliers in, bits per second out.
#[test]
fn a_shaped_rate_is_converted_to_bits() {
	for (written, bits) in [
		("100mbit", 100_000_000_u64),
		("1gbit", 1_000_000_000),
		("512kbit", 512_000),
		("2000000", 2_000_000),
	] {
		let document = build_ok(&format!(
			"interface eth0 {{\n\tqdisc {{ kind = \"cake\"; bandwidth = \"{written}\" }}\n}}"
		));
		let qdisc = document.interfaces[0].qdisc.expect("a qdisc");
		assert_eq!(qdisc.bandwidth_bits, Some(bits), "for {written}");
	}
}

/// A scheduler netcfgd does not set is refused by name, with the set that is
/// allowed and the reason the rest are not.
#[test]
fn a_classful_scheduler_is_refused_with_the_reason() {
	let rendered = errors("interface eth0 {\n\tqdisc = \"htb\"\n}");
	assert!(
		rendered.contains("not a queueing discipline netcfgd sets"),
		"got: {rendered}"
	);
	assert!(rendered.contains("fq_codel"), "got: {rendered}");
	assert!(rendered.contains("0023"), "got: {rendered}");
}

/// A rate on a scheduler that cannot shape is refused rather than dropped.
///
/// Dropping it would leave somebody with an unshaped uplink and a config
/// saying otherwise, which is the failure that is hardest to notice.
#[test]
fn a_rate_on_a_scheduler_that_cannot_shape_is_refused() {
	let rendered =
		errors("interface eth0 {\n\tqdisc { kind = \"fq_codel\"; bandwidth = \"100mbit\" }\n}");
	assert!(
		rendered.contains("cannot shape to a rate"),
		"got: {rendered}"
	);
}

/// A rate that is not a rate says what one looks like.
#[test]
fn a_malformed_rate_is_reported() {
	let rendered = errors("interface eth0 {\n\tqdisc { kind = \"cake\"; bandwidth = \"fast\" }\n}");
	assert!(rendered.contains("is not a rate"), "got: {rendered}");

	let rendered =
		errors("interface eth0 {\n\tqdisc { kind = \"cake\"; bandwidth = \"0mbit\" }\n}");
	assert!(rendered.contains("would pass nothing"), "got: {rendered}");
}

/// `ingress_bandwidth` expands into a device to shape on and a redirect to it.
#[test]
fn ingress_shaping_expands_into_a_device_and_a_redirect() {
	let document = build_ok(
		"interface wan0 {\n\tqdisc { kind = \"cake\"; ingress_bandwidth = \"50mbit\" }\n}",
	);

	let wan = document
		.interfaces
		.iter()
		.find(|i| i.name == "wan0")
		.expect("wan0");
	assert_eq!(wan.ingress_redirect.as_deref(), Some("ifb-wan0"));
	// Consumed by the expansion rather than left on both: two places holding
	// the same rate is two places to disagree.
	assert_eq!(wan.qdisc.expect("a qdisc").ingress_bandwidth_bits, None);

	let ifb = document
		.interfaces
		.iter()
		.find(|i| i.name == "ifb-wan0")
		.expect("the synthesised ifb");
	assert!(matches!(ifb.kind, netcfgd_model::InterfaceKind::Ifb));
	let qdisc = ifb.qdisc.expect("a qdisc on the ifb");
	assert_eq!(qdisc.bandwidth_bits, Some(50_000_000));
	assert!(qdisc.ingress, "cake has to know it is metering arrivals");
}

/// The derived device name has to fit in IFNAMSIZ, and the arithmetic is in
/// the message rather than left to the reader.
#[test]
fn an_interface_too_long_to_shape_arrivals_on_is_refused() {
	let rendered = errors(
		"interface twelvechars0 {\n\tqdisc { kind = \"cake\"; ingress_bandwidth = \"50mbit\" }\n}",
	);
	assert!(
		rendered.contains("too long a name to shape arriving traffic"),
		"got: {rendered}"
	);
	assert!(rendered.contains("ifb-twelvechars0"), "got: {rendered}");
}

/// Only cake shapes, so only cake can shape arrivals.
#[test]
fn ingress_shaping_needs_cake() {
	let rendered = errors(
		"interface wan0 {\n\tqdisc { kind = \"fq_codel\"; ingress_bandwidth = \"50mbit\" }\n}",
	);
	assert!(
		rendered.contains("cannot shape arriving traffic"),
		"got: {rendered}"
	);
}

/// A device that would collide with one the operator declared is refused
/// rather than taken over.
#[test]
fn a_colliding_ifb_name_is_refused() {
	let rendered = errors(
		"interface ifb-wan0 { config = \"null\" }\ninterface wan0 {\n\tqdisc { kind = \"cake\"; ingress_bandwidth = \"50mbit\" }\n}",
	);
	assert!(
		rendered.contains("needs to create a device of that name"),
		"got: {rendered}"
	);
}

/// The request half of prefix delegation, which had no spelling until now.
///
/// The model has carried `PdRequest` since the M4 freeze and nothing could set
/// it, so a router could consume a prefix (`@pd:`) that it had no way to ask
/// for. Decision 0051.
#[test]
fn a_dhcp6_source_can_ask_for_a_prefix() {
	let document = build_ok(
		r#"
		interface wan0 { config = "dhcp6 pd" }
		"#,
	);
	let AddressSource::Dhcp6(dhcp6) = &document.interfaces[0].addressing[0] else {
		panic!("got {:?}", document.interfaces[0].addressing);
	};
	let request = dhcp6.prefix_delegation.as_ref().expect("`pd` asks for one");
	// Bare `pd` asks for whatever the ISP gives out, which is odhcp6c's `-P 0`.
	assert_eq!(request.length, None);
	assert_eq!(request.hint, None);
}

/// And it can say what to ask for. Both are a request rather than a value: a
/// server may hand back a different size or a different block, which is why the
/// prefix that arrives is read back from the report.
#[test]
fn a_prefix_request_can_carry_a_length_and_a_hint() {
	let document = build_ok(
		r#"
		interface wan0 { config = "dhcp6 pd_length 56 pd_hint 2001:db8::" }
		"#,
	);
	let AddressSource::Dhcp6(dhcp6) = &document.interfaces[0].addressing[0] else {
		panic!("got {:?}", document.interfaces[0].addressing);
	};
	let request = dhcp6.prefix_delegation.as_ref().expect("a request");
	assert_eq!(request.length, Some(56));
	assert_eq!(request.hint.as_deref(), Some("2001:db8::"));
}

/// A `dhcp6` with nothing said about delegation asks for no prefix.
///
/// It used to ask anyway -- `-P 0` went to odhcp6c unconditionally, so every
/// `config = "dhcp6"` solicited a delegation nobody had written down.
#[test]
fn a_plain_dhcp6_asks_for_no_prefix() {
	let document = build_ok(r#"interface wan0 { config = "dhcp6" }"#);
	let AddressSource::Dhcp6(dhcp6) = &document.interfaces[0].addressing[0] else {
		panic!("got {:?}", document.interfaces[0].addressing);
	};
	assert!(dhcp6.prefix_delegation.is_none());
}

/// A length or a hint implies the request, so neither is silently inert.
#[test]
fn a_length_alone_still_asks() {
	let document = build_ok(r#"interface wan0 { config = "dhcp6 pd_length 60" }"#);
	let AddressSource::Dhcp6(dhcp6) = &document.interfaces[0].addressing[0] else {
		panic!("got {:?}", document.interfaces[0].addressing);
	};
	assert_eq!(
		dhcp6
			.prefix_delegation
			.as_ref()
			.and_then(|request| request.length),
		Some(60)
	);
}

/// A value that is not a length says so where the line is.
#[test]
fn a_prefix_length_that_is_not_one_is_refused() {
	assert!(
		errors(r#"interface wan0 { config = "dhcp6 pd_length wide" }"#)
			.contains("is not a prefix length")
	);
	assert!(
		errors(r#"interface wan0 { config = "dhcp6 pd_hint nonsense" }"#)
			.contains("is not an IPv6 prefix to ask for")
	);
}

/// A modifier a keyword source does not take is refused rather than dropped.
///
/// These arms used to return before the modifier loop ran, so
/// `config = "dhcp4 metric 100"` compiled and threw the metric away. Section 2's
/// rule about unknown fields is a rule about the language too.
#[test]
fn a_modifier_a_keyword_source_does_not_take_is_refused() {
	let message = errors(r#"interface eth0 { config = "dhcp4 preferred_lft 60" }"#);
	assert!(
		message.contains("is not something `dhcp4` takes"),
		"got {message}"
	);
	assert!(
		errors(r#"interface wan0 { config = "dhcp6 preferred_lft 60" }"#)
			.contains("is not something `dhcp6` takes")
	);
}

/// The router half of decision 0009: what a LAN tells the hosts behind it.
///
/// The prefix is a reference for the same reason the address was -- no config
/// file can contain a block an ISP has not handed out yet.
#[test]
fn an_interface_can_advertise_a_delegated_prefix() {
	let document = build_ok(
		r#"
		interface lan0 {
			config = "@pd:wan0=::1/64"
			advertise { prefixes = ["@pd:wan0"] }
		}
		"#,
	);
	let policy = document.interfaces[0]
		.advertise
		.as_ref()
		.expect("an advertise block");
	assert_eq!(policy.prefixes.len(), 1);
	assert_eq!(policy.prefixes[0].source, "wan0");
	// The defaults are the ones a LAN wants: no DHCPv6 server to send hosts to,
	// and the nameservers this interface's scope carries go out with the RA.
	assert!(!policy.managed);
	assert!(!policy.other_config);
	assert!(policy.dns);
}

/// A sub-prefix, for a router with more than one LAN behind one delegation.
#[test]
fn an_advertised_prefix_can_name_a_subnet() {
	let document = build_ok(
		r#"
		interface lan1 {
			config = "@pd:wan0/2=::1/64"
			advertise { prefixes = ["@pd:wan0/2"]; managed = true; lifetime = 0 }
		}
		"#,
	);
	let policy = document.interfaces[0].advertise.as_ref().expect("a policy");
	assert_eq!(policy.prefixes[0].subnet, 2);
	assert!(policy.managed);
	// Zero is a lifetime and means "not a default router", so it survives as a
	// value rather than being read as "unset".
	assert_eq!(policy.lifetime, Some(0));
}

/// A prefix that is not a reference is refused where the line is.
///
/// A literal would be a prefix somebody typed, which is the thing an ISP hands
/// out and a config file cannot know.
#[test]
fn an_advertised_prefix_must_be_a_reference() {
	let message = errors(r#"interface lan0 { advertise { prefixes = ["2001:db8::/64"] } }"#);
	assert!(
		message.contains("is not a prefix reference"),
		"got {message}"
	);
}

/// And a block with nothing to advertise is refused rather than starting a
/// daemon that advertises a router and no prefix.
#[test]
fn an_advertise_block_needs_something_to_advertise() {
	let message = errors("interface lan0 { advertise { managed = true } }");
	assert!(
		message.contains("needs a prefix to advertise"),
		"got {message}"
	);
}

/// A network can ask to roam, with three numbers and no module name.
///
/// The operator says how weak is weak and how often to look; which bgscan
/// module renders that is the backend's business. A `bgscan="simple:30:-70:300"`
/// in a config file would be netcfgd asking the operator which supplicant is
/// underneath (0089).
#[test]
fn a_network_can_ask_to_roam() {
	let document = build_ok(
		r#"network "Corridor" { wifi { psk = "@secret:c"; roam { signal = -68; interval = 20; slow_interval = 240 } } }"#,
	);
	let roam = document.networks[0].roam.as_ref().expect("a roam policy");
	assert_eq!(roam.signal, -68);
	assert_eq!(roam.interval, 20);
	assert_eq!(roam.slow_interval, 240);
}

/// And an empty block takes the numbers an operator would recognise.
#[test]
fn a_roam_block_has_defaults_worth_having() {
	let document = build_ok(r#"network "C" { wifi { psk = "@secret:c"; roam { } } }"#);
	let roam = document.networks[0].roam.as_ref().expect("a roam policy");
	assert_eq!(
		(roam.signal, roam.interval, roam.slow_interval),
		(-70, 30, 300)
	);
}

/// A network that does not mention roaming does not get it.
///
/// `wpa_supplicant`'s own default is to look only after the link is gone, and a
/// background scan costs airtime -- so anything that never moves must not be
/// made to pay for it by default.
#[test]
fn roaming_is_off_unless_asked_for() {
	let document = build_ok(r#"network "C" { wifi { psk = "@secret:c" } }"#);
	assert!(document.networks[0].roam.is_none());
}

/// Pinned to one access point, or roaming between them. Not both.
///
/// Two different requests -- "use this access point" and "use whichever is
/// loudest" -- and `wpa_supplicant` given both scans in the background for a
/// better BSSID it is then forbidden to associate with.
#[test]
fn a_pinned_network_cannot_also_roam() {
	// Both orders, because `bssid` is a network key and `roam` is a wifi one:
	// a check made inside the wifi block would catch one of these and miss the
	// other, depending only on which line somebody typed first.
	for text in [
		"network \"C\" {\n\tbssid = \"aa:bb:cc:dd:ee:ff\"\n\twifi { psk = \"@secret:c\"; roam { } }\n}",
		"network \"C\" {\n\twifi { psk = \"@secret:c\"; roam { } }\n\tbssid = \"aa:bb:cc:dd:ee:ff\"\n}",
	] {
		let message = errors(text);
		assert!(
			message.contains("pinned to one access point"),
			"got: {message}"
		);
	}
}

/// A signal threshold that is not a signal strength is refused.
///
/// dBm is negative by construction. A positive one is a signal stronger than
/// the transmitter, and `wpa_supplicant` would scan forever.
#[test]
fn a_roam_threshold_has_to_be_a_signal_strength() {
	for bad in ["70", "0", "-200"] {
		let message = errors(&format!(
			r#"network "C" {{ wifi {{ psk = "@secret:c"; roam {{ signal = {bad} }} }} }}"#
		));
		assert!(
			message.contains("not a signal strength"),
			"{bad}: {message}"
		);
	}
}

/// And looking less often when the signal is bad is the policy inverted.
#[test]
fn a_short_interval_longer_than_the_long_one_is_refused() {
	let message = errors(
		r#"network "C" { wifi { psk = "@secret:c"; roam { interval = 600; slow_interval = 60 } } }"#,
	);
	assert!(message.contains("cannot be longer"), "got: {message}");
}

/// A network can name access points instead of a name.
///
/// "The one in the lobby", by address. netcfgd reads what it is called off a
/// scan before configuring the supplicant, because WPA derives its key from the
/// passphrase *and* the SSID -- so the name has to be learned, not skipped
/// (0090).
#[test]
fn a_network_can_be_named_by_its_access_points() {
	let document = build_ok(
		"network \"Lobby\" {\n\tbssid = \"aa:bb:cc:dd:ee:ff\"\n\tssid = \"@bssid\"\n\twifi { psk = \"@secret:l\" }\n}",
	);
	let network = &document.networks[0];
	assert!(network.ssid.is_none(), "the name should not be stated");
	assert_eq!(network.bssid, ["aa:bb:cc:dd:ee:ff"]);
	// The label is still the id, so the network has one readable handle.
	assert_eq!(network.id, "Lobby");
}

/// And it can name several, which is a choice among them rather than a pin.
#[test]
fn a_network_can_list_several_access_points() {
	let document = build_ok(
		"network \"Site\" {\n\tbssid = [\"aa:bb:cc:dd:ee:ff\", \"11:22:33:44:55:66\"]\n\tssid = \"@bssid\"\n\twifi { psk = \"@secret:s\" }\n}",
	);
	assert_eq!(
		document.networks[0].bssid,
		["aa:bb:cc:dd:ee:ff", "11:22:33:44:55:66"]
	);
}

/// A list composes with roaming; a single pin does not.
///
/// "Any of these, whichever is loudest" is exactly what an operator who listed
/// their site's access points wants, and it is the one case where naming
/// addresses and roaming are not contradictory.
#[test]
fn several_access_points_may_be_roamed_between() {
	let document = build_ok(
		"network \"Site\" {\n\tbssid = [\"aa:bb:cc:dd:ee:ff\", \"11:22:33:44:55:66\"]\n\twifi { psk = \"@secret:s\"; roam { } }\n}",
	);
	assert!(document.networks[0].roam.is_some());
	assert_eq!(document.networks[0].bssid.len(), 2);
}

/// A name that has to be read off a scan needs somewhere to read it from.
#[test]
fn a_discovered_name_with_no_access_points_is_refused() {
	let message = errors(r#"network "Nowhere" { ssid = "@bssid"; wifi { psk = "@secret:n" } }"#);
	assert!(message.contains("lists none"), "got: {message}");
}

/// `portal_check` is an operator's URL, and `https` is refused with the reason.
///
/// 0061 refused a boolean with an address inside netcfgd and named the shape a
/// probe would take; 0095 built that shape. The `https` refusal is the half
/// worth a test: a portal detects by *intercepting* a request, which is exactly
/// what TLS prevents, so an `https` probe reports no portal on the networks it
/// was written for -- accepted and quietly useless.
#[test]
fn a_portal_check_is_an_http_url() {
	let document =
		build_ok(r#"device wlan0 { wifi { portal_check = "http://example.com/generate_204" } }"#);
	assert_eq!(
		document.devices[0]
			.wifi
			.as_ref()
			.expect("a wifi policy")
			.portal_check
			.as_deref(),
		Some("http://example.com/generate_204")
	);

	let message = errors(r#"device wlan0 { wifi { portal_check = "https://example.com/x" } }"#);
	assert!(message.contains("cannot use `https`"), "got: {message}");
	// And the reason, not just the refusal: an operator told "no https" without
	// being told why will reasonably think netcfgd is being lazy.
	assert!(message.contains("intercepts the request"), "got: {message}");

	for bad in ["ftp://example.com/x", "example.com/x", "http:///x"] {
		let message = errors(&format!(
			r#"device wlan0 {{ wifi {{ portal_check = "{bad}" }} }}"#
		));
		assert!(
			message.contains("is not an `http://` URL") || message.contains("names no host"),
			"{bad}: {message}"
		);
	}
}

/// A device that does not ask gets no probe and no default.
#[test]
fn a_device_that_names_no_url_is_not_probed() {
	let document = build_ok("device wlan0 { wifi { } }");
	assert!(document.devices[0]
		.wifi
		.as_ref()
		.expect("a wifi policy")
		.portal_check
		.is_none());
}

/// **`global` is the one block several independent things contribute to**, so
/// distinct contributions combine rather than colliding.
///
/// The case that forced it is the ordinary one: `ncfg control set` writes a
/// `control` block into its own drop-in, and after that no other tool could add
/// anything to `global` at all. Setting the dns mode from a gui was refused on
/// a machine that had ever set a control policy, which is most of them.
///
/// `override` is not the answer and the config example says why in its own
/// words: an `override global` carrying only a `control` block "silently
/// discards the `dns` block the file it replaced was carrying, and takes name
/// resolution away from the machine in order to change who may open a socket".
#[test]
fn two_files_may_each_contribute_to_global() {
	let mut sources = SourceMap::new();
	sources.add(
		"conf.d/00-control.conf",
		"global { control { observe = \"any\" } }",
	);
	sources.add(
		"conf.d/50-dns.conf",
		"global { dns { mode = \"write_resolv_conf\" } }",
	);

	let document = compile(&sources, &mut NoHooks).expect("both contributions are kept");
	assert_eq!(
		document.globals.dns.mode,
		netcfgd_model::DnsMode::WriteResolvConf,
		"the later file's dns block took effect"
	);
	assert_eq!(
		document.globals.control.observe,
		netcfgd_model::Principal::Any,
		"and the earlier file's control block survived it, which `override` \
		 would not have"
	);
}

/// And a real disagreement is still an error.
///
/// The point is to let independent contributions coexist, not to make the last
/// file quietly win: two files both setting `dns` are two files disagreeing
/// about one setting, which is what `override` is for.
#[test]
fn two_files_setting_the_same_thing_in_global_is_still_an_error() {
	let mut sources = SourceMap::new();
	sources.add("conf.d/00-a.conf", "global { dns { mode = \"none\" } }");
	sources.add(
		"conf.d/50-b.conf",
		"global { dns { mode = \"write_resolv_conf\" } }",
	);

	let diagnostics = compile(&sources, &mut NoHooks).expect_err("must refuse");
	let rendered = diagnostics.render(&sources);
	assert!(
		rendered.contains("already set in `global`"),
		"it should say what collided: {rendered}"
	);
	assert!(
		rendered.contains("conf.d/00-a.conf"),
		"and name the file that set it first: {rendered}"
	);
}

/// A Bluetooth device reads as the wifi vocabulary in different words.
///
/// 0149's whole claim: an operator who knows `network "Cafe" { wifi { ... } }`
/// can read this without being told. The label is a handle they chose and the
/// address is the fact, so replacing the hardware is one line rather than
/// every reference to it.
#[test]
fn a_bluetooth_device_compiles() {
	let mut sources = SourceMap::new();
	sources.add(
		"netcfgd.conf",
		"bluetooth \"headphones\" {\n\
		 \taddress = \"aa:bb:cc:dd:ee:ff\"\n\
		 \tprofile = \"a2dp-sink\"\n\
		 }\n",
	);

	let document = compile(&sources, &mut NoHooks).expect("it compiles");
	assert_eq!(document.bluetooth.len(), 1);
	let device = &document.bluetooth[0];
	assert_eq!(device.id, "headphones");
	// Uppercased rather than kept as written: the same address in two cases is
	// two strings to a diff, a duplicate check, and a comparison against what
	// the adapter reports.
	assert_eq!(device.address, "AA:BB:CC:DD:EE:FF");
	assert_eq!(
		device.profile,
		netcfgd_model::bluetooth::BluetoothProfile::A2dpSink
	);
	assert!(
		device.autoconnect,
		"true unless said otherwise, as a network is"
	);
}

/// **Multiple in and out is multiple blocks**, which is what was asked for and
/// falls out of the shape rather than being added.
///
/// Two sinks are two speakers, each its own PCM to `bluealsa`. A device used
/// as both a sink and a hands-free unit is two blocks, because those are
/// different things to the audio layer.
#[test]
fn several_devices_and_directions_coexist() {
	let mut sources = SourceMap::new();
	sources.add(
		"netcfgd.conf",
		"bluetooth \"desk\"    { address = \"AA:00:00:00:00:01\"\n\
		 profile = \"a2dp-sink\" }\n\
		 bluetooth \"kitchen\" { address = \"AA:00:00:00:00:02\"\n\
		 profile = \"a2dp-sink\" }\n\
		 bluetooth \"headset\" { address = \"AA:00:00:00:00:03\"\n\
		 profile = \"hfp\" }\n\
		 bluetooth \"phone\"   { address = \"AA:00:00:00:00:04\"\n\
		 profile = \"pan\"\n\
		 autoconnect = false }\n",
	);

	let document = compile(&sources, &mut NoHooks).expect("they compile");
	assert_eq!(document.bluetooth.len(), 4);
	let audio = document
		.bluetooth
		.iter()
		.filter(|d| d.profile.is_audio())
		.count();
	assert_eq!(audio, 3, "two sinks and a hands-free unit carry audio");
	let phone = document
		.bluetooth
		.iter()
		.find(|d| d.id == "phone")
		.expect("the pan device");
	assert!(!phone.profile.is_audio(), "pan carries packets, not audio");
	assert!(!phone.autoconnect, "and autoconnect = false survived");
}

/// A profile netcfgd does not know is refused by name, with the set listed.
///
/// The closed set is the point: a free-form string would have to keep
/// accepting whatever anybody wrote, for ever, because a document written
/// today has to still compile.
#[test]
fn an_unknown_bluetooth_profile_is_refused() {
	let mut sources = SourceMap::new();
	sources.add(
		"netcfgd.conf",
		"bluetooth \"x\" { address = \"AA:BB:CC:DD:EE:FF\"\nprofile = \"a2dp\" }\n",
	);

	let rendered = compile(&sources, &mut NoHooks)
		.expect_err("must refuse")
		.render(&sources);
	assert!(
		rendered.contains("a2dp"),
		"it names what was written: {rendered}"
	);
	assert!(
		rendered.contains("a2dp-sink"),
		"and lists what it could have been: {rendered}"
	);
}

/// An address that is not one is refused rather than stored.
///
/// Stored, it would reach the adapter as a string that matches nothing, and
/// the failure would surface as a device that never connects with nothing
/// saying why.
#[test]
fn a_malformed_bluetooth_address_is_refused() {
	for bad in [
		"AA:BB:CC:DD:EE",
		"AA:BB:CC:DD:EE:FF:00",
		"not-an-address",
		"AA-BB-CC-DD-EE-FF",
	] {
		let mut sources = SourceMap::new();
		sources.add(
			"netcfgd.conf",
			format!("bluetooth \"x\" {{ address = \"{bad}\"\nprofile = \"pan\" }}\n"),
		);
		let rendered = compile(&sources, &mut NoHooks)
			.unwrap_err()
			.render(&sources);
		assert!(
			rendered.contains("not a Bluetooth address"),
			"`{bad}` should be refused: {rendered}"
		);
	}
}

/// Neither address nor profile has a defensible default.
///
/// An address netcfgd invented would name somebody else's hardware, and a
/// profile it guessed would decide whether the device carries audio or
/// packets. Both are required and the diagnostic says which is missing.
#[test]
fn a_bluetooth_device_needs_an_address_and_a_profile() {
	let mut sources = SourceMap::new();
	sources.add("netcfgd.conf", "bluetooth \"x\" { profile = \"pan\" }\n");
	let rendered = compile(&sources, &mut NoHooks)
		.unwrap_err()
		.render(&sources);
	assert!(rendered.contains("no address"), "got: {rendered}");

	let mut sources = SourceMap::new();
	sources.add(
		"netcfgd.conf",
		"bluetooth \"x\" { address = \"AA:BB:CC:DD:EE:FF\" }\n",
	);
	let rendered = compile(&sources, &mut NoHooks)
		.unwrap_err()
		.render(&sources);
	assert!(rendered.contains("no profile"), "got: {rendered}");
}

/// The host-wide off switch a "no networking" profile needs.
///
/// Applied by the compiler rather than by the planner, so that `ncfg show`
/// says what netcfgd wants instead of a configuration something downstream
/// ignores. A profile cannot say "every interface, down" -- the language has
/// no wildcard, so it would have to name them, and the names differ per
/// machine.
#[test]
fn networking_off_disables_every_interface() {
	let document = build_ok(
		"global {\n\
		 \tnetworking = \"off\"\n\
		 }\n\
		 interface eth0 {\n\
		 \tconfig = \"dhcp\"\n\
		 }\n\
		 interface wlan0 {\n\
		 \tconfig = \"dhcp\"\n\
		 }\n",
	);
	assert_eq!(document.globals.networking, netcfgd_model::Networking::Off);
	assert!(
		document
			.interfaces
			.iter()
			.all(|interface| !interface.enabled),
		"every interface is down"
	);
	// The addressing is left in the document rather than stripped: it is what
	// the machine goes back to, and the planner withdraws addresses when it
	// takes a disabled link down.
	assert!(!document.interfaces[0].addressing.is_empty());
}

/// On is the default, and saying it explicitly changes nothing.
#[test]
fn networking_on_is_the_default_and_is_sayable() {
	let implied = build_ok("interface eth0 {\n\tconfig = \"dhcp\"\n}\n");
	assert_eq!(implied.globals.networking, netcfgd_model::Networking::On);
	assert!(implied.interfaces[0].enabled);

	let stated =
		build_ok("global {\n\tnetworking = \"on\"\n}\ninterface eth0 {\n\tconfig = \"dhcp\"\n}\n");
	assert_eq!(implied, stated);
}

/// A word that is neither is refused, with the two that are.
#[test]
fn an_unknown_networking_setting_is_refused() {
	let complaint = errors("global {\n\tnetworking = \"maybe\"\n}\n");
	assert!(
		complaint.contains("not a networking setting"),
		"{complaint}"
	);
	assert!(complaint.contains("on, off"), "{complaint}");
}

/// 0150's vocabulary: which SIM source is wanted, and which APN.
///
/// The order is the statement. A board with two sources and a mux gets one at
/// a time, and "which one do you want, and what next" is one question -- so
/// the list is ordered rather than being a preference plus a separate
/// fallback that could disagree with it.
#[test]
fn a_modem_block_carries_the_sim_order_and_the_apn() {
	let document = build_ok(
		"device wwan0 {\n\
		 \tmodem {\n\
		 \t\tsim = [\"esim\", \"socket\"]\n\
		 \t\tapn = \"im.cxn\"\n\
		 \t}\n\
		 }\n",
	);
	let modem = document.devices[0]
		.modem
		.as_ref()
		.expect("the modem policy");
	assert_eq!(modem.sim, vec!["esim".to_owned(), "socket".to_owned()]);
	assert_eq!(modem.apn.as_deref(), Some("im.cxn"));
}

/// A source listed twice is two answers to "what next".
#[test]
fn a_repeated_sim_source_is_refused() {
	let rendered = errors("device wwan0 { modem { sim = [\"esim\", \"esim\"] } }\n");
	assert!(rendered.contains("listed twice"), "got: {rendered}");
}

/// The APN reaches `helper/netcfgd-modem-at`, which interpolates it into
/// `AT+CGDCONT=1,"IP","<apn>"`. A quote there ends the command early and what
/// follows becomes another one, so the character is refused where it is
/// written rather than where it would detonate.
///
/// This is not netcfgd being clever about the value: 0150 is explicit that an
/// APN cannot be discovered or validated, and nothing here tries to. What is
/// checked is only what netcfgd is responsible for passing on safely.
#[test]
fn an_apn_that_would_break_an_at_command_is_refused() {
	// Written as configuration text rather than by interpolating a value, so
	// each case exercises the escape the lexer resolves and the checker then
	// sees: `\"` is a quote, `\\` a backslash, `\n` a control character.
	for bad in [
		r#"apn = "im\".cxn""#,
		r#"apn = "im\\cxn""#,
		r#"apn = "im\ncxn""#,
	] {
		let text = format!("device wwan0 {{ modem {{ {bad} }} }}\n");
		let rendered = errors(&text);
		assert!(
			rendered.contains("quote, a backslash or a control character"),
			"`{bad}` should be refused, got: {rendered}"
		);
	}
}

/// The same check guards a SIM source name, which reaches a `pre_up` hook.
#[test]
fn a_sim_source_that_would_break_a_hook_is_refused() {
	let rendered = errors("device wwan0 { modem { sim = \"e\\\"sim\" } }\n");
	assert!(
		rendered.contains("quote, a backslash or a control character"),
		"got: {rendered}"
	);
}

/// An unknown key inside `modem` is named rather than ignored.
#[test]
fn an_unknown_modem_key_is_refused() {
	let rendered = errors("device wwan0 { modem { imsi = \"1234\" } }\n");
	assert!(
		rendered.contains("unknown modem key `imsi`"),
		"got: {rendered}"
	);
}
