//! The language, exercised from fixtures with no filesystem in sight.

use netcfgd_compile::{compile, Diagnostics, HookSink, NoHooks, SourceMap};
use netcfgd_model::dns::DnsMode;
use netcfgd_model::{AddressSource, Document, HookPhase, HookRef, InterfaceKind};

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
		interface eth0 {
			config = "192.168.1.10/24"
			routes = "default via 192.168.1.1"
			dns    = "192.168.1.1 1.1.1.1"
			mtu    = 1500
		}
		"#,
	);

	assert_eq!(document.interfaces.len(), 1);
	let eth0 = &document.interfaces[0];
	assert_eq!(eth0.name, "eth0");
	assert_eq!(eth0.mtu, Some(1500));
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
		interface eth0 { config = "dhcp"; mtu = 9000 } # jumbo
		"#,
	);
	assert_eq!(document.interfaces[0].mtu, Some(9000));
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
		"interface eth0 { config = \"dhcp\"\nmtu = 1500 }",
	);
	sources.add(
		"conf.d/10-lan.conf",
		"override interface eth0 { config = \"10.0.0.1/24\" }",
	);

	let document = compile(&sources, &mut NoHooks).expect("compiles");
	assert_eq!(document.interfaces.len(), 1);
	// Wholesale, not merged: the mtu from the first definition is gone. A
	// merge would make the result depend on which keys the earlier block
	// happened to set.
	assert_eq!(document.interfaces[0].mtu, None);
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
	sources.add("netcfgd.conf", "interface eth0 {\n\tmtu = \"big\"\n}\n");

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
		"interface eth0 {\n\
		 \tmtu = \"big\"\n\
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
	let rendered = errors("interface eth0 { mtu = 15.5 }");
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

/// Features that exist in the model but not in this build say which milestone
/// they arrive in, rather than reporting an unknown keyword.
#[test]
fn an_unimplemented_feature_names_its_milestone() {
	let rendered = errors("interface wg0 {\n\twireguard { listen_port = 51820 }\n}");
	assert!(rendered.contains("M4"), "got: {rendered}");
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
		portal_check = true
		regdom       = "SE"
		powersave    = "off"
	}
}

network "HomeFiber" {
	wifi   { psk = "@secret:HomeFiber"; priority = 30 }
	config = "dhcp"
}

network "Office" {
	wifi {
		eap      = "peap"
		identity = "dave"
		password = "@secret:Office"
		ca_cert  = "/etc/ssl/certs/office.pem"
		priority = 20
	}
	config = "dhcp"
}

network "Phone Hotspot" {
	wifi    { psk = "@secret:Hotspot"; priority = 5 }
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
	assert_eq!(home.ssid.as_bytes(), b"HomeFiber");
	assert_eq!(home.priority, 30);
	assert!(matches!(home.security, netcfgd_model::Security::Psk(_)));

	// A space in an SSID is ordinary and must survive being a block label.
	assert_eq!(document.networks[2].ssid.as_bytes(), b"Phone Hotspot");
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

/// An EAP network with no CA certificate authenticates to any server that
/// answers. Plenty of real deployments pin nothing, so this is said rather
/// than refused -- but it is said.
#[test]
fn eap_without_a_ca_certificate_is_reported() {
	let message = errors(
		r#"network "Corp" { wifi { eap = "ttls"; identity = "d"; password = "@secret:c" } }"#,
	);
	assert!(message.contains("trust any server"), "got: {message}");
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
	assert_eq!(document.networks[0].ssid.as_bytes(), &[0xff, 0x00, 0x80]);
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
