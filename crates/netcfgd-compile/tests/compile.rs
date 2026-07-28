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
	let rendered = errors("network \"home\" { }");
	assert!(rendered.contains("M3"), "got: {rendered}");
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
