//! The options file netcfgd hands pppd.
//!
//! Verified against real pppd where it can be: pppd parses the file and gets
//! as far as `/dev/ppp`, which needs the module and real root, so what is
//! checked here is the content. A live DSL line is the part nobody has.

use netcfgd_apply::kernel::ppp_options;
use netcfgd_model::interface::PppoeConfig;
use netcfgd_model::{SecretProvider, SecretRef};

fn config() -> PppoeConfig {
	PppoeConfig {
		parent: "eth-wan".to_owned(),
		username: "alice@isp.example".to_owned(),
		password: SecretRef {
			provider: SecretProvider::File,
			name: "dsl".to_owned(),
		},
		service: Some("internet".to_owned()),
		ac: None,
	}
}

/// netcfgd owns routes and resolvers. `defaultroute` would install a route
/// nobody wrote down, and `usepeerdns` would rewrite resolv.conf underneath
/// the dns backend -- both are somebody else configuring the network behind
/// netcfgd's back, which is what constraint 1 exists to prevent.
#[test]
fn pppd_is_told_to_touch_neither_routes_nor_dns() {
	let text = ppp_options("ppp0", &config(), "hunter2");

	// Options, not text. The file explains in a comment why `usepeerdns` is
	// absent, so a substring search finds the word and proves nothing -- which
	// is how the first version of this test failed. `defaultroute` has the
	// same problem from the other direction, being a prefix of
	// `nodefaultroute`.
	let options: Vec<&str> = text
		.lines()
		.map(str::trim)
		.filter(|line| !line.is_empty() && !line.starts_with('#'))
		.collect();

	assert!(options.contains(&"nodefaultroute"), "got:\n{text}");
	assert!(!options.contains(&"defaultroute"), "got:\n{text}");
	assert!(
		!options.iter().any(|line| line.starts_with("usepeerdns")),
		"pppd must not write resolv.conf:\n{text}"
	);
}

/// The unit number comes from the interface name, so `interface ppp0` is ppp0
/// and not whichever unit happened to be free. Without it the document stops
/// describing the system after the second session.
#[test]
fn the_unit_number_comes_from_the_interface_name() {
	assert!(ppp_options("ppp0", &config(), "x")
		.lines()
		.any(|line| line == "unit 0"));
	assert!(ppp_options("ppp7", &config(), "x")
		.lines()
		.any(|line| line == "unit 7"));

	// A name that is not `pppN` gets no unit, because there is none to derive.
	// pppd then picks, which is worse but is what the operator asked for by
	// naming the interface something else.
	assert!(!ppp_options("dsl0", &config(), "x").contains("unit "));
}

/// A DSL password with a space in it is ordinary. One with a quote would
/// otherwise end the option and turn the rest of it into pppd directives.
#[test]
fn the_password_is_quoted_and_escaped() {
	let text = ppp_options("ppp0", &config(), r#"pass with "quotes" and \ backslash"#);
	let line = text
		.lines()
		.find(|line| line.starts_with("password "))
		.expect("a password line");

	assert_eq!(line, r#"password "pass with \"quotes\" and \\ backslash""#);
	// One line, whatever the password contains: a newline in it would make the
	// rest of the password into options.
	assert_eq!(
		text.lines()
			.filter(|line| line.starts_with("password"))
			.count(),
		1
	);
}

/// The parent goes in as the plugin's own option rather than as a bare device
/// argument, so there is no question about whether quotes end up in the name.
#[test]
fn the_parent_is_the_plugins_option() {
	let text = ppp_options("ppp0", &config(), "x");
	assert!(
		text.lines().any(|line| line == "nic-eth-wan"),
		"got:\n{text}"
	);
	assert!(text.contains("plugin pppoe.so"));
}

/// Provider-specific names are passed through where given and omitted where
/// not -- an empty service name is not the same as no service name.
#[test]
fn service_and_concentrator_are_optional() {
	let text = ppp_options("ppp0", &config(), "x");
	assert!(
		text.contains(r#"rp_pppoe_service "internet""#),
		"got:\n{text}"
	);
	assert!(!text.contains("rp_pppoe_ac"), "got:\n{text}");

	let mut with_ac = config();
	with_ac.service = None;
	with_ac.ac = Some("BRAS-01".to_owned());
	let text = ppp_options("ppp0", &with_ac, "x");
	assert!(!text.contains("rp_pppoe_service"), "got:\n{text}");
	assert!(text.contains(r#"rp_pppoe_ac "BRAS-01""#), "got:\n{text}");
}
