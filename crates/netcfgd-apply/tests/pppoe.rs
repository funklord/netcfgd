//! The options file netcfgd hands pppd.
//!
//! Verified against real pppd where it can be: pppd parses the file and gets
//! as far as `/dev/ppp`, which needs the module and real root, so what is
//! checked here is the content. A live DSL line is the part nobody has.

use netcfgd_apply::kernel::{ppp_options, ppp_script};
use netcfgd_model::interface::PppoeConfig;
use netcfgd_model::{SecretProvider, SecretRef};
use std::path::Path;

/// The two scripts netcfgd generates, as `ppp_options` is handed them.
fn options(iface: &str, config: &PppoeConfig, password: &str) -> String {
	ppp_options(
		iface,
		config,
		password,
		Path::new("/run/netcfgd/ppp/ppp0.up"),
		Path::new("/run/netcfgd/ppp/ppp0.down"),
	)
}

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

/// netcfgd owns the routes. `defaultroute` would install one nobody wrote
/// down, which is somebody else configuring the network behind netcfgd's back.
///
/// **`usepeerdns` is now on, and used to be off for a reason that was wrong.**
/// The comment here said it "would rewrite resolv.conf underneath the dns
/// backend". It does not: `create_resolv` in pppd's `ipcp.c` writes
/// `PPP_PATH_CONFDIR "/resolv.conf"`, which is `/etc/ppp/resolv.conf` -- pppd's
/// own file, which nothing on the host reads unless somebody points it there.
/// What the option is actually for is `DNS1` and `DNS2` in the scripts'
/// environment, and those are the only thing on a DSL line that nothing but
/// pppd learns. A belief nobody checked cost this feature; reading the source
/// settled it in a minute.
#[test]
fn pppd_is_told_to_leave_routes_alone_and_to_ask_for_resolvers() {
	let text = options("ppp0", &config(), "hunter2");

	// Options, not text. The file explains itself in comments, so a substring
	// search finds a word and proves nothing -- which is how the first version
	// of this test failed. `defaultroute` has the same problem from the other
	// direction, being a prefix of `nodefaultroute`.
	let options: Vec<&str> = text
		.lines()
		.map(str::trim)
		.filter(|line| !line.is_empty() && !line.starts_with('#'))
		.collect();

	assert!(options.contains(&"nodefaultroute"), "got:\n{text}");
	assert!(!options.contains(&"defaultroute"), "got:\n{text}");
	assert!(options.contains(&"usepeerdns"), "got:\n{text}");
	// Two scripts, not one under two names. pppd leaves DNS1 and DNS2 set for
	// the ip-down call, so one script could not tell the calls apart.
	assert!(
		options.contains(&"ip-up-script /run/netcfgd/ppp/ppp0.up"),
		"got:\n{text}"
	);
	assert!(
		options.contains(&"ip-down-script /run/netcfgd/ppp/ppp0.down"),
		"got:\n{text}"
	);
}

/// The up script reports what pppd learned; the down script reports nothing.
///
/// Run rather than read, because the trap is in the environment: pppd hands the
/// ip-down call the same `DNS1` and `DNS2` it handed the ip-up call, so a check
/// that only read the text would miss the whole point of there being two files.
#[test]
fn the_two_scripts_differ_where_the_environment_does_not() {
	use std::process::Command;

	let dir = netcfgd_testdir::TestDir::new("ppp");
	let report = dir.join("ppp0");

	let run = |going_up: bool| {
		let path = dir.join(if going_up { "up" } else { "down" });
		std::fs::write(&path, ppp_script("ppp0", &report, going_up)).expect("write");
		let status = Command::new("sh")
			.arg(&path)
			// pppd's own argv, and its own environment on *both* calls.
			.args(["ppp0", "/dev/pts/3", "0", "10.0.0.2", "10.0.0.1", ""])
			.env("IPLOCAL", "10.0.0.2")
			.env("IPREMOTE", "10.0.0.1")
			.env("USEPEERDNS", "1")
			.env("DNS1", "195.190.228.10")
			.env("DNS2", "195.190.228.20")
			.status()
			.expect("run the script");
		assert!(status.success());
		std::fs::read_to_string(&report).expect("a report")
	};

	let up = run(true);
	assert!(up.contains("dns=195.190.228.10"), "got:\n{up}");
	assert!(up.contains("dns=195.190.228.20"), "got:\n{up}");
	// Nothing else. The address is IPCP's and stays with pppd (decision 0047),
	// and the only route a ppp link has is the one the document writes.
	assert!(!up.contains("address="), "got:\n{up}");
	assert!(!up.contains("route="), "got:\n{up}");

	let down = run(false);
	assert!(
		!down.contains("dns="),
		"the session is gone and its resolvers with it:\n{down}"
	);
}

/// The unit number comes from the interface name, so `interface ppp0` is ppp0
/// and not whichever unit happened to be free. Without it the document stops
/// describing the system after the second session.
#[test]
fn the_unit_number_comes_from_the_interface_name() {
	assert!(options("ppp0", &config(), "x")
		.lines()
		.any(|line| line == "unit 0"));
	assert!(options("ppp7", &config(), "x")
		.lines()
		.any(|line| line == "unit 7"));

	// A name that is not `pppN` gets no unit, because there is none to derive.
	// pppd then picks, which is worse but is what the operator asked for by
	// naming the interface something else.
	assert!(!options("dsl0", &config(), "x").contains("unit "));
}

/// A DSL password with a space in it is ordinary. One with a quote would
/// otherwise end the option and turn the rest of it into pppd directives.
#[test]
fn the_password_is_quoted_and_escaped() {
	let text = options("ppp0", &config(), r#"pass with "quotes" and \ backslash"#);
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
	let text = options("ppp0", &config(), "x");
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
	let text = options("ppp0", &config(), "x");
	assert!(
		text.contains(r#"rp_pppoe_service "internet""#),
		"got:\n{text}"
	);
	assert!(!text.contains("rp_pppoe_ac"), "got:\n{text}");

	let mut with_ac = config();
	with_ac.service = None;
	with_ac.ac = Some("BRAS-01".to_owned());
	let text = options("ppp0", &with_ac, "x");
	assert!(!text.contains("rp_pppoe_service"), "got:\n{text}");
	assert!(text.contains(r#"rp_pppoe_ac "BRAS-01""#), "got:\n{text}");
}

/// Every generated writer stages under a name the reader will skip.
///
/// All four in one test, because what they share is the bug: each staged at
/// `<report>.tmp`, which is a perfectly good interface name, and netcfgd's own
/// reader took it for one. Decision 0113.
///
/// Asserted as the whole path rather than "contains a dot", so a writer that
/// staged under *some* dotted name in the wrong directory would still fail --
/// the rename has to be within one filesystem, which means within this
/// directory.
#[test]
fn every_generated_writer_stages_under_a_dot() {
	use netcfgd_apply::kernel::{dhcpcd_script, pd_hook_script, udhcpc_script};
	use std::path::Path;

	let report = Path::new("/run/netcfgd/reported/eth0");
	let state = Path::new("/run/netcfgd/udhcpc/eth0.state");
	let staged = "/run/netcfgd/reported/.eth0.tmp";

	let scripts = [
		("ppp ip-up", ppp_script("eth0", report, true)),
		("ppp ip-down", ppp_script("eth0", report, false)),
		("dhcpcd", dhcpcd_script("eth0", report)),
		("udhcpc", udhcpc_script("eth0", state, report)),
		("odhcp6c", pd_hook_script("eth0", report)),
	];

	for (which, text) in &scripts {
		assert!(
			text.contains(staged),
			"{which} does not stage at {staged}:\n{text}"
		);
		assert!(
			!text.contains("/reported/eth0.tmp"),
			"{which} still stages beside the report under a name that reads as an interface:\n{text}"
		);
	}
}
