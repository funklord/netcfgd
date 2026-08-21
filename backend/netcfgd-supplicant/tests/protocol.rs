//! What the control protocol has to get right, as tests.
//!
//! All of this runs without a radio, without root, and without
//! `wpa_supplicant` installed. The association path cannot be tested that way
//! and is covered by `tests/live.rs`, which skips when there is no supplicant.

use netcfgd_model::device::MacPolicy;
use netcfgd_model::security::{PskConfig, PskProto};
use netcfgd_model::{
	CertSource, EapConfig, EapMethod, SecretProvider, SecretRef, Security, Ssid, WifiNetwork,
};
use netcfgd_secret::Resolver;
use netcfgd_supplicant::network::settings;
use netcfgd_supplicant::protocol::{
	is_event, parse_network_list, parse_scan_results, parse_status, passphrase_argument,
	passphrase_is_sendable, printf_decode, ssid_argument, status_field, Event, Reply,
};
use netcfgd_supplicant::Unsupported;
use std::fs;

/// Tests run in parallel in one process, so the directory has to be unique per
/// call rather than per name -- otherwise one test's cleanup removes another's
/// secret, and the failure looks like a resolver bug. The counter that did that
/// here now lives in `netcfgd-testdir`, along with the guard that removes it.
fn scratch(name: &str) -> netcfgd_testdir::TestDir {
	netcfgd_testdir::TestDir::new(&format!("supp-{name}"))
}

#[cfg(unix)]
fn write_secret(dir: &std::path::Path, name: &str, body: &str) {
	use std::os::unix::fs::PermissionsExt;
	let path = dir.join(name);
	fs::write(&path, body).expect("write");
	fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("chmod");
}

fn network(ssid: &str, security: Security) -> WifiNetwork {
	WifiNetwork {
		id: "test".to_owned(),
		ssid: Some(Ssid::new(ssid.as_bytes().to_vec()).expect("ssid")),
		hidden: false,
		security,
		priority: 0,
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

fn psk(passphrase: &str, proto: PskProto) -> (Resolver, Security, netcfgd_testdir::TestDir) {
	let dir = scratch("psk");
	write_secret(&dir, "pass", passphrase);
	(
		Resolver::with_secrets_dir(&*dir),
		Security::Psk(PskConfig {
			passphrase: SecretRef {
				provider: SecretProvider::File,
				name: "pass".to_owned(),
			},
			proto,
		}),
		dir,
	)
}

fn rendered(network: &WifiNetwork, resolver: &Resolver) -> Vec<String> {
	settings(network, MacPolicy::Permanent, resolver)
		.expect("settings")
		.iter()
		.map(|setting| setting.command(0))
		.collect()
}

#[test]
fn ok_fail_and_data_are_distinguished() {
	assert_eq!(Reply::parse("OK\n"), Reply::Ok);
	assert_eq!(Reply::parse("FAIL\n"), Reply::Fail);
	assert_eq!(Reply::parse("UNKNOWN COMMAND\n"), Reply::Fail);
	assert_eq!(Reply::parse("PONG\n"), Reply::Data("PONG".to_owned()));
	// The supplicant NUL-terminates some replies.
	assert_eq!(Reply::parse("OK\n\0"), Reply::Ok);
}

/// A reply arriving as an event would be acted on as the answer to whatever
/// command was outstanding. Telling them apart is the whole reason the client
/// loops rather than reading once.
#[test]
fn events_are_not_mistaken_for_replies() {
	assert!(is_event(
		"<3>CTRL-EVENT-CONNECTED - Connection to 00:11 completed"
	));
	assert!(is_event("<2>CTRL-EVENT-SCAN-RESULTS "));
	assert!(!is_event("OK"));
	assert!(!is_event("PONG"));
	// A scan result row starts with a BSSID, never a priority.
	assert!(!is_event(
		"00:11:22:33:44:55\t2412\t-40\t[WPA2-PSK-CCMP][ESS]\thome"
	));
	// Not an event just because it opens with a bracket a long way from a
	// close: a network name could.
	assert!(!is_event("<this is not a priority>"));
}

#[test]
fn an_event_keeps_its_priority_and_name() {
	let event = Event::parse("<3>CTRL-EVENT-DISCONNECTED bssid=00:11:22:33:44:55 reason=3")
		.expect("parses");
	assert_eq!(event.priority, 3);
	assert_eq!(event.name(), "CTRL-EVENT-DISCONNECTED");
	assert!(Event::parse("OK").is_none());
}

#[test]
fn scan_results_parse() {
	let body = "bssid / frequency / signal level / flags / ssid\n\
		00:11:22:33:44:55\t2412\t-40\t[WPA2-PSK-CCMP][ESS]\thome\n\
		66:77:88:99:aa:bb\t5180\t-72\t[ESS]\tcafe wifi\n";
	let results = parse_scan_results(body);
	assert_eq!(results.len(), 2);
	assert_eq!(results[0].frequency, 2412);
	assert_eq!(results[0].signal, -40);
	assert_eq!(results[0].ssid.as_bytes(), b"home");
	assert!(results[0].is_secured());
	assert!(!results[1].is_secured());
	assert_eq!(results[1].ssid.as_bytes(), b"cafe wifi");
}

/// The supplicant does not return the octets it was given: it escapes a quote,
/// a backslash, the usual control characters, and **every byte outside
/// printable ASCII**. A reader that takes the field literally shows
/// `caf\\xc3\\xa9` to somebody looking for their coffee shop -- so this is
/// wrong for every network name that is not plain ASCII, which is most of them
/// outside the English-speaking world.
///
/// The escapes below are copied from what a real `wpa_supplicant` 2.10
/// produced, not from its documentation, which does not mention any of this.
#[test]
fn escaped_ssids_are_decoded() {
	let cases: &[(&str, &[u8])] = &[
		("home", b"home"),
		("caf\\xc3\\xa9", "caf\u{e9}".as_bytes()),
		("\\xe2\\x8c\\x98", "\u{2318}".as_bytes()),
		("\\xff\\x00\\x80a", &[0xff, 0x00, 0x80, b'a']),
		("\\\"", b"\""),
		("\\\\", b"\\"),
		("\\n", b"\n"),
		("\\t", b"\t"),
		("with space", b"with space"),
	];
	for (escaped, expected) in cases {
		let body = format!("header\n00:11:22:33:44:55\t2412\t-40\t[ESS]\t{escaped}\n");
		let results = parse_scan_results(&body);
		assert_eq!(
			results[0].ssid.as_bytes(),
			*expected,
			"decoding `{escaped}`"
		);
	}
}

/// Because a tab inside a name arrives escaped, the line and field structure
/// is never ambiguous -- which is the property that makes a line-oriented
/// parser safe here at all.
#[test]
fn a_tab_or_newline_in_a_name_cannot_break_the_row_structure() {
	let body = "header\n00:11:22:33:44:55\t2412\t-40\t[ESS]\tone\\ttwo\\nthree\n";
	let results = parse_scan_results(body);
	assert_eq!(results.len(), 1, "one row, whatever the name contains");
	assert_eq!(results[0].ssid.as_bytes(), b"one\ttwo\nthree");
}

/// A malformed escape must not lose the rest of the name.
#[test]
fn a_truncated_escape_is_not_fatal() {
	assert_eq!(printf_decode("a\\xzz"), b"a\\xzz");
	assert_eq!(printf_decode("trailing\\"), b"trailing\\");
}

/// One unparseable row from a misbehaving access point must not cost the
/// operator the whole scan.
#[test]
fn a_malformed_scan_row_is_skipped_not_fatal() {
	let body = "header\ngarbage\n00:11:22:33:44:55\t2412\t-40\t[ESS]\tgood\n\tnot\tenough\n";
	let results = parse_scan_results(body);
	assert_eq!(results.len(), 1);
	assert_eq!(results[0].ssid.as_bytes(), b"good");
}

#[test]
fn network_lists_and_status_parse() {
	let list = "network id / ssid / bssid / flags\n\
		0\thome\tany\t[CURRENT]\n\
		1\twork\tany\t[DISABLED]\n";
	let entries = parse_network_list(list);
	assert_eq!(entries.len(), 2);
	assert_eq!(entries[0].id, 0);
	assert_eq!(entries[0].ssid.as_bytes(), b"home");
	assert!(entries[0].is_current());
	assert!(!entries[1].is_current());

	let status = parse_status("wpa_state=COMPLETED\nssid=home\nip_address=192.0.2.5\n");
	assert_eq!(status_field(&status, "wpa_state"), Some("COMPLETED"));
	assert_eq!(status_field(&status, "absent"), None);
}

/// An entry with no flags column is normal -- a network that is neither
/// current nor disabled has nothing there -- and must not be dropped.
#[test]
fn a_network_with_no_flags_still_parses() {
	let entries = parse_network_list("header\n0\thome\tany\n");
	assert_eq!(entries.len(), 1);
	assert_eq!(entries[0].flags, "");
}

/// The reason SSIDs go out as hex: a network name is 32 arbitrary octets
/// chosen by whoever named it, and a quoted one would be a place where those
/// octets become protocol syntax.
#[test]
fn an_ssid_cannot_inject_a_command() {
	let hostile = Ssid::new(br#""; REMOVE_NETWORK all; ""#.to_vec()).expect("ssid");
	let argument = ssid_argument(&hostile);

	assert!(!argument.contains('"'), "got: {argument}");
	assert!(!argument.contains(' '), "got: {argument}");
	assert!(!argument.contains("REMOVE"), "got: {argument}");
	assert!(
		argument.bytes().all(|byte| byte.is_ascii_hexdigit()),
		"an SSID argument is hex and nothing else: {argument}"
	);
}

/// Hex also means a name that is not text at all survives intact, which a
/// quoted encoding would have had to mangle or refuse.
#[test]
fn a_non_utf8_ssid_round_trips() {
	let ssid = Ssid::new(vec![0xff, 0x00, 0x80, b'a']).expect("ssid");
	assert_eq!(ssid_argument(&ssid), "ff0080 61".replace(' ', ""));
}

/// A passphrase must be quoted, so the escaping is the control rather than an
/// encoding detail.
#[test]
fn a_passphrase_cannot_escape_its_quotes() {
	let argument = passphrase_argument(r#"a"; REMOVE_NETWORK all; b"#);
	// Every quote inside is escaped, so the string still ends where it should.
	assert!(argument.starts_with('"') && argument.ends_with('"'));
	assert_eq!(argument.matches(r#"\""#).count(), 1);
	assert_eq!(
		argument
			.chars()
			.filter(|character| *character == '"')
			.count(),
		3,
		"two delimiters and one escaped: {argument}"
	);

	// A trailing backslash must not escape the closing quote.
	let trailing = passphrase_argument(r"pass\");
	assert_eq!(trailing, r#""pass\\""#);
}

/// There is no escape for a newline in the control protocol, so a passphrase
/// containing one is refused rather than sent and hoped for.
#[test]
fn a_passphrase_with_a_newline_is_refused() {
	assert!(passphrase_is_sendable("ordinary passphrase"));
	assert!(!passphrase_is_sendable(
		"first\nSET_NETWORK 0 psk \"pwned\""
	));
	assert!(!passphrase_is_sendable("carriage\rreturn"));
	assert!(!passphrase_is_sendable("nul\0byte"));

	let (resolver, security, dir) = psk("bad\npassphrase", PskProto::Wpa2);
	let error =
		settings(&network("home", security), MacPolicy::Permanent, &resolver).expect_err("refused");
	assert!(
		error
			.downcast_ref::<Unsupported>()
			.is_some_and(|unsupported| *unsupported == Unsupported::PassphraseNotSendable),
		"got: {error}"
	);
	let _ = fs::remove_dir_all(&dir);
}

/// WPA3 personal is SAE with management frame protection required. Sending
/// `WPA-PSK` for a network the operator asked to be WPA3 would associate
/// successfully and silently be WPA2, which is the kind of downgrade nobody
/// notices.
#[test]
fn wpa3_is_sae_with_protected_management_frames() {
	let (resolver, security, dir) = psk("hunter2hunter2", PskProto::Wpa3);
	let commands = rendered(&network("home", security), &resolver);

	assert!(commands.contains(&"SET_NETWORK 0 key_mgmt SAE FT-SAE".to_owned()));
	assert!(commands.contains(&"SET_NETWORK 0 ieee80211w 2".to_owned()));
	assert!(
		!commands.iter().any(|line| line.contains("WPA-PSK")),
		"WPA3 must not offer the WPA2 key management: {commands:?}"
	);
	let _ = fs::remove_dir_all(&dir);
}

/// Every mode that can fast-transition offers it, and the open one does not.
///
/// The property is easy to lose by accident, because losing it breaks nothing:
/// a network with no `FT-` mode in its `key_mgmt` associates exactly as well
/// and roams slowly, so the only thing that would notice is this test. 802.11r
/// is negotiated at association, so a supplicant that did not offer it cannot
/// change its mind at the first roam.
#[test]
fn fast_transition_is_offered_wherever_it_can_be() {
	for (proto, expected) in [
		(PskProto::Wpa2, "WPA-PSK FT-PSK"),
		(PskProto::Wpa3, "SAE FT-SAE"),
		(PskProto::Wpa2Wpa3, "WPA-PSK SAE FT-PSK FT-SAE"),
	] {
		let (resolver, security, dir) = psk("hunter2hunter2", proto);
		let commands = rendered(&network("home", security), &resolver);
		assert!(
			commands.contains(&format!("SET_NETWORK 0 key_mgmt {expected}")),
			"{proto:?} did not offer fast transition: {commands:?}"
		);
		let _ = fs::remove_dir_all(&dir);
	}
}

/// Transitional mode has to work against both, and `ieee80211w` is the field
/// where getting it wrong excludes one of them.
#[test]
fn transitional_mode_can_reach_both_generations() {
	let (resolver, security, dir) = psk("hunter2hunter2", PskProto::Wpa2Wpa3);
	let commands = rendered(&network("home", security), &resolver);

	assert!(commands.contains(&"SET_NETWORK 0 key_mgmt WPA-PSK SAE FT-PSK FT-SAE".to_owned()));
	assert!(
		commands.contains(&"SET_NETWORK 0 ieee80211w 1".to_owned()),
		"2 excludes WPA2 access points and 0 excludes SAE: {commands:?}"
	);
	let _ = fs::remove_dir_all(&dir);
}

/// OWE without management frame protection is not OWE.
#[test]
fn owe_requires_protected_management_frames() {
	let resolver = Resolver::default();
	let commands = rendered(&network("cafe", Security::Owe), &resolver);
	assert!(commands.contains(&"SET_NETWORK 0 key_mgmt OWE".to_owned()));
	assert!(commands.contains(&"SET_NETWORK 0 ieee80211w 2".to_owned()));
}

/// A hidden network is never probed for without this, so it simply never
/// appears -- with nothing anywhere saying why.
#[test]
fn a_hidden_network_is_probed_for() {
	let resolver = Resolver::default();
	let mut hidden = network("secret", Security::Open);
	hidden.hidden = true;
	let commands = rendered(&hidden, &resolver);
	assert!(commands.contains(&"SET_NETWORK 0 scan_ssid 1".to_owned()));

	let visible = rendered(&network("secret", Security::Open), &resolver);
	assert!(!visible.iter().any(|line| line.contains("scan_ssid")));
}

/// A BSSID reaches the command line unquoted, and the set of valid values is
/// small enough to check exactly rather than escape.
#[test]
fn a_bssid_is_validated_rather_than_quoted() {
	let resolver = Resolver::default();
	let mut pinned = network("home", Security::Open);

	pinned.bssid = vec!["00:11:22:33:44:55".to_owned()];
	assert!(
		rendered(&pinned, &resolver).contains(&"SET_NETWORK 0 bssid 00:11:22:33:44:55".to_owned())
	);

	for hostile in [
		"00:11:22:33:44:55 \nREMOVE_NETWORK all",
		"not-a-mac",
		"00:11:22:33:44",
		"00:11:22:33:44:55:66",
		"gg:11:22:33:44:55",
	] {
		pinned.bssid = vec![hostile.to_owned()];
		let error = settings(&pinned, MacPolicy::Permanent, &resolver).expect_err("refused");
		assert!(
			matches!(
				error.downcast_ref::<Unsupported>(),
				Some(Unsupported::MalformedBssid { .. })
			),
			"`{hostile}` must be refused, got: {error}"
		);
	}
}

/// `FAIL` with no detail is what the supplicant answers to a short
/// passphrase, and a stray space is a common enough mistake to deserve better.
#[test]
fn a_passphrase_of_the_wrong_length_is_refused_with_its_length() {
	for (passphrase, len) in [("short", 5_usize), (&"x".repeat(64), 64)] {
		let (resolver, security, dir) = psk(passphrase, PskProto::Wpa2);
		let error = settings(&network("home", security), MacPolicy::Permanent, &resolver)
			.expect_err("refused");
		assert_eq!(
			error.downcast_ref::<Unsupported>(),
			Some(&Unsupported::PassphraseLength { len }),
			"got: {error}"
		);
		assert!(
			!error.to_string().contains(passphrase),
			"a diagnostic must not quote the passphrase: {error}"
		);
		let _ = fs::remove_dir_all(&dir);
	}
}

/// The failing command gets reported when a setting is refused, and the one
/// most likely to be refused is the one carrying the passphrase.
#[test]
fn a_secret_setting_redacts_itself() {
	let (resolver, security, dir) = psk("hunter2hunter2", PskProto::Wpa2);
	let all =
		settings(&network("home", security), MacPolicy::Permanent, &resolver).expect("settings");
	let secret = all
		.iter()
		.find(|setting| setting.variable == "psk")
		.expect("a psk setting");

	assert!(secret.sensitive);
	assert!(secret.command(0).contains("hunter2hunter2"));
	assert!(!secret.redacted(0).contains("hunter2hunter2"));
	assert!(secret.redacted(0).contains("<redacted>"));

	// And an ordinary setting is not hidden, or a plan is unreadable.
	let plain = all
		.iter()
		.find(|setting| setting.variable == "key_mgmt")
		.expect("a key_mgmt setting");
	assert_eq!(plain.redacted(0), plain.command(0));
	let _ = fs::remove_dir_all(&dir);
}

/// An EAP identity is a username. It goes out redacted for the same reason a
/// passphrase does -- it is half of a credential -- and quoted for the same
/// reason: a RADIUS realm is text somebody else chose.
#[test]
fn eap_settings_quote_and_redact_the_identity() {
	let dir = scratch("eap");
	write_secret(&dir, "password", "corporate");
	let resolver = Resolver::with_secrets_dir(&*dir);

	let eap = Security::Eap(EapConfig {
		method: EapMethod::Peap,
		identity: r#"user"; REMOVE_NETWORK all; ""#.to_owned(),
		anonymous_identity: Some("anonymous@example.net".to_owned()),
		password: Some(SecretRef {
			provider: SecretProvider::File,
			name: "password".to_owned(),
		}),
		ca_cert: Some(CertSource::Path("/etc/ssl/certs/corporate.pem".to_owned())),
		client_cert: None,
		private_key: None,
		phase2: Some("auth=MSCHAPV2".to_owned()),
	});

	let all = settings(&network("corp", eap), MacPolicy::Permanent, &resolver).expect("settings");
	let commands: Vec<String> = all.iter().map(|setting| setting.command(0)).collect();

	assert!(commands.contains(&"SET_NETWORK 0 key_mgmt WPA-EAP FT-EAP".to_owned()));
	assert!(commands.contains(&"SET_NETWORK 0 eap PEAP".to_owned()));
	assert!(commands.contains(&r#"SET_NETWORK 0 phase2 "auth=MSCHAPV2""#.to_owned()));

	let identity = all
		.iter()
		.find(|setting| setting.variable == "identity")
		.expect("an identity");
	assert_eq!(identity.value, r#""user\"; REMOVE_NETWORK all; \"""#);
	assert!(identity.sensitive, "an identity is half a credential");

	let password = all
		.iter()
		.find(|setting| setting.variable == "password")
		.expect("a password");
	assert!(!password.redacted(0).contains("corporate"));

	let _ = fs::remove_dir_all(&dir);
}

/// A method that needs a password and has none fails here, naming the field,
/// rather than at association time with a `FAIL`.
#[test]
fn an_eap_method_missing_its_credential_says_which() {
	let resolver = Resolver::default();
	let eap = Security::Eap(EapConfig {
		method: EapMethod::Ttls,
		identity: "user".to_owned(),
		anonymous_identity: None,
		password: None,
		ca_cert: None,
		client_cert: None,
		private_key: None,
		phase2: None,
	});
	let error =
		settings(&network("corp", eap), MacPolicy::Permanent, &resolver).expect_err("refused");
	assert_eq!(
		error.downcast_ref::<Unsupported>(),
		Some(&Unsupported::MissingEapField { field: "password" })
	);

	let tls = Security::Eap(EapConfig {
		method: EapMethod::Tls,
		identity: "user".to_owned(),
		anonymous_identity: None,
		password: None,
		ca_cert: None,
		client_cert: Some(CertSource::Path("/etc/ssl/client.pem".to_owned())),
		private_key: None,
		phase2: None,
	});
	let error =
		settings(&network("corp", tls), MacPolicy::Permanent, &resolver).expect_err("refused");
	assert_eq!(
		error.downcast_ref::<Unsupported>(),
		Some(&Unsupported::MissingEapField {
			field: "private_key"
		})
	);
}

/// The `mac_addr` mapping, which is the whole of the MAC randomization
/// feature at this layer. The numbers are not guessable from the names, and
/// getting one wrong is a privacy setting that silently does something else.
#[test]
fn the_mac_policy_maps_to_the_documented_numbers() {
	use netcfgd_supplicant::mac_addr_value;

	assert_eq!(mac_addr_value(MacPolicy::Permanent), "0");
	assert_eq!(mac_addr_value(MacPolicy::PerNetwork), "1");
	assert_eq!(mac_addr_value(MacPolicy::PerConnection), "2");
}

/// It is sent for every policy including `Permanent`, because leaving it unset
/// inherits the supplicant's global -- and a privacy property that depends on
/// somebody else's default is not a property.
#[test]
fn the_mac_policy_is_always_sent() {
	let resolver = Resolver::default();
	for (policy, expected) in [
		(MacPolicy::Permanent, "0"),
		(MacPolicy::PerNetwork, "1"),
		(MacPolicy::PerConnection, "2"),
	] {
		let rendered: Vec<String> = settings(&network("home", Security::Open), policy, &resolver)
			.expect("settings")
			.iter()
			.map(|setting| setting.command(0))
			.collect();
		assert!(
			rendered.contains(&format!("SET_NETWORK 0 mac_addr {expected}")),
			"{policy:?} should send mac_addr {expected}: {rendered:?}"
		);
	}
}

/// Roaming reaches `wpa_supplicant` as the module it understands.
///
/// The oldest thing wifi does: an ESS is several access points sharing one
/// SSID, and a station moves to whichever it hears best. `wpa_supplicant` does
/// that itself -- "roaming within an ESS", in its own configuration's words --
/// but only while a `bgscan` module is asking it to look. netcfgd set none, so
/// a laptop re-selected only after the link had already gone, which is roaming
/// by first losing the network.
#[test]
fn a_roaming_network_asks_the_supplicant_to_keep_looking() {
	let dir = scratch("roam");
	write_secret(&dir, "pass", "passphrase123");
	let resolver = Resolver::with_secrets_dir(&*dir);
	let mut wanted = network(
		"Corridor",
		Security::Psk(PskConfig {
			passphrase: SecretRef {
				provider: SecretProvider::File,
				name: "pass".to_owned(),
			},
			proto: PskProto::Wpa2Wpa3,
		}),
	);
	wanted.roam = Some(netcfgd_model::RoamPolicy {
		signal: -68,
		interval: 20,
		slow_interval: 240,
	});

	let lines = rendered(&wanted, &resolver);
	// The order is the module's own: short interval, threshold, long interval.
	// Getting the first two the wrong way round is a station that scans every
	// -68 seconds above a 20 dBm signal, which is a plausible-looking string
	// and no roaming at all.
	assert!(
		lines
			.iter()
			.any(|line| line.ends_with("bgscan \"simple:20:-68:240\"")),
		"the roam policy did not reach the supplicant: {lines:?}"
	);
}

/// And a network that did not ask for it says nothing at all.
///
/// `wpa_supplicant`'s default is to look only after the link is gone, and a
/// background scan costs airtime and interrupts traffic -- so a router with a
/// radio, or anything that never moves, must not be made to pay for it.
#[test]
fn a_network_that_does_not_roam_carries_no_bgscan() {
	let dir = scratch("noroam");
	write_secret(&dir, "pass", "passphrase123");
	let resolver = Resolver::with_secrets_dir(&*dir);
	let wanted = network(
		"Fixed",
		Security::Psk(PskConfig {
			passphrase: SecretRef {
				provider: SecretProvider::File,
				name: "pass".to_owned(),
			},
			proto: PskProto::Wpa2Wpa3,
		}),
	);

	let lines = rendered(&wanted, &resolver);
	assert!(
		!lines.iter().any(|line| line.starts_with("bgscan")),
		"a network that does not roam was given a background scan: {lines:?}"
	);
}

/// One access point pins; several are a choice among them.
///
/// `wpa_supplicant` spells those differently and the difference is the whole
/// feature: `bssid` refuses every other access point, `bssid_accept` limits
/// selection to the set and picks among them by signal. Rendering a list as a
/// pin would join one of them and never move (0090).
#[test]
fn one_access_point_pins_and_several_are_a_choice() {
	let dir = scratch("bssid-list");
	write_secret(&dir, "pass", "passphrase123");
	let resolver = Resolver::with_secrets_dir(&*dir);
	let security = Security::Psk(PskConfig {
		passphrase: SecretRef {
			provider: SecretProvider::File,
			name: "pass".to_owned(),
		},
		proto: PskProto::Wpa2Wpa3,
	});

	let mut one = network("Site", security.clone());
	one.bssid = vec!["aa:bb:cc:dd:ee:ff".to_owned()];
	let lines = rendered(&one, &resolver);
	assert!(
		lines
			.iter()
			.any(|line| line.ends_with("bssid aa:bb:cc:dd:ee:ff")),
		"one access point should pin: {lines:?}"
	);
	assert!(
		!lines.iter().any(|line| line.contains("bssid_accept")),
		"one access point should not be a list: {lines:?}"
	);

	let mut several = network("Site", security);
	several.bssid = vec![
		"aa:bb:cc:dd:ee:ff".to_owned(),
		"11:22:33:44:55:66".to_owned(),
	];
	let lines = rendered(&several, &resolver);
	// Masked, because that is the form wpa_supplicant parses, and every bit
	// set is one specific address.
	assert!(
		lines.iter().any(|line| line.ends_with(
			"bssid_accept aa:bb:cc:dd:ee:ff/ff:ff:ff:ff:ff:ff 11:22:33:44:55:66/ff:ff:ff:ff:ff:ff"
		)),
		"several access points should be a choice: {lines:?}"
	);
	assert!(
		!lines.iter().any(|line| line.contains(" bssid ")),
		"several access points should not pin one: {lines:?}"
	);
}

/// A network whose name was never resolved is refused rather than sent.
///
/// Sending it would mean an empty SSID, which associates with anything. The
/// caller skipped a step and says so.
#[test]
fn a_network_with_no_resolved_name_is_refused() {
	let dir = scratch("unresolved");
	let resolver = Resolver::with_secrets_dir(&*dir);
	let mut wanted = network("ignored", Security::Owe);
	wanted.ssid = None;
	wanted.bssid = vec!["aa:bb:cc:dd:ee:ff".to_owned()];

	let error = settings(&wanted, MacPolicy::Permanent, &resolver)
		.expect_err("an unresolved network is not sendable");
	assert!(
		error.to_string().contains("never read off a scan"),
		"got: {error}"
	);
}

/// A network named by address learns what it is called from a scan.
///
/// WPA derives its key from the passphrase *and* the SSID, so the name has to
/// be read before anything can be sent -- `wpa_supplicant`'s wildcard, which
/// matches any name, is documented as working for plaintext access points only,
/// and for that reason. Decision 0090.
#[test]
fn a_network_named_by_address_learns_its_name() {
	let seen = netcfgd_supplicant::protocol::parse_scan_results(
		"bssid / frequency / signal level / flags / ssid\n\
		 aa:bb:cc:dd:ee:ff\t2412\t-40\t[WPA2-PSK-CCMP][ESS]\tlobby\n\
		 11:22:33:44:55:66\t2437\t-60\t[WPA2-PSK-CCMP][ESS]\tlobby\n\
		 99:99:99:99:99:99\t2462\t-70\t[ESS]\tsomeone-else\n",
	);

	let mut wanted = network("ignored", Security::Owe);
	wanted.ssid = None;
	// Upper case on purpose: an address an operator typed and one a driver
	// reported differ in case often enough that comparing them exactly is a
	// bug waiting for a capital letter.
	wanted.bssid = vec!["AA:BB:CC:DD:EE:FF".to_owned()];

	let learned = netcfgd_supplicant::pick_ssid(&wanted, &seen).expect("the name is readable");
	assert_eq!(learned.as_bytes(), b"lobby");

	// Several that agree is the ordinary site: one network, two radios.
	wanted.bssid = vec![
		"aa:bb:cc:dd:ee:ff".to_owned(),
		"11:22:33:44:55:66".to_owned(),
	];
	let learned = netcfgd_supplicant::pick_ssid(&wanted, &seen).expect("they agree");
	assert_eq!(learned.as_bytes(), b"lobby");

	// One in range and one not is still answerable: the absent one says
	// nothing, rather than making the whole network unreachable.
	wanted.bssid = vec![
		"aa:bb:cc:dd:ee:ff".to_owned(),
		"de:ad:be:ef:00:00".to_owned(),
	];
	let learned = netcfgd_supplicant::pick_ssid(&wanted, &seen).expect("one of them is in range");
	assert_eq!(learned.as_bytes(), b"lobby");
}

/// None of them in range is a failure that names the addresses.
///
/// "Network not found", about a network identified by address, is not a
/// sentence anybody can act on.
#[test]
fn an_absent_access_point_is_reported_with_its_address() {
	let seen = netcfgd_supplicant::protocol::parse_scan_results(
		"bssid / frequency / signal level / flags / ssid\n\
		 99:99:99:99:99:99\t2462\t-70\t[ESS]\tsomeone-else\n",
	);
	let mut wanted = network("ignored", Security::Owe);
	// The helper's first argument is the SSID; the *id* is what the message
	// names, because that is the handle in the operator's config file.
	wanted.id = "Lobby".to_owned();
	wanted.ssid = None;
	wanted.bssid = vec!["aa:bb:cc:dd:ee:ff".to_owned()];

	let error = netcfgd_supplicant::pick_ssid(&wanted, &seen).expect_err("it is not in range");
	let message = error.to_string();
	assert!(message.contains("aa:bb:cc:dd:ee:ff"), "got: {message}");
	assert!(message.contains("Lobby"), "got: {message}");
}

/// Access points advertising different names are different networks.
///
/// One passphrase cannot be right for both -- WPA's key is derived per SSID --
/// so picking either would be netcfgd choosing for the operator.
#[test]
fn access_points_on_different_networks_are_refused() {
	let seen = netcfgd_supplicant::protocol::parse_scan_results(
		"bssid / frequency / signal level / flags / ssid\n\
		 aa:bb:cc:dd:ee:ff\t2412\t-40\t[WPA2-PSK-CCMP][ESS]\tlobby\n\
		 11:22:33:44:55:66\t2437\t-60\t[WPA2-PSK-CCMP][ESS]\twarehouse\n",
	);
	let mut wanted = network("ignored", Security::Owe);
	wanted.id = "Site".to_owned();
	wanted.ssid = None;
	wanted.bssid = vec![
		"aa:bb:cc:dd:ee:ff".to_owned(),
		"11:22:33:44:55:66".to_owned(),
	];

	let error = netcfgd_supplicant::pick_ssid(&wanted, &seen).expect_err("they disagree");
	let message = error.to_string();
	assert!(message.contains("different networks"), "got: {message}");
	// Both addresses and both names, so the operator can see which is which.
	assert!(message.contains("aa:bb:cc:dd:ee:ff"), "got: {message}");
	assert!(message.contains("11:22:33:44:55:66"), "got: {message}");
}

/// A roam is a `CONNECTED` naming a different access point.
///
/// The format string is `wpa_supplicant`'s own, read out of the binary:
/// `CTRL-EVENT-CONNECTED - Connection to %02x:...:%02x completed [id=%d
/// id_str=%s%s]`. Decision 0091.
#[test]
fn a_connected_event_names_the_access_point() {
	let event = netcfgd_supplicant::protocol::Event::parse(
		"<3>CTRL-EVENT-CONNECTED - Connection to aa:bb:cc:dd:ee:ff completed [id=0 id_str=]",
	)
	.expect("an event");
	assert_eq!(event.connected_bssid(), Some("aa:bb:cc:dd:ee:ff"));

	// Every other event says nothing, including the disconnect that carries an
	// address of its own in a different shape -- a reader that took any address
	// it found would report a roam every time the link dropped.
	for other in [
		"<3>CTRL-EVENT-DISCONNECTED bssid=aa:bb:cc:dd:ee:ff reason=3",
		"<3>CTRL-EVENT-SCAN-STARTED ",
		"<3>CTRL-EVENT-CONNECTED - Connection to nonsense completed [id=0 id_str=]",
		// The one that reaches the *name* check rather than the shape check.
		// Without it the three above pass with the name check deleted -- their
		// fifth word is either absent or not an address, so the shape check
		// alone rejects them, and the guard that says "only a connect is a
		// move" was never exercised by anything. Synthetic, and deliberately:
		// what it stands for is any future event with an address in that
		// position, which is a thing `wpa_supplicant` could add without asking.
		"<3>CTRL-EVENT-SOMETHING-ELSE a b c aa:bb:cc:dd:ee:ff",
	] {
		let event = netcfgd_supplicant::protocol::Event::parse(other).expect("an event");
		assert_eq!(event.connected_bssid(), None, "{other}");
	}
}

/// Stored certificates and a stored key become real files, and paths.
///
/// The point of the whole change. `wpa_supplicant` opens all three as files, so
/// everything reaching it has to be a path -- and before this the only way to
/// have one was to put the file there yourself, which a desktop client cannot
/// do. A `Stored` source is content netcfgd already holds; the resolver writes
/// it where the supplicant can read it and hands back that path.
///
/// The old behaviour is worth remembering: `private_key` was sent as the
/// secret's *value*, so an EAP-TLS network rendered
/// `private_key "-----BEGIN PRIVATE KEY-----` followed by a newline -- a
/// filename that does not exist, and a newline that terminates the line-based
/// `SET_NETWORK` command in the middle.
#[test]
fn stored_certificates_are_materialised_and_sent_as_paths() {
	use std::os::unix::fs::PermissionsExt as _;

	let dir = scratch("tls-stored");
	write_secret(&dir, "corp-ca", "-----BEGIN CERTIFICATE-----\nCA==\n");
	write_secret(&dir, "corp-crt", "-----BEGIN CERTIFICATE-----\nCRT==\n");
	write_secret(&dir, "corp-key", "-----BEGIN PRIVATE KEY-----\nKEY==\n");

	let run = scratch("tls-run");
	let resolver = Resolver::with_secrets_dir(&*dir).materialising_into(run.join("certs"));

	let tls = Security::Eap(EapConfig {
		method: EapMethod::Tls,
		identity: "user@corp.example".to_owned(),
		anonymous_identity: None,
		password: None,
		ca_cert: Some(CertSource::Stored(stored("corp-ca"))),
		client_cert: Some(CertSource::Stored(stored("corp-crt"))),
		private_key: Some(CertSource::Stored(stored("corp-key"))),
		phase2: None,
	});
	let lines = rendered(&network("corp", tls), &resolver);

	// Every one is a path under /run, and none carries the material.
	for (field, file) in [
		("ca_cert", "ca.pem"),
		("client_cert", "client.pem"),
		("private_key", "client.key"),
	] {
		let wanted = run.join("certs").join(file);
		assert!(
			lines
				.iter()
				.any(|line| line.contains(&format!("{field} \"{}\"", wanted.display()))),
			"{field} is not the materialised path: {lines:?}"
		);
		assert!(
			wanted.exists(),
			"{field} was named but never written: {}",
			wanted.display()
		);
		let mode = std::fs::metadata(&wanted)
			.expect("readable")
			.permissions()
			.mode();
		assert_eq!(mode & 0o777, 0o600, "{field} is {mode:o}");
	}

	// And nothing rendered carries the key material itself, which is the
	// failure the old code had and the one worth asserting against by name.
	assert!(
		!lines.iter().any(|line| line.contains("BEGIN PRIVATE KEY")),
		"key material reached the control socket: {lines:?}"
	);
}

/// A resolver with nowhere to write refuses rather than choosing a directory.
///
/// The safe direction: a resolver that invented somewhere would put key
/// material in a place its caller did not pick.
#[test]
fn a_stored_certificate_with_nowhere_to_go_is_refused() {
	let dir = scratch("tls-nowhere");
	write_secret(&dir, "corp-key", "material");
	let resolver = Resolver::with_secrets_dir(&*dir);
	assert!(settings(
		&network("corp", tls_with(CertSource::Stored(stored("corp-key")))),
		MacPolicy::Permanent,
		&resolver,
	)
	.is_err());
}

fn stored(name: &str) -> SecretRef {
	SecretRef {
		provider: SecretProvider::File,
		name: name.to_owned(),
	}
}

/// A certificate given as a path is sent unchanged, and nothing is written.
///
/// The other half of the pair. An operator with certificates already in
/// `/etc/ssl` should not have to hand them to netcfgd to use them, so a `Path`
/// source passes straight through -- and materialising one would be netcfgd
/// copying a file it was only asked to name.
///
/// **This replaces two tests that bounded the old defect** rather than fixing
/// it: before certificates could be content, a private key holding material
/// was refused, because sending it was the only other option and sending it
/// corrupted the control socket. Refusing is no longer right -- stored key
/// material is the supported case now, and `stored_certificates_are_...` is
/// where it is checked.
#[test]
fn a_certificate_given_as_a_path_is_sent_unchanged() {
	let dir = scratch("tls-path");
	let run = scratch("tls-path-run");
	let resolver = Resolver::with_secrets_dir(&*dir).materialising_into(run.join("certs"));
	let lines = rendered(
		&network(
			"corp",
			tls_with(CertSource::Path("/etc/ssl/private/client.key".to_owned())),
		),
		&resolver,
	);

	assert!(
		lines
			.iter()
			.any(|line| line.contains("private_key \"/etc/ssl/private/client.key\"")),
		"{lines:?}"
	);
	assert!(lines
		.iter()
		.any(|line| line.contains("ca_cert \"/etc/ssl/ca.pem\"")));
	assert!(
		!run.join("certs").exists(),
		"a path source made netcfgd write a file it was only asked to name"
	);
}

/// An EAP-TLS network with everything but the key, which the two above vary.
fn tls_with(private_key: CertSource) -> Security {
	Security::Eap(EapConfig {
		method: EapMethod::Tls,
		identity: "user@corp.example".to_owned(),
		anonymous_identity: None,
		password: None,
		ca_cert: Some(CertSource::Path("/etc/ssl/ca.pem".to_owned())),
		client_cert: Some(CertSource::Path("/etc/ssl/client.pem".to_owned())),
		private_key: Some(private_key),
		phase2: None,
	})
}

/// The mobility domain, read from a `BSS <bssid>` reply.
///
/// 802.11r: access points an operator configured into one roaming domain
/// advertise the same id. It is the only standard, machine-readable statement
/// that two BSSes belong together -- and it is **not** a trust signal, because
/// the element is unauthenticated bytes in a beacon. netcfgd shows it and does
/// not group by it, which is the distinction this pins by existing.
#[test]
fn the_mobility_domain_is_read_where_there_is_one() {
	use netcfgd_supplicant::protocol::parse_mobility_domain;

	let with = "bssid=f0:9f:c2:7d:bd:7d\nfreq=2412\nmdid=a1b2\nssid=OpenPC.se\n";
	assert_eq!(parse_mobility_domain(with), Some("a1b2".to_owned()));

	// The ordinary case: an access point that does no fast transition has no
	// element, and absent is the honest answer rather than an empty string a
	// caller would print.
	let without = "bssid=00:11:22:33:44:55\nfreq=2437\nssid=Cafe\n";
	assert_eq!(parse_mobility_domain(without), None);
	assert_eq!(parse_mobility_domain("mdid=\n"), None);
}

/// Fast transition is read from the flags, which cost nothing.
///
/// The cheap test that decides whether asking for the domain is worth a round
/// trip. With fifty networks in range, asking every one would make a scan
/// slower to serve something almost none of them have.
#[test]
fn fast_transition_is_visible_in_the_scan_flags() {
	let results = netcfgd_supplicant::protocol::parse_scan_results(
		"bssid / frequency / signal level / flags / ssid\n\
		 f0:9f:c2:7d:bd:7d\t2412\t-40\t[WPA2-FT/PSK-CCMP][ESS]\tOpenPC.se\n\
		 00:11:22:33:44:55\t2437\t-35\t[WPA2-PSK-CCMP][ESS]\tCafe\n",
	);
	assert_eq!(results.len(), 2);
	assert!(results[0].does_fast_transition(), "{}", results[0].flags);
	assert!(!results[1].does_fast_transition(), "{}", results[1].flags);
	// Both are secured, so the new test is not accidentally reading that.
	assert!(results[0].is_secured() && results[1].is_secured());
}
