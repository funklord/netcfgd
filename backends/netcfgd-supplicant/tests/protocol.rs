//! What the control protocol has to get right, as tests.
//!
//! All of this runs without a radio, without root, and without
//! `wpa_supplicant` installed. The association path cannot be tested that way
//! and is covered by `tests/live.rs`, which skips when there is no supplicant.

use netcfgd_model::security::{PskConfig, PskProto};
use netcfgd_model::{EapConfig, EapMethod, SecretProvider, SecretRef, Security, Ssid, WifiNetwork};
use netcfgd_secret::Resolver;
use netcfgd_supplicant::network::settings;
use netcfgd_supplicant::protocol::{
	is_event, parse_network_list, parse_scan_results, parse_status, passphrase_argument,
	passphrase_is_sendable, printf_decode, ssid_argument, status_field, Event, Reply,
};
use netcfgd_supplicant::Unsupported;
use std::fs;
use std::path::PathBuf;

/// Tests run in parallel in one process, so the directory has to be unique
/// per call rather than per name -- otherwise one test's cleanup removes
/// another's secret, and the failure looks like a resolver bug.
static NEXT: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);

fn scratch(name: &str) -> PathBuf {
	let serial = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
	let dir =
		std::env::temp_dir().join(format!("ncfg-supp-{name}-{}-{serial}", std::process::id()));
	let _ = fs::remove_dir_all(&dir);
	fs::create_dir_all(&dir).expect("scratch");
	dir
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
		ssid: Ssid::new(ssid.as_bytes().to_vec()).expect("ssid"),
		hidden: false,
		security,
		priority: 0,
		autoconnect: true,
		metered: false,
		bssid_pin: None,
		addressing: Vec::new(),
		routes: Vec::new(),
		dns: None,
		hooks: Vec::new(),
	}
}

fn psk(passphrase: &str, proto: PskProto) -> (Resolver, Security, PathBuf) {
	let dir = scratch("psk");
	write_secret(&dir, "pass", passphrase);
	(
		Resolver::with_secrets_dir(&dir),
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
	settings(network, resolver)
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
	let error = settings(&network("home", security), &resolver).expect_err("refused");
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

	assert!(commands.contains(&"SET_NETWORK 0 key_mgmt SAE".to_owned()));
	assert!(commands.contains(&"SET_NETWORK 0 ieee80211w 2".to_owned()));
	assert!(
		!commands.iter().any(|line| line.contains("WPA-PSK")),
		"WPA3 must not offer the WPA2 key management: {commands:?}"
	);
	let _ = fs::remove_dir_all(&dir);
}

/// Transitional mode has to work against both, and `ieee80211w` is the field
/// where getting it wrong excludes one of them.
#[test]
fn transitional_mode_can_reach_both_generations() {
	let (resolver, security, dir) = psk("hunter2hunter2", PskProto::Wpa2Wpa3);
	let commands = rendered(&network("home", security), &resolver);

	assert!(commands.contains(&"SET_NETWORK 0 key_mgmt WPA-PSK SAE".to_owned()));
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

	pinned.bssid_pin = Some("00:11:22:33:44:55".to_owned());
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
		pinned.bssid_pin = Some(hostile.to_owned());
		let error = settings(&pinned, &resolver).expect_err("refused");
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
		let error = settings(&network("home", security), &resolver).expect_err("refused");
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
	let all = settings(&network("home", security), &resolver).expect("settings");
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
	let resolver = Resolver::with_secrets_dir(&dir);

	let eap = Security::Eap(EapConfig {
		method: EapMethod::Peap,
		identity: r#"user"; REMOVE_NETWORK all; ""#.to_owned(),
		anonymous_identity: Some("anonymous@example.net".to_owned()),
		password: Some(SecretRef {
			provider: SecretProvider::File,
			name: "password".to_owned(),
		}),
		ca_cert: Some("/etc/ssl/certs/corporate.pem".to_owned()),
		client_cert: None,
		private_key: None,
		phase2: Some("auth=MSCHAPV2".to_owned()),
	});

	let all = settings(&network("corp", eap), &resolver).expect("settings");
	let commands: Vec<String> = all.iter().map(|setting| setting.command(0)).collect();

	assert!(commands.contains(&"SET_NETWORK 0 key_mgmt WPA-EAP".to_owned()));
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
	let error = settings(&network("corp", eap), &resolver).expect_err("refused");
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
		client_cert: Some("/etc/ssl/client.pem".to_owned()),
		private_key: None,
		phase2: None,
	});
	let error = settings(&network("corp", tls), &resolver).expect_err("refused");
	assert_eq!(
		error.downcast_ref::<Unsupported>(),
		Some(&Unsupported::MissingEapField {
			field: "private_key"
		})
	);
}
