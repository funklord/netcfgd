//! What netcfgd writes, read back by the program that has to read it.
//!
//! The unit tests in `render` assert that WPA3 is spelled `SAE` and that a
//! hidden network sets `ignore_broadcast_ssid`. They cannot tell whether
//! hostapd has ever heard of either, because they are asserting against the
//! same beliefs that produced the file. This test asks hostapd.
//!
//! That distinction is the whole reason it exists. Every netlink bug this
//! project has shipped -- the `WireGuard` flags attribute, the nftables meta
//! key, the qdisc rate unit -- was a correctly encoded message that the kernel
//! did not agree with, and none would have been found by reading the encoder
//! more carefully. A configuration file is the same shape of problem with an
//! easier answer available: hostapd will parse a file without a radio, and it
//! reports what it disliked and on which line.
//!
//! What this cannot check is anything hostapd only decides once a driver is
//! attached -- whether the regulatory domain permits the channel, whether the
//! radio supports the mode. `tests/live/ap.sh` goes one step further, and a
//! radio would be needed for the rest.

use netcfgd_hostapd::{config, to_file};
use netcfgd_model::secret::{SecretProvider, SecretRef};
use netcfgd_model::security::{PskConfig, PskProto};
use netcfgd_model::{AccessPoint, Security, Ssid};
use std::path::{Path, PathBuf};
use std::process::Command;

/// Where hostapd is, or nothing.
///
/// `netcfgd_hostapd::binary()` and not a bare `hostapd`, so the test looks
/// where netcfgd itself looks -- a test that found the binary somewhere
/// netcfgd does not would pass while netcfgd reported "no hostapd found".
fn hostapd() -> Option<PathBuf> {
	netcfgd_hostapd::binary()
}

fn access_point(id: &str, security: Security) -> AccessPoint {
	AccessPoint {
		id: id.to_owned(),
		ssid: Ssid::new(id.as_bytes().to_vec()).expect("a valid ssid"),
		device: "wlan0".to_owned(),
		security,
		channel: Some(6),
		band: None,
		hidden: false,
		regdom: None,
	}
}

fn psk(proto: PskProto) -> Security {
	Security::Psk(PskConfig {
		passphrase: SecretRef {
			provider: SecretProvider::File,
			name: "guest".to_owned(),
		},
		proto,
	})
}

/// Run hostapd against a rendered file and return its complaints.
///
/// hostapd exits nonzero either way here -- there is no `wlan0` to attach to
/// on the machine running this -- so the exit status says nothing. What
/// separates the two cases is the text: a file it could not parse produces
/// `N errors found in configuration file` and one or more `Line N:` lines,
/// which is the whole vocabulary this needs.
fn complaints(program: &Path, name: &str, text: &str) -> Vec<String> {
	let dir = std::env::temp_dir().join(format!("ncfg-hostapd-{}", std::process::id()));
	std::fs::create_dir_all(&dir).expect("a working directory");
	let path = dir.join(format!("{name}.conf"));
	std::fs::write(&path, text).expect("the configuration is written");

	let output = Command::new(program)
		.arg(&path)
		.output()
		.expect("hostapd runs");
	let said = String::from_utf8_lossy(&output.stdout).into_owned()
		+ &String::from_utf8_lossy(&output.stderr);

	let _ = std::fs::remove_file(&path);
	said.lines()
		.filter(|line| line.starts_with("Line ") || line.contains("errors found in configuration"))
		.map(std::borrow::ToOwned::to_owned)
		.collect()
}

#[test]
fn every_variant_is_a_file_hostapd_accepts() {
	let Some(program) = hostapd() else {
		// Skipped rather than failed: hostapd is an optional package, and
		// decision 0026 is explicit that a machine which never runs an access
		// point should not need it installed.
		println!("skipping: no hostapd installed, so there is nothing to check the file against");
		return;
	};

	let hidden = {
		let mut point = access_point("hidden", psk(PskProto::Wpa2));
		point.hidden = true;
		point.regdom = Some("SE".to_owned());
		point
	};
	let five_gigahertz = {
		let mut point = access_point("fiveghz", Security::Open);
		point.band = Some("5".to_owned());
		point.channel = Some(36);
		point
	};
	let chosen_channel = {
		let mut point = access_point("acs", Security::Open);
		point.channel = None;
		point
	};
	// An SSID that is not text at all. The reason `ssid2` is used rather than
	// `ssid`, and the case that would silently become a differently named
	// network if it were ever rendered as a quoted string.
	let binary_name = {
		let mut point = access_point("binary", Security::Open);
		point.ssid = Ssid::new(vec![0x00, 0xff, 0x20, 0x22]).expect("a valid ssid");
		point
	};

	let cases = [
		("open", access_point("open", Security::Open)),
		("wpa2", access_point("wpa2", psk(PskProto::Wpa2))),
		("wpa3", access_point("wpa3", psk(PskProto::Wpa3))),
		(
			"transition",
			access_point("transition", psk(PskProto::Wpa2Wpa3)),
		),
		("owe", access_point("owe", Security::Owe)),
		("hidden", hidden),
		("fiveghz", five_gigahertz),
		("acs", chosen_channel),
		("binary", binary_name),
	];

	for (name, point) in &cases {
		let lines = config(
			point,
			Path::new("/run/netcfgd/hostapd"),
			Some("hunter2hunter2"),
		)
		.unwrap_or_else(|error| panic!("`{name}` did not render: {error}"));
		let text = to_file(&point.id, &lines);
		let complaints = complaints(&program, name, &text);
		assert!(
			complaints.is_empty(),
			"hostapd rejected the `{name}` configuration netcfgd wrote:\n{}\n\nthe file was:\n{text}",
			complaints.join("\n")
		);
	}
}

/// The check above has to be able to fail.
///
/// A test that runs a program and looks for complaints passes just as happily
/// when it is looking for the wrong words, or reading the wrong stream, or
/// running something that is not hostapd. So it is pointed at a file that is
/// definitely wrong, and required to notice.
#[test]
fn the_check_notices_a_configuration_hostapd_hates() {
	let Some(program) = hostapd() else {
		println!("skipping: no hostapd installed");
		return;
	};

	let complaints = complaints(
		&program,
		"deliberately-wrong",
		"interface=wlan0\ndriver=nl80211\nssid2=6775657374\nhw_mode=g\nchannel=6\n\
		 wpa=2\nwpa_key_mgmt=WPA3-SAE-THE-WAY-EVERYONE-WRITES-IT\n",
	);
	assert!(
		complaints
			.iter()
			.any(|line| line.contains("invalid key_mgmt")),
		"the reference check did not notice an invalid key management value: {complaints:?}"
	);
}
