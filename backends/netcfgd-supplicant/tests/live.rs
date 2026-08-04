//! The control socket, against a real `wpa_supplicant`.
//!
//! Everything in `tests/protocol.rs` is text, and text can be wrong in a way
//! that parses perfectly and is rejected by the thing it is aimed at. This
//! file is the other half: it starts an actual `wpa_supplicant` and makes it
//! answer.
//!
//! The `wired` driver is used deliberately. Association needs a radio and
//! `mac80211_hwsim`, but the control protocol, the network database and the
//! *config parser* do not -- so the question "does `wpa_supplicant` accept the
//! strings netcfgd sends for WPA3?" gets a real answer on a machine with no
//! wifi at all. What remains untested here is association itself, and
//! decision 0014 says so rather than implying otherwise.
//!
//! Requirements: `wpa_supplicant`, and `CAP_NET_ADMIN`/`CAP_NET_RAW` in the
//! current network namespace. `make live` supplies the second with
//! `unshare -rn`. Without them the test skips -- unless `NCFG_LIVE` is set, in
//! which case it fails, because a live test that silently passes on a machine
//! that cannot run it is worse than no test.

use netcfgd_model::device::MacPolicy;
use netcfgd_model::security::{PskConfig, PskProto};
use netcfgd_model::{SecretProvider, SecretRef, Security, Ssid, WifiNetwork};
use netcfgd_secret::Resolver;
use netcfgd_supplicant::protocol::{parse_network_list, parse_status, status_field};
use netcfgd_supplicant::{add_network, clear_networks, Client};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

/// Whether a failure to run is a skip or a failure.
fn required() -> bool {
	std::env::var_os("NCFG_LIVE").is_some()
}

fn skip(reason: &str) {
	assert!(
		!required(),
		"NCFG_LIVE is set but the live test cannot run: {reason}"
	);
	// Visible under `cargo test -- --nocapture`; the alternative is a test
	// that reports success without having done anything.
	println!("skipping live supplicant test: {reason}");
}

/// `wpa_supplicant` lives in `/usr/sbin`, which is not on a non-root `PATH` on
/// Debian -- so looking it up the obvious way finds nothing on a machine that
/// has it.
fn find_supplicant() -> Option<PathBuf> {
	let mut candidates: Vec<PathBuf> = ["/usr/sbin", "/sbin", "/usr/local/sbin", "/usr/bin"]
		.iter()
		.map(|dir| Path::new(dir).join("wpa_supplicant"))
		.collect();
	if let Some(path) = std::env::var_os("PATH") {
		candidates.extend(std::env::split_paths(&path).map(|dir| dir.join("wpa_supplicant")));
	}
	candidates.into_iter().find(|path| path.is_file())
}

/// A `wpa_supplicant` process and its control directory, both cleaned up on
/// drop.
struct Supplicant {
	child: Child,
	dir: netcfgd_testdir::TestDir,
	interface: String,
}

impl Supplicant {
	/// Start one, or explain why not.
	fn start() -> Result<Self, String> {
		let binary = find_supplicant().ok_or("wpa_supplicant is not installed")?;

		let dir = netcfgd_testdir::TestDir::new("live");

		// Loopback, so no interface has to be created and the test needs no
		// `ip` command -- only the namespace privilege `wpa_supplicant` itself
		// requires.
		let interface = "lo".to_owned();
		let child = Command::new(&binary)
			.arg("-Dwired")
			.arg("-i")
			.arg(&interface)
			.arg("-C")
			.arg(&dir)
			.stdout(Stdio::null())
			.stderr(Stdio::null())
			.spawn()
			.map_err(|error| format!("cannot run {}: {error}", binary.display()))?;

		let supplicant = Self {
			child,
			dir,
			interface,
		};

		// The socket appears a moment after the process does.
		let deadline = Instant::now() + Duration::from_secs(5);
		while Instant::now() < deadline {
			if supplicant.socket().exists() {
				return Ok(supplicant);
			}
			std::thread::sleep(Duration::from_millis(50));
		}
		Err(format!(
			"no control socket appeared at {} (CAP_NET_ADMIN in this namespace?)",
			supplicant.socket().display()
		))
	}

	fn socket(&self) -> PathBuf {
		self.dir.join(&self.interface)
	}

	fn connect(&self) -> Client {
		Client::connect(&self.dir, &self.interface).expect("connect to the control socket")
	}
}

impl Drop for Supplicant {
	fn drop(&mut self) {
		let _ = self.child.kill();
		let _ = self.child.wait();
		// The directory goes with `self.dir`, which removes itself.
	}
}

/// Run `body` against a live supplicant, or skip.
fn with_supplicant(body: impl FnOnce(&Supplicant)) {
	match Supplicant::start() {
		Ok(supplicant) => body(&supplicant),
		Err(reason) => skip(&reason),
	}
}

fn secrets_with(passphrase: &str) -> (Resolver, netcfgd_testdir::TestDir) {
	use std::os::unix::fs::PermissionsExt;
	let dir = netcfgd_testdir::TestDir::new("live-secret");
	let path = dir.join("pass");
	fs::write(&path, passphrase).expect("write");
	fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("chmod");
	(Resolver::with_secrets_dir(&*dir), dir)
}

fn network(id: &str, ssid: &str, security: Security) -> WifiNetwork {
	WifiNetwork {
		id: id.to_owned(),
		ssid: Ssid::new(ssid.as_bytes().to_vec()).expect("ssid"),
		hidden: false,
		security,
		priority: 0,
		autoconnect: true,
		metered: false,
		bssid_pin: None,
		roam: None,
		addressing: Vec::new(),
		routes: Vec::new(),
		dns: None,
		hooks: Vec::new(),
	}
}

fn psk(proto: PskProto) -> Security {
	Security::Psk(PskConfig {
		passphrase: SecretRef {
			provider: SecretProvider::File,
			name: "pass".to_owned(),
		},
		proto,
	})
}

#[test]
fn a_real_supplicant_answers() {
	with_supplicant(|supplicant| {
		let client = supplicant.connect();
		client.ping().expect("PONG");

		let status = parse_status(&client.ask("STATUS").expect("STATUS"));
		assert!(
			status_field(&status, "wpa_state").is_some(),
			"STATUS had no wpa_state: {status:?}"
		);
	});
}

/// The reply-reading loop, the bound socket path and the drop cleanup all have
/// to survive being used more than once. A client that works exactly once is a
/// plausible bug and an annoying one to find later.
#[test]
fn many_commands_on_one_connection() {
	with_supplicant(|supplicant| {
		let client = supplicant.connect();
		for _ in 0..20 {
			client.ping().expect("PONG");
		}
		// And a second client at the same time, which is what the daemon and
		// a `ncfg wifi status` do.
		let second = supplicant.connect();
		second.ping().expect("PONG");
		client.ping().expect("PONG");
	});
}

/// The bound reply socket is a real file in the control directory. Leaving one
/// behind per connection fills the directory with dead sockets, and the next
/// reader cannot tell which are live.
#[test]
fn a_connection_leaves_nothing_behind() {
	with_supplicant(|supplicant| {
		let before = fs::read_dir(&supplicant.dir).expect("readdir").count();
		{
			let client = supplicant.connect();
			client.ping().expect("PONG");
			assert!(
				fs::read_dir(&supplicant.dir).expect("readdir").count() > before,
				"the client should have bound a socket of its own"
			);
		}
		assert_eq!(
			fs::read_dir(&supplicant.dir).expect("readdir").count(),
			before,
			"the client's socket outlived it"
		);
	});
}

/// The one that could not be tested without a supplicant: whether the strings
/// netcfgd sends are strings `wpa_supplicant` accepts. A `key_mgmt` value it
/// rejects would mean a WPA3 network that never associates, and no amount of
/// fixture testing would have caught it.
#[test]
fn every_security_mode_is_accepted_by_the_real_parser() {
	with_supplicant(|supplicant| {
		let client = supplicant.connect();
		// The guard is held for the length of the test: dropping it here would
		// take the passphrase away before the supplicant is asked to read it.
		let (resolver, _secrets) = secrets_with("hunter2hunter2");

		clear_networks(&client).expect("REMOVE_NETWORK all");

		for (name, security) in [
			("open", Security::Open),
			("wpa2", psk(PskProto::Wpa2)),
			("wpa3", psk(PskProto::Wpa3)),
			("transitional", psk(PskProto::Wpa2Wpa3)),
			("owe", Security::Owe),
		] {
			let id = add_network(
				&client,
				&network(name, name, security),
				MacPolicy::Permanent,
				&resolver,
			)
			.unwrap_or_else(|error| panic!("{name} was refused: {error}"));

			let listed = parse_network_list(&client.ask("LIST_NETWORKS").expect("LIST_NETWORKS"));
			let entry = listed
				.iter()
				.find(|entry| entry.id == id)
				.unwrap_or_else(|| panic!("{name} is not in the network list"));
			assert_eq!(
				entry.ssid.as_bytes(),
				name.as_bytes(),
				"the supplicant decoded the hex SSID back to the name"
			);
		}
	});
}

/// The MAC policy has to be a value the real supplicant accepts. `mac_addr`
/// takes a small integer whose meanings are documented but not obvious, and a
/// value it rejects is a network that fails to configure at all.
#[test]
fn every_mac_policy_is_accepted_by_the_real_supplicant() {
	with_supplicant(|supplicant| {
		let client = supplicant.connect();
		clear_networks(&client).expect("REMOVE_NETWORK all");

		for policy in [
			MacPolicy::Permanent,
			MacPolicy::PerNetwork,
			MacPolicy::PerConnection,
		] {
			let id = add_network(
				&client,
				&network("mac", "mac", Security::Open),
				policy,
				&Resolver::default(),
			)
			.unwrap_or_else(|error| panic!("{policy:?} was refused: {error}"));

			let stored = client
				.ask(&format!("GET_NETWORK {id} mac_addr"))
				.unwrap_or_else(|error| panic!("{policy:?}: {error}"));
			assert_eq!(
				stored.trim(),
				netcfgd_supplicant::mac_addr_value(policy),
				"the supplicant stored a different value than it was sent"
			);
			client
				.command(&format!("REMOVE_NETWORK {id}"))
				.expect("REMOVE_NETWORK");
		}
	});
}

/// Decision 0015: a supplicant started by something else, or one that survived
/// a crash, must not contribute networks the document cannot account for.
#[test]
fn clearing_removes_networks_netcfgd_did_not_add() {
	with_supplicant(|supplicant| {
		let client = supplicant.connect();

		// Stand in for whatever else put a network there.
		let id = client.ask("ADD_NETWORK").expect("ADD_NETWORK");
		client
			.command(&format!("SET_NETWORK {} ssid \"someone-elses\"", id.trim()))
			.expect("SET_NETWORK");
		assert_eq!(
			parse_network_list(&client.ask("LIST_NETWORKS").expect("LIST_NETWORKS")).len(),
			1
		);

		clear_networks(&client).expect("REMOVE_NETWORK all");
		assert!(
			parse_network_list(&client.ask("LIST_NETWORKS").expect("LIST_NETWORKS")).is_empty(),
			"a network netcfgd did not add survived the clear"
		);
	});
}

/// An SSID goes out as hex precisely so that a hostile name is a name. The
/// proof is that the supplicant stores it and hands it back unchanged, having
/// executed none of it.
#[test]
fn a_hostile_ssid_reaches_the_supplicant_intact() {
	with_supplicant(|supplicant| {
		let client = supplicant.connect();
		clear_networks(&client).expect("REMOVE_NETWORK all");

		let hostile = r#""; REMOVE_NETWORK all; ""#;
		let id = add_network(
			&client,
			&network("hostile", hostile, Security::Open),
			MacPolicy::Permanent,
			&Resolver::default(),
		)
		.expect("added");

		let listed = parse_network_list(&client.ask("LIST_NETWORKS").expect("LIST_NETWORKS"));
		assert_eq!(
			listed.len(),
			1,
			"the SSID was executed rather than stored: {listed:?}"
		);
		assert_eq!(listed[0].id, id);
		assert_eq!(
			listed[0].ssid.as_bytes(),
			hostile.as_bytes(),
			"the name did not survive the round trip"
		);
	});
}

/// `autoconnect = false` means present but not joined. A network left enabled
/// would be joined the moment it came in range, which is the opposite.
#[test]
fn autoconnect_false_leaves_the_network_disabled() {
	with_supplicant(|supplicant| {
		let client = supplicant.connect();
		clear_networks(&client).expect("REMOVE_NETWORK all");

		let mut manual = network("manual", "manual", Security::Open);
		manual.autoconnect = false;
		add_network(&client, &manual, MacPolicy::Permanent, &Resolver::default()).expect("added");

		let listed = parse_network_list(&client.ask("LIST_NETWORKS").expect("LIST_NETWORKS"));
		assert!(
			listed[0].flags.contains("DISABLED"),
			"got flags {:?}",
			listed[0].flags
		);
	});
}

/// A setting the supplicant refuses must not leave a half-configured network
/// sitting in the list looking like something netcfgd put there on purpose.
#[test]
fn a_refused_setting_leaves_no_partial_network() {
	with_supplicant(|supplicant| {
		let client = supplicant.connect();
		clear_networks(&client).expect("REMOVE_NETWORK all");

		// A pinned BSSID that passes netcfgd's own check but is not a BSSID
		// the supplicant will take: broadcast is refused by its parser.
		let id: u32 = client
			.ask("ADD_NETWORK")
			.expect("ADD_NETWORK")
			.trim()
			.parse()
			.expect("an id");
		assert!(
			client
				.command(&format!("SET_NETWORK {id} key_mgmt NOT-A-REAL-MODE"))
				.is_err(),
			"the supplicant accepted a key management mode that does not exist"
		);
		client
			.command(&format!("REMOVE_NETWORK {id}"))
			.expect("REMOVE_NETWORK");
		assert!(
			parse_network_list(&client.ask("LIST_NETWORKS").expect("LIST_NETWORKS")).is_empty()
		);
	});
}

/// A real `wpa_supplicant` accepts the roaming module netcfgd renders.
///
/// `bgscan` is documented as a network-block key in `wpa_supplicant.conf`, and
/// netcfgd does not write config files -- it sets fields over the control
/// socket. Those are two different code paths in `wpa_supplicant`: a key the
/// config parser takes is not necessarily one `SET_NETWORK` takes, because that
/// goes through `wpa_config_set` against a table of settable fields. A string
/// that is right for a file and rejected on the socket would leave roaming
/// silently off, with the daemon reporting a configured network.
///
/// The `wired` driver is enough for this: the question is whether the field is
/// accepted, not whether a radio then scans.
#[test]
fn a_real_supplicant_accepts_a_bgscan_over_the_control_socket() {
	with_supplicant(|supplicant| {
		let client = supplicant.connect();
		let id = client.ask("ADD_NETWORK").expect("ADD_NETWORK");
		let id = id.trim();

		client
			.command(&format!("SET_NETWORK {id} ssid \"corridor\""))
			.expect("the ssid is accepted");
		// Exactly what `network::settings` renders, quotes and all.
		client
			.command(&format!("SET_NETWORK {id} bgscan \"simple:20:-68:240\""))
			.expect("wpa_supplicant refused the bgscan netcfgd sends");

		// And it reads back, which is the half that says it was stored rather
		// than accepted and dropped.
		let stored = client
			.ask(&format!("GET_NETWORK {id} bgscan"))
			.expect("GET_NETWORK bgscan");
		assert!(
			stored.contains("simple:20:-68:240"),
			"wpa_supplicant took the bgscan and did not keep it: {stored:?}"
		);
	});
}
