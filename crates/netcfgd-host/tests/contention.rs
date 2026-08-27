//! Detecting another daemon on the same interface.
//!
//! Driven from a fake `/run` rather than from whatever happens to be installed
//! -- a test that only passes on a machine running `NetworkManager` is a test
//! that passes on one machine.
//!
//! The NM layout below was read off a running `NetworkManager`. The `networkd`
//! one now is too: `tests/networkd/` holds link state files copied verbatim
//! from systemd 257, and the tests at the bottom of this file use those rather
//! than a hand-written approximation of them.

use netcfgd_host::contention::{contenders, describe};
use std::fs;

fn scratch(name: &str) -> netcfgd_testdir::TestDir {
	netcfgd_testdir::TestDir::new(&format!("cont-{name}"))
}

fn nm_device(root: &std::path::Path, index: u32, body: &str) {
	let dir = root.join("NetworkManager/devices");
	fs::create_dir_all(&dir).expect("mkdir");
	fs::write(dir.join(index.to_string()), body).expect("write");
}

/// A fake `/proc` with one process per name.
///
/// Liveness has to come from the fixture for the same reason `/run` does. This
/// machine runs `NetworkManager`, so a liveness check read off the real `/proc`
/// would make every test here pass without testing anything -- and pass for the
/// opposite reason on a machine that does not.
///
/// It also holds the two shapes a `/proc` scan trips over: a non-numeric entry,
/// and a numeric one with no `comm` at all, which is what a process exiting
/// mid-scan looks like.
fn fake_proc(root: &std::path::Path, comms: &[&str]) {
	for (n, comm) in comms.iter().enumerate() {
		let dir = root.join("proc").join((100 + n).to_string());
		fs::create_dir_all(&dir).expect("mkdir");
		fs::write(dir.join("comm"), format!("{comm}\n")).expect("write");
	}
	fs::create_dir_all(root.join("proc/self")).expect("mkdir");
	fs::create_dir_all(root.join("proc/999")).expect("mkdir");
}

/// Serialised, because they share process-wide environment variables.
///
/// Both daemons are alive unless a test says otherwise, which is what every
/// test written before liveness mattered assumed.
fn with_root<T>(root: &std::path::Path, body: impl FnOnce() -> T) -> T {
	with_root_and_daemons(root, &["NetworkManager", "systemd-network"], body)
}

fn with_root_and_daemons<T>(root: &std::path::Path, comms: &[&str], body: impl FnOnce() -> T) -> T {
	use std::sync::Mutex;
	static LOCK: Mutex<()> = Mutex::new(());
	let _guard = LOCK
		.lock()
		.unwrap_or_else(std::sync::PoisonError::into_inner);
	fake_proc(root, comms);
	std::env::set_var("NCFG_RUN_ROOT", root);
	std::env::set_var("NCFG_PROC", root.join("proc"));
	let out = body();
	std::env::remove_var("NCFG_RUN_ROOT");
	std::env::remove_var("NCFG_PROC");
	out
}

/// The state file exists for every device NM knows about, so its presence
/// proves nothing. `managed=true` is the claim -- and reporting on presence
/// alone would announce a contest with a daemon that has already stepped
/// aside, which is the sort of false alarm that gets a warning ignored.
#[test]
fn only_a_managed_device_is_a_claim() {
	let root = scratch("managed");
	nm_device(&root, 3, "[device]\nmanaged=true\nconnection-uuid=abc\n");
	// A device NM knows about and does not manage: this is the exact shape a
	// real `NetworkManager` wrote for an ethernet port with the cable out.
	nm_device(&root, 2, "[device]\nperm-hw-addr-fake=00:00:00:00:00:00\n");
	// And one it was explicitly told to leave alone.
	nm_device(&root, 4, "[device]\nmanaged=false\n");

	let found = with_root(&root, || {
		contenders(&[
			("wlan0".to_owned(), 3),
			("eth0".to_owned(), 2),
			("eth1".to_owned(), 4),
		])
	});

	assert_eq!(found.len(), 1, "got {found:?}");
	assert_eq!(found[0].name, "NetworkManager");
	assert_eq!(found[0].interfaces, ["wlan0"]);

	let _ = fs::remove_dir_all(&root);
}

/// An interface netcfgd does not claim is not a conflict. The two daemons can
/// share a machine perfectly well as long as they do not share a device, and
/// warning otherwise would make the message noise.
#[test]
fn an_interface_netcfgd_does_not_claim_is_not_reported() {
	let root = scratch("unclaimed");
	nm_device(&root, 3, "[device]\nmanaged=true\n");

	let found = with_root(&root, || contenders(&[("eth0".to_owned(), 2)]));
	assert!(found.is_empty(), "got {found:?}");

	let _ = fs::remove_dir_all(&root);
}

/// A machine with neither daemon reports nothing, and does not mind that the
/// directories are absent.
#[test]
fn a_clean_machine_reports_nothing() {
	let root = scratch("clean");
	let found = with_root(&root, || contenders(&[("eth0".to_owned(), 2)]));
	assert!(found.is_empty(), "got {found:?}");
	let _ = fs::remove_dir_all(&root);
}

/// `networkd`, from its documented layout. Unlike the NM case this has not been
/// checked against a running `networkd`.
#[test]
fn networkd_is_detected_from_its_link_state() {
	let root = scratch("networkd");
	let links = root.join("systemd/netif/links");
	fs::create_dir_all(&links).expect("mkdir");
	fs::write(
		links.join("2"),
		"ADMIN_STATE=configured\nOPER_STATE=routable\n",
	)
	.expect("write");
	fs::write(links.join("3"), "ADMIN_STATE=unmanaged\n").expect("write");

	let found = with_root(&root, || {
		contenders(&[("eth0".to_owned(), 2), ("wlan0".to_owned(), 3)])
	});
	assert_eq!(found.len(), 1, "got {found:?}");
	assert_eq!(found[0].name, "systemd-networkd");
	assert_eq!(found[0].interfaces, ["eth0"]);

	let _ = fs::remove_dir_all(&root);
}

/// The message has to be actionable, which means naming the device rather than
/// a placeholder the operator has to interpret.
#[test]
fn the_message_names_the_device_and_the_command() {
	let root = scratch("message");
	nm_device(&root, 3, "[device]\nmanaged=true\n");
	nm_device(&root, 5, "[device]\nmanaged=true\n");

	let found = with_root(&root, || {
		contenders(&[("wlan0".to_owned(), 3), ("wlan1".to_owned(), 5)])
	});
	let text = describe(&found[0]);

	assert!(
		text.contains("nmcli device set wlan0 managed no"),
		"got: {text}"
	);
	assert!(
		text.contains("nmcli device set wlan1 managed no"),
		"got: {text}"
	);
	assert!(!text.contains("DEV"), "no placeholder survives: {text}");
	// And it says what goes wrong, not just that something might.
	assert!(text.contains("intermittently"), "got: {text}");

	let _ = fs::remove_dir_all(&root);
}

/// What a real `systemd-networkd` writes, used as it wrote it.
fn networkd_link(root: &std::path::Path, index: u32, sample: &str) {
	let dir = root.join("systemd/netif/links");
	fs::create_dir_all(&dir).expect("mkdir");
	let body = fs::read_to_string(
		std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
			.join("tests/networkd")
			.join(sample),
	)
	.expect("the captured sample is in the tree");
	fs::write(dir.join(index.to_string()), body).expect("write");
}

/// The three states a running networkd actually produced, against the detector.
///
/// This is the test the module header used to disclaim. It was written from
/// systemd's documentation because networkd would not start here -- it drops
/// privileges to `systemd-network`, which cannot map inside a user namespace,
/// so it took a privileged container to run one at all.
///
/// What that found: the documented two states are right, and there is a third.
/// `pending` is a link networkd has seen and not yet decided about, and it
/// persisted for the whole run rather than flickering past. It is deliberately
/// *not* a claim -- networkd has configured nothing on such a link, so warning
/// about a contest there would be the false alarm the NM test above exists to
/// avoid.
#[test]
fn the_three_states_a_real_networkd_writes() {
	let root = scratch("networkd-real");
	networkd_link(&root, 7, "configured");
	networkd_link(&root, 8, "unmanaged");
	networkd_link(&root, 1, "pending");

	let found = with_root(&root, || {
		contenders(&[
			("nd0".to_owned(), 7),
			("nd1".to_owned(), 8),
			("lo".to_owned(), 1),
		])
	});

	assert_eq!(found.len(), 1, "only networkd should be reported");
	assert_eq!(found[0].name, "systemd-networkd");
	assert_eq!(
		found[0].interfaces,
		vec!["nd0".to_owned()],
		"the configured link is the claim; unmanaged and pending are not"
	);
}

/// The header line is part of what is parsed, and it says not to.
///
/// `# This is private data. Do not parse.` is the first line of every one of
/// these files. netcfgd parses them anyway, and that is a decision rather than
/// an oversight: the supported ways to ask are `networkctl` and networkd's
/// D-Bus API, and section 1 constraint 3 keeps a message bus off the core's
/// mandatory path. The cost is that this can break on a systemd release, and
/// the mitigation is that it is a *warning* -- netcfgd loses a diagnostic, not
/// a network, if the format moves.
///
/// Asserted so the assumption is visible rather than implied by a fixture.
#[test]
fn the_link_file_is_private_data_and_says_so() {
	let body = fs::read_to_string(
		std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/networkd/configured"),
	)
	.expect("the captured sample is in the tree");
	assert!(
		body.starts_with("# This is private data. Do not parse."),
		"systemd still marks these files private; if this line has gone, the \
		 format may have moved and the detector is what to check"
	);
}

/// The operator's question is "how do I make this stop", and the per-device
/// answer is not always the one they want.
///
/// The holder's instruction is that netcfgd should displace what stands in its
/// way, and 0125 settled how: a drop-in that has the init system stop the
/// other daemons. It shipped as documentation and the refusal never mentioned
/// it, so the only remedy an operator ever saw was the per-device `nmcli` one
/// -- which is the wrong shape for somebody who wants netcfgd to own the
/// machine, and which they must then repeat for every device.
///
/// The path is asserted literally because it is where `debian/rules` installs
/// the file, and a message naming a path that is not there is worse than one
/// naming no path at all.
#[test]
fn the_message_also_names_the_whole_machine_remedy() {
	let root = scratch("machine_remedy");
	nm_device(&root, 3, "[device]\nmanaged=true\n");

	let found = with_root(&root, || contenders(&[("wlan0".to_owned(), 3)]));
	let text = describe(&found[0]);

	assert!(
		text.contains("/usr/share/doc/netcfgd/netcfgd-exclusive.conf"),
		"got: {text}"
	);
	assert!(
		text.contains("/etc/systemd/system/netcfgd.service.d"),
		"got: {text}"
	);
	// The per-device remedy is still there: this adds an option, it does not
	// replace the one an operator sharing a machine actually wants.
	assert!(
		text.contains("nmcli device set wlan0 managed no"),
		"got: {text}"
	);
	// And it says who stops them, because netcfgd killing daemons itself is
	// the thing 0125 declined to do.
	assert!(text.contains("init system"), "got: {text}");

	let _ = fs::remove_dir_all(&root);
}

/// **A stopped daemon leaves its claim behind, and this is the machine's whole
/// wireless failure.**
///
/// `NetworkManager.service` has no `RuntimeDirectory=` and no `ExecStop=`, so
/// `/run/NetworkManager/devices/*` outlives the daemon with `managed=true`
/// still in it. `systemd-networkd` is worse in the same way: it has a
/// `RuntimeDirectory=` and sets `RuntimeDirectoryPreserve=yes`.
///
/// That composes with the `netcfgd-exclusive.conf` drop-in into a machine with
/// no network at all. The drop-in conflicts with `NetworkManager.service` *and*
/// `wpa_supplicant.service`, so starting netcfgd stops both -- and then netcfgd
/// reads NM's abandoned files, believes NM still holds the radio, and declines
/// to start a supplicant. Every daemon that could have configured the network
/// is now stopped, including netcfgd by its own choice, and the reported
/// symptom is exactly "when I start netcfgd, ping stops working".
///
/// The file says *which* interfaces. Only a live process says the claim is
/// *current*. Neither is sufficient alone, which is why this checks both
/// rather than replacing one with the other.
#[test]
fn a_stopped_daemon_has_no_claim_however_much_state_it_left() {
	let root = scratch("stopped");
	// Exactly what a real NetworkManager leaves behind when it is stopped.
	nm_device(&root, 3, "[device]\nmanaged=true\nconnection-uuid=abc\n");

	// Alive: the claim stands. This is the control, and without it the
	// assertion below would pass just as happily against a broken reader.
	let alive = with_root_and_daemons(&root, &["NetworkManager"], || {
		contenders(&[("wlan0".to_owned(), 3)])
	});
	assert_eq!(alive.len(), 1, "a running NM still claims: {alive:?}");

	// Stopped, same files: no claim.
	let stopped = with_root_and_daemons(&root, &["bash", "sshd"], || {
		contenders(&[("wlan0".to_owned(), 3)])
	});
	assert!(
		stopped.is_empty(),
		"a stopped NM must not hold the radio: {stopped:?}"
	);

	let _ = fs::remove_dir_all(&root);
}
