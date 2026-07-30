//! Detecting another daemon on the same interface.
//!
//! Driven from a fake `/run` rather than from whatever happens to be installed
//! -- a test that only passes on a machine running `NetworkManager` is a test
//! that passes on one machine.
//!
//! The NM layout below was read off a running `NetworkManager`; the `networkd` one
//! was not, and its test is worth exactly what that is worth.

use netcfgd_host::contention::{contenders, describe};
use std::fs;
use std::path::PathBuf;

fn scratch(name: &str) -> PathBuf {
	let dir = std::env::temp_dir().join(format!("ncfg-cont-{name}-{}", std::process::id()));
	let _ = fs::remove_dir_all(&dir);
	fs::create_dir_all(&dir).expect("scratch");
	dir
}

fn nm_device(root: &std::path::Path, index: u32, body: &str) {
	let dir = root.join("NetworkManager/devices");
	fs::create_dir_all(&dir).expect("mkdir");
	fs::write(dir.join(index.to_string()), body).expect("write");
}

/// Serialised, because they share one process-wide environment variable.
fn with_root<T>(root: &std::path::Path, body: impl FnOnce() -> T) -> T {
	use std::sync::Mutex;
	static LOCK: Mutex<()> = Mutex::new(());
	let _guard = LOCK
		.lock()
		.unwrap_or_else(std::sync::PoisonError::into_inner);
	std::env::set_var("NCFG_RUN_ROOT", root);
	let out = body();
	std::env::remove_var("NCFG_RUN_ROOT");
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
