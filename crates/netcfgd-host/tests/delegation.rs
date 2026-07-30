//! The contract between a shell script and a Rust reader.
//!
//! netcfgd learns a delegated prefix because a `DHCPv6` client's hook writes a
//! file and the observer reads it. The two halves never call each other and
//! share nothing but that file's format, so the only way to know they agree is
//! to run one and parse with the other.

use netcfgd_host::state::read_delegations;
use std::fs;
use std::path::PathBuf;

fn scratch(name: &str) -> PathBuf {
	let dir = std::env::temp_dir().join(format!("ncfg-pd-{name}-{}", std::process::id()));
	let _ = fs::remove_dir_all(&dir);
	fs::create_dir_all(dir.join("prefixes")).expect("scratch");
	dir
}

/// Write the hook and run it with the environment a client would set.
fn run_hook(run_dir: &std::path::Path, iface: &str, environment: &[(&str, &str)]) {
	use std::os::unix::fs::PermissionsExt;

	let target = run_dir.join("prefixes").join(iface);
	let script = netcfgd_apply::kernel::pd_hook_script(iface, &target);
	let path = run_dir.join("hook.sh");
	fs::write(&path, script).expect("write hook");
	fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).expect("chmod");

	let mut command = std::process::Command::new("sh");
	command.arg(&path);
	// A client sets one variable and leaves the other unset, so the hook has
	// to work with `set -u` in force either way.
	for (key, value) in environment {
		command.env(key, value);
	}
	let status = command.status().expect("run hook");
	assert!(status.success(), "the hook exited with {status}");
}

/// odhcp6c reports `prefix,preferred,valid` and may report several.
#[test]
fn the_hook_and_the_reader_agree_for_odhcp6c() {
	let dir = scratch("odhcp6c");
	run_hook(
		&dir,
		"wan0",
		&[(
			"PREFIXES",
			"2001:db8:1234::/56,3600,7200 2001:db8:5678::/60,3600,7200",
		)],
	);

	let delegations = read_delegations(&dir);
	assert_eq!(delegations.len(), 1);
	assert_eq!(delegations[0].interface, "wan0");
	assert_eq!(
		delegations[0].prefixes,
		["2001:db8:1234::/56", "2001:db8:5678::/60"],
		"the lifetimes after the comma are not part of the prefix"
	);

	let _ = fs::remove_dir_all(&dir);
}

/// dhcpcd uses a different variable and reports one.
#[test]
fn the_hook_and_the_reader_agree_for_dhcpcd() {
	let dir = scratch("dhcpcd");
	run_hook(&dir, "wan0", &[("new_dhcp6_prefix", "2001:db8:abcd::/56")]);

	let delegations = read_delegations(&dir);
	assert_eq!(delegations[0].prefixes, ["2001:db8:abcd::/56"]);

	let _ = fs::remove_dir_all(&dir);
}

/// The lease going away is reported, not merely absent. An empty file says
/// "the client ran and has nothing", which is different from no file at all --
/// though both produce no prefixes, so nothing downstream has to care.
#[test]
fn an_expired_lease_leaves_an_empty_file() {
	let dir = scratch("expired");
	run_hook(&dir, "wan0", &[("PREFIXES", "2001:db8::/56,3600,7200")]);
	assert_eq!(read_delegations(&dir)[0].prefixes.len(), 1);

	run_hook(&dir, "wan0", &[]);
	assert!(
		dir.join("prefixes/wan0").exists(),
		"the file stays, so `gone` is distinguishable from `never`"
	);
	assert!(read_delegations(&dir)[0].prefixes.is_empty());

	let _ = fs::remove_dir_all(&dir);
}

/// A renewal that changes the prefix must replace, not append -- otherwise the
/// old prefix keeps deriving an address nobody can reach.
#[test]
fn a_renewal_replaces_rather_than_appends() {
	let dir = scratch("renew");
	run_hook(
		&dir,
		"wan0",
		&[("PREFIXES", "2001:db8:1111::/56,3600,7200")],
	);
	run_hook(
		&dir,
		"wan0",
		&[("PREFIXES", "2001:db8:2222::/56,3600,7200")],
	);

	assert_eq!(read_delegations(&dir)[0].prefixes, ["2001:db8:2222::/56"]);

	let _ = fs::remove_dir_all(&dir);
}

/// A machine that is not a router has no such directory, which is not an
/// error -- constraint 2 says the filesystem reflects use.
#[test]
fn no_directory_means_no_delegations() {
	let dir = std::env::temp_dir().join(format!("ncfg-pd-absent-{}", std::process::id()));
	let _ = fs::remove_dir_all(&dir);
	assert!(read_delegations(&dir).is_empty());
}

/// Comments and blanks are ignored, so an operator can annotate a file they
/// have pinned by hand while debugging.
#[test]
fn comments_and_blanks_are_ignored() {
	let dir = scratch("comments");
	fs::write(
		dir.join("prefixes/wan0"),
		"# pinned by hand while the ISP is broken\n\n2001:db8::/56\n\n",
	)
	.expect("write");

	assert_eq!(read_delegations(&dir)[0].prefixes, ["2001:db8::/56"]);

	let _ = fs::remove_dir_all(&dir);
}
