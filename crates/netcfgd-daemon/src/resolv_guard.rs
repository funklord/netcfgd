//! Removing what keeps taking `/etc/resolv.conf` back.
//!
//! [0165](../../../doc/decision/0165-the-file-netcfgd-owns-is-defended.md)
//! made netcfgd notice a foreign write and put its own file back, which is
//! enough to win every round. What it does not do is stop the rounds: a writer
//! that rewrites the file every few seconds leaves the machine's resolver
//! flapping between two answers, and a name looked up in the wrong second gets
//! the wrong server.
//!
//! **This is the last resort and it is deliberately hard to reach.** It fires
//! only where netcfgd was told to own the file outright, and only after the
//! file has been taken away and put back several times in a row -- so a single
//! write during boot, which is ordinary, never reaches it.
//!
//! **It cannot tell who wrote the file, and the consequence is blunt.** There
//! is no way to ask the kernel which process last wrote a path -- `fanotify`
//! could report it and needs `CAP_SYS_ADMIN`, which netcfgd does not take.
//! So what this actually does is signal **every** known resolver-writing
//! program netcfgd did not start, not the one that is interfering. An idle
//! `dhclient` that has written nothing is terminated alongside the one that
//! will not stop.
//!
//! That is defensible and it is not what the instruction sounds like, so it is
//! written here rather than discovered: on a machine where netcfgd has been
//! told to own `resolv.conf`, a foreign DHCP client that is running *will*
//! write that file when its lease renews, so the distinction between "is
//! interfering" and "is going to" is thinner than it looks. It is still a
//! bystander at the moment it is killed, and `tests/live/resolv_defended.sh`
//! asserts that this is what happens rather than letting it be a surprise.
//!
//! **A supervised process is reported and not signalled.** Killing
//! `systemd-resolved` buys seconds: its unit carries `Restart=`, so the
//! supervisor puts it straight back and netcfgd would be fighting something
//! that cannot lose. The answer there is `Conflicts=` in
//! `packaging/systemd/netcfgd-exclusive.conf`, and saying so is worth more
//! than a signal that achieves nothing.

use std::collections::BTreeSet;
use std::path::Path;

/// How many reclaims in a row before netcfgd stops merely rewriting.
///
/// Three rather than one, because one is ordinary. A DHCP client that took a
/// lease, a hook that ran, an operator with an editor -- each writes the file
/// once, netcfgd puts its own back, and nothing else should happen. Something
/// that has done it three times running is not passing through.
pub(crate) const PATIENCE: u32 = 3;

/// Programs known to write `/etc/resolv.conf`.
///
/// **`/proc/<pid>/comm` is truncated to 15 characters**, which is why
/// `systemd-resolved` is spelled `systemd-resolve` here. A name one character
/// too long never matches, and the sweep would report nothing while looking
/// like it had looked -- the vacuous pass in its most literal form.
///
/// `dhcpcd` is on the list and netcfgd starts its own, which is exactly why
/// the pids netcfgd recorded starting are excluded before anything is
/// signalled. Killing its own DHCP client to defend a file that client's lease
/// filled in would be the worst outcome available.
const WRITERS: &[&str] = &[
	"NetworkManager",
	"systemd-resolve",
	"connmand",
	"dhclient",
	"dhcpcd",
	"resolvconf",
];

/// Every pid netcfgd recorded starting, so none of them is a target.
///
/// The backends write `<run>/<kind>/<iface>.pid`, one directory down. A file
/// that cannot be read or does not hold a number is skipped rather than
/// guessed at: the cost of missing one is signalling something netcfgd owns,
/// so the reading is deliberately strict.
fn ours(run_dir: &Path) -> BTreeSet<i32> {
	let mut pids = BTreeSet::new();
	// Own pid first: netcfgd is not called any of the names above, but a
	// future rename should not be able to make it kill itself.
	if let Ok(mine) = i32::try_from(std::process::id()) {
		pids.insert(mine);
	}
	let Ok(kinds) = std::fs::read_dir(run_dir) else {
		return pids;
	};
	for kind in kinds.flatten() {
		let Ok(entries) = std::fs::read_dir(kind.path()) else {
			continue;
		};
		for entry in entries.flatten() {
			if entry.path().extension().is_none_or(|ext| ext != "pid") {
				continue;
			}
			if let Ok(text) = std::fs::read_to_string(entry.path()) {
				if let Ok(pid) = text.trim().parse::<i32>() {
					pids.insert(pid);
				}
			}
		}
	}
	pids
}

/// Signal whatever is taking the file back, and say what was left alone.
///
/// Returns how many processes were signalled, so the caller can say whether
/// the sweep did anything rather than inferring it.
pub(crate) fn sweep(run_dir: &Path) -> usize {
	let mine = ours(run_dir);
	let mut signalled = 0;

	for (pid, program) in netcfgd_sys::process::pids_of_programs(WRITERS) {
		if mine.contains(&pid) {
			// Not a diagnostic anybody needs on every pass: netcfgd's own
			// dhcpcd is on the list by construction and is not interference.
			continue;
		}
		if netcfgd_sys::process::is_service_supervised(pid) {
			eprintln!(
				"netcfgd: {program} (pid {pid}) keeps rewriting resolv.conf and is run by a service manager, so netcfgd is not signalling it"
			);
			eprintln!(
				"netcfgd:   a killed service is restarted; stand it down with Conflicts= -- see packaging/systemd/netcfgd-exclusive.conf"
			);
			continue;
		}
		match netcfgd_sys::process::terminate(pid) {
			Ok(()) => {
				eprintln!(
					"netcfgd: terminated {program} (pid {pid}): it took /etc/resolv.conf back {PATIENCE} times running and netcfgd owns that file"
				);
				signalled += 1;
			}
			Err(error) => {
				eprintln!("netcfgd: could not terminate {program} (pid {pid}): {error}");
			}
		}
	}

	if signalled == 0 {
		eprintln!(
			"netcfgd: resolv.conf has been taken back {PATIENCE} times and netcfgd found nothing it could signal"
		);
	}
	signalled
}
