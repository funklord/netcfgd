//! Finding out whether something else is already managing an interface.
//!
//! Two network daemons on one interface is the failure this whole project is
//! arranged against, and until now netcfgd would simply have joined the fight:
//! it would apply its config, `NetworkManager` would apply its own a second
//! later, and the operator would watch an address appear and disappear with
//! neither tool saying why.
//!
//! Detection is by the files these daemons leave in `/run`, not by D-Bus:
//! D-Bus is the dependency decision 0014 declined to take, and the files are
//! the only per-interface evidence available -- which is the part that matters,
//! since netcfgd and `NetworkManager` can share a machine perfectly well as
//! long as they do not share a device.
//!
//! **A process name is consulted as well, and only for liveness.** This file
//! used to rule that out too, on the grounds that a process name tells you
//! something is running without telling you which interfaces it has opinions
//! about. That is true, and it argues against using process names *instead of*
//! the files rather than against using both. Reading it as though it forbade
//! both is what left decision 0145's failure unexamined: `NetworkManager` has
//! no `RuntimeDirectory=` and no `ExecStop=`, so its device files outlive it
//! with `managed=true` still in them, and netcfgd declined a radio on behalf of
//! a daemon systemd had already stopped -- leaving a machine with no network
//! manager at all.
//!
//! So: **the file says which interfaces, and a live process says the claim is
//! current.** Neither is sufficient alone.
//!
//! netcfgd never acts on what it finds here. It reports, and the operator
//! decides -- the same posture as a guard or a drift report.

use std::fs;
use std::path::{Path, PathBuf};

/// Another daemon that claims interfaces netcfgd also claims.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Contender {
	/// What to call it, as the operator would.
	pub name: &'static str,
	/// The interfaces of netcfgd's that it also manages, sorted.
	pub interfaces: Vec<String>,
	/// How to hand a device over, with `{}` where its name goes.
	remedy: &'static str,
}

/// Where the evidence lives, overridable so this is testable without
/// installing `NetworkManager`.
fn run_root() -> PathBuf {
	std::env::var_os("NCFG_RUN_ROOT").map_or_else(|| PathBuf::from("/run"), PathBuf::from)
}

/// Where to look for running processes. `NCFG_PROC` is for the tests, which
/// otherwise could only assert against whatever this machine happens to run --
/// and this machine runs `NetworkManager`, so every liveness test would have
/// passed for the wrong reason.
fn proc_root() -> PathBuf {
	std::env::var_os("NCFG_PROC").map_or_else(|| PathBuf::from("/proc"), PathBuf::from)
}

/// Whether a daemon with one of these `comm` names is running.
///
/// `comm` rather than the executable link because `/proc/<pid>/comm` is
/// world-readable and `/proc/<pid>/exe` is not: netcfgd runs as root, but a
/// check that silently degrades when it does not is a check that lies. It is
/// truncated to 15 characters by the kernel, which is why `systemd-networkd`
/// is listed under its truncation as well as its full name.
fn daemon_is_running(names: &[&str]) -> bool {
	let Ok(entries) = fs::read_dir(proc_root()) else {
		// Unreadable /proc: fall back to believing the files, which is the
		// direction that keeps the guard rather than the one that starts a
		// second supplicant on somebody else's radio.
		return true;
	};
	for entry in entries.flatten() {
		if !entry
			.file_name()
			.to_str()
			.is_some_and(|name| name.bytes().all(|b| b.is_ascii_digit()))
		{
			continue;
		}
		if let Ok(comm) = fs::read_to_string(entry.path().join("comm")) {
			if names.contains(&comm.trim()) {
				return true;
			}
		}
	}
	false
}

/// Whether the daemon state under `/run` describes interfaces netcfgd can see.
///
/// Every daemon here keys its state by kernel index, and **an index means
/// nothing outside the network namespace that issued it**. `/run` is a mount
/// rather than a namespace, so a netcfgd in a private network namespace that
/// can still see the host's `/run` reads the host's files and matches them
/// against its own indices. Those collide immediately, because both numberings
/// start at 1.
///
/// **Measured, and it is why this function exists.** `tests/live/hwsim.sh`
/// puts two simulated radios in a private namespace, where the station is
/// index 3. On the host, index 3 was the operator's real `wlp0s20f3` with
/// `managed=true`, so netcfgd refused to start a supplicant on a radio
/// `NetworkManager` could not see and had never heard of -- naming
/// `NetworkManager` in a refusal that was entirely fictional. The guard that
/// exists to stop two daemons fighting over one radio was the only thing
/// preventing the association it was protecting.
///
/// There is nothing in the file to cross-check against: `NetworkManager`'s
/// device file records neither the interface name nor a permanent MAC. What
/// can be checked is whether we are in the namespace those files were written
/// from. Pid 1 is the machine's init, host daemons write `/run` from its
/// network namespace, and if ours is not that one then their indices are not
/// about our interfaces.
///
/// Unreadable is treated as ours, deliberately. Only a privileged process can
/// read another's namespace link, and being wrong in that direction costs a
/// refusal the operator can override, while being wrong in the other lets
/// netcfgd start a second supplicant on a radio somebody else is holding --
/// which is the failure this whole module exists to prevent.
fn run_root_is_ours() -> bool {
	// An explicit root is a tree somebody pointed at this netcfgd on purpose:
	// a test fixture or a container with its own state. The question of whose
	// namespace wrote it does not arise.
	if std::env::var_os("NCFG_RUN_ROOT").is_some() {
		return true;
	}
	match (
		fs::read_link("/proc/self/ns/net"),
		fs::read_link("/proc/1/ns/net"),
	) {
		(Ok(ours), Ok(init)) => ours == init,
		_ => true,
	}
}

/// Which other daemons claim any of `interfaces`.
///
/// `interfaces` is `(name, kernel index)`, because every daemon here keys its
/// state by index rather than by name -- an interface can be renamed and the
/// index cannot.
#[must_use]
pub fn contenders(interfaces: &[(String, u32)]) -> Vec<Contender> {
	if !run_root_is_ours() {
		return Vec::new();
	}
	let root = run_root();
	let mut found = Vec::new();

	let claimed = network_manager_claims(&root, interfaces);
	if !claimed.is_empty() {
		found.push(Contender {
			name: "NetworkManager",
			interfaces: claimed,
			remedy: "nmcli device set {} managed no",
		});
	}

	let claimed = networkd_claims(&root, interfaces);
	if !claimed.is_empty() {
		found.push(Contender {
			name: "systemd-networkd",
			interfaces: claimed,
			remedy: "remove the .network file matching {}, or set Unmanaged=yes for it",
		});
	}

	found
}

/// `NetworkManager` writes `/run/NetworkManager/devices/<ifindex>`.
///
/// The file exists for every device NM knows about, so its presence proves
/// nothing -- an unmanaged device has one too. `managed=true` is the claim,
/// and checking for the file alone would report a contest with a daemon that
/// has already stepped aside.
fn network_manager_claims(root: &Path, interfaces: &[(String, u32)]) -> Vec<String> {
	if !daemon_is_running(&["NetworkManager"]) {
		return Vec::new();
	}
	let devices = root.join("NetworkManager/devices");
	let mut claimed: Vec<String> = interfaces
		.iter()
		.filter(|(_, index)| {
			fs::read_to_string(devices.join(index.to_string()))
				.is_ok_and(|body| body.lines().any(|line| line.trim() == "managed=true"))
		})
		.map(|(name, _)| name.clone())
		.collect();
	claimed.sort();
	claimed
}

/// `systemd-networkd` writes `/run/systemd/netif/links/<ifindex>`.
///
/// `ADMIN_STATE=configured` is the equivalent claim: `networkd` writes a file
/// for every link it can see, and one it was given no `.network` for reports
/// `unmanaged`.
///
/// **Checked against a running `networkd`** -- systemd 257, two dummy links,
/// one with a `.network` and one without. `tests/networkd/` holds the files it
/// wrote. It took a privileged container to do it: networkd drops privileges
/// to `systemd-network`, which cannot map inside a user namespace, and that is
/// why this went unverified for as long as it did.
///
/// It found a third state the documentation above did not mention. `pending`
/// is a link networkd has seen and not yet decided about, and it persisted for
/// the whole run rather than flickering past. It is deliberately not a claim:
/// networkd has configured nothing on such a link, and warning about a contest
/// there is the false alarm that gets a warning ignored.
///
/// Every one of these files opens with `# This is private data. Do not parse.`
/// This parses them anyway, which is a decision and not an oversight -- the
/// supported ways to ask are `networkctl` and networkd's D-Bus API, and
/// constraint 3 keeps a message bus off the core's mandatory path. The cost is
/// that a systemd release can move the format; the mitigation is that this
/// feeds a *warning*, so what breaks is a diagnostic and not a network.
fn networkd_claims(root: &Path, interfaces: &[(String, u32)]) -> Vec<String> {
	if !daemon_is_running(&["systemd-network", "systemd-networkd"]) {
		return Vec::new();
	}
	let links = root.join("systemd/netif/links");
	let mut claimed: Vec<String> = interfaces
		.iter()
		.filter(|(_, index)| {
			fs::read_to_string(links.join(index.to_string())).is_ok_and(|body| {
				body.lines()
					.any(|line| line.trim() == "ADMIN_STATE=configured")
			})
		})
		.map(|(name, _)| name.clone())
		.collect();
	claimed.sort();
	claimed
}

impl Contender {
	/// The command that hands one device over, with the name filled in.
	///
	/// Filled in rather than left as a placeholder: an operator who has to
	/// work out what `DEV` stands for is an operator who might use the wrong
	/// name, and the whole point of the message is that they act on it.
	#[must_use]
	pub fn remedy_for(&self, interface: &str) -> String {
		self.remedy.replace("{}", interface)
	}
}

/// One message per contender, for a plan warning or a startup line.
#[must_use]
pub fn describe(contender: &Contender) -> String {
	let commands: Vec<String> = contender
		.interfaces
		.iter()
		.map(|interface| contender.remedy_for(interface))
		.collect();
	format!(
		"{} also manages {}. Two daemons on one interface will fight, and \
		 whichever applied last wins until the other notices -- so this will \
		 look like the config working intermittently.\n\n\
		 Hand over just this device with `{}`, or set `managed = false` on \
		 the device here.\n\n\
		 To make netcfgd the only network daemon on the machine instead:\n\n    \
		 mkdir -p /etc/systemd/system/netcfgd.service.d\n    \
		 cp /usr/share/doc/netcfgd/netcfgd-exclusive.conf \\\n        \
		 /etc/systemd/system/netcfgd.service.d/\n    \
		 systemctl daemon-reload && systemctl restart netcfgd\n\n\
		 That drop-in conflicts with NetworkManager, systemd-networkd, connman, \
		 wpa_supplicant and ModemManager, so the init system stops them rather \
		 than netcfgd killing anything itself.",
		contender.name,
		contender.interfaces.join(", "),
		commands.join("` and `")
	)
}
