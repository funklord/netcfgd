//! Finding out whether something else is already managing an interface.
//!
//! Two network daemons on one interface is the failure this whole project is
//! arranged against, and until now netcfgd would simply have joined the fight:
//! it would apply its config, `NetworkManager` would apply its own a second
//! later, and the operator would watch an address appear and disappear with
//! neither tool saying why.
//!
//! Detection is by the files these daemons leave in `/run`, not by D-Bus and
//! not by scanning process names. Both alternatives are worse: D-Bus is the
//! dependency decision 0014 declined to take, and a process name tells you
//! something is running without telling you which interfaces it has opinions
//! about -- which is the only part that matters, since netcfgd and
//! `NetworkManager` can share a machine perfectly well as long as they do not
//! share a device.
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

/// Which other daemons claim any of `interfaces`.
///
/// `interfaces` is `(name, kernel index)`, because every daemon here keys its
/// state by index rather than by name -- an interface can be renamed and the
/// index cannot.
#[must_use]
pub fn contenders(interfaces: &[(String, u32)]) -> Vec<Contender> {
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
		 look like the config working intermittently. Hand it over with `{}`, \
		 or set `managed = false` on the device here.",
		contender.name,
		contender.interfaces.join(", "),
		commands.join("` and `")
	)
}
