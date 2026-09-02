//! Print what a live observation makes of each link's wifi association.
//!
//! **Read-only, and deliberately the daemon's own path rather than a shortcut
//! to the interesting function.** It loads the prior state and the document
//! netcfgd is actually running, then calls `netcfgd_observe::current` -- the
//! same call `reobserve` makes. A probe that called
//! `netcfgd_supplicant::associated` directly would prove the function and say
//! nothing about whether the observation is wired to it, which is the half
//! that has actually been wrong before.
//!
//! It writes nothing: `current` reads netlink, sysfs and the supplicant's
//! control socket, and the caller is what persists an observation. Running it
//! beside a live daemon adds one reader and no writer.
//!
//! Needs root, because the supplicant's control socket is `root:root` with no
//! write bit for anybody else -- and without being able to connect, the
//! association read reports "not associated" for a radio that is. That failure
//! is silent, which is why this refuses rather than reporting it as a result.
//!
//!     cargo build -p netcfgd-host --example live_association
//!     sudo ./target/debug/examples/live_association
//!
//! One line per link, tab separated: name, whether it is a radio, and the
//! configured network it is associated to (`-` for none).

use std::path::{Path, PathBuf};

fn main() {
	let run_dir: PathBuf = std::env::args()
		.nth(1)
		.map_or_else(|| PathBuf::from("/run/netcfgd"), PathBuf::from);

	// The supplicant's socket refuses a connection from anybody but root, and
	// a refused connection is indistinguishable from an unassociated radio in
	// the result. Refusing up front is the difference between "no association"
	// and "this probe could not have seen one".
	if !is_root() {
		eprintln!("live_association: needs root: the supplicant control socket is root-only,");
		eprintln!("live_association:   and without it every radio reads as unassociated");
		std::process::exit(2);
	}

	let document = match read_document(&run_dir) {
		Ok(document) => document,
		Err(message) => {
			eprintln!("live_association: {message}");
			std::process::exit(2);
		}
	};

	let prior = netcfgd_host::state::prior_state(&run_dir);
	// Worth saying out loud: `ask_supplicants` only asks a supplicant netcfgd
	// believes it started, and that belief lives in the prior state. Loading an
	// empty one would make every radio read as unassociated for a reason that
	// has nothing to do with the code under test.
	eprintln!(
		"live_association: {} backend(s) in the prior state under {}",
		prior.backends.len(),
		run_dir.display()
	);

	let observed = match netcfgd_observe::current(&prior, &run_dir, Some(&document)) {
		Ok(observed) => observed,
		Err(error) => {
			eprintln!("live_association: cannot observe: {error}");
			std::process::exit(2);
		}
	};

	for link in &observed.links {
		println!(
			"{}\t{}\t{}",
			link.name,
			if link.wireless { "radio" } else { "wired" },
			link.network.as_deref().unwrap_or("-")
		);
	}
}

/// The document netcfgd compiled, as it wrote it out.
///
/// Read from `/run` rather than recompiled from `/etc`, so this sees what the
/// running daemon is actually working from -- a tree edited since the last
/// apply would otherwise give this probe a different document from the one the
/// association is being resolved against.
fn read_document(run_dir: &Path) -> Result<netcfgd_model::Document, String> {
	let path = run_dir.join("desired.json");
	let text = std::fs::read_to_string(&path)
		.map_err(|error| format!("cannot read {}: {error}", path.display()))?;
	serde_json::from_str(&text).map_err(|error| format!("cannot parse {}: {error}", path.display()))
}

/// Whether this process is root, without pulling in libc for one call.
///
/// `/proc/self/status` names the effective uid on its `Uid:` line, second
/// field. A kernel that does not offer it is not one netcfgd runs on.
fn is_root() -> bool {
	std::fs::read_to_string("/proc/self/status").is_ok_and(|status| {
		status
			.lines()
			.find_map(|line| line.strip_prefix("Uid:"))
			.and_then(|line| line.split_whitespace().nth(1))
			.is_some_and(|euid| euid == "0")
	})
}
