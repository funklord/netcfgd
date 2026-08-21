//! Which interfaces are radios, asked of the kernel.
//!
//! **One fact, in one place.** `/sys/class/net/<name>/wireless` exists for a
//! wireless interface and for nothing else. Three parts of netcfgd need to
//! know: the observer fills in `ObservedLink::wireless`, the executor picks
//! `nl80211` over `wired` when it starts a supplicant, and `ncfg wifi add`
//! decides which radio to write configuration for on a machine with no daemon
//! running. Each had -- or would have grown -- its own copy of the same
//! `Path::exists`, which is how three copies of a fact end up disagreeing
//! about one interface.
//!
//! Cheaper and more reliable than asking `nl80211`, and it needs no privilege,
//! which is what lets `ncfg wifi add` use it on the machine it is for: one
//! with no network and nothing else running.
//!
//! **`kind` cannot answer this.** A real wireless device is a plain device and
//! reports an empty link kind, exactly as an ethernet port does.

use std::path::PathBuf;

/// Where the kernel publishes per-interface attributes.
const CLASS_NET: &str = "/sys/class/net";

/// The directory to ask, which is the kernel's unless a test says otherwise.
///
/// `NCFG_SYS_CLASS_NET` exists for the same reason `NCFG_WPA_CTRL_DIR` does,
/// and it was added the moment it was needed: a test of `ncfg wifi add` began
/// reading the *host's* hardware, so it passed on a build machine with no
/// radio and did something else on a laptop. A test whose result depends on
/// what the developer's machine happens to contain is not a test.
#[must_use]
pub fn class_net() -> PathBuf {
	std::env::var_os("NCFG_SYS_CLASS_NET").map_or_else(|| PathBuf::from(CLASS_NET), PathBuf::from)
}

/// Whether `name` under `root` is a radio.
///
/// The root is a parameter rather than read from the environment inside here,
/// because two tests setting the same environment variable while running in
/// parallel is a race, and a predicate whose answer depends on hidden global
/// state is one nobody can test twice. [`class_net`] supplies the default.
///
/// False for an interface that does not exist, which is the same answer as
/// "not a radio" for every caller here: none of them can do anything with a
/// name the kernel does not know.
#[must_use]
pub fn is_wireless(root: &std::path::Path, name: &str) -> bool {
	// Rejected rather than joined. A name with a separator in it would escape
	// `/sys/class/net` and ask about some other directory entirely -- and this
	// takes names from a configuration file, which is exactly where one could
	// come from.
	if name.is_empty() || name.contains('/') || name.contains("..") {
		return false;
	}
	root.join(name).join("wireless").exists()
}

/// Every radio the kernel reports, in the order it lists them.
///
/// Empty where `/sys` is not mounted, which is a container rather than a
/// machine with no radio -- the two are indistinguishable from here and the
/// callers treat them the same, because neither has a radio to configure.
#[must_use]
pub fn wireless_links(root: &std::path::Path) -> Vec<String> {
	let Ok(entries) = std::fs::read_dir(root) else {
		return Vec::new();
	};
	let mut found: Vec<String> = entries
		.filter_map(Result::ok)
		.filter_map(|entry| entry.file_name().into_string().ok())
		.filter(|name| is_wireless(root, name))
		.collect();
	// Sorted, so that a message listing them reads the same twice running.
	// `read_dir` order is the filesystem's and is not stable.
	found.sort();
	found
}

#[cfg(test)]
mod tests {
	/// A name that would leave `/sys/class/net` is refused rather than joined.
	///
	/// These come from configuration files, and `..` in one would ask about a
	/// directory that has nothing to do with interfaces. The answer would
	/// usually be false anyway, which is what makes it worth refusing
	/// explicitly: a check that is accidentally right is one that stops being
	/// right when the filesystem changes.
	#[test]
	fn a_name_that_is_a_path_is_not_a_radio() {
		let root = super::class_net();
		assert!(!super::is_wireless(&root, "../../dev/null"));
		assert!(!super::is_wireless(&root, "wlan0/../eth0"));
		assert!(!super::is_wireless(&root, ""));
	}

	/// `lo` exists on every machine and is never a radio, which makes it the
	/// one negative case that can be asserted anywhere.
	#[test]
	fn loopback_is_not_a_radio() {
		assert!(!super::is_wireless(&super::class_net(), "lo"));
	}

	/// Whatever it finds, it finds consistently.
	///
	/// The list cannot be asserted -- a build machine may have no radio and a
	/// laptop has one -- so what is checked is that every name it returns
	/// answers true to the predicate, which is the invariant a caller relies
	/// on when it uses the list to pick an interface.
	#[test]
	fn every_name_it_lists_is_one_it_calls_a_radio() {
		let root = super::class_net();
		for name in super::wireless_links(&root) {
			assert!(
				super::is_wireless(&root, &name),
				"{name} was listed and is not a radio"
			);
		}
	}

	/// A fixture directory answers instead of the machine.
	///
	/// The property the parameter exists for: with a root of its own this
	/// gives the same answer on a laptop and on a build machine, which is what
	/// lets `ncfg wifi add` be tested at all.
	#[test]
	fn a_fixture_root_is_asked_instead_of_the_machine() {
		let dir = netcfgd_testdir::TestDir::new("radio-root");
		std::fs::create_dir_all(dir.join("wlan9/wireless")).expect("a fake radio");
		std::fs::create_dir_all(dir.join("eth9")).expect("a fake wired port");

		let root = dir.path();
		assert!(super::is_wireless(root, "wlan9"));
		assert!(!super::is_wireless(root, "eth9"));
		assert_eq!(super::wireless_links(root), vec!["wlan9".to_owned()]);
	}
}
