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
///
/// **Two attributes, and the obvious one is the wrong one (0231).** This asked
/// only for `wireless`, which is the Wireless Extensions attribute -- and on a
/// cfg80211 radio that attribute exists only when the kernel was built with
/// `CONFIG_CFG80211_WEXT`. It is a config option, on by default in the big
/// distributions and routinely off in the small ones, which is exactly the kind
/// of kernel netcfgd is aimed at on a board.
///
/// On such a kernel a working radio answered "not a radio", and everything
/// downstream followed: `start_supplicant` chose `-Dwired` for it, `radios_of`
/// left it out of the plan, `ObservedLink::wireless` said false, and
/// `ncfg wifi` refused to talk about it. No message anywhere named a cause,
/// because from netcfgd's side there was no radio to have a problem with.
///
/// `phy80211` is the one to ask. cfg80211 creates it for every device it
/// registers, with no config option in front of it. Read from the machine this
/// was written on:
///
/// ```text
/// /sys/class/net/wlp0s20f3/wireless   present
/// /sys/class/net/wlp0s20f3/phy80211   present
/// $ grep CFG80211_WEXT /boot/config-$(uname -r)
/// CONFIG_CFG80211_WEXT=y
/// ```
///
/// Both are present here *because* that option is on; the fixture that tested
/// this made a `wireless` directory and so could only ever have agreed.
///
/// **`wireless` is still asked, second**, and it is not dead weight: a driver
/// old enough to have no cfg80211 device at all has that attribute and nothing
/// else. That is also why `start_supplicant` passes `-Dnl80211,wext` rather
/// than `-Dnl80211` -- the fallback in the driver list and the second test here
/// are the same case, and they should agree about whether it exists.
#[must_use]
pub fn is_wireless(root: &std::path::Path, name: &str) -> bool {
	// Rejected rather than joined. A name with a separator in it would escape
	// `/sys/class/net` and ask about some other directory entirely -- and this
	// takes names from a configuration file, which is exactly where one could
	// come from.
	if name.is_empty() || name.contains('/') || name.contains("..") {
		return false;
	}
	let interface = root.join(name);
	interface.join("phy80211").exists() || interface.join("wireless").exists()
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

	/// A radio on a kernel built without the Wireless Extensions layer.
	///
	/// **The case the old fixture could not produce.** It made a `wireless`
	/// directory, which is what `CONFIG_CFG80211_WEXT` provides -- so it agreed
	/// with a test that asked for exactly that, and a kernel without the option
	/// was outside what it could describe. cfg80211 creates `phy80211`
	/// unconditionally, and that is the one to ask. 0231.
	#[test]
	fn a_radio_is_one_whether_or_not_the_kernel_has_wireless_extensions() {
		let dir = netcfgd_testdir::TestDir::new("radio-phy");
		let root = dir.path();

		// A modern kernel with the compatibility layer off: cfg80211's own
		// attribute and nothing else.
		std::fs::create_dir_all(dir.join("wlan0/phy80211")).expect("a radio");
		assert!(
			super::is_wireless(root, "wlan0"),
			"a radio with no wext attribute is still a radio"
		);

		// The same kernel with the option on, which is what the reporting
		// machine has: both attributes.
		std::fs::create_dir_all(dir.join("wlan1/phy80211")).expect("a radio");
		std::fs::create_dir_all(dir.join("wlan1/wireless")).expect("and wext");
		assert!(super::is_wireless(root, "wlan1"));

		// A driver too old to have a cfg80211 device at all. This is the case
		// `-Dnl80211,wext` exists for, and the two have to agree that it is a
		// radio.
		std::fs::create_dir_all(dir.join("wlan2/wireless")).expect("wext only");
		assert!(super::is_wireless(root, "wlan2"));

		// And a wired port, which has neither.
		std::fs::create_dir_all(dir.join("eth0")).expect("a wired port");
		assert!(!super::is_wireless(root, "eth0"));

		let mut found = super::wireless_links(root);
		found.sort();
		assert_eq!(found, vec!["wlan0", "wlan1", "wlan2"]);
	}
}
