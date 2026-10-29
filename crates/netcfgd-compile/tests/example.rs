//! `netcfgd.conf.example` is inert where it is installed.
//!
//! **This file used to compile every example in it, and the C does that now.**
//! The example documents the language the shipped program speaks, and since
//! 0266 that is the C: it carries `firewall`, `fast_roaming`, `mesh` and
//! `host_list`, which this compiler never learned, so compiling the file here
//! failed on documentation that is correct. The checks moved rather than went:
//! `c/tests/lower_test.c` compiles every example block with named exceptions
//! and writes each back, its mutations included, and `tool/example_gate.py`
//! runs `ncfg plan` on each against the C -- the gate made that move in
//! `f6e87d00` for the same reason. What is left here is the one property that
//! is not about which compiler reads the file.

/// The installed example must not be a file the loader reads.
///
/// The whole safety of shipping a configuration file full of examples is that
/// netcfgd never loads it: `netcfgd-host`'s loader takes `netcfgd.conf` by
/// exact name and `conf.d/*.conf` by extension. `netcfgd.conf.example` is
/// neither. If that ever changed, a default install would apply every example
/// in this file at once, so the property is asserted rather than assumed.
#[test]
fn installed_name_is_not_one_the_loader_reads() {
	let name = "netcfgd.conf.example";
	assert_ne!(name, "netcfgd.conf");
	assert!(
		!std::path::Path::new(name)
			.extension()
			.is_some_and(|ext| ext.eq_ignore_ascii_case("conf")),
		"the loader takes conf.d/*.conf by extension, and this would match"
	);
}
