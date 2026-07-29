//! A config file is input a privileged daemon reads at boot and on every
//! reload. It is less hostile than netlink -- it is usually written by the
//! operator -- but "usually" is not a security argument, and a drop-in
//! directory is writable by anything that can write to /etc.

#![no_main]

use libfuzzer_sys::fuzz_target;
use netcfgd_compile::{compile, NoHooks, SourceMap};

fuzz_target!(|data: &[u8]| {
	let Ok(text) = std::str::from_utf8(data) else {
		return;
	};
	let mut sources = SourceMap::new();
	sources.add("fuzz.conf", text);
	// Any outcome is acceptable except a panic or a hang. A document that
	// compiles is then canonicalised, because that path is only reachable
	// through a successful compile and would otherwise never be fuzzed.
	if let Ok(document) = compile(&sources, &mut NoHooks) {
		let _ = document.to_json_canonical();
	}
});
