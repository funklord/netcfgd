#![forbid(unsafe_code)]

//! One binary, two programs, chosen by the name it was invoked as.
//!
//! `netcfgd` and `ncfg` share the model, the compiler, the planner, the
//! executor and the netlink layer -- which is nearly everything either of them
//! is. Built as two binaries they each carried a private copy: measured at
//! 775 KB duplicated between them, against a 2.89 MB install. That is a
//! quarter of the whole thing, spent on shipping identical machine code twice,
//! on the class of device design section 10 targets and which has single-digit
//! megabytes of flash free.
//!
//! So they are one file with two names, the way busybox and `util-linux` do
//! it. The binary is `netcfgd`; `ncfg` is a symlink to it. Nothing else
//! changes: both keep their own argument parsing, their own usage text and
//! their own exit codes, because they are still two programs.

use std::process::ExitCode;

fn main() -> ExitCode {
	// `argv[0]`, reduced to its filename. A symlink invoked through `PATH`
	// arrives as `ncfg`, one invoked by absolute path as `/usr/bin/ncfg`, and
	// one run from a build directory as `./target/debug/ncfg`.
	let called_as = std::env::args_os()
		.next()
		.map(std::path::PathBuf::from)
		.and_then(|path| {
			path.file_name()
				.map(|name| name.to_string_lossy().into_owned())
		})
		.unwrap_or_default();

	match called_as.as_str() {
		"ncfg" => netcfgd_cli::main(),
		"netcfgd" => netcfgd_daemon::main(),
		// Neither name. This is a build tree or a rename, not an install, so
		// it says what the two names are rather than guessing at one -- a
		// wrong guess would start a daemon for somebody who wanted a client.
		other => {
			eprintln!(
				"this binary is both `netcfgd` and `ncfg`, and picks by the name it is \
				 called as; it was called as `{other}`"
			);
			eprintln!("install it as `netcfgd` and symlink `ncfg` to it");
			ExitCode::from(2)
		}
	}
}
