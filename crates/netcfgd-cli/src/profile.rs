//! `ncfg profile` -- which configuration profile the machine is running.
//!
//! [0151]: a profile is a directory of drop-ins layered on `conf.d`, and it is
//! switched by hand. This is the hand.
//!
//! **Setting one is an ordinary configuration write**, not a mode the daemon
//! remembers: it puts `global { profile = "<name>" }` in a drop-in, through
//! the daemon like every other write since 0127. So the state is in the
//! configuration where it can be read, diffed and committed, `ncfg plan` shows
//! what changing it would do before it does it, and there is nothing for a
//! reboot to forget.
//!
//! [0151]: ../../../doc/decision/0151-a-profile-is-a-directory-and-it-is-switched-by-hand.md

use crate::Options;
use std::process::ExitCode;

// The drop-in this command owns, named where the loader's guard reads it so
// that the writer and the reader cannot drift apart.
use netcfgd_host::config::PROFILE_DROP_IN as DROP_IN;

pub(crate) fn run(positional: &[String], options: &Options) -> Result<ExitCode, String> {
	let Some(subcommand) = positional.first() else {
		return Err("`ncfg profile` takes `get`, `set`, `unset` or `list`".to_owned());
	};
	match subcommand.as_str() {
		"get" => get(options),
		"list" => Ok(list(options)),
		"set" => set(&positional[1..], options),
		"unset" => unset(options),
		other => Err(format!(
			"unknown profile subcommand `{other}`; it is `get`, `set`, `unset` or `list`"
		)),
	}
}

/// The profiles this machine has, from both layers.
///
/// Shipped ones and the operator's, and which is which: an operator editing
/// what looks like their own file and finding it replaced on upgrade is the
/// confusion this column exists to prevent.
fn profile_dirs(options: &Options) -> Vec<(String, bool)> {
	let config = netcfgd_host::config::resolve_dir(options.config_dir.as_deref());
	let factory = netcfgd_host::config::resolve_factory_dir(options.factory_dir.as_deref());

	let mut found: Vec<(String, bool)> = Vec::new();
	// The operator's first, so a name in both is reported as theirs -- which
	// is what it effectively is, since their files layer on top.
	for (root, mine) in [(config, true), (factory, false)] {
		let Ok(entries) = std::fs::read_dir(root.join("profile")) else {
			continue;
		};
		for entry in entries.flatten() {
			if !entry.path().is_dir() {
				continue;
			}
			let name = entry.file_name().to_string_lossy().into_owned();
			if !found.iter().any(|(seen, _)| seen == &name) {
				found.push((name, mine));
			}
		}
	}
	found.sort_by(|a, b| a.0.cmp(&b.0));
	found
}

fn active(options: &Options) -> Result<Option<String>, String> {
	let (document, _) = crate::compile(options)?;
	Ok(document.globals.profile)
}

fn get(options: &Options) -> Result<ExitCode, String> {
	match active(options)? {
		// **Not a profile called "none".** 0151: an absent selection and the
		// shipped do-nothing profile are different states, and printing one
		// name for both would make every diagnostic ambiguous.
		None => println!("no profile chosen"),
		Some(name) => println!("{name}"),
	}
	Ok(ExitCode::SUCCESS)
}

fn list(options: &Options) -> ExitCode {
	let chosen = active(options).unwrap_or(None);
	let found = profile_dirs(options);
	if found.is_empty() {
		println!("no profiles; a profile is a directory under `profile/`");
		return ExitCode::SUCCESS;
	}
	for (name, mine) in found {
		let mark = if Some(&name) == chosen.as_ref() {
			"*"
		} else {
			" "
		};
		let origin = if mine { "yours" } else { "shipped" };
		println!("{mark} {name}  ({origin})");
	}
	ExitCode::SUCCESS
}

fn set(rest: &[String], options: &Options) -> Result<ExitCode, String> {
	let Some(name) = rest.first() else {
		return Err("`ncfg profile set` needs a name; `ncfg profile list` shows them".to_owned());
	};

	// Refused here as well as by the compiler, because the round trip would
	// not say which part of the name was the problem.
	if name.is_empty() || name.contains('/') || name.starts_with('.') {
		return Err(format!(
			"`{name}` cannot be a profile name: a plain name, since netcfgd \
			 chooses the directory it is read from"
		));
	}

	// **A name with no directory is refused rather than written.** Writing it
	// would produce a machine whose configuration names a profile that does
	// not exist, and the failure would surface later as a profile that
	// changes nothing.
	let found = profile_dirs(options);
	if !found.iter().any(|(seen, _)| seen == name) {
		let known: Vec<&str> = found.iter().map(|(seen, _)| seen.as_str()).collect();
		return Err(format!(
			"no profile called `{name}`{}",
			if known.is_empty() {
				String::new()
			} else {
				format!("; this machine has {}", known.join(", "))
			}
		));
	}

	let text = format!("global {{\n\tprofile = \"{name}\"\n}}\n");
	// Replacing, because switching twice must edit one file rather than
	// leaving the previous choice behind for the loader to argue with.
	crate::drop_in::put_text(
		DROP_IN,
		text,
		true,
		&format!("the profile `{name}`"),
		options,
	)?;
	println!("profile is now `{name}`");
	// Said because a profile switch is the change most likely to need it: it
	// is large, deliberate, and cannot be undone from the far end of a link it
	// just took down.
	println!(
		"`ncfg plan` shows what that changes; `ncfg apply --confirm 60` \
	          keeps a way back"
	);
	Ok(ExitCode::SUCCESS)
}

fn unset(options: &Options) -> Result<ExitCode, String> {
	crate::drop_in::remove_named(DROP_IN, "a chosen profile", options)?;
	println!(
		"no profile is chosen now, which is the default rather than a \
	          profile called `none`"
	);
	Ok(ExitCode::SUCCESS)
}

#[cfg(test)]
mod tests {
	use super::*;

	/// A config tree with two profiles and no socket, so every write takes the
	/// local path.
	fn fixture(tag: &str) -> (netcfgd_testdir::TestDir, Options) {
		let root = netcfgd_testdir::TestDir::new(&format!("profile-{tag}"));
		for dir in [
			"etc/conf.d",
			"etc/profile/office",
			"etc/profile/offline",
			"run",
		] {
			std::fs::create_dir_all(root.join(dir)).expect("a directory");
		}
		std::fs::write(
			root.join("etc/netcfgd.conf"),
			"interface eth0 {\n\tconfig = \"dhcp\"\n}\n",
		)
		.expect("a config file");
		std::fs::write(
			root.join("etc/profile/office/10-office.conf"),
			"override interface eth0 {\n\tconfig = \"dhcp\"\n\tmtu = 9000\n}\n",
		)
		.expect("a profile file");

		let options = Options {
			config_dir: Some(root.join("etc").display().to_string()),
			factory_dir: Some(root.join("factory").display().to_string()),
			run_dir: Some(root.join("run").display().to_string()),
			..Options::default()
		};
		(root, options)
	}

	/// The round trip, which is the whole command: nothing chosen, choose one,
	/// read it back, take it away again.
	#[test]
	fn set_get_and_unset_round_trip() {
		let (root, options) = fixture("round-trip");
		assert_eq!(active(&options).expect("compiles"), None, "nothing chosen");

		set(&["office".to_owned()], &options).expect("set");
		assert_eq!(
			active(&options).expect("compiles").as_deref(),
			Some("office")
		);

		// The fixed name of 0151: switching twice must edit one file rather
		// than leaving the previous choice behind.
		let written = root.join("etc/conf.d/90-profile.conf");
		assert!(written.exists(), "the drop-in it owns");

		set(&["offline".to_owned()], &options).expect("set again");
		assert_eq!(
			active(&options).expect("compiles").as_deref(),
			Some("offline")
		);
		let files: Vec<_> = std::fs::read_dir(root.join("etc/conf.d"))
			.expect("conf.d")
			.filter_map(Result::ok)
			.map(|entry| entry.file_name().to_string_lossy().into_owned())
			.collect();
		assert_eq!(
			files,
			vec!["90-profile.conf".to_owned()],
			"one file, {files:?}"
		);

		unset(&options).expect("unset");
		assert_eq!(active(&options).expect("compiles"), None, "back to none");
		assert!(!written.exists(), "the drop-in is gone");
	}

	/// A settings write that is refused changed no setting, so it must not
	/// have taken the machine off its profile either. The fold has to happen
	/// before the write -- folding afterwards would have to preserve a
	/// document in which the profile still overrides the new edit, so it would
	/// land late and the edit would never take effect -- which means the only
	/// way to keep this true is to put the profile back.
	#[test]
	fn a_refused_write_leaves_the_profile_alone() {
		let (root, options) = fixture("refused-write");
		set(&["office".to_owned()], &options).expect("set");

		let error = crate::drop_in::put_text(
			"50-bad",
			"override interface eth0 { nonsense = 1 }\n".to_owned(),
			false,
			"`50-bad`",
			&options,
		)
		.expect_err("it does not compile");
		assert!(error.contains("nonsense"), "{error}");

		assert_eq!(
			active(&options).expect("compiles").as_deref(),
			Some("office"),
			"still on the profile"
		);
		assert!(root.join("etc/conf.d/90-profile.conf").exists());
		assert!(!root.join("etc/conf.d/05-profile-office.conf").exists());
		assert!(!root.join("etc/conf.d/zz-profile-office.conf").exists());
	}

	/// And the write that succeeds does take it off, folding the profile in so
	/// that what is running does not move -- early enough that the edit which
	/// caused it actually wins.
	#[test]
	fn a_settings_write_takes_the_machine_off_its_profile() {
		let (root, options) = fixture("takes-off");
		set(&["office".to_owned()], &options).expect("set");

		crate::drop_in::put_text(
			"50-mine",
			"override interface eth0 { mtu = 1400 }\n".to_owned(),
			false,
			"`50-mine`",
			&options,
		)
		.expect("it compiles");

		assert_eq!(active(&options).expect("compiles"), None, "on none now");
		assert!(root.join("etc/conf.d/05-profile-office.conf").exists());
		let (document, _) = crate::compile(&options).expect("compiles");
		assert_eq!(document.interfaces[0].mtu, Some(1400), "the edit won");
	}

	/// A name with no directory is refused rather than written. Writing it
	/// would produce a machine whose configuration names a profile that does
	/// not exist, and the fault would surface later as a profile that changes
	/// nothing -- which reads as netcfgd ignoring the operator.
	#[test]
	fn a_name_with_no_directory_is_refused() {
		let (root, options) = fixture("no-directory");
		let error = set(&["nosuch".to_owned()], &options).expect_err("refused");
		assert!(error.contains("no profile called `nosuch`"), "{error}");
		assert!(error.contains("office"), "it says what there is: {error}");
		assert!(
			!root.join("etc/conf.d/90-profile.conf").exists(),
			"and wrote nothing"
		);
	}

	/// A name that is a path, or hidden, is refused before it reaches the
	/// compiler, so that the message can say which part was the problem.
	#[test]
	fn a_name_that_is_a_path_is_refused() {
		let (_root, options) = fixture("path-name");
		for bad in ["../elsewhere", "office/inner", ".hidden", ""] {
			let error = set(&[bad.to_owned()], &options).expect_err("refused");
			assert!(error.contains("cannot be a profile name"), "{bad}: {error}");
		}
	}

	/// Both layers are listed, and a name in both is reported as the
	/// operator's, since their copy is what layers on top.
	#[test]
	fn list_reports_both_layers_and_who_owns_a_name() {
		let (root, options) = fixture("layers");
		std::fs::create_dir_all(root.join("factory/profile/shipped")).expect("a factory profile");
		std::fs::create_dir_all(root.join("factory/profile/office")).expect("shadowed");

		let found = profile_dirs(&options);
		let names: Vec<&str> = found.iter().map(|(name, _)| name.as_str()).collect();
		assert_eq!(names, vec!["office", "offline", "shipped"], "{names:?}");
		assert!(found[0].1, "office is the operator's, not the factory's");
		assert!(!found[2].1, "shipped is the factory's");
	}
}
