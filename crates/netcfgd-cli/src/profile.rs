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
		return Err("`ncfg profile` takes `get`, `set`, `save`, `unset` or `list`".to_owned());
	};
	match subcommand.as_str() {
		"get" => get(options),
		"list" => Ok(list(options)),
		"save" => save(&positional[1..], options),
		"set" => set(&positional[1..], options),
		"unset" => unset(options),
		other => Err(format!(
			"unknown profile subcommand `{other}`; it is `get`, `set`, `save`, \
			 `unset` or `list`"
		)),
	}
}

/// The profiles this machine has, from both layers.
///
/// Shipped ones and the operator's, and which is which: an operator editing
/// what looks like their own file and finding it replaced on upgrade is the
/// confusion this column exists to prevent.
fn profile_dirs(options: &Options) -> Vec<(String, bool)> {
	if let Some((found, _)) = from_daemon(options) {
		return found;
	}
	let config = netcfgd_host::config::resolve_dir(options.config_dir.as_deref());
	let factory = netcfgd_host::config::resolve_factory_dir(options.factory_dir.as_deref());
	netcfgd_host::config::list_profiles(&config, &factory)
		.into_iter()
		.map(|entry| (entry.name, !entry.shipped))
		.collect()
}

/// What netcfgd has, and what it is running: the profiles paired with whose
/// each is, and the one in effect.
type Listing = (Vec<(String, bool)>, Option<String>);

/// What netcfgd says it has and what it is running, when one is listening.
///
/// A client only ever talks to netcfgd: listing the local
/// `/etc/netcfgd/profile` would show this laptop while configuring a remote
/// machine, and would then offer to switch that machine to a profile it does
/// not have. The daemon's `chosen` comes from the document it compiled, so it
/// is what is in effect rather than what a file asked for.
fn from_daemon(options: &Options) -> Option<Listing> {
	let socket = crate::client::socket_path(&crate::state::resolve_dir(options.run_dir.as_deref()));
	if !socket.exists() {
		return None;
	}
	match crate::client::ask(&socket, &netcfgd_proto::Request::ProfileList) {
		Ok(crate::client::Answer::Profiles { profiles, chosen }) => Some((
			profiles
				.into_iter()
				.map(|entry| (entry.name, !entry.shipped))
				.collect(),
			chosen,
		)),
		_ => None,
	}
}

fn active(options: &Options) -> Result<Option<String>, String> {
	if let Some((_, chosen)) = from_daemon(options) {
		return Ok(chosen);
	}
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

/// Write what the machine is running into a profile, and select it.
///
/// **The only door into a profile directory.** 0151: nothing else writes
/// there -- not a settings edit, not the gui, not the shim, not the daemon --
/// because a profile may be carefully crafted and none of that is recoverable
/// from the running state once something has helpfully rewritten it.
///
/// The fold is taken out of `conf.d` as part of this, so that saving really
/// moves the configuration into the profile rather than copying it. Leaving it
/// behind would keep the old profile in force after switching to a different
/// one, which is not what "saved it into office" means to anybody.
///
/// **Verified, then kept.** The whole thing is written, the loader is asked
/// what the machine now compiles to, and it must be what was running. Anything
/// else and every part of it is put back -- the profile written here is the
/// thing somebody will rely on months later, and a snapshot that is subtly not
/// what they saved is worse than a refusal today.
fn save(rest: &[String], options: &Options) -> Result<ExitCode, String> {
	let Some(name) = rest.first() else {
		return Err("`ncfg profile save` needs a name to save as".to_owned());
	};

	let config = netcfgd_host::config::resolve_dir(options.config_dir.as_deref());
	let factory = netcfgd_host::config::resolve_factory_dir(options.factory_dir.as_deref());

	// What is running, before anything moves.
	let (running, _) = crate::compile(options)?;

	// The whole of it is in `netcfgd-host` so that the daemon can do it too:
	// this was the only way to save a profile, which meant a machine with a
	// gui could switch between profiles it already had and never make one.
	let snapshot = netcfgd_host::config::save_profile(
		&config,
		&factory,
		name,
		options.replace,
		&running,
		// The remedy in this caller's vocabulary: `ncfg` has a flag to
		// name, and a message naming a gui's button would be useless here.
		"`--replace`",
	)?;
	println!("wrote {}", snapshot.display());
	println!("`{name}` is now the profile in use");
	Ok(ExitCode::SUCCESS)
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
	write_selection(Some(name), text, options)?;
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

/// Put the selection where netcfgd keeps it.
///
/// **Through `ProfileSet` when a daemon is listening**, which is the verb the
/// gui uses -- so the two clients take one path and the daemon's own checks
/// run for both. Writing the drop-in directly from here would have been a
/// second way to do the same thing, and the day the name or the rules change
/// one of them would be wrong.
///
/// The local write is for a machine being configured before netcfgd runs on
/// it, which is the fallback every other write here takes.
fn write_selection(name: Option<&str>, text: String, options: &Options) -> Result<(), String> {
	let socket = crate::client::socket_path(&crate::state::resolve_dir(options.run_dir.as_deref()));
	if socket.exists() {
		let request = netcfgd_proto::Request::ProfileSet {
			name: name.map(str::to_owned),
		};
		return match crate::client::ask(&socket, &request) {
			Ok(crate::client::Answer::Ok) => Ok(()),
			Ok(crate::client::Answer::Error { message }) | Err(message) => Err(message),
			Ok(other) => Err(format!("the daemon sent {}", other.describe())),
		};
	}

	match name {
		// Replacing, because switching twice must edit one file rather than
		// leaving the previous choice behind for the loader to argue with.
		Some(name) => crate::drop_in::put_text(
			DROP_IN,
			text,
			true,
			&format!("the profile `{name}`"),
			options,
		)
		.map(|_| ()),
		None => crate::drop_in::remove_named(DROP_IN, "a chosen profile", options).map(|_| ()),
	}
}

fn unset(options: &Options) -> Result<ExitCode, String> {
	write_selection(None, String::new(), options)?;
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

	/// The workflow of 0151 end to end: choose a profile, change a setting,
	/// save it. What the machine runs must not move at any step, and the
	/// profile that was chosen at the start must come out of it untouched --
	/// which is the whole reason saving is a separate explicit act.
	#[test]
	fn the_set_change_save_workflow_keeps_what_is_running() {
		let (root, options) = fixture("workflow");
		let crafted = root.join("etc/profile/office/10-office.conf");
		let before = std::fs::read_to_string(&crafted).expect("the profile");

		set(&["office".to_owned()], &options).expect("set");
		crate::drop_in::put_text(
			"50-mine",
			"override interface eth0 { mtu = 1400 }\n".to_owned(),
			false,
			"`50-mine`",
			&options,
		)
		.expect("the edit compiles");

		let (running, _) = crate::compile(&options).expect("compiles");
		assert_eq!(running.interfaces[0].mtu, Some(1400));

		save(&["office-v2".to_owned()], &options).expect("save");

		let (after, _) = crate::compile(&options).expect("compiles");
		assert_eq!(after.interfaces[0].mtu, Some(1400), "nothing moved");
		assert_eq!(
			after.globals.profile.as_deref(),
			Some("office-v2"),
			"selected"
		);
		assert!(root.join("etc/profile/office-v2/00-saved.conf").exists());

		// The crafted profile is byte-identical. Nothing here may rewrite it.
		assert_eq!(
			std::fs::read_to_string(&crafted).expect("still there"),
			before,
			"the profile that was chosen was rewritten"
		);
		// And the fold moved into the profile rather than being copied, so
		// switching away later does not leave the old profile in the base.
		assert!(!root.join("etc/conf.d/05-profile-office.conf").exists());
		assert!(!root.join("etc/conf.d/zz-profile-office.conf").exists());
	}

	/// Saving over an existing profile needs saying so, because an existing
	/// profile is somebody's work.
	#[test]
	fn saving_over_a_profile_is_refused_without_replace() {
		let (_root, options) = fixture("save-over");
		let error = save(&["office".to_owned()], &options).expect_err("refused");
		assert!(error.contains("already exists"), "{error}");
		assert!(error.contains("--replace"), "{error}");
	}

	/// And a hand-written profile is refused even with `--replace`, since
	/// saving cannot reproduce files it did not write.
	#[test]
	fn a_hand_written_profile_is_not_saved_over() {
		let (_root, mut options) = fixture("hand-written");
		options.replace = true;
		let error = save(&["office".to_owned()], &options).expect_err("refused");
		assert!(error.contains("written by hand"), "{error}");
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
