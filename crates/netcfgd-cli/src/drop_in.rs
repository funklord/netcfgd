//! `ncfg config`: putting configuration where netcfgd will read it.
//!
//! **The general case of what `ncfg wifi add` does for one block.** 0127 makes
//! netcfgd the only writer of `/etc/netcfgd`, so a client with configuration
//! to contribute sends the text and netcfgd decides where it goes. This is the
//! command that does that, and until it existed the mechanism was reachable
//! only by a program somebody wrote themselves.
//!
//! # Why a name and a file are different things
//!
//! The file is read *here*, by whoever ran the command, with their own
//! permissions -- so it may be anywhere they can read, including their home
//! directory or standard input. What crosses the socket is the **text**, and
//! the name is what netcfgd files it under.
//!
//! That split is the whole of 0127 in one command. A request carrying a path
//! would be a request to read a file as root, which is a different and much
//! larger permission than "add this to the configuration".
//!
//! # What it does not check
//!
//! Whether the configuration compiles, and whether the caller may send what is
//! in it. Both are netcfgd's, and asking here as well would put a second
//! answer in a second place: the daemon compiles the whole directory with this
//! file in it, which is the only way to know that a drop-in does not collide
//! with one already there, and it classifies the text against the same table
//! it uses for every other caller.

use crate::Options;
use netcfgd_host::config;
use std::process::ExitCode;

/// `ncfg config SUBCOMMAND`.
///
/// # Errors
///
/// Returns the sentence to print, which for configuration that does not
/// compile is netcfgd's own diagnostics.
pub(crate) fn run(positional: &[String], options: &Options) -> Result<ExitCode, String> {
	let Some(subcommand) = positional.first() else {
		return Err("`ncfg config` takes `put` or `rm`".to_owned());
	};
	match subcommand.as_str() {
		"put" => put(&positional[1..], options),
		"rm" => remove(&positional[1..], options),
		other => Err(format!(
			"unknown config subcommand `{other}`; it is `put` or `rm`"
		)),
	}
}

/// Read the text a `put` is to send.
///
/// A path, or standard input when the path is `-` or absent. Standard input is
/// the form that matters for the audience this is for: a fleet tool generating
/// configuration has it in a pipe, not in a file it wants to leave lying
/// around.
fn text_from(source: Option<&String>) -> Result<String, String> {
	match source.map(String::as_str) {
		None | Some("-") => {
			use std::io::Read as _;
			let mut text = String::new();
			std::io::stdin()
				.read_to_string(&mut text)
				.map_err(|error| format!("could not read standard input: {error}"))?;
			Ok(text)
		}
		Some(path) => {
			std::fs::read_to_string(path).map_err(|error| format!("could not read {path}: {error}"))
		}
	}
}

fn put(rest: &[String], options: &Options) -> Result<ExitCode, String> {
	let Some(name) = rest.first() else {
		return Err(
			"`ncfg config put` needs a name: what netcfgd files it under, as in \
			 `ncfg config put site site.conf`. The name is not a path"
				.to_owned(),
		);
	};
	if rest.len() > 2 {
		return Err(format!(
			"`ncfg config put` takes a name and at most one file, and got {} arguments",
			rest.len()
		));
	}

	let text = text_from(rest.get(1))?;
	if text.trim().is_empty() {
		return Err(format!(
			"nothing was given for `{name}`, and an empty drop-in is a file that \
			 configures nothing. Use `ncfg config rm {name}` to take one away"
		));
	}

	// The daemon first, and the local write only when none is listening -- the
	// same order `ncfg wifi add` and `ncfg secret set` take since 0127, and for
	// the same reason. The local path is for a machine being configured before
	// netcfgd runs on it.
	let socket = crate::client::socket_path(&crate::state::resolve_dir(options.run_dir.as_deref()));
	if socket.exists() {
		let request = netcfgd_proto::Request::ConfigPut {
			name: name.clone(),
			text,
			replace: options.replace,
		};
		return match crate::client::ask(&socket, &request) {
			Ok(crate::client::Answer::Ok) => {
				println!("netcfgd stored `{name}` and re-read its configuration");
				Ok(ExitCode::SUCCESS)
			}
			Ok(crate::client::Answer::Error { message }) | Err(message) => Err(message),
			Ok(other) => Err(format!("the daemon sent {}", other.describe())),
		};
	}

	let config_dir = config::resolve_dir(options.config_dir.as_deref());
	let factory_dir = config::resolve_factory_dir(options.factory_dir.as_deref());
	let path = config::install_drop_in(&config_dir, &factory_dir, name, &text, options.replace)?;
	println!("wrote {}", path.display());
	println!(
		"nothing is listening on {}, so this was written directly",
		socket.display()
	);
	Ok(ExitCode::SUCCESS)
}

fn remove(rest: &[String], options: &Options) -> Result<ExitCode, String> {
	let Some(name) = rest.first() else {
		return Err("`ncfg config rm` needs the name a drop-in was put under".to_owned());
	};

	let socket = crate::client::socket_path(&crate::state::resolve_dir(options.run_dir.as_deref()));
	if socket.exists() {
		let request = netcfgd_proto::Request::ConfigDelete { name: name.clone() };
		return match crate::client::ask(&socket, &request) {
			Ok(crate::client::Answer::Ok) => {
				// Said plainly, because an absent file is success and somebody
				// who mistyped the name would otherwise read that as "removed".
				println!("netcfgd no longer has a drop-in called `{name}`");
				Ok(ExitCode::SUCCESS)
			}
			Ok(crate::client::Answer::Error { message }) | Err(message) => Err(message),
			Ok(other) => Err(format!("the daemon sent {}", other.describe())),
		};
	}

	let config_dir = config::resolve_dir(options.config_dir.as_deref());
	let factory_dir = config::resolve_factory_dir(options.factory_dir.as_deref());
	config::remove_drop_in(&config_dir, &factory_dir, name)?;
	println!("`{name}` is not in {}", config_dir.display());
	Ok(ExitCode::SUCCESS)
}

#[cfg(test)]
mod tests {
	use super::*;

	/// A config tree with one interface, and a run directory with no socket.
	fn fixture(tag: &str) -> (netcfgd_testdir::TestDir, Options) {
		let root = netcfgd_testdir::TestDir::new(&format!("config-put-{tag}"));
		std::fs::create_dir_all(root.join("etc/conf.d")).expect("a config directory");
		std::fs::create_dir_all(root.join("run")).expect("a run directory");
		std::fs::write(
			root.join("etc/netcfgd.conf"),
			"interface eth0 {\n\tconfig = \"dhcp\"\n}\n",
		)
		.expect("a config file");

		let options = Options {
			config_dir: Some(root.join("etc").display().to_string()),
			factory_dir: Some(root.join("factory").display().to_string()),
			run_dir: Some(root.join("run").display().to_string()),
			..Options::default()
		};
		(root, options)
	}

	fn file(root: &netcfgd_testdir::TestDir, name: &str, text: &str) -> String {
		let path = root.join(name);
		std::fs::write(&path, text).expect("written");
		path.display().to_string()
	}

	/// With no daemon, the drop-in is written locally.
	#[test]
	fn with_no_daemon_the_drop_in_is_written_locally() {
		let (root, options) = fixture("local");
		let source = file(
			&root,
			"site.conf",
			"interface eth1 {\n\tconfig = \"dhcp\"\n}\n",
		);
		run(&["put".to_owned(), "site".to_owned(), source], &options).expect("it is written");
		assert!(root.join("etc/conf.d/site.conf").exists());
	}

	/// With a daemon listening, the text goes to it and no file is written.
	///
	/// The property this command exists for: 0127 makes netcfgd the writer, so
	/// what proves the route is that `conf.d` is empty afterwards. The wait is
	/// bounded and the timeout is the assertion, because the version of this
	/// test that joins a thread *hangs* when the preference regresses -- which
	/// stalls the suite instead of reporting, and is a mistake this tree has
	/// already made once today.
	#[test]
	fn with_a_daemon_listening_the_text_goes_to_it() {
		use std::io::{BufRead, BufReader, Write};

		let (root, options) = fixture("daemon");
		let source = file(
			&root,
			"site.conf",
			"interface eth1 {\n\tconfig = \"dhcp\"\n}\n",
		);
		let listener = std::os::unix::net::UnixListener::bind(root.join("run/netcfgd.sock"))
			.expect("it binds");

		let (sender, asked) = std::sync::mpsc::channel();
		std::thread::spawn(move || {
			let Ok((stream, _)) = listener.accept() else {
				return;
			};
			let Ok(clone) = stream.try_clone() else {
				return;
			};
			let mut line = String::new();
			let _ = BufReader::new(clone).read_line(&mut line);
			let mut writer = stream;
			let _ = writer.write_all(b"{\"response\":\"ok\"}\n");
			let _ = writer.flush();
			let _ = sender.send(line);
		});

		run(&["put".to_owned(), "site".to_owned(), source], &options)
			.expect("the daemon answers ok");

		let sent = asked
			.recv_timeout(std::time::Duration::from_secs(5))
			.expect("nothing connected within 5s, so the daemon was not asked");
		assert!(sent.contains("config_put"), "sent something else: {sent}");
		// The text crossed and the path did not, which is 0127 in one
		// assertion: a request naming a path would be a request to read a file
		// as root.
		assert!(
			sent.contains("interface eth1"),
			"the text did not cross: {sent}"
		);
		assert!(
			!sent.contains("site.conf"),
			"the request carried the path it was read from: {sent}"
		);
		assert!(!root.join("etc/conf.d/site.conf").exists());
	}

	/// An empty drop-in is refused, and says what to use instead.
	#[test]
	fn an_empty_drop_in_is_refused() {
		let (root, options) = fixture("empty");
		let source = file(&root, "nothing.conf", "\n   \n");
		let error = run(&["put".to_owned(), "gone".to_owned(), source], &options)
			.expect_err("an empty drop-in configures nothing");
		assert!(error.contains("ncfg config rm"), "{error}");
	}

	/// Removing one that is not there is success, because that is the state
	/// being asked for.
	#[test]
	fn removing_an_absent_drop_in_is_success() {
		let (_root, options) = fixture("absent");
		run(&["rm".to_owned(), "never-existed".to_owned()], &options)
			.expect("absent is the state asked for");
	}

	/// A name is a name. The daemon refuses one that is a path, and so does
	/// the local route -- checked here because a client that only ever met the
	/// daemon's refusal would be a client somebody ran without one.
	#[test]
	fn a_name_that_is_a_path_is_refused_locally_too() {
		let (root, options) = fixture("path-name");
		let source = file(
			&root,
			"x.conf",
			"interface eth1 {\n\tconfig = \"dhcp\"\n}\n",
		);
		assert!(run(
			&["put".to_owned(), "../escape".to_owned(), source],
			&options
		)
		.is_err());
	}
}
