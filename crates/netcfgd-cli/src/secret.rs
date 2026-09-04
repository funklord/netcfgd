//! `ncfg secret set NAME` -- store a credential the config refers to.
//!
//! **What this is for, and what it is not.** The config never holds secret
//! material: section 2's rule is that a document carries a `SecretRef` and
//! nothing else, so `password = "@secret:vpn"` needs a file at
//! `<config-dir>/secrets/vpn` for the `file` provider to find. Writing that
//! file needed an editor, a `chmod` and the discipline to remember both --
//! and the compiler's diagnostic for a missing one used to tell the reader to
//! run this command, which did not exist. That is 0061's disease in a help
//! string, and decision 0075 is the answer.
//!
//! It is deliberately *only* the write. `ncfg wifi add` writes a config block
//! and a secret together because a network is both; a `WireGuard` key or a DSL
//! password belongs to a block the operator is editing anyway, so this stores
//! the credential and says which of them refer to it.
//!
//! The two things it does that an editor does not: the value never appears on
//! a command line, in a prompt, or in a shell history -- and the file is 0600
//! from the moment it exists, because a `chmod` afterwards is a window.

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use crate::config;
use crate::Options;

pub(crate) fn read_without_echo(prompt: &str) -> Result<String, String> {
	use std::io::{BufRead as _, Write as _};

	// Standard input, by number, because that is what the terminal calls want.
	const STDIN: std::os::fd::RawFd = 0;
	let interactive = netcfgd_sys::term::is_terminal(STDIN);

	// The signals are blocked for exactly as long as echo is off. `^C` at the
	// prompt then arrives after the restore rather than instead of it, which is
	// the difference between an aborted command and a shell with echo off --
	// see `netcfgd_sys::signals`, which exists because that happened.
	//
	// Declared first so that it is dropped last: Rust drops in reverse
	// declaration order, and unblocking before restoring would reopen the
	// window this closes.
	let _signals = if interactive {
		netcfgd_sys::signals::Signals::new().ok()
	} else {
		None
	};
	let _echo = if interactive {
		netcfgd_sys::term::EchoOff::new(STDIN)
			.map_err(|error| format!("could not turn echo off: {error}"))?
	} else {
		None
	};

	if interactive {
		// On standard error, so that a shell function wrapping this command can
		// still capture its output, and flushed by hand because a prompt with
		// no newline would otherwise appear after the answer.
		eprint!("{prompt}: ");
		let _ = std::io::stderr().flush();
	}

	let mut line = String::new();
	let read = std::io::stdin()
		.lock()
		.read_line(&mut line)
		.map_err(|error| format!("could not read it: {error}"))?;
	if interactive {
		// The newline the operator typed was not echoed either.
		eprintln!();
	}
	if read == 0 {
		return Err(format!("nothing was given for the {prompt}"));
	}

	// The line terminator, and nothing else. A secret may legitimately
	// begin or end with a space, and trimming one that does would store
	// something that never associates and looks right in every diagnostic.
	let mut passphrase = line.as_str();
	if let Some(shorter) = passphrase.strip_suffix('\n') {
		passphrase = shorter;
	}
	if let Some(shorter) = passphrase.strip_suffix('\r') {
		passphrase = shorter;
	}

	Ok(passphrase.to_owned())
}

pub(crate) fn usable_name(name: &str) -> Result<(), &'static str> {
	if name.is_empty() {
		return Err("it is empty");
	}
	if name.len() > 64 {
		return Err("it is longer than 64 bytes");
	}
	if name.contains(['"', '\\']) {
		return Err("it contains a quote or a backslash");
	}
	if name.chars().any(char::is_control) {
		return Err("it contains a control character");
	}
	if name.contains('/') {
		return Err("it contains a path separator, and it names a file");
	}
	if name.contains("..") || name.starts_with('.') {
		return Err("it would name a hidden file or one outside the directory");
	}
	Ok(())
}

pub(crate) fn make_secrets_dir(secret: &Path) -> Result<(), String> {
	use std::os::unix::fs::DirBuilderExt as _;

	let directory = secret.parent().unwrap_or_else(|| Path::new("."));
	if directory.is_dir() {
		return Ok(());
	}
	std::fs::DirBuilder::new()
		.recursive(true)
		.mode(0o700)
		.create(directory)
		.map_err(|error| format!("could not create {}: {error}", directory.display()))
}

/// Where the `file` provider will look for this one.
fn secret_path(config_dir: &Path, name: &str) -> PathBuf {
	config_dir.join("secrets").join(name)
}

/// `ncfg secret set NAME`.
///
/// # Errors
///
/// If the name cannot be a filename, if a secret of that name already exists
/// and `--replace` was not given, if nothing was typed, or if the write fails.
pub(crate) fn set(positional: &[String], options: &Options) -> Result<ExitCode, String> {
	let Some(name) = positional.first() else {
		return Err(
			"`ncfg secret set` needs a name: the one the config refers to, as in \
		            `password = \"@secret:vpn\"` -- so `ncfg secret set vpn`"
				.to_owned(),
		);
	};
	if let Some(extra) = positional.get(1) {
		return Err(format!(
			"`ncfg secret set` takes one name, and got `{extra}` as well. The value is never \
			 an argument -- it is typed at the prompt, or read from standard input"
		));
	}
	usable_name(name).map_err(|why| format!("`{name}` cannot be used as a secret name: {why}"))?;

	let config_dir = config::resolve_dir(options.config_dir.as_deref());
	let secret = secret_path(&config_dir, name);
	// Refused rather than replaced, unless the operator says. `set` reads as
	// "overwrite" and for most things it could be -- but one of the credentials
	// this stores is a WireGuard private key, which decision 0042 calls the one
	// thing on a machine that nobody can get back. A flag is cheap; that is not.
	if secret.exists() && !options.replace {
		return Err(format!(
			"{} already exists. Pass --replace to overwrite it -- and note that a private \
			 key nobody has a copy of cannot be got back (doc/decision/0042)",
			secret.display()
		));
	}
	let replacing = secret.exists();

	// Last, because it is the only step that stops and waits for a person: a
	// refusal that was going to happen anyway should not happen after the
	// secret has been typed. The same order `wifi add` takes, for the same
	// reason.
	let value = read_without_echo(&format!("value for `{name}`"))?;
	if value.is_empty() {
		return Err(format!(
			"nothing was given for `{name}`, and an empty secret is a secret that fails at \
			 the moment it is used rather than now"
		));
	}
	// **The daemon first**, for 0127's reason and by the same rule `wifi add`
	// follows: `/etc/netcfgd/secrets` is root's, a client is not root, and the
	// channel carries what the client cannot write. The local write stays for
	// the case the daemon cannot serve -- a machine being configured before
	// netcfgd runs on it.
	let socket = crate::client::socket_path(&crate::state::resolve_dir(options.run_dir.as_deref()));
	if socket.exists() {
		let request = netcfgd_proto::Request::SecretPut {
			name: name.clone(),
			value,
			replace: options.replace,
		};
		return match crate::client::ask(&socket, &request) {
			Ok(crate::client::Answer::Ok) => {
				report(&secret, name, replacing, options);
				Ok(ExitCode::SUCCESS)
			}
			// `Error` and a transport failure are one arm on purpose: both
			// are a sentence naming what went wrong, and the caller does
			// nothing different for having been told which layer produced it.
			Ok(crate::client::Answer::Error { message }) | Err(message) => Err(message),
			Ok(other) => Err(format!("the daemon sent {}", other.describe())),
		};
	}

	make_secrets_dir(&secret)?;
	config::write_atomically(&secret, value.as_bytes(), 0o600)
		.map_err(|error| format!("could not write {}: {error}", secret.display()))?;

	report(&secret, name, replacing, options);
	Ok(ExitCode::SUCCESS)
}

/// What was written, and whether anything refers to it.
///
/// The second half is the useful part: a secret whose name does not match the
/// reference in the document is a file that will be read by nothing, and the
/// failure arrives later as "no such secret" from a backend. Saying so here
/// turns a typo into a sentence rather than into an afternoon.
///
/// Never the value, never its length. `netcfgd-secret` keeps that rule
/// everywhere and a convenience command is not the place to break it.
fn report(secret: &Path, name: &str, replacing: bool, options: &Options) {
	let verb = if replacing { "replaced" } else { "stored" };
	println!("{verb} {} (0600)", secret.display());

	// The document is compiled to answer "does anything use this?", and a
	// configuration that does not compile is not an error *here*: the secret is
	// written either way, and an operator storing a credential before writing
	// the block that names it is the ordinary order to do things in.
	let Ok((document, _)) = crate::compile(options) else {
		return;
	};
	let users = referring_to(&document, name);
	if users.is_empty() {
		println!("note: nothing in the configuration refers to `@secret:{name}` yet");
	} else {
		println!("used by: {}", users.join(", "));
	}
}

/// Everything in the document that names this secret, as a human would say it.
///
/// A walk rather than a search of the file text: the document is what the
/// backends resolve against, so a reference the compiler dropped or renamed is
/// not one anything will look for.
/// The blocks that refer to this name.
///
/// The walk itself is `netcfgd_host::secrets`, because the socket needs the
/// same knowledge inverted -- every name and who refers to it -- and two walks
/// would be two chances to miss a shape when the model grows one.
fn referring_to(document: &netcfgd_model::Document, name: &str) -> Vec<String> {
	netcfgd_host::secrets::referring_to(document, name)
}

#[cfg(test)]
mod tests {
	use super::{referring_to, secret_path, set, usable_name};
	use crate::Options;

	/// A configuration that uses one secret in four different places, so that
	/// the walk cannot pass by covering only the one shape somebody wrote first.
	fn document(text: &str) -> netcfgd_model::Document {
		let mut sources = netcfgd_compile::SourceMap::new();
		sources.add("netcfgd.conf", text);
		netcfgd_compile::compile(&sources, &mut netcfgd_compile::NoHooks)
			.unwrap_or_else(|diagnostics| panic!("{}", diagnostics.render(&sources)))
	}

	/// The report's useful half: which blocks refer to this name.
	///
	/// **The name claimed exhaustiveness and the enumeration was short by
	/// two.** An `OpenVPN` tunnel's password and an access point's passphrase
	/// were both absent from the walk, so `ncfg secret set` told an operator
	/// that a credential their configuration names is used by nothing -- which
	/// invites deleting it. No assertion can fail about a shape it does not
	/// name, so the fixture below carries one of every block that can hold a
	/// secret, and the walk itself now destructures `Document` so a new block
	/// list cannot be missed the way `access_points` was.
	#[test]
	fn every_kind_of_reference_is_found() {
		let document = document(
			r#"
device wg0 {
	wireguard {
		private_key = "@secret:shared"
		peer office {
			public_key    = "0000000000000000000000000000000000000000000="
			preshared_key = "@secret:shared"
			allowed_ips   = ["10.0.0.0/24"]
		}
	}
}

device dsl0 {
	pppoe {
		parent   = "eth0"
		username = "user"
		password = "@secret:shared"
	}
}

device vpn0 {
	openvpn {
		config   = "/etc/openvpn/work.ovpn"
		username = "user"
		password = "@secret:shared"
	}
}

device ap0 {
	kind = "dummy"
}

network home {
	wifi { psk = "@secret:shared" }
}

access_point guest {
	device = "ap0"
	wifi { psk = "@secret:shared" }
}
"#,
		);
		let users = referring_to(&document, "shared");
		assert_eq!(
			users,
			[
				"access point guest",
				"interface dsl0",
				"interface vpn0",
				"interface wg0 (peer office)",
				"interface wg0 (private key)",
				"network home",
			],
			"a reference was missed or invented"
		);
		// And a name nothing uses is nothing, which is the other half of the
		// report and the one that catches a typo.
		assert!(referring_to(&document, "other").is_empty());
	}

	/// A name that would be a path is refused before anything is written.
	#[test]
	fn a_name_that_is_not_a_filename_is_refused() {
		for bad in ["", "../shadow", "a/b", ".hidden", "quote\"here"] {
			assert!(usable_name(bad).is_err(), "`{bad}` should be refused");
		}
		assert!(usable_name("wg-key").is_ok());
	}

	/// The file is 0600 from the moment it exists, and the directory 0700.
	///
	/// Asserted on the mode rather than on a `chmod` having been called,
	/// because the window between creating and tightening is the thing that
	/// must not exist -- `write_atomically` sets the mode on the open.
	#[test]
	fn what_it_writes_is_readable_by_nobody_else() {
		use std::os::unix::fs::PermissionsExt as _;

		let dir = netcfgd_testdir::TestDir::new("secret-set");
		let options = Options {
			config_dir: Some(dir.display().to_string()),
			..Options::default()
		};
		let secret = secret_path(&dir, "vpn");
		std::fs::create_dir_all(secret.parent().expect("a parent")).expect("a directory");
		crate::config::write_atomically(&secret, b"value", 0o600).expect("written");

		let mode = std::fs::metadata(&secret)
			.expect("stat")
			.permissions()
			.mode() & 0o777;
		assert_eq!(mode, 0o600, "the secret is readable by somebody else");

		// And a second `set` refuses rather than overwriting, because one of
		// these is a key nobody can get back.
		let refusal = set(&["vpn".to_owned()], &options).expect_err("it refuses");
		assert!(refusal.contains("--replace"), "{refusal}");
	}

	/// One name, and never a value.
	#[test]
	fn the_value_is_not_an_argument() {
		let dir = netcfgd_testdir::TestDir::new("secret-argv");
		let options = Options {
			config_dir: Some(dir.display().to_string()),
			..Options::default()
		};
		let refusal =
			set(&["vpn".to_owned(), "hunter2".to_owned()], &options).expect_err("it refuses");
		assert!(refusal.contains("never an argument"), "{refusal}");
		assert!(!secret_path(&dir, "vpn").exists(), "it wrote a file anyway");
	}
}
