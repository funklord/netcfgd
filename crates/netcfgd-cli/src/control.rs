//! `ncfg control`: who may ask netcfgd for what.
//!
//! The bootstrap [0118](../../../docs/decisions/0118-two-ways-to-be-allowed-and-one-of-them-is-visible.md)
//! describes. Every tier defaults to root, so a default install refuses its own
//! GUI -- and the fix cannot go over the socket, because that would be asking
//! the daemon for permission to ask the daemon. It goes through this, run once
//! by somebody who is already root.
//!
//! **Typed, like `wifi_add` and for the same reason.** The subcommand takes
//! three principals and renders the block itself; it never accepts config text.
//! A config file may name a hook and a hook's `run_as` defaults to root, so a
//! privileged command that wrote text a caller supplied would be a way to run
//! anything as root. There is no field here that could name a hook or a path.
//!
//! It writes one drop-in and rewrites it whole. That is deliberate: the policy
//! deciding who may configure the network should be one visible file an
//! operator can read, diff and delete -- deleting it restores the root-only
//! default rather than breaking the machine.

use crate::Options;
use netcfgd_host::config;
use netcfgd_model::{Control, Principal};
use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

/// Which tiers `set` was told to change.
#[derive(Default)]
pub(crate) struct Wanted {
	pub(crate) observe: Option<String>,
	pub(crate) wifi: Option<String>,
	pub(crate) admin: Option<String>,
}

/// The drop-in this writes.
///
/// `00-` so it sorts first: later files win for scalar keys, so a policy an
/// operator wrote by hand in their own file overrides this one rather than
/// being silently overridden by it.
fn control_path(config_dir: &Path) -> PathBuf {
	config_dir.join("conf.d").join("00-control.conf")
}

fn render(control: &Control) -> String {
	let mut text = String::new();
	text.push_str(
		"# Who may ask netcfgd for what. Written by `ncfg control set`.\n\
		 #\n\
		 # Ordinary netcfgd configuration: read it, diff it, commit it, or\n\
		 # delete it. Deleting it restores the default, which is root only.\n\
		 #\n\
		 # observe -- ask what the network looks like\n\
		 # wifi    -- join, leave and scan networks the configuration describes\n\
		 # admin   -- change anything else, including adding a network\n",
	);
	text.push_str("\nglobal {\n\tcontrol {\n");
	for (key, principal) in [
		("observe", &control.observe),
		("wifi", &control.wifi),
		("admin", &control.admin),
	] {
		let _ = writeln!(text, "\t\t{key} = \"{}\"", principal.render());
	}
	text.push_str("\t}\n}\n");
	text
}

/// Which file defines a `global` block, if one does.
///
/// Read as text rather than asked of the compiler, because what matters here is
/// *where the block is written*, and a compiled document has already merged
/// everything into one set of globals.
fn defines_global(config_dir: &Path, options: &Options) -> Result<Option<PathBuf>, String> {
	let factory_dir = config::resolve_factory_dir(options.factory_dir.as_deref());
	let sources = config::load_layered(&factory_dir, config_dir)
		.map_err(|error| format!("could not read {}: {error}", config_dir.display()))?;

	for id in sources.ids() {
		for line in sources.text(id).lines() {
			let line = line.trim_start();
			if line.starts_with("global") || line.starts_with("override global") {
				return Ok(Some(PathBuf::from(sources.name(id))));
			}
		}
	}
	Ok(None)
}

/// Just the `control { ... }` part, for pasting into a block that exists.
fn render_inner(control: &Control) -> String {
	let mut text = String::from("\tcontrol {\n");
	for (key, principal) in [
		("observe", &control.observe),
		("wifi", &control.wifi),
		("admin", &control.admin),
	] {
		let _ = writeln!(text, "\t\t{key} = \"{}\"", principal.render());
	}
	text.push_str("\t}\n");
	text
}

/// `ncfg control show|set`.
///
/// # Errors
///
/// Returns a sentence for a person.
pub(crate) fn run(positional: &[String], options: &Options) -> Result<ExitCode, String> {
	let Some(subcommand) = positional.first() else {
		return Err("`ncfg control` takes `show` or `set`".to_owned());
	};
	match subcommand.as_str() {
		"show" => show(options),
		"set" => set(options),
		other => Err(format!(
			"unknown control subcommand `{other}`; it is `show` or `set`"
		)),
	}
}

fn show(options: &Options) -> Result<ExitCode, String> {
	let (document, _) = super::compile(options)?;
	let control = &document.globals.control;

	println!("observe  {}", control.observe.render());
	println!("wifi     {}", control.wifi.render());
	println!("admin    {}", control.admin.render());

	// The socket's mode follows the policy, and an operator reading this is
	// nearly always asking why a client was refused. Saying which file decides
	// is the part that saves the afternoon.
	if !control.opens_beyond_root() {
		println!();
		println!("every tier is root, so the socket is root-only and no client run");
		println!("by an ordinary user can reach it. `ncfg control set` changes that.");
	}
	Ok(ExitCode::SUCCESS)
}

/// Parse `--observe`, `--wifi` and `--admin`, leaving what was not named alone.
fn set(options: &Options) -> Result<ExitCode, String> {
	let (document, _) = super::compile(options)?;
	let mut control = document.globals.control.clone();
	let mut named = false;

	for (given, tier) in [
		(&options.control.observe, &mut control.observe),
		(&options.control.wifi, &mut control.wifi),
		(&options.control.admin, &mut control.admin),
	] {
		let Some(value) = given else { continue };
		*tier = Principal::parse(value).map_err(|message| {
			format!(
				"`{value}` is not a principal: {message}. For example: \
				 group:netcfgd, user:alice, any, root"
			)
		})?;
		named = true;
	}
	if !named {
		return Err(
			"`ncfg control set` needs at least one of --observe, --wifi or --admin. \
			 `ncfg control show` prints the policy now"
				.to_owned(),
		);
	}

	let config_dir = config::resolve_dir(options.config_dir.as_deref());

	// A drop-in can only *replace* a `global` block, never adjust one key of
	// it: section 3 makes redefining a block a compile error and `override`
	// replace it whole, deliberately, so that last-wins is never silent.
	//
	// Measured rather than assumed, because the failure is quiet and severe:
	// with `override global { control { ... } }` beside a `global` naming a
	// DNS mode, the compiled mode came back `none`. Writing this drop-in on a
	// configured machine would take that machine's name resolution away to
	// change who may open a socket.
	//
	// So it is refused where a `global` block already exists, with the text to
	// paste. Editing somebody's own file is the other answer and is a bigger
	// piece of work than this: it means locating a block in a file a person
	// wrote and splicing into it, on the file that decides who may configure
	// the network.
	if let Some(existing) = defines_global(&config_dir, options)? {
		let block = render_inner(&control);
		return Err(format!(
			"{} already defines a `global` block, and a drop-in can only replace \
			 one whole rather than adjust a key of it -- writing one here would \
			 silently take away every other global setting, name resolution \
			 included.\n\nAdd this to that block instead:\n\n{block}",
			existing.display()
		));
	}

	let path = control_path(&config_dir);
	if let Some(parent) = path.parent() {
		std::fs::create_dir_all(parent)
			.map_err(|error| format!("could not create {}: {error}", parent.display()))?;
	}
	// Kept, so a failed verification can put back exactly what was there. A
	// command that widens who may configure the network must not be able to
	// leave the machine with a policy nobody chose.
	let previous = std::fs::read(&path).ok();

	config::write_atomically(&path, render(&control).as_bytes(), 0o644)
		.map_err(|error| format!("could not write {}: {error}", path.display()))?;

	// Compiled back through the loader the daemon uses, for the reason
	// `wifi_profile::install` does it: a generated file that does not compile
	// takes the whole directory with it, and this one decides who may talk to
	// the daemon at all.
	if let Err(error) = verify(options, &control) {
		match previous {
			Some(bytes) => {
				let _ = config::write_atomically(&path, &bytes, 0o644);
			}
			None => {
				let _ = std::fs::remove_file(&path);
			}
		}
		return Err(error);
	}

	println!("{}", path.display());
	println!("observe  {}", control.observe.render());
	println!("wifi     {}", control.wifi.render());
	println!("admin    {}", control.admin.render());
	if control.opens_beyond_root() {
		println!();
		println!("netcfgd applies this when it next reads its configuration. A member of");
		println!("a named group has to log out and back in before the kernel gives their");
		println!("session that membership.");
	}
	Ok(ExitCode::SUCCESS)
}

fn verify(options: &Options, wanted: &Control) -> Result<(), String> {
	let (document, _) = super::compile(options)
		.map_err(|error| format!("that policy does not compile, so it was put back:\n{error}"))?;
	if &document.globals.control != wanted {
		return Err(
			"the policy was written and compiled to something else, so it was put \
			 back. This is a bug in `ncfg control set`"
				.to_owned(),
		);
	}
	Ok(())
}
