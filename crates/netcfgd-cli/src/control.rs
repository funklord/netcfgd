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

/// The end of the block whose opening brace is at `open`.
///
/// Strings and comments are skipped, because a brace inside either is not a
/// brace: an SSID may be written `"{}"` and a comment may say anything. Hook
/// bodies are the config language's one irregular production and cannot occur
/// here -- they are per-interface, and this only ever walks `global`.
fn matching_brace(text: &str, open: usize) -> Option<usize> {
	let bytes = text.as_bytes();
	let mut depth = 0usize;
	let mut at = open;
	let mut in_string = false;
	let mut in_comment = false;

	while at < bytes.len() {
		let byte = bytes[at];
		if in_comment {
			if byte == b'\n' {
				in_comment = false;
			}
		} else if in_string {
			if byte == b'\\' {
				at += 1;
			} else if byte == b'"' {
				in_string = false;
			}
		} else {
			match byte {
				b'"' => in_string = true,
				b'#' => in_comment = true,
				b'{' => depth += 1,
				b'}' => {
					depth -= 1;
					if depth == 0 {
						return Some(at);
					}
				}
				_ => {}
			}
		}
		at += 1;
	}
	None
}

/// Where a block with this head begins and ends, searching only `within`.
///
/// Returns the span from the start of the head word to just past its closing
/// brace, so a caller can replace the whole thing.
fn block_span(text: &str, within: std::ops::Range<usize>, head: &str) -> Option<(usize, usize)> {
	let mut at = within.start;
	while let Some(found) = text[at..within.end].find(head) {
		let start = at + found;
		// A word, not a substring: `controller = ...` is not `control`.
		let before_ok = start == 0
			|| !text.as_bytes()[start - 1].is_ascii_alphanumeric()
				&& text.as_bytes()[start - 1] != b'_';
		let after = start + head.len();
		let rest = &text[after..within.end];
		let brace = rest.find('{').map(|offset| after + offset);
		if before_ok {
			if let Some(brace) = brace {
				// Nothing but whitespace between the head and its brace.
				if text[after..brace].trim().is_empty() {
					if let Some(close) = matching_brace(text, brace) {
						return Some((start, close + 1));
					}
				}
			}
		}
		at = after;
	}
	None
}

/// Put this policy into the `global` block of a file that already has one.
///
/// A drop-in cannot do this: section 3 makes `override global` replace the
/// block *whole*, so a policy written that way silently takes every other
/// global setting with it -- measured, and it turned a machine's DNS mode from
/// `write_resolv_conf` into `none`. So the block is edited where it lives.
///
/// Text in, text out, and nothing else touched: an existing `control` block is
/// replaced in place and a missing one is inserted before the closing brace,
/// with the indentation the file already uses. **The proof that this did not
/// eat anything is in the caller**, which compiles before and after and refuses
/// to keep a result that differs anywhere but the control policy.
fn splice_control(text: &str, control: &Control) -> Result<String, String> {
	let (global_start, global_end) = block_span(text, 0..text.len(), "global")
		.ok_or_else(|| "that file has no `global` block after all".to_owned())?;
	let open = text[global_start..global_end]
		.find('{')
		.map(|offset| global_start + offset)
		.ok_or_else(|| "the `global` block has no opening brace".to_owned())?;
	let close = global_end - 1;

	// The indentation of whatever is already inside, so the result looks like
	// the file rather than like this function.
	let indent = text[open + 1..close]
		.lines()
		.find(|line| !line.trim().is_empty())
		.map_or("\t".to_owned(), |line| {
			line.chars()
				.take_while(|c| *c == '\t' || *c == ' ')
				.collect()
		});
	let block = render_inner(control, &indent);

	if let Some((start, end)) = block_span(text, open + 1..close, "control") {
		let mut out = String::with_capacity(text.len() + block.len());
		out.push_str(&text[..start]);
		out.push_str(block.trim_start_matches(['\t', ' ']).trim_end_matches('\n'));
		out.push_str(&text[end..]);
		return Ok(out);
	}

	let mut out = String::with_capacity(text.len() + block.len());
	out.push_str(&text[..close]);
	if !out.ends_with('\n') {
		out.push('\n');
	}
	out.push_str(&block);
	out.push_str(&text[close..]);
	Ok(out)
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
fn render_inner(control: &Control, indent: &str) -> String {
	let mut text = format!("{indent}control {{\n");
	for (key, principal) in [
		("observe", &control.observe),
		("wifi", &control.wifi),
		("admin", &control.admin),
	] {
		let _ = writeln!(text, "{indent}{indent}{key} = \"{}\"", principal.render());
	}
	let _ = writeln!(text, "{indent}}}");
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
		return splice_into(&existing, &control, options);
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
	report(&control);
	Ok(ExitCode::SUCCESS)
}

/// What the policy is now, and what an operator still has to do about it.
fn report(control: &Control) {
	println!("observe  {}", control.observe.render());
	println!("wifi     {}", control.wifi.render());
	println!("admin    {}", control.admin.render());
	if control.opens_beyond_root() {
		println!();
		println!("netcfgd applies this when it next reads its configuration. A member of");
		println!("a named group has to log out and back in before the kernel gives their");
		println!("session that membership.");
	}
}

/// Edit the `global` block that exists, and prove nothing else moved.
///
/// The proof is the point and it is stated as an invariant rather than left to
/// review: **compile before, compile after, and the two documents may differ in
/// `globals.control` and nowhere else.** Splicing text into a file somebody
/// wrote is the kind of change that eats a line and looks fine, and this one
/// happens on the file that decides who may configure the network -- so a
/// result that fails the invariant is put back rather than reported.
fn splice_into(path: &Path, wanted: &Control, options: &Options) -> Result<ExitCode, String> {
	let (before, _) = super::compile(options)?;
	let text = std::fs::read_to_string(path)
		.map_err(|error| format!("could not read {}: {error}", path.display()))?;
	let spliced = splice_control(&text, wanted)?;

	config::write_atomically(path, spliced.as_bytes(), 0o644)
		.map_err(|error| format!("could not write {}: {error}", path.display()))?;

	let put_back = |why: String| -> String {
		let _ = config::write_atomically(path, text.as_bytes(), 0o644);
		why
	};

	let (after, _) = match super::compile(options) {
		Ok(compiled) => compiled,
		Err(error) => {
			return Err(put_back(format!(
				"editing {} produced something that does not compile, so it was \
				 put back:\n{error}",
				path.display()
			)))
		}
	};
	if &after.globals.control != wanted {
		return Err(put_back(format!(
			"{} was edited and the policy compiled to something else, so it was \
			 put back. This is a bug in `ncfg control set`",
			path.display()
		)));
	}

	// Everything but the policy, compared as the compiler sees it. Normalising
	// the one field that is *meant* to differ is what makes this an assertion
	// about the rest rather than a restatement of the edit.
	let mut before_rest = before;
	let mut after_rest = after;
	before_rest.globals.control = Control::default();
	after_rest.globals.control = Control::default();
	if before_rest != after_rest {
		return Err(put_back(format!(
			"editing {} changed something other than the control policy, so it \
			 was put back. This is a bug in `ncfg control set`",
			path.display()
		)));
	}

	println!("{}", path.display());
	report(wanted);
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

#[cfg(test)]
mod tests {
	use super::*;

	fn policy() -> Control {
		Control {
			observe: Principal::parse("group:netcfgd").expect("a principal"),
			wifi: Principal::parse("any").expect("a principal"),
			admin: Principal::default(),
		}
	}

	/// A block that is not there is inserted, and everything else is kept.
	#[test]
	fn a_missing_control_block_is_inserted_without_touching_the_rest() {
		let text = "# mine\nglobal {\n\tdns { mode = \"none\" }\n}\n\ninterface eth0 { }\n";
		let out = splice_control(text, &policy()).expect("it splices");

		assert!(out.contains("# mine"), "{out}");
		assert!(out.contains("dns { mode = \"none\" }"), "{out}");
		assert!(out.contains("interface eth0 { }"), "{out}");
		assert!(out.contains("observe = \"group:netcfgd\""), "{out}");
	}

	/// One that is there is replaced rather than added beside.
	#[test]
	fn an_existing_control_block_is_replaced_not_doubled() {
		let text =
			"global {\n\tcontrol {\n\t\tobserve = \"root\"\n\t}\n\tdns { mode = \"none\" }\n}\n";
		let out = splice_control(text, &policy()).expect("it splices");

		assert_eq!(out.matches("control {").count(), 1, "{out}");
		assert!(out.contains("observe = \"group:netcfgd\""), "{out}");
		assert!(!out.contains("observe = \"root\""), "{out}");
		assert!(out.contains("dns { mode = \"none\" }"), "{out}");
	}

	/// A brace inside a string is not a brace.
	///
	/// An SSID may be written `"weird {name}"`, and a scanner that counted it
	/// would find the wrong end of the block and splice into somebody else's
	/// network. Checked because it is the one input that makes naive brace
	/// matching wrong, and the damage would be silent.
	#[test]
	fn a_brace_inside_a_string_does_not_move_the_end_of_the_block() {
		let text = "global {\n\tdns { mode = \"none\" }\n}\nnetwork \"weird {name}\" {\n\twifi { open = true }\n}\n";
		let out = splice_control(text, &policy()).expect("it splices");

		assert!(out.contains("network \"weird {name}\" {"), "{out}");
		assert!(out.contains("wifi { open = true }"), "{out}");
		// The policy went into `global`, not into the network.
		let global_end = out.find("\nnetwork").expect("the network is still there");
		assert!(out[..global_end].contains("control {"), "{out}");
	}

	/// `controller` is not `control`.
	#[test]
	fn a_head_is_a_word_and_not_a_prefix() {
		let text = "global {\n\tcontroller { x = \"y\" }\n}\n";
		let out = splice_control(text, &policy()).expect("it splices");

		assert!(out.contains("controller { x = \"y\" }"), "{out}");
		assert_eq!(out.matches("control {").count(), 1, "{out}");
	}
}
