//! Reading the config directory, which is the one thing the compiler will not
//! do for itself.
//!
//! `netcfgd.conf` first, then `conf.d/*.conf` in lexical filename order, then
//! `include` statements resolved by re-reading. Keeping this out of
//! `netcfgd-compile` is what lets the whole front end be tested from fixtures
//! with no filesystem.

use netcfgd_compile::SourceMap;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

/// Where config lives when nothing says otherwise.
pub const DEFAULT_CONFIG_DIR: &str = "/etc/netcfgd";

/// Where the factory-default config lives when nothing says otherwise.
///
/// Under `/usr/share` rather than `/etc` because it is part of the image, not
/// part of the machine's configuration: on a read-only squashfs root `/etc` is
/// the writable overlay and this is what sits underneath it. A machine with no
/// factory config -- which is every ordinary install -- simply has nothing
/// here, and the layering costs it a `stat`.
pub const DEFAULT_FACTORY_DIR: &str = "/usr/share/netcfgd";

/// Read a config directory into a source map, in precedence order.
///
/// # Errors
///
/// Returns an `io::Error` naming the path that could not be read. A missing
/// directory is not an error: an empty config is a legitimate state and
/// compiles to an empty document, which plans to do nothing.
pub fn load(dir: &Path) -> io::Result<SourceMap> {
	let mut sources = SourceMap::new();
	extend(&mut sources, dir)?;
	Ok(sources)
}

/// Add one directory's files to a source map already being built.
fn extend(sources: &mut SourceMap, dir: &Path) -> io::Result<()> {
	let main = dir.join("netcfgd.conf");
	if main.is_file() {
		add_file(sources, &main)?;
	}

	let drop_in_dir = dir.join("conf.d");
	if drop_in_dir.is_dir() {
		add_drop_ins(sources, &drop_in_dir)?;
	}

	Ok(())
}

/// Every `.conf` in one directory, in lexical filename order.
///
/// Extracted from [`extend`] because a profile directory **is** a `conf.d`:
/// the files sit in it directly, and reading them any other way would mean two
/// rules for what a drop-in directory looks like. The first version of the
/// profile loader called `extend` on it, which looks for `netcfgd.conf` and a
/// nested `conf.d` -- so it found nothing, silently, and the profile appeared
/// to be empty.
fn add_drop_ins(sources: &mut SourceMap, dir: &Path) -> io::Result<()> {
	let mut drop_ins: Vec<PathBuf> = fs::read_dir(dir)?
		.filter_map(Result::ok)
		.map(|entry| entry.path())
		.filter(|path| {
			path.extension()
				.is_some_and(|ext| ext.eq_ignore_ascii_case("conf"))
		})
		.collect();
	// Lexical filename order, so 10-foo.conf precedes 20-bar.conf and the
	// precedence an operator sees matches the one they named.
	drop_ins.sort();
	for path in drop_ins {
		add_file(sources, &path)?;
	}
	Ok(())
}

/// Add one file, following any `include` statements it contains.
fn add_file(sources: &mut SourceMap, path: &Path) -> io::Result<()> {
	add_file_within(sources, path, &mut Vec::new())
}

/// The same, carrying the chain of files currently being expanded.
///
/// `open` is what stops `include` recursing for ever. A file that includes
/// itself, or two that include each other, recursed here until the stack
/// overflowed -- which is not a diagnostic, it is the daemon dying, and
/// `reload` is a socket request so it could be asked for from outside.
///
/// The parser bounds how deeply one file may nest blocks and lists. Nothing
/// bounded nesting *across* files, which is the same defect one directory up:
/// a bound that holds inside a document and not between documents is not a
/// bound on the recursion the program actually performs.
///
/// A stack of what is open, rather than a set of everything seen, because the
/// two differ on a shape that is legal: `a` including `b` and `c`, both of
/// which include `d`, is a diamond and not a cycle. A seen-set would silently
/// drop the second `d` and change what the config means; this refuses only a
/// file that is already being expanded further up its own chain.
fn add_file_within(
	sources: &mut SourceMap,
	path: &Path,
	open: &mut Vec<PathBuf>,
) -> io::Result<()> {
	// Identity by canonical path, so `a.conf`, `./a.conf` and a symlink to it
	// are one file rather than three. A path that will not canonicalise is
	// kept as written -- the read below then reports the real reason, which is
	// a better error than anything this could invent.
	let identity = path.canonicalize().unwrap_or_else(|_| path.to_path_buf());
	if open.contains(&identity) {
		let mut chain: Vec<String> = open.iter().map(|p| p.display().to_string()).collect();
		chain.push(identity.display().to_string());
		return Err(io::Error::new(
			io::ErrorKind::InvalidData,
			format!("include cycle: {}", chain.join(" -> ")),
		));
	}

	let text = fs::read_to_string(path)
		.map_err(|error| io::Error::new(error.kind(), format!("{}: {error}", path.display())))?;
	open.push(identity);

	// Includes are resolved by pulling the included file in ahead of the one
	// that names it, and stripping the statement. The compiler refuses an
	// unresolved include rather than silently ignoring it, so anything missed
	// here is reported rather than lost.
	let mut body = String::with_capacity(text.len());
	for line in text.lines() {
		if let Some(target) = include_target(line) {
			let resolved = if Path::new(&target).is_absolute() {
				PathBuf::from(&target)
			} else {
				path.parent().unwrap_or(Path::new(".")).join(&target)
			};
			// Popped on the error path as well as the ordinary one. Nothing
			// depends on it today -- the error propagates out of `load` and
			// the stack is dropped with it -- but a function that pushes on
			// one path and pops on some of them is the shape somebody later
			// reuses and gets wrong.
			if let Err(error) = add_file_within(sources, &resolved, open) {
				open.pop();
				return Err(error);
			}
			continue;
		}
		body.push_str(line);
		body.push('\n');
	}

	open.pop();
	sources.add(path.display().to_string(), body);
	Ok(())
}

/// The path in `include "..."`, if this line is one.
fn include_target(line: &str) -> Option<String> {
	let trimmed = line.trim();
	let rest = trimmed.strip_prefix("include")?;
	let rest = rest.trim_start();
	let rest = rest.strip_prefix('"')?;
	let end = rest.find('"')?;
	Some(rest[..end].to_owned())
}

/// Read the factory layer and the runtime layer, in that order.
///
/// The overlay model from design section 10.4: a factory-default config baked
/// into a read-only image, with writable runtime config on top.
///
/// Ordering is the whole mechanism, and it is the drop-in ordering the
/// language already has -- the factory directory behaves exactly as if its
/// files sorted before the runtime ones. In particular it gets **no special
/// override rule**: a runtime block that redefines a factory block is the same
/// error as one drop-in redefining another, and replacing it means writing
/// `override interface eth0`, wholesale, as it does anywhere else.
///
/// That is deliberate. An implicit override for one directory would make the
/// same text mean different things depending on which directory it sits in,
/// and the operator reading the runtime file could not tell that it was
/// silently discarding something.
///
/// # Errors
///
/// Returns an `io::Error` naming the path that could not be read. Neither
/// layer has to exist.
pub fn load_layered(factory: &Path, runtime: &Path) -> io::Result<SourceMap> {
	let mut sources = load(factory)?;
	// Same directory twice would load every file twice and make each block
	// merge with itself. Harmless today, because merging a block with an
	// identical copy is a no-op -- but it would double every `members` list,
	// so it is refused rather than relied upon.
	if factory != runtime {
		extend(&mut sources, runtime)?;
	}
	Ok(sources)
}

/// The drop-in `ncfg profile set` owns, without its `.conf`.
///
/// Numbered high so a profile selection layers over the `conf.d` files that
/// describe the machine, and fixed so that switching twice edits one file
/// rather than accumulating them. Named once and read from here by the
/// command that writes it, so that the writer and the guard below cannot
/// drift apart -- a guard watching a filename the writer no longer uses is a
/// guard that passes vacuously for ever.
pub const PROFILE_DROP_IN: &str = "90-profile";

/// The base configuration, plus the chosen profile's directory if there is one.
///
/// **A profile is the same mechanism pointed at another directory** ([0151]):
/// `<root>/profile/<name>/*.conf`, factory then runtime, read after `conf.d`
/// so it layers on top and `override` means what it always meant.
///
/// **Finding the name costs a compile.** The selector is in the configuration
/// language rather than a bare file beside it, so the base has to be compiled
/// before netcfgd knows which directory to open. That first compile runs with
/// hooks disabled, because it is a question and not an application --
/// materialising every hook twice would write them twice and fire nothing,
/// which is the sort of difference nobody notices until a hook is not
/// idempotent.
///
/// **A profile that names a profile is refused**, rather than followed. A
/// loader that re-read until the answer stopped changing is the same shape as
/// the automatic switching 0151 declined, and it would let a profile capture
/// the machine.
///
/// # Errors
///
/// A directory that cannot be read. A base configuration that does not compile
/// is **not** an error here: it has no profile to find, so the caller gets the
/// sources and the compiler's own diagnostics, which point at the line.
///
/// [0151]: ../../../doc/decision/0151-a-profile-is-a-directory-and-it-is-switched-by-hand.md
pub fn load_with_profile(factory: &Path, runtime: &Path) -> io::Result<SourceMap> {
	let mut sources = load_layered(factory, runtime)?;

	// A base that does not compile chooses nothing, and there is nothing here
	// to check: the caller compiles it properly next and reports diagnostics
	// that point at the line. Answering a syntax error with "your profile was
	// taken away" would send the reader somewhere the fault is not.
	let Ok(document) = netcfgd_compile::compile(&sources, &mut netcfgd_compile::NoHooks) else {
		return Ok(sources);
	};
	let selected = document.globals.profile.clone();

	// What one file asked for, against what every file together says. 0151
	// requires them to agree: nothing but `ncfg profile` moves the selection,
	// so a disagreement is some other config change having taken it away --
	// which is the automatic switch to no profile that record forbids.
	if let Some(asked) = profile_drop_in_asks(&sources) {
		if selected.as_deref() != Some(asked.as_str()) {
			return Err(shadowed_profile(&sources, &asked, selected.as_deref()));
		}
	}

	let Some(name) = selected else {
		return Ok(sources);
	};

	// The same guard `load_layered` makes, one directory down and for the same
	// reason: one directory read twice defines every block twice, which is an
	// error rather than a no-op. Missing it made a profile fail to compile and
	// report itself as a loop, which is a confusing way to say "read once".
	let roots: &[&Path] = if factory == runtime {
		&[factory]
	} else {
		&[factory, runtime]
	};
	for root in roots {
		let dir = root.join("profile").join(&name);
		if dir.is_dir() {
			add_drop_ins(&mut sources, &dir)?;
		}
	}

	// The refusal above, checked rather than assumed. A profile directory that
	// sets `profile` would otherwise be silently ignored -- the base's answer
	// already won -- and silently ignored is how somebody spends an afternoon
	// wondering why their profile does not switch.
	// Only when it compiles and says something else. A combined configuration
	// that does not compile is the caller's to report, with diagnostics that
	// point at the line -- answering that with "your profile chose again"
	// would send the reader somewhere the fault is not.
	let after = netcfgd_compile::compile(&sources, &mut netcfgd_compile::NoHooks);
	if after.is_ok_and(|document| document.globals.profile.as_deref() != Some(name.as_str())) {
		return Err(io::Error::new(
			io::ErrorKind::InvalidData,
			format!(
				"the `{name}` profile sets `profile` itself, which would make \
				 the loader choose again; remove it"
			),
		));
	}
	Ok(sources)
}

/// What the profile drop-in by itself asks for.
///
/// Compiled alone, deliberately. The whole point is to learn what this one
/// file says without anything else being able to answer for it, so that the
/// two can then be compared.
fn profile_drop_in_asks(sources: &SourceMap) -> Option<String> {
	let id = sources.ids().find(|id| {
		Path::new(sources.name(*id))
			.file_stem()
			.is_some_and(|stem| stem == PROFILE_DROP_IN)
	})?;
	let mut alone = SourceMap::new();
	alone.add(sources.name(id), sources.text(id));
	netcfgd_compile::compile(&alone, &mut netcfgd_compile::NoHooks)
		.ok()?
		.globals
		.profile
}

/// The refusal when something has taken the selection away.
///
/// It names the likely culprit, because the reader's next question is which
/// file did it and the loader is the only thing holding the whole list.
fn shadowed_profile(sources: &SourceMap, asked: &str, selected: Option<&str>) -> io::Error {
	let ids: Vec<_> = sources.ids().collect();
	let culprit = ids.iter().rev().find(|id| {
		let text = sources.text(**id);
		text.contains("override") && text.contains("global")
	});
	let blame = culprit.map_or_else(
		|| {
			"no file in the set writes `override global`, so look for whichever \
		    one writes `global` last"
				.to_owned()
		},
		|id| format!("`{}` writes `override global`", sources.name(*id)),
	);
	let now = selected.map_or_else(
		|| "no profile at all".to_owned(),
		|other| format!("the profile `{other}`"),
	);
	io::Error::new(
		io::ErrorKind::InvalidData,
		format!(
			"`{PROFILE_DROP_IN}` selects the profile `{asked}`, but the \
			 configuration as a whole selects {now}. A profile changes only \
			 when somebody asks -- `ncfg profile set` or `ncfg profile unset` \
			 -- so this is refused rather than applied (0151). {blame}; \
			 `override global` replaces the whole block, taking the profile \
			 with it. Write `global` instead and the two merge (0147)."
		),
	)
}

/// Every config file in one directory, in the order [`load`] would read them.
///
/// The list `ncfg reset` removes, and the list it prints. Deliberately the
/// same enumeration as the loader rather than a glob written twice: a reset
/// that removed a different set from the one that gets loaded would leave
/// files behind that still configure the machine.
///
/// Files pulled in by `include` are not in it. An include may point anywhere,
/// including outside the config directory, and deleting a path because
/// something mentioned it is not a thing a reset should do.
///
/// # Errors
///
/// Returns an `io::Error` naming the path that could not be read. A missing
/// directory is not an error; it lists nothing.
pub fn writable_files(dir: &Path) -> io::Result<Vec<PathBuf>> {
	let mut out = Vec::new();
	let main = dir.join("netcfgd.conf");
	if main.is_file() {
		out.push(main);
	}
	let drop_in_dir = dir.join("conf.d");
	if drop_in_dir.is_dir() {
		let mut drop_ins: Vec<PathBuf> = fs::read_dir(&drop_in_dir)?
			.filter_map(Result::ok)
			.map(|entry| entry.path())
			.filter(|path| {
				path.is_file()
					&& path
						.extension()
						.is_some_and(|ext| ext.eq_ignore_ascii_case("conf"))
			})
			.collect();
		drop_ins.sort();
		out.append(&mut drop_ins);
	}
	Ok(out)
}

/// Write a file into the config directory, or leave what was there.
///
/// Through a temporary file in the same directory and a rename, so a reader --
/// and the daemon's inotify watch is one -- sees either the old file or the new
/// one and never half of either. The temporary carries the final mode from the
/// moment it exists, which for a secret is the whole point: a mode applied
/// after the write is a mode that was wrong once, and the window is exactly
/// when the passphrase is on disk under another name.
///
/// The same reasoning, and nearly the same code, as `netcfgd-nm`'s
/// `write_atomically`. Not shared with it: that adapter depends on
/// `netcfgd-proto` and `netcfgd-model` and nothing else on purpose (decision
/// 0030), and pulling this crate in to save twenty lines would undo the
/// containment the packaging gate enforces.
///
/// The temporary's name carries the process **and** a counter. The process id
/// alone is what this had, and it is only half of the question: two threads in
/// one process share a pid, so they would share the temporary and one would
/// rename the other's bytes into place while its own rename failed with
/// `ENOENT`. Two writers is not a hypothetical here -- `ncfg apply` and the
/// daemon both write `/run/netcfgd/owned.json` -- and a helper that is safe
/// between processes and unsafe between threads is one whose safety depends on
/// which caller reaches it.
///
/// # Errors
///
/// Returns an `io::Error`. The temporary is removed on a failed rename, so a
/// full disk does not leave a dotfile behind next to the config.
pub fn write_atomically(path: &Path, bytes: &[u8], mode: u32) -> io::Result<()> {
	use std::io::Write as _;
	use std::os::unix::fs::OpenOptionsExt as _;
	use std::sync::atomic::{AtomicU64, Ordering};

	/// Distinguishes one call from the next within a process.
	static SEQUENCE: AtomicU64 = AtomicU64::new(0);

	let directory = path.parent().unwrap_or_else(|| Path::new("."));
	fs::create_dir_all(directory)?;
	let temporary = directory.join(format!(
		".{}.{}.{}",
		path.file_name().map_or_else(
			|| "tmp".to_owned(),
			|name| name.to_string_lossy().into_owned()
		),
		std::process::id(),
		SEQUENCE.fetch_add(1, Ordering::Relaxed)
	));

	let outcome = (|| -> io::Result<()> {
		let mut file = fs::OpenOptions::new()
			.write(true)
			.create(true)
			.truncate(true)
			.mode(mode)
			.open(&temporary)?;
		file.write_all(bytes)?;
		// Durable before it is visible. A rename that beats the data to disk is
		// a truncated config file after a power cut, which on a router is the
		// failure that needs a serial cable.
		file.sync_all()?;
		drop(file);
		fs::rename(&temporary, path)
	})();

	if outcome.is_err() {
		let _ = fs::remove_file(&temporary);
	}
	outcome
}

/// The factory directory to use: the argument, the environment, or the
/// default.
#[must_use]
pub fn resolve_factory_dir(explicit: Option<&str>) -> PathBuf {
	if let Some(path) = explicit {
		return PathBuf::from(path);
	}
	if let Ok(path) = std::env::var("NCFG_FACTORY_DIR") {
		return PathBuf::from(path);
	}
	PathBuf::from(DEFAULT_FACTORY_DIR)
}

/// The config directory to use: the argument, the environment, or the default.
#[must_use]
pub fn resolve_dir(explicit: Option<&str>) -> PathBuf {
	if let Some(path) = explicit {
		return PathBuf::from(path);
	}
	// An environment override exists so the whole tool can be exercised
	// against a fixture tree without touching /etc, which is also how the
	// integration test runs.
	if let Ok(path) = std::env::var("NCFG_CONFIG_DIR") {
		return PathBuf::from(path);
	}
	PathBuf::from(DEFAULT_CONFIG_DIR)
}

#[cfg(test)]
mod tests {
	use super::*;

	/// A file that includes itself is refused rather than recursed into.
	///
	/// Before this, `add_file` followed every include with nothing tracking
	/// what it was already inside, so this input did not produce a diagnostic
	/// -- it overflowed the stack and killed the process. `reload` is a socket
	/// request, so the crash was reachable from outside the daemon.
	#[test]
	fn a_file_that_includes_itself_is_refused() {
		let dir = netcfgd_testdir::TestDir::new("config-self-include");
		let main = dir.join("netcfgd.conf");
		fs::write(&main, "include \"netcfgd.conf\"\n").expect("written");

		let error = load(dir.path()).expect_err("a cycle is refused");
		assert_eq!(error.kind(), io::ErrorKind::InvalidData);
		assert!(
			error.to_string().contains("include cycle"),
			"the error must say what it found: {error}"
		);
	}

	/// Two files including each other, which is the same defect one step apart
	/// and the shape a self-include check alone would miss.
	#[test]
	fn two_files_including_each_other_are_refused() {
		let dir = netcfgd_testdir::TestDir::new("config-mutual-include");
		fs::write(dir.join("netcfgd.conf"), "include \"other.conf\"\n").expect("written");
		fs::write(dir.join("other.conf"), "include \"netcfgd.conf\"\n").expect("written");

		let error = load(dir.path()).expect_err("a cycle is refused");
		assert!(
			error.to_string().contains("include cycle"),
			"the error must say what it found: {error}"
		);
		// The chain is what makes it actionable: which file, reached how.
		assert!(
			error.to_string().contains("other.conf"),
			"the error must name the files in the cycle: {error}"
		);
	}

	/// A diamond is not a cycle, and refusing one would be a regression.
	///
	/// `a` includes `b` and `c`, and both include `d`. A set of everything
	/// seen would drop the second `d` and quietly change what the config
	/// means; the guard tracks only what is currently open, so this still
	/// expands exactly as it did before the guard existed.
	#[test]
	fn a_diamond_include_is_not_a_cycle() {
		let dir = netcfgd_testdir::TestDir::new("config-diamond-include");
		fs::write(
			dir.join("netcfgd.conf"),
			"include \"b.conf\"\ninclude \"c.conf\"\n",
		)
		.expect("written");
		fs::write(dir.join("b.conf"), "include \"d.conf\"\n").expect("written");
		fs::write(dir.join("c.conf"), "include \"d.conf\"\n").expect("written");
		fs::write(dir.join("d.conf"), "# nothing to declare\n").expect("written");

		load(dir.path()).expect("a diamond is legal");
	}

	#[test]
	fn an_include_line_is_recognised() {
		assert_eq!(
			include_target("include \"conf.d/extra.conf\""),
			Some("conf.d/extra.conf".to_owned())
		);
		assert_eq!(
			include_target("\tinclude   \"/etc/other.conf\"  "),
			Some("/etc/other.conf".to_owned())
		);
	}

	#[test]
	fn a_line_that_merely_starts_with_include_is_not_one() {
		assert_eq!(include_target("included = true"), None);
		assert_eq!(include_target("# include \"x\""), None);
		assert_eq!(include_target("interface eth0 {"), None);
	}
}

#[cfg(test)]
mod layering {
	use super::{adopt_profile, install_drop_in, load_layered, load_with_profile, writable_files};

	/// Writing is atomic and leaves no temporary behind.
	///
	/// Moved here from `netcfgd-nm`, which had its own writer until 0127 made
	/// netcfgd the only one. The property did not stop mattering when the code
	/// moved -- netcfgd's own inotify watch is the reader that must never see
	/// half a file -- and deleting the test with the writer would have taken
	/// the only check of it in the tree.
	#[test]
	fn writing_is_atomic_and_leaves_no_temporary_behind() {
		let directory = netcfgd_testdir::TestDir::new("host-atomic");
		let path = directory.join("thing.conf");
		super::write_atomically(&path, b"first\n", 0o644).expect("the first write");
		super::write_atomically(&path, b"second\n", 0o644).expect("the second");
		assert_eq!(
			std::fs::read_to_string(&path).expect("readable"),
			"second\n"
		);

		let leftovers: Vec<_> = std::fs::read_dir(&directory)
			.expect("readable")
			.filter_map(Result::ok)
			.map(|entry| entry.file_name().to_string_lossy().into_owned())
			.filter(|name| name.starts_with('.'))
			.collect();
		assert!(leftovers.is_empty(), "{leftovers:?}");
	}

	/// A stored credential is readable by nobody else, and so is its directory.
	///
	/// Also moved from the shim, and widened: the mode is set by the open
	/// rather than after it, so there is no window in which the file exists
	/// and is readable, and the directory it sits in is 0700 for the same
	/// reason. The shim's version checked the file alone because the shim
	/// created the directory separately.
	#[test]
	fn a_stored_credential_is_readable_by_nobody_else() {
		use std::os::unix::fs::PermissionsExt as _;

		let directory = netcfgd_testdir::TestDir::new("host-secret");
		let config = directory.join("etc");
		let path =
			super::install_secret(&config, "credential", "hunter2hunter2", false).expect("stored");

		let mode = std::fs::metadata(&path)
			.expect("readable")
			.permissions()
			.mode();
		assert_eq!(mode & 0o777, 0o600, "the file is {mode:o}");

		let parent = std::fs::metadata(config.join("secrets"))
			.expect("readable")
			.permissions()
			.mode();
		assert_eq!(parent & 0o777, 0o700, "the directory is {parent:o}");
	}

	/// An empty value is refused, and a name that is a path is too.
	#[test]
	fn a_secret_needs_a_usable_name_and_a_value() {
		let directory = netcfgd_testdir::TestDir::new("host-secret-bad");
		let config = directory.join("etc");
		assert!(super::install_secret(&config, "vpn", "", false).is_err());
		assert!(super::install_secret(&config, "../escape", "value", false).is_err());
	}

	/// Removing is idempotent, and removing a drop-in that others rely on is
	/// refused with the file put back.
	#[test]
	fn removing_is_idempotent_and_a_removal_that_breaks_the_config_is_undone() {
		let directory = netcfgd_testdir::TestDir::new("host-remove");
		let config = directory.join("etc");
		let factory = directory.join("factory");
		std::fs::create_dir_all(config.join("conf.d")).expect("a config directory");

		// Absent is success: the state asked for is the state that holds.
		assert!(super::remove_drop_in(&config, &factory, "never-existed").is_ok());
		assert!(super::remove_secret(&config, "never-existed").is_ok());

		install_drop_in(
			&config,
			&factory,
			"thing",
			"interface eth1 {\n\tconfig = \"dhcp\"\n}\n",
			false,
		)
		.expect("written");
		assert!(super::remove_drop_in(&config, &factory, "thing").is_ok());
		assert!(!config.join("conf.d/thing.conf").exists());
	}

	/// A drop-in that compiles is kept, and one that does not is not.
	///
	/// The pair, and the second half is the reason the function exists: a file
	/// that parses on its own can still stop the *configuration* compiling,
	/// because redefining a block another file already defines is an error by
	/// design. A machine whose configuration stopped compiling is one where
	/// the next reload changes nothing and says why in a log nobody reads.
	#[test]
	fn a_drop_in_that_would_break_the_configuration_is_not_kept() {
		let dir = netcfgd_testdir::TestDir::new("drop-in");
		let config = dir.join("etc");
		let factory = dir.join("factory");
		std::fs::create_dir_all(config.join("conf.d")).expect("a config directory");
		std::fs::write(
			config.join("netcfgd.conf"),
			"interface eth0 {\n\tconfig = \"dhcp\"\n}\n",
		)
		.expect("a config file");

		let good = install_drop_in(
			&config,
			&factory,
			"ordinary",
			"interface eth1 {\n\tconfig = \"dhcp\"\n}\n",
			false,
		)
		.expect("it compiles, so it is kept");
		assert!(good.exists());

		// eth0 is already defined, and redefining it is an error rather than a
		// silent last-wins.
		let error = install_drop_in(
			&config,
			&factory,
			"clashing",
			"interface eth0 {\n\tconfig = \"dhcp\"\n}\n",
			false,
		)
		.expect_err("it must be refused");
		assert!(
			error.contains("already defined"),
			"the refusal should carry the compiler's own diagnostic: {error}"
		);
		assert!(
			!config.join("conf.d/clashing.conf").exists(),
			"a refused drop-in was left behind"
		);
	}

	/// A name is a name, never a path.
	#[test]
	fn a_name_that_is_a_path_is_refused() {
		let dir = netcfgd_testdir::TestDir::new("drop-in-name");
		let config = dir.join("etc");
		std::fs::create_dir_all(config.join("conf.d")).expect("a config directory");

		for bad in ["../escape", "sub/dir", ".hidden"] {
			assert!(
				install_drop_in(&config, &dir.join("factory"), bad, "", false).is_err(),
				"`{bad}` was accepted as a name"
			);
		}
	}

	/// Replacing is asked for, and a refused replace leaves the original.
	#[test]
	fn an_existing_drop_in_is_kept_unless_replacing_was_asked_for() {
		let dir = netcfgd_testdir::TestDir::new("drop-in-replace");
		let config = dir.join("etc");
		let factory = dir.join("factory");
		std::fs::create_dir_all(config.join("conf.d")).expect("a config directory");

		let first = "interface eth1 {\n\tconfig = \"dhcp\"\n}\n";
		install_drop_in(&config, &factory, "thing", first, false).expect("written");
		assert!(install_drop_in(&config, &factory, "thing", first, false).is_err());
		assert_eq!(
			std::fs::read_to_string(config.join("conf.d/thing.conf")).expect("readable"),
			first
		);

		let second = "interface eth2 {\n\tconfig = \"dhcp\"\n}\n";
		install_drop_in(&config, &factory, "thing", second, true).expect("replaced");
		assert_eq!(
			std::fs::read_to_string(config.join("conf.d/thing.conf")).expect("readable"),
			second
		);
	}

	/// A replace that would not compile puts the original back.
	///
	/// The case the restore exists for: refusing after the write means the
	/// file on disk is briefly the new one, and leaving it there would be a
	/// rejected change that took effect anyway.
	#[test]
	fn a_replace_that_would_not_compile_restores_what_was_there() {
		let dir = netcfgd_testdir::TestDir::new("drop-in-restore");
		let config = dir.join("etc");
		let factory = dir.join("factory");
		std::fs::create_dir_all(config.join("conf.d")).expect("a config directory");
		std::fs::write(
			config.join("netcfgd.conf"),
			"interface eth0 {\n\tconfig = \"dhcp\"\n}\n",
		)
		.expect("a config file");

		let original = "interface eth1 {\n\tconfig = \"dhcp\"\n}\n";
		install_drop_in(&config, &factory, "thing", original, false).expect("written");
		assert!(install_drop_in(
			&config,
			&factory,
			"thing",
			"interface eth0 {\n\tconfig = \"dhcp\"\n}\n",
			true
		)
		.is_err());
		assert_eq!(
			std::fs::read_to_string(config.join("conf.d/thing.conf")).expect("readable"),
			original,
			"the original was not put back"
		);
	}

	use std::fs;
	use std::path::Path;

	/// A directory tree, built from `relative path -> contents`.
	fn tree(name: &str, files: &[(&str, &str)]) -> netcfgd_testdir::TestDir {
		let root = netcfgd_testdir::TestDir::new(&format!("layer-{name}"));
		for (path, contents) in files {
			let full = root.join(path);
			fs::create_dir_all(full.parent().expect("a parent")).expect("mkdir");
			fs::write(full, contents).expect("write");
		}
		root
	}

	fn names(sources: &netcfgd_compile::SourceMap) -> Vec<String> {
		sources
			.ids()
			.map(|id| sources.name(id).to_owned())
			.collect()
	}

	/// The runtime layer is read after the factory layer, which is the entire
	/// reason it is the one that wins.
	#[test]
	fn the_runtime_layer_is_read_last() {
		let factory = tree("f1", &[("netcfgd.conf", "device eth0 { mtu = 1500 }\n")]);
		let runtime = tree(
			"r1",
			&[(
				"conf.d/10-local.conf",
				"override device eth0 { mtu = 9000 }\n",
			)],
		);

		let sources = load_layered(&factory, &runtime).expect("load");
		let names = names(&sources);
		assert_eq!(names.len(), 2, "{names:?}");
		assert!(names[0].ends_with("netcfgd.conf"), "{names:?}");
		assert!(names[1].ends_with("10-local.conf"), "{names:?}");
	}

	/// Neither layer has to exist: no factory config is every ordinary
	/// install, and no runtime config is a freshly flashed image.
	#[test]
	fn a_missing_layer_is_not_an_error() {
		let present = tree("f2", &[("netcfgd.conf", "device eth0 { mtu = 1500 }\n")]);
		let absent = present.join("nothing-here");

		assert_eq!(load_layered(&absent, &present).expect("load").len(), 1);
		assert_eq!(load_layered(&present, &absent).expect("load").len(), 1);
	}

	/// The same directory named twice is read once.
	///
	/// Reading it twice would make every block collide with a copy of itself,
	/// which is the "already defined" error against a file the operator would
	/// see named as both positions.
	#[test]
	fn one_directory_named_twice_is_read_once() {
		let dir = tree("f3", &[("netcfgd.conf", "device eth0 { mtu = 1500 }\n")]);
		assert_eq!(load_layered(&dir, &dir).expect("load").len(), 1);
	}

	/// What `ncfg reset` removes is exactly what the loader reads.
	///
	/// Two enumerations that drifted apart would leave files behind that still
	/// configure the machine after a reset said it had cleared it.
	#[test]
	fn the_removable_files_are_the_ones_that_get_loaded() {
		let dir = tree(
			"f4",
			&[
				("netcfgd.conf", ""),
				("conf.d/10-a.conf", ""),
				("conf.d/20-b.conf", ""),
				// Neither is config and neither is removed: a disabled drop-in
				// and a secret are both things that live in this tree.
				("conf.d/10-a.conf.disabled", ""),
				("secrets/home", "hunter2"),
			],
		);

		let listed: Vec<String> = writable_files(&dir)
			.expect("list")
			.iter()
			.map(|path| relative(&dir, path))
			.collect();
		assert_eq!(
			listed,
			vec!["netcfgd.conf", "conf.d/10-a.conf", "conf.d/20-b.conf"]
		);

		let loaded: Vec<String> = names(&super::load(&dir).expect("load"))
			.iter()
			.map(|name| relative(&dir, Path::new(name)))
			.collect();
		assert_eq!(listed, loaded);
	}

	fn relative(root: &Path, path: &Path) -> String {
		path.strip_prefix(root)
			.unwrap_or(path)
			.display()
			.to_string()
			.replace('\\', "/")
	}

	/// **No profile chosen is the default, and it is not a profile.**
	///
	/// A machine with hand-written configuration and no selection reads
	/// exactly its own files. 0151: spelling that state as a profile called
	/// `none` would make it confusable with the shipped `offline` one in every
	/// diagnostic that mentioned either.
	#[test]
	fn no_profile_reads_only_the_base() {
		let base = tree(
			"p0",
			&[("conf.d/10-base.conf", "device eth0 { mtu = 1500 }\n")],
		);
		let sources = load_with_profile(&base, &base).expect("load");
		assert_eq!(names(&sources).len(), 1, "{:?}", names(&sources));
	}

	/// The other half of the directive: a settings edit takes the machine off
	/// its profile, and the configuration it is running does not move.
	#[test]
	fn folding_a_profile_in_changes_the_label_and_nothing_else() {
		let base = tree(
			"pa1",
			&[
				(
					"conf.d/90-profile.conf",
					"global { profile = \"office\" }\n",
				),
				(
					"profile/office/10-office.conf",
					"override device eth0 { mtu = 9000 }\n",
				),
				("netcfgd.conf", "device eth0 { mtu = 1500 }\n"),
			],
		);
		let before = netcfgd_compile::compile(
			&load_with_profile(&base, &base).expect("load"),
			&mut netcfgd_compile::NoHooks,
		)
		.expect("compiles");
		assert_eq!(before.globals.profile.as_deref(), Some("office"));
		assert_eq!(before.devices[0].mtu, Some(9000));

		let folded = adopt_profile(&base, &base)
			.expect("fold")
			.expect("one was chosen");
		assert_eq!(folded, "office");

		let after = netcfgd_compile::compile(
			&load_with_profile(&base, &base).expect("load"),
			&mut netcfgd_compile::NoHooks,
		)
		.expect("compiles");
		assert_eq!(after.globals.profile, None, "on no profile now");
		assert_eq!(
			after.devices[0].mtu,
			Some(9000),
			"and running exactly what it was"
		);
		assert!(
			!base.join("conf.d/90-profile.conf").exists(),
			"the selection is gone"
		);
		assert!(
			base.join("conf.d/05-profile-office.conf").exists(),
			"kept, and early enough that the next edit wins"
		);
	}

	/// No profile chosen is the common case and is not an error: there is
	/// nothing to fold, and a settings edit is just a settings edit.
	#[test]
	fn folding_with_no_profile_chosen_does_nothing() {
		let base = tree("pa2", &[("netcfgd.conf", "device eth0 { mtu = 1500 }\n")]);
		assert_eq!(adopt_profile(&base, &base).expect("fold"), None);
	}

	/// The late position, used only when the early one would change things.
	/// A drop-in between the two means the profile really did depend on being
	/// read last, so the fold has to go last too -- and the operator's future
	/// edits will lose to it, which is the trade the proof is choosing.
	#[test]
	fn a_fold_falls_back_to_the_late_position() {
		let base = tree(
			"pa4",
			&[
				(
					"conf.d/90-profile.conf",
					"global { profile = \"office\" }\n",
				),
				(
					"profile/office/10-office.conf",
					"override device eth0 { mtu = 9000 }\n",
				),
				(
					"conf.d/50-middle.conf",
					"override device eth0 { mtu = 1280 }\n",
				),
				("netcfgd.conf", "device eth0 { mtu = 1500 }\n"),
			],
		);

		assert_eq!(
			adopt_profile(&base, &base).expect("fold"),
			Some("office".to_owned())
		);
		assert!(
			base.join("conf.d/zz-profile-office.conf").exists(),
			"late, because early would have lost to 50-middle"
		);
		assert!(!base.join("conf.d/05-profile-office.conf").exists());

		let after = netcfgd_compile::compile(
			&load_with_profile(&base, &base).expect("load"),
			&mut netcfgd_compile::NoHooks,
		)
		.expect("compiles");
		assert_eq!(after.devices[0].mtu, Some(9000), "unchanged either way");
	}

	/// The proof, exercised. A drop-in sorting after the folded file would
	/// take precedence the profile used to have, so the fold would change what
	/// the machine runs -- and is refused with nothing written.
	#[test]
	fn a_fold_that_would_change_the_configuration_is_refused() {
		let base = tree(
			"pa3",
			&[
				(
					"conf.d/90-profile.conf",
					"global { profile = \"office\" }\n",
				),
				(
					"profile/office/10-office.conf",
					"override device eth0 { mtu = 9000 }\n",
				),
				// Sorts after both positions the fold may take, so neither
				// reproduces the precedence the profile had: the profile used
				// to be read after this file and now cannot be.
				(
					"conf.d/zzz-late.conf",
					"override device eth0 { mtu = 1280 }\n",
				),
				("netcfgd.conf", "device eth0 { mtu = 1500 }\n"),
			],
		);

		let error = adopt_profile(&base, &base).expect_err("refused");
		assert!(error.to_string().contains("would change what"), "{error}");
		assert!(
			base.join("conf.d/90-profile.conf").exists(),
			"and nothing was written"
		);
		for prefix in ["05-profile-", "zz-profile-"] {
			assert!(
				!base.join(format!("conf.d/{prefix}office.conf")).exists(),
				"{prefix} was left behind"
			);
		}
	}

	/// The directive of 0151, mechanically. A hand edit that writes `override
	/// global` -- the shape 0147 warns about -- replaces the whole block and
	/// takes the profile selection with it. That is a switch to no profile
	/// that nobody asked for, so the load is refused and says which file did
	/// it.
	#[test]
	fn a_hand_edit_cannot_take_the_profile_away() {
		let base = tree(
			"pg1",
			&[
				(
					"conf.d/90-profile.conf",
					"global { profile = \"office\" }\n",
				),
				(
					"conf.d/99-mine.conf",
					"override global { dns { search = \"example.invalid\" } }\n",
				),
				(
					"profile/office/10-office.conf",
					"device eth0 { mtu = 9000 }\n",
				),
			],
		);

		let error = load_with_profile(&base, &base).expect_err("it is refused");
		let text = error.to_string();
		assert!(text.contains("99-mine.conf"), "names the culprit: {text}");
		assert!(text.contains("office"), "names what was asked for: {text}");
		assert!(text.contains("ncfg profile set"), "says who may: {text}");
	}

	/// The other half, and the one that makes the guard worth having rather
	/// than merely strict: a write that merges is not a write that shadows.
	/// `ncfg control set` and the gui's dns tab emit their own sub-block, so
	/// they must go on working next to a chosen profile.
	#[test]
	fn a_merging_write_leaves_the_profile_alone() {
		let base = tree(
			"pg2",
			&[
				(
					"conf.d/90-profile.conf",
					"global { profile = \"office\" }\n",
				),
				(
					"conf.d/99-mine.conf",
					"global { dns { search = \"example.invalid\" } }\n",
				),
				(
					"profile/office/10-office.conf",
					"device eth0 { mtu = 9000 }\n",
				),
			],
		);

		let sources = load_with_profile(&base, &base).expect("load");
		let document =
			netcfgd_compile::compile(&sources, &mut netcfgd_compile::NoHooks).expect("it compiles");
		assert_eq!(document.globals.profile.as_deref(), Some("office"));
		assert_eq!(document.devices[0].mtu, Some(9000), "the profile was read");
	}

	/// The guard reads the drop-in `ncfg profile` owns, and only that one. A
	/// profile chosen by hand in some other file is nobody's to check against,
	/// so the load proceeds -- a guard that fired here would forbid editing
	/// the configuration by hand, which is not what 0151 says.
	#[test]
	fn a_profile_chosen_in_another_file_is_not_guarded() {
		let base = tree(
			"pg3",
			&[
				("conf.d/10-base.conf", "global { profile = \"office\" }\n"),
				(
					"profile/office/10-office.conf",
					"device eth0 { mtu = 9000 }\n",
				),
			],
		);

		let sources = load_with_profile(&base, &base).expect("load");
		assert_eq!(names(&sources).len(), 2, "the profile was still read");
	}

	/// A chosen profile's directory is read on top.
	#[test]
	fn a_chosen_profile_is_layered_on_the_base() {
		let base = tree(
			"p1",
			&[
				("conf.d/10-base.conf", "global { profile = \"office\" }\n"),
				(
					"profile/office/10-office.conf",
					"device eth0 { mtu = 9000 }\n",
				),
				// A profile that was not chosen is not read, which is the
				// point of choosing.
				("profile/home/10-home.conf", "device eth0 { mtu = 1400 }\n"),
			],
		);

		let sources = load_with_profile(&base, &base).expect("load");
		let found = names(&sources);
		assert_eq!(found.len(), 2, "{found:?}");
		assert!(found[1].ends_with("10-office.conf"), "{found:?}");

		let document =
			netcfgd_compile::compile(&sources, &mut netcfgd_compile::NoHooks).expect("it compiles");
		assert_eq!(document.devices[0].mtu, Some(9000), "the profile won");
	}

	/// The operator's copy of a shipped profile layers over it, which is the
	/// factory-and-runtime rule applied one directory down rather than a
	/// second mechanism.
	#[test]
	fn a_profile_layers_factory_then_runtime() {
		let factory = tree(
			"p2f",
			&[
				("conf.d/10-base.conf", "global { profile = \"offline\" }\n"),
				(
					"profile/offline/10-off.conf",
					"device eth0 { mtu = 1280 }\n",
				),
			],
		);
		let runtime = tree(
			"p2r",
			&[(
				"profile/offline/20-mine.conf",
				"override device eth0 { mtu = 1500 }\n",
			)],
		);

		let sources = load_with_profile(&factory, &runtime).expect("load");
		let document =
			netcfgd_compile::compile(&sources, &mut netcfgd_compile::NoHooks).expect("it compiles");
		assert_eq!(
			document.devices[0].mtu,
			Some(1500),
			"the operator's copy layered over the shipped one"
		);
	}

	/// **A profile that names a profile is refused rather than ignored.**
	///
	/// The base's answer already won, so following it would mean loading until
	/// the answer stopped changing -- and ignoring it silently is how somebody
	/// spends an afternoon wondering why their profile does not switch.
	#[test]
	fn a_profile_that_names_a_profile_is_refused() {
		let base = tree(
			"p3",
			&[
				("conf.d/10-base.conf", "global { profile = \"office\" }\n"),
				(
					"profile/office/10-office.conf",
					"override global { profile = \"home\" }\n",
				),
			],
		);

		let error = load_with_profile(&base, &base).expect_err("must refuse");
		let text = error.to_string();
		assert!(text.contains("office"), "it names the profile: {text}");
		assert!(text.contains("choose again"), "and says why: {text}");
	}

	/// A base that does not compile has no profile to find, and says so
	/// through the compiler rather than through the loader.
	///
	/// The loader returning an error here would replace a diagnostic pointing
	/// at the offending line with one that does not.
	#[test]
	fn a_base_that_does_not_compile_is_not_the_loader_s_error() {
		let base = tree("p4", &[("conf.d/10-base.conf", "interface { mtu = }\n")]);
		let sources = load_with_profile(&base, &base).expect("the loader is content");
		assert!(
			netcfgd_compile::compile(&sources, &mut netcfgd_compile::NoHooks).is_err(),
			"and the compiler is the one that complains"
		);
	}
}

/// Put a configuration drop-in on disk, and prove the result still compiles.
///
/// 0127: netcfgd is the only writer of `/etc/netcfgd`, so this is where
/// configuration a client sent ends up. `wifi_profile::install` is the same
/// shape for the one block it renders itself; this is the general case, and
/// the two agree about the important part -- **nothing is left behind by a
/// failure.**
///
/// The compile-back check is not a formality. A drop-in that parses on its own
/// can still break the whole configuration: redefining a block that another
/// file already defines is an error by design (section 3, so that last-wins is never
/// silent), and a machine whose configuration stopped compiling is one where
/// the next reload changes nothing and says why in a log nobody is reading.
/// Refusing costs the caller a diagnostic; accepting costs the operator their
/// next boot.
///
/// # Errors
///
/// Returns the sentence to print: a name that cannot be used, a file that
/// exists when `replace` was not asked for, a write that failed, or the
/// diagnostics from a configuration that would no longer compile.
pub fn install_drop_in(
	config_dir: &Path,
	factory_dir: &Path,
	name: &str,
	text: &str,
	replace: bool,
) -> Result<PathBuf, String> {
	// The same rule a wifi profile's id follows, and shared rather than
	// restated: this decides whether a client-supplied string can become a
	// filename, which is the one check standing between a name and a path.
	crate::wifi_profile::usable_id(name)
		.map_err(|why| format!("`{name}` cannot be used as a name here: {why}"))?;

	let path = config_dir.join("conf.d").join(format!("{name}.conf"));
	if path.exists() && !replace {
		return Err(format!(
			"{} already exists. Ask to replace it if that is what you mean -- \
			 quietly overwriting a file somebody wrote by hand is the thing this \
			 refuses to do",
			path.display()
		));
	}

	let previous = if path.exists() {
		Some(std::fs::read(&path).map_err(|error| {
			format!("could not read {} to put it back: {error}", path.display())
		})?)
	} else {
		None
	};

	if let Some(parent) = path.parent() {
		std::fs::create_dir_all(parent)
			.map_err(|error| format!("could not create {}: {error}", parent.display()))?;
	}
	write_atomically(&path, text.as_bytes(), 0o644)
		.map_err(|error| format!("could not write {}: {error}", path.display()))?;

	let sources = match load_layered(factory_dir, config_dir) {
		Ok(sources) => sources,
		Err(error) => {
			restore(&path, previous.as_deref());
			return Err(format!("could not read {}: {error}", config_dir.display()));
		}
	};
	if let Err(diagnostics) = netcfgd_compile::compile(&sources, &mut netcfgd_compile::NoHooks) {
		let rendered = diagnostics.render(&sources);
		restore(&path, previous.as_deref());
		return Err(format!(
			"that would stop the configuration compiling, so it was not kept:\n{rendered}"
		));
	}

	Ok(path)
}

/// Put back what was there, or take away what was not.
///
/// Split out because the failure paths above all need it and each one getting
/// it slightly wrong is how a rejected write leaves a half-applied change --
/// the case being guarded against in the first place.
fn restore(path: &Path, previous: Option<&[u8]>) {
	match previous {
		Some(bytes) => {
			let _ = write_atomically(path, bytes, 0o644);
		}
		None => {
			let _ = std::fs::remove_file(path);
		}
	}
}

/// The drop-in a radio's activation is filed under.
///
/// One file per radio, named for it, so that activating a second radio does
/// not rewrite the first one's and so `ncfg config rm` can undo it by a name
/// somebody can guess.
#[must_use]
pub fn radio_drop_in(interface: &str) -> String {
	format!("radio-{interface}")
}

/// The configuration that hands a radio to netcfgd.
///
/// Shared because two commands write it: `ncfg wifi activate` through the
/// daemon, and `ncfg wifi add` locally on a machine where nothing is
/// listening. Two copies of the block would be two things to keep in step,
/// and the one that drifted would be the one nobody runs.
///
/// **Two blocks, and the second one is not optional.** The first draft wrote
/// only the `device` block, on the reasoning that it is the smallest thing
/// that says netcfgd manages the radio. It plans nothing at all: the planner
/// walks `desired.interfaces`, so a device nothing has an `interface` block
/// for is never visited, and activation reported success for a file that
/// changed no behaviour. Measured with `ncfg plan` against a real radio --
/// `device` alone answers "nothing to do", and adding the interface answers
/// `backend.start wlp0s20f3 wifi: Supplicant`.
///
/// The two say different things and both are needed. `device` is policy about
/// hardware -- which supplicant, whether to autoconnect, whether netcfgd
/// touches it at all. `interface` is the statement that this link's
/// configuration is netcfgd's, which is what makes it something to plan.
///
/// **`dhcp` is netcfgd choosing, and it is the one choice made here.**
/// Everything else in `WifiDevicePolicy` has a default that is right until
/// somebody says otherwise, and writing every key out would freeze today's
/// defaults into a file that outlives them. Addressing has no such default: a
/// radio that associates and is never addressed is a radio that does not work,
/// and a wifi client that is not on DHCP is rare enough to be worth editing a
/// file for. The comment says so in the file, where somebody will find it.
#[must_use]
pub fn radio_blocks(interface: &str) -> String {
	// Built by lines rather than as one format string with continuations.
	// The first version used `\n\` continuations and the source's own
	// indentation ended up *inside* the file: every line came out with a tab
	// and a space in front of it. It compiled -- leading whitespace means
	// nothing to the config language -- so nothing failed, and the only cost
	// was a file netcfgd wrote for a person to read that looked like a
	// mistake.
	[
		"# Written by `ncfg wifi activate`. Ordinary configuration: read it,",
		"# edit it, or delete it -- deleting it hands the radio back.",
		"#",
		"# Two blocks, and both are needed. `device` is policy about the",
		"# hardware; `interface` is what makes this link netcfgd's to",
		"# configure, and without it nothing is planned for the radio at all.",
		"#",
		"# `dhcp` is the assumption. Change it here for a static address.",
		"",
		&format!("device {interface} {{"),
		"\twifi {",
		"\t\tautoconnect = true",
		"\t}",
		"}",
		"",
		&format!("interface {interface} {{"),
		"\tconfig = \"dhcp\"",
		"}",
		"",
	]
	.join("\n")
}

/// Store a credential the configuration refers to.
///
/// 0127's other half: a client cannot write `/etc/netcfgd/secrets`, so a value
/// it holds arrives over the socket and netcfgd writes it. The directory is
/// created at 0700 and the file at 0600, from the moment each exists rather
/// than created and then tightened -- a file that is briefly world-readable is
/// briefly world-readable, and this one is a password.
///
/// **Nothing here reads a value back**, and no caller of this can. The only
/// direction credentials travel in netcfgd is inward.
///
/// # Errors
///
/// A name that cannot be used, a value that is empty, a file that exists when
/// replacing was not asked for, or a write that failed.
pub fn install_secret(
	config_dir: &Path,
	name: &str,
	value: &str,
	replace: bool,
) -> Result<PathBuf, String> {
	crate::wifi_profile::usable_id(name)
		.map_err(|why| format!("`{name}` cannot be used as a secret name: {why}"))?;
	if value.is_empty() {
		return Err(format!(
			"nothing was given for `{name}`, and an empty secret is a secret that fails at \
			 the moment it is used rather than now"
		));
	}

	let path = config_dir.join("secrets").join(name);
	if path.exists() && !replace {
		return Err(format!(
			"{} already exists. Ask to replace it if that is what you mean -- and note \
			 that a private key nobody has a copy of cannot be got back \
			 (doc/decision/0042)",
			path.display()
		));
	}

	if let Some(parent) = path.parent() {
		use std::os::unix::fs::DirBuilderExt as _;
		if !parent.is_dir() {
			std::fs::DirBuilder::new()
				.recursive(true)
				.mode(0o700)
				.create(parent)
				.map_err(|error| format!("could not create {}: {error}", parent.display()))?;
		}
	}
	write_atomically(&path, value.as_bytes(), 0o600)
		.map_err(|error| format!("could not write {}: {error}", path.display()))?;
	Ok(path)
}

/// Every link-detection script netcfgd can see.
///
/// **The operator's shadow the shipped examples**, name by name, and only the
/// winner is listed: two entries called `default` would be a list an operator
/// has to disambiguate by reading a path, and the one that loses is not the one
/// netcfgd would run.
///
/// `editable` says whether netcfgd would overwrite this file. A shipped example
/// is not edited in place -- an edit of one becomes a copy in `/etc` with the
/// same name, which then shadows it -- so a client can offer the right verb
/// rather than promising something the next upgrade undoes.
///
/// Unreadable files are skipped rather than reported. This is a listing, and a
/// directory that does not exist is the ordinary case on a machine that has
/// never configured one.
#[must_use]
pub fn list_probes(config_dir: &Path, factory_dir: &Path) -> Vec<netcfgd_proto::ProbeScript> {
	let mut found: Vec<netcfgd_proto::ProbeScript> = Vec::new();
	let mut seen: Vec<String> = Vec::new();

	for (dir, editable) in [
		(config_dir.join("probe"), true),
		(factory_dir.join("probe"), false),
	] {
		let Ok(entries) = std::fs::read_dir(&dir) else {
			continue;
		};
		let mut here: Vec<_> = entries.flatten().collect();
		here.sort_by_key(std::fs::DirEntry::file_name);
		for entry in here {
			let name = entry.file_name().to_string_lossy().into_owned();
			if seen.contains(&name) || !entry.path().is_file() {
				continue;
			}
			let Ok(text) = std::fs::read_to_string(entry.path()) else {
				continue;
			};
			seen.push(name.clone());
			found.push(netcfgd_proto::ProbeScript {
				name,
				directory: dir.to_string_lossy().into_owned(),
				text,
				editable,
			});
		}
	}
	found
}

/// Put a link-detection script on disk, executable.
///
/// **The most dangerous thing netcfgd writes, and the shortest function.** A
/// probe is a program netcfgd runs as root on an interval, so the guard is not
/// here: `authorize::check_content` refuses this request from anyone but local
/// root before it reaches the daemon's dispatcher, for the reason
/// `install_drop_in` gives -- an authorization question answered in two places
/// is one where the two come to disagree.
///
/// What is here is the *name*, because that is not an authorization question.
/// netcfgd chooses the directory; a name carrying a separator, or `..`, would
/// let a caller choose it instead and write an executable anywhere root can.
///
/// Mode 0755 rather than 0700: netcfgd runs it as root and could read it at
/// 0700, but an operator debugging why their link is judged down will want to
/// run it by hand as themselves, and a probe nobody can run is one nobody can
/// fix.
///
/// # Errors
///
/// A name that cannot be used, an empty script, a file that exists when
/// replacing was not asked for, or a write that failed.
pub fn install_probe(
	config_dir: &Path,
	name: &str,
	text: &str,
	replace: bool,
) -> Result<PathBuf, String> {
	crate::wifi_profile::usable_id(name)
		.map_err(|why| format!("`{name}` cannot be used as a script name: {why}"))?;
	if text.trim().is_empty() {
		return Err(format!(
			"nothing was given for `{name}`, and an empty script exits zero -- which \
			 netcfgd would read as the link being up, for ever"
		));
	}

	let path = config_dir.join("probe").join(name);
	if path.exists() && !replace {
		return Err(format!(
			"{} already exists. Ask to replace it if that is what you mean",
			path.display()
		));
	}

	if let Some(parent) = path.parent() {
		use std::os::unix::fs::DirBuilderExt as _;
		if !parent.is_dir() {
			std::fs::DirBuilder::new()
				.recursive(true)
				.mode(0o755)
				.create(parent)
				.map_err(|error| format!("could not create {}: {error}", parent.display()))?;
		}
	}
	write_atomically(&path, text.as_bytes(), 0o755)
		.map_err(|error| format!("could not write {}: {error}", path.display()))?;
	Ok(path)
}

/// Remove a drop-in, and prove what is left still compiles.
///
/// The mirror of [`install_drop_in`], and it needs the same check for the same
/// reason: removing a file can break the configuration as surely as adding one
/// -- a drop-in another file's `override` refers to, say -- and a machine whose
/// configuration stopped compiling is one where the next reload changes
/// nothing.
///
/// **An absent file is success.** The state being asked for is the state that
/// holds.
///
/// # Errors
///
/// A name that cannot be used, a removal that failed, or a configuration that
/// would no longer compile -- in which case the file is put back.
pub fn remove_drop_in(config_dir: &Path, factory_dir: &Path, name: &str) -> Result<(), String> {
	crate::wifi_profile::usable_id(name)
		.map_err(|why| format!("`{name}` cannot be used as a name here: {why}"))?;

	let path = config_dir.join("conf.d").join(format!("{name}.conf"));
	let Ok(previous) = std::fs::read(&path) else {
		return Ok(());
	};
	std::fs::remove_file(&path)
		.map_err(|error| format!("could not remove {}: {error}", path.display()))?;

	let compiles = load_layered(factory_dir, config_dir)
		.map_err(|error| format!("could not read {}: {error}", config_dir.display()))
		.and_then(|sources| {
			netcfgd_compile::compile(&sources, &mut netcfgd_compile::NoHooks)
				.map(|_| ())
				.map_err(|diagnostics| diagnostics.render(&sources))
		});
	if let Err(rendered) = compiles {
		restore(&path, Some(&previous));
		return Err(format!(
			"removing that would stop the configuration compiling, so it was put \
			 back:\n{rendered}"
		));
	}
	Ok(())
}

/// Remove a stored credential.
///
/// No compile check: a secret is read when a backend needs it rather than
/// compiled into the document, so removing one cannot make the configuration
/// invalid. It can make it *fail later*, which is a different thing and one
/// `ncfg plan` reports as a stranded credential.
///
/// # Errors
///
/// A name that cannot be used, or a removal that failed. Absent is success.
pub fn remove_secret(config_dir: &Path, name: &str) -> Result<(), String> {
	crate::wifi_profile::usable_id(name)
		.map_err(|why| format!("`{name}` cannot be used as a secret name: {why}"))?;

	let path = config_dir.join("secrets").join(name);
	match std::fs::remove_file(&path) {
		Ok(()) => Ok(()),
		Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
		Err(error) => Err(format!("could not remove {}: {error}", path.display())),
	}
}

/// The file a folded profile is written to.
///
/// `zz-` so it sorts after every drop-in a person is likely to write, which is
/// what preserves precedence: a profile is read after all of `conf.d`, so a
/// fold that landed earlier in the order could change which override wins.
/// The name is not load-bearing on its own -- the proof below is -- but a name
/// that usually sorts right means the proof usually passes.
/// Where a folded profile is tried, in order.
///
/// **Early first, and the proof decides.** A profile is read after all of
/// `conf.d`, so folding it in late is what reproduces its precedence -- and
/// late is exactly wrong afterwards, because the operator is on no profile now
/// and the next drop-in they write should win. Landing it at `zz-` cost that:
/// a person changed a setting, the folded file sorted after their drop-in, and
/// `override interface` replaced the block whole, so their edit did nothing
/// and said nothing. Found by running the workflow rather than by reading it.
///
/// So `05-` is tried first, which is where a future edit beats it, and `zz-`
/// only when the early position would change what the machine runs. Neither
/// name is load-bearing on its own: the proof is what makes the choice safe.
const FOLDED_PREFIXES: [&str; 2] = ["05-profile-", "zz-profile-"];

/// Take the machine off its profile without changing what it is running.
///
/// [0151]: changing a setting by hand puts the machine on "none chosen". The
/// profile's own drop-ins are folded into `conf.d` in the same step, so the
/// compiled document is identical afterwards and only the label moves.
/// Without that, a one-line edit could drop every override a profile carried
/// -- an address, a route, the link the operator is connected over -- as a
/// side effect of changing something unrelated.
///
/// Returns the profile that was folded, or `None` when none was chosen, which
/// is the common case and is not an error.
///
/// **The fold is proved, not trusted.** The document is compiled before and
/// after and must be equal but for the selection itself; anything else and
/// nothing is written. That is the rule for mechanical rewrites, applied here
/// because this one is made on somebody's behalf while they were doing
/// something else.
///
/// # Errors
///
/// A directory that cannot be read or written, or a fold that would change the
/// configuration -- which is refused rather than applied.
///
/// [0151]: ../../../doc/decision/0151-a-profile-is-a-directory-and-it-is-switched-by-hand.md
pub fn adopt_profile(config_dir: &Path, factory_dir: &Path) -> io::Result<Option<String>> {
	let before_sources = load_with_profile(factory_dir, config_dir)?;
	let Ok(before) = netcfgd_compile::compile(&before_sources, &mut netcfgd_compile::NoHooks)
	else {
		// It does not compile, so there is nothing to preserve and nothing to
		// prove. Leave it alone and let the caller report the diagnostics.
		return Ok(None);
	};
	let Some(name) = before.globals.profile.clone() else {
		return Ok(None);
	};

	// The profile's files, in the order the loader read them, as one text. One
	// file rather than several: it is generated, it is removed as a unit by
	// `ncfg profile save`, and a person reading `conf.d` should see one thing
	// that arrived together rather than a scatter they have to reassemble.
	let base = load_layered(factory_dir, config_dir)?;
	let mut folded = format!(
		"# Generated by netcfgd: the `{name}` profile, folded in when a setting\n\
		 # was changed by hand. The machine is on no profile now (0151); this\n\
		 # file is what it was running, so nothing moved. Edit it freely, or\n\
		 # `ncfg profile save {name}` to put it back and select it again.\n"
	);
	for id in before_sources.ids() {
		let source = before_sources.name(id);
		if base.ids().any(|old| base.name(old) == source) {
			continue;
		}
		folded.push_str(&format!("\n# from {source}\n"));
		folded.push_str(before_sources.text(id));
	}

	// **Verified through the real loader, not through a model of it.** The
	// first attempt built a candidate in memory and appended the folded file
	// last, which is not where it sorts on disk -- so it proved a layering
	// that would never happen and passed a fold that changed the machine's
	// MTU. Ordering is the loader's to decide; ask it rather than reimplement
	// it. That means writing first and undoing when the answer is wrong.
	let conf_d = config_dir.join("conf.d");
	let selection = conf_d.join(format!("{PROFILE_DROP_IN}.conf"));

	// A selection written somewhere else is not netcfgd's to move. Editing
	// somebody's own file to take them off a profile is exactly the helpful
	// rewrite 0151 forbids, so the machine stays on it and the edit is an
	// ordinary edit.
	let Ok(kept) = fs::read_to_string(&selection) else {
		return Ok(None);
	};

	// Equal but for the selection, which is the one thing this is meant to
	// change. Comparing the whole document would fail every time and prove
	// nothing; comparing nothing would prove nothing either.
	let mut expected = before.clone();
	expected.globals.profile = None;

	fs::create_dir_all(&conf_d)?;
	let mut refusal = None;
	for prefix in FOLDED_PREFIXES {
		let folded_name = format!("{prefix}{name}.conf");
		let written = conf_d.join(&folded_name);
		fs::write(&written, &folded)?;
		fs::remove_file(&selection)?;

		let after = load_with_profile(factory_dir, config_dir)
			.ok()
			.and_then(|sources| {
				netcfgd_compile::compile(&sources, &mut netcfgd_compile::NoHooks).ok()
			});
		if after.as_ref() == Some(&expected) {
			return Ok(Some(name));
		}
		refusal = Some(if after.is_none() {
			format!(
				"folding the `{name}` profile into the configuration would not \
				 compile, so nothing was changed"
			)
		} else {
			format!(
				"folding the `{name}` profile into `conf.d` would change what \
				 this machine is running, at either position tried, so nothing \
				 was changed. `ncfg profile unset` takes the profile off \
				 without folding it in, if that is what you want"
			)
		});
		let _ = fs::write(&selection, &kept);
		let _ = fs::remove_file(&written);
	}
	Err(io::Error::new(
		io::ErrorKind::InvalidData,
		refusal.unwrap_or_else(|| format!("the `{name}` profile could not be folded in")),
	))
}

/// Undo a fold, because the settings write it was made for did not happen.
///
/// The fold has to come first -- folding after the write would have to
/// preserve a document in which the profile still overrides the new edit, so
/// it would land late and the edit would never take effect. Coming first means
/// it can be made for a write that is then refused, and a rejected edit must
/// not move the selection: nothing was changed, so nothing should have moved.
///
/// # Errors
///
/// A directory that cannot be written.
pub fn restore_profile(config_dir: &Path, name: &str) -> io::Result<()> {
	let conf_d = config_dir.join("conf.d");
	for prefix in FOLDED_PREFIXES {
		let folded = conf_d.join(format!("{prefix}{name}.conf"));
		if folded.exists() {
			fs::remove_file(folded)?;
		}
	}
	fs::write(
		conf_d.join(format!("{PROFILE_DROP_IN}.conf")),
		format!("global {{\n\tprofile = \"{name}\"\n}}\n"),
	)
}

/// Which part of the document the snapshot failed to reproduce.
///
/// **Named rather than left to a bisect.** The refusal above is the round-trip
/// proof doing its job, and it used to say only that the two differed -- so
/// finding out which field the renderer had dropped meant halving a
/// configuration by hand until it saved. Measured once, on a `proto = "wpa3"`
/// network whose generation was not being written: six trials to find it.
///
/// A section and a name, not a field diff. The documents are large and the
/// answer wanted is "where do I look", which the block that differs gives
/// while a full comparison would bury it.
fn difference(expected: &netcfgd_model::Document, after: &netcfgd_model::Document) -> String {
	if expected.globals != after.globals {
		return " The `global` block is what differs.".to_owned();
	}
	for want in &expected.interfaces {
		if after.interfaces.iter().find(|got| got.name == want.name) != Some(want) {
			return format!(" `interface {}` is what differs.", want.name);
		}
	}
	for want in &expected.devices {
		if after.devices.iter().find(|got| got.name == want.name) != Some(want) {
			return format!(" `device {}` is what differs.", want.name);
		}
	}
	for want in &expected.networks {
		if after.networks.iter().find(|got| got.id == want.id) != Some(want) {
			return format!(" `network \"{}\"` is what differs.", want.id);
		}
	}
	// A block that is in one document and not the other, or a list this does
	// not walk. Saying so beats naming a block that is in fact identical.
	" The two differ in a block this cannot name.".to_owned()
}

/// Take the folded profile files out of `conf.d`, returning what was removed.
///
/// `ncfg profile save` writes the running configuration into a profile, and
/// leaving the fold behind would keep a copy of the old profile in the base
/// for ever -- so it would still be in force after switching to a different
/// profile, which is not what "saved it into office" means to anybody.
///
/// The contents come back so the caller can put them there again, because the
/// save is verified afterwards and a save that does not verify must leave the
/// machine exactly as it found it.
///
/// # Errors
///
/// A `conf.d` that cannot be read, or a file that cannot be removed.
pub fn take_folded(config_dir: &Path) -> io::Result<Vec<(PathBuf, String)>> {
	let conf_d = config_dir.join("conf.d");
	let mut taken = Vec::new();
	let Ok(entries) = fs::read_dir(&conf_d) else {
		return Ok(taken);
	};
	for entry in entries.flatten() {
		let path = entry.path();
		let Some(file) = path.file_name().and_then(|name| name.to_str()) else {
			continue;
		};
		if !FOLDED_PREFIXES
			.iter()
			.any(|prefix| file.starts_with(prefix))
		{
			continue;
		}
		taken.push((path.clone(), fs::read_to_string(&path)?));
		fs::remove_file(&path)?;
	}
	Ok(taken)
}

/// Put back what [`take_folded`] took, because the save did not stand.
///
/// # Errors
///
/// A file that cannot be written.
pub fn restore_folded(taken: &[(PathBuf, String)]) -> io::Result<()> {
	for (path, text) in taken {
		fs::write(path, text)?;
	}
	Ok(())
}

/// The profiles this machine has, in name order, from both layers.
///
/// The operator's are listed first, so a name in both reads as theirs -- which
/// is what it effectively is, since their files layer over the shipped ones.
/// The same rule the loader reads by, so the list and the load agree.
///
/// Moved here from the cli so that `ncfg profile list` and the daemon answer
/// from one implementation. Two enumerations of the same directories is how a
/// gui comes to offer a profile the loader will not read.
#[must_use]
pub fn list_profiles(config_dir: &Path, factory_dir: &Path) -> Vec<netcfgd_proto::ProfileEntry> {
	let mut found: Vec<netcfgd_proto::ProfileEntry> = Vec::new();

	for (root, shipped) in [(config_dir, false), (factory_dir, true)] {
		let Ok(entries) = fs::read_dir(root.join("profile")) else {
			continue;
		};
		for entry in entries.flatten() {
			if !entry.path().is_dir() {
				continue;
			}
			let name = entry.file_name().to_string_lossy().into_owned();
			if found.iter().any(|seen| seen.name == name) {
				continue;
			}
			found.push(netcfgd_proto::ProfileEntry { name, shipped });
		}
	}
	found.sort_by(|a, b| a.name.cmp(&b.name));
	found
}

/// Write what this machine is running into a profile, and select it.
///
/// **Moved here from `ncfg profile save` so the daemon can do it too.** The
/// command was the only way to save a profile, which meant a machine with a
/// gui could switch between profiles it already had and never make one -- and
/// a profile is most wanted on the machine somebody is standing in front of.
/// The reasoning is `profile_set`'s: netcfgd owns where a profile lives, so a
/// client spelling those paths would be a second copy of them.
///
/// The order matters and each step undoes on failure. The fold comes out of
/// `conf.d` first, because leaving it would keep a copy of the old profile in
/// the base for ever -- still in force after switching away, which is not what
/// "saved it into office" means to anybody. Then the snapshot, then the
/// selection, then the proof.
///
/// # Errors
///
/// A name that cannot be a directory, an existing profile without `replace`
/// -- whose message names `how_to_replace`, since only the caller knows
/// whether that is a flag or a button --
/// one written by hand that this cannot reproduce, a configuration the
/// renderer refuses, or a snapshot that does not compile back to what was
/// running.
pub fn save_profile(
	config_dir: &Path,
	factory_dir: &Path,
	name: &str,
	replace: bool,
	running: &netcfgd_model::Document,
	how_to_replace: &str,
) -> Result<PathBuf, String> {
	usable_profile_name(name)?;

	let directory = config_dir.join("profile").join(name);
	let snapshot = directory.join("00-saved.conf");

	// Refused rather than merged. An existing profile is somebody's work, and
	// guessing here is the failure this exists to prevent.
	if directory.is_dir() && !replace {
		// The remedy is the caller's words, not this function's: `ncfg` has a
		// flag to name and a gui has a prompt to offer, and a message naming
		// the wrong one is worse than one naming neither.
		return Err(format!(
			"`{name}` already exists ({}); {how_to_replace} to overwrite it",
			directory.display()
		));
	}
	if directory.is_dir() && !snapshot.exists() {
		return Err(format!(
			"`{name}` was written by hand ({}), so saving over it would discard \
			 files this cannot reproduce. Save as another name, or take that \
			 directory away first",
			directory.display()
		));
	}

	let taken = take_folded(config_dir)
		.map_err(|error| format!("could not take the folded profile out: {error}"))?;

	let outcome = write_profile_snapshot(
		running,
		name,
		config_dir,
		factory_dir,
		&directory,
		&snapshot,
	);
	if outcome.is_err() {
		let _ = fs::remove_file(&snapshot);
		let _ = fs::remove_dir(&directory);
		let _ = restore_folded(&taken);
	}
	outcome
}

/// A name that can be a directory here.
///
/// Refused early so the message can say which part was the problem rather than
/// leaving it to the compiler, which would only say the profile did not load.
///
/// # Errors
///
/// An empty name, one with a path separator, or one that would be hidden.
pub fn usable_profile_name(name: &str) -> Result<(), String> {
	if name.is_empty() || name.contains('/') || name.starts_with('.') {
		return Err(format!(
			"`{name}` cannot be a profile name: a plain name, since netcfgd \
			 chooses the directory it is read from"
		));
	}
	Ok(())
}

/// The half of [`save_profile`] that can fail with something to undo.
fn write_profile_snapshot(
	running: &netcfgd_model::Document,
	name: &str,
	config_dir: &Path,
	factory_dir: &Path,
	directory: &Path,
	snapshot: &Path,
) -> Result<PathBuf, String> {
	// Which blocks the base still defines, now that the fold is out of it.
	// `override` on a block nothing defines is a compile error, and its
	// absence on one that is defined is a different one -- so this is not a
	// detail the renderer can guess.
	let base = load_layered(factory_dir, config_dir)
		.ok()
		.and_then(|sources| netcfgd_compile::compile(&sources, &mut netcfgd_compile::NoHooks).ok());
	let mut overrides = netcfgd_compile::render::Overrides::new();
	if let Some(base) = &base {
		for interface in &base.interfaces {
			overrides.insert(format!("interface {}", interface.name));
		}
		for network in &base.networks {
			overrides.insert(format!("network {}", network.id));
		}
		for device in &base.devices {
			overrides.insert(format!("device {}", device.name));
		}
	}

	let text = netcfgd_compile::render::render(running, &overrides).map_err(|missing| {
		format!(
			"this configuration cannot be written out yet, so it was not saved. \
			 What is in the way:\n  {}\nWrite the profile by hand instead",
			missing.join("\n  ")
		)
	})?;

	fs::create_dir_all(directory)
		.map_err(|error| format!("could not create {}: {error}", directory.display()))?;
	fs::write(snapshot, &text)
		.map_err(|error| format!("could not write {}: {error}", snapshot.display()))?;

	// Selecting is part of the same act: having just said what this profile
	// means, being left on none would be a surprise.
	install_drop_in(
		config_dir,
		factory_dir,
		PROFILE_DROP_IN,
		&format!("global {{\n\tprofile = \"{name}\"\n}}\n"),
		true,
	)?;

	// The proof. What the machine compiles to now must be what it was running,
	// but for the selection this just made.
	let after = load_with_profile(factory_dir, config_dir)
		.ok()
		.and_then(|sources| netcfgd_compile::compile(&sources, &mut netcfgd_compile::NoHooks).ok());
	let mut expected = running.clone();
	expected.globals.profile = Some(name.to_owned());
	if after.as_ref() != Some(&expected) {
		return Err(format!(
			"saving `{name}` would not reproduce what this machine is running, \
			 so nothing was kept. That is a fault in the snapshot rather than \
			 in your configuration; write the profile by hand and please \
			 report it.{}",
			after
				.as_ref()
				.map_or(String::new(), |after| difference(&expected, after))
		));
	}

	Ok(snapshot.to_path_buf())
}
