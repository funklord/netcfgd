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
		let mut drop_ins: Vec<PathBuf> = fs::read_dir(&drop_in_dir)?
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
	use super::{install_drop_in, load_layered, writable_files};

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
		let factory = tree("f1", &[("netcfgd.conf", "interface eth0 { mtu = 1500 }\n")]);
		let runtime = tree(
			"r1",
			&[(
				"conf.d/10-local.conf",
				"override interface eth0 { mtu = 9000 }\n",
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
		let present = tree("f2", &[("netcfgd.conf", "interface eth0 { mtu = 1500 }\n")]);
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
		let dir = tree("f3", &[("netcfgd.conf", "interface eth0 { mtu = 1500 }\n")]);
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
			 (docs/decisions/0042)",
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
