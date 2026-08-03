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
	let text = fs::read_to_string(path)
		.map_err(|error| io::Error::new(error.kind(), format!("{}: {error}", path.display())))?;

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
			add_file(sources, &resolved)?;
			continue;
		}
		body.push_str(line);
		body.push('\n');
	}

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
/// # Errors
///
/// Returns an `io::Error`. The temporary is removed on a failed rename, so a
/// full disk does not leave a dotfile behind next to the config.
pub fn write_atomically(path: &Path, bytes: &[u8], mode: u32) -> io::Result<()> {
	use std::io::Write as _;
	use std::os::unix::fs::OpenOptionsExt as _;

	let directory = path.parent().unwrap_or_else(|| Path::new("."));
	fs::create_dir_all(directory)?;
	let temporary = directory.join(format!(
		".{}.{}",
		path.file_name().map_or_else(
			|| "tmp".to_owned(),
			|name| name.to_string_lossy().into_owned()
		),
		std::process::id()
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
	use super::{load_layered, writable_files};
	use std::fs;
	use std::path::{Path, PathBuf};

	/// A directory tree that takes itself away again.
	///
	/// The `Drop` rather than a line at the end of each test, because a test
	/// that panics never reaches its last line and a leaked temporary directory
	/// is invisible to every gate here. Five per run of the suite, and 1252 of
	/// them had accumulated in `/tmp` before anybody counted.
	struct Tree(PathBuf);

	impl Drop for Tree {
		fn drop(&mut self) {
			let _ = fs::remove_dir_all(&self.0);
		}
	}

	impl std::ops::Deref for Tree {
		type Target = Path;

		fn deref(&self) -> &Path {
			&self.0
		}
	}

	/// A directory tree, built from `relative path -> contents`.
	fn tree(name: &str, files: &[(&str, &str)]) -> Tree {
		let root = std::env::temp_dir().join(format!("ncfg-layer-{name}-{}", std::process::id()));
		let _ = fs::remove_dir_all(&root);
		for (path, contents) in files {
			let full = root.join(path);
			fs::create_dir_all(full.parent().expect("a parent")).expect("mkdir");
			fs::write(full, contents).expect("write");
		}
		fs::create_dir_all(&root).expect("mkdir");
		Tree(root)
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
