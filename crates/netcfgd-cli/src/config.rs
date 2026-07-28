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
pub(crate) const DEFAULT_CONFIG_DIR: &str = "/etc/netcfgd";

/// Read a config directory into a source map, in precedence order.
///
/// # Errors
///
/// Returns an `io::Error` naming the path that could not be read. A missing
/// directory is not an error: an empty config is a legitimate state and
/// compiles to an empty document, which plans to do nothing.
pub(crate) fn load(dir: &Path) -> io::Result<SourceMap> {
	let mut sources = SourceMap::new();

	let main = dir.join("netcfgd.conf");
	if main.is_file() {
		add_file(&mut sources, &main)?;
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
			add_file(&mut sources, &path)?;
		}
	}

	Ok(sources)
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

/// The config directory to use: the argument, the environment, or the default.
#[must_use]
pub(crate) fn resolve_dir(explicit: Option<&str>) -> PathBuf {
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
