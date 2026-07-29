//! Materialising hook bodies into `/run/netcfgd/hooks/`.
//!
//! Section 2.2: the DSL lets an author write inline shell, and the compiler
//! turns those blocks into files so the document carries only
//! `{phase, path, sha256}`. This is the half that touches a filesystem, which
//! is why it lives in the CLI and reaches the compiler through a trait.

use netcfgd_compile::HookSink;
use netcfgd_model::{HookPhase, HookRef};
use std::fs;
use std::path::PathBuf;

/// Writes hook bodies under a directory and hashes them.
pub struct RunHooks {
	dir: PathBuf,
	written: usize,
}

impl RunHooks {
	/// Materialise into `run_dir/hooks/`.
	#[must_use]
	pub fn new(run_dir: &std::path::Path) -> Self {
		Self {
			dir: run_dir.join("hooks"),
			written: 0,
		}
	}
}

impl HookSink for RunHooks {
	fn materialise(
		&mut self,
		phase: HookPhase,
		owner: &str,
		body: &str,
	) -> Result<HookRef, String> {
		fs::create_dir_all(&self.dir)
			.map_err(|error| format!("could not create {}: {error}", self.dir.display()))?;

		let name = format!("{owner}.{}.{}", phase_name(phase), self.written);
		let path = self.dir.join(&name);

		// A hook body is shell, and the runner executes it directly rather
		// than through `sh -c`, so it needs a shebang and the execute bit. A
		// body that already declares one keeps it.
		let script = if body.starts_with("#!") {
			body.to_owned()
		} else {
			format!("#!/bin/sh\n{body}")
		};

		fs::write(&path, &script)
			.map_err(|error| format!("could not write {}: {error}", path.display()))?;
		set_executable(&path)?;

		self.written += 1;
		Ok(HookRef {
			phase,
			path: path.display().to_string(),
			sha256: sha256_hex(script.as_bytes()),
			run_as: None,
			timeout: None,
		})
	}
}

#[cfg(unix)]
fn set_executable(path: &std::path::Path) -> Result<(), String> {
	use std::os::unix::fs::PermissionsExt;
	// 0700: the hook runs as root and nobody else needs to read it, let alone
	// write it. A world-writable hook is a root shell for whoever finds it.
	fs::set_permissions(path, fs::Permissions::from_mode(0o700))
		.map_err(|error| format!("could not set permissions on {}: {error}", path.display()))
}

#[cfg(not(unix))]
fn set_executable(_path: &std::path::Path) -> Result<(), String> {
	Ok(())
}

fn phase_name(phase: HookPhase) -> &'static str {
	match phase {
		HookPhase::PreUp => "pre_up",
		HookPhase::Up => "up",
		HookPhase::PostUp => "post_up",
		HookPhase::PreDown => "pre_down",
		HookPhase::Down => "down",
		HookPhase::PostDown => "post_down",
		HookPhase::Carrier => "carrier",
		HookPhase::Lease => "lease",
		HookPhase::Roam => "roam",
		HookPhase::Portal => "portal",
		HookPhase::Drift => "drift",
	}
}

/// SHA-256, from the model so that the hash written here and the hash
/// checked before execution cannot disagree.
pub use netcfgd_model::hash::sha256_hex;

#[cfg(test)]
mod tests {
	use super::sha256_hex;

	/// The published vectors, because a hash implementation that is nearly
	/// right is worth nothing and looks fine.
	#[test]
	fn it_matches_the_published_vectors() {
		assert_eq!(
			sha256_hex(b""),
			"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
		);
		assert_eq!(
			sha256_hex(b"abc"),
			"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
		);
		assert_eq!(
			sha256_hex(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"),
			"248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
		);
	}

	/// The padding boundary: 55, 56 and 64 bytes take different paths through
	/// the length-append, and an off-by-one there is invisible on short input.
	#[test]
	fn the_padding_boundaries_are_right() {
		assert_eq!(
			sha256_hex(&[b'a'; 55]),
			"9f4390f8d30c2dd92ec9f095b65e2b9ae9b0a925a5258e241c9f1e910f734318"
		);
		assert_eq!(
			sha256_hex(&[b'a'; 56]),
			"b35439a4ac6f0948b6d6f9e3c6af0f5f590ce20f1bde7090ef7970686ec6738a"
		);
		assert_eq!(
			sha256_hex(&[b'a'; 64]),
			"ffe054fe7ae0cb6dc65c3af9b61d5209f439851db43d0ba5997337df154668eb"
		);
	}
}
