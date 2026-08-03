//! Writing a GUI's edits into `/etc/netcfgd`, and deciding who may.
//!
//! Design section 9.4's promise, made concrete: a network created from a
//! desktop applet is a plain text file under the operator's configuration, not
//! a record in a store only this program understands. Delete `netcfgd-nm` and
//! the file is still there and still valid.
//!
//! # Where the files go
//!
//! Section 9.4 says `/etc/netcfgd/conf.d/nm/`, a directory. It is
//! `/etc/netcfgd/conf.d/nm-<id>.conf` instead, flat, because netcfgd reads
//! `conf.d/*.conf` and does not descend: a file in a subdirectory is not
//! ignored with a warning, it is simply never read, which was checked rather
//! than assumed. Making the loader recursive would be a change to the core
//! justified solely by an adapter's preference for a tidier path, which is the
//! one thing constraint 6 forbids. The prefix gives everything the directory
//! was for -- machine-generated files are identifiable, greppable, and
//! removable in one glob.
//!
//! # Who may
//!
//! Writing configuration is the `admin` tier's business (decision 0013), and
//! the shim is not privileged to decide otherwise. A bus caller's uid comes
//! from the bus, and the tier comes from the document netcfgd already gave us,
//! so the policy is netcfgd's own rather than a second one invented here.

use crate::emit::Emitted;
use netcfgd_model::Principal;
use std::io;
use std::path::{Path, PathBuf};

/// Where the configuration directory is.
#[must_use]
pub(crate) fn config_dir() -> PathBuf {
	std::env::var_os("NCFG_CONFIG_DIR").map_or_else(|| PathBuf::from("/etc/netcfgd"), PathBuf::from)
}

/// The file a profile id is written to.
///
/// The id sanitised down to what a filename should be, because an SSID may
/// contain a slash and the label is not a path. Collisions between two ids
/// that sanitise the same are caught by netcfgd rather than here: two blocks
/// with one label is a compile error, which the reload reports.
#[must_use]
pub(crate) fn path_for(id: &str) -> PathBuf {
	let safe: String = id
		.chars()
		.map(|c| {
			if c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.' {
				c
			} else {
				'_'
			}
		})
		.collect();
	config_dir().join("conf.d").join(format!("nm-{safe}.conf"))
}

/// Whether a profile is one this program wrote.
///
/// The file is the marker, which means the answer survives a restart and does
/// not need remembering. A hand-written block has no such file and is therefore
/// read-only through the bus -- which is section 9.4's rule, enforced by asking
/// the filesystem rather than by keeping a list.
#[must_use]
pub(crate) fn is_machine_generated(id: &str) -> bool {
	path_for(id).is_file()
}

/// Whether a credential is already stored for a profile.
#[must_use]
pub(crate) fn has_secret(id: &str) -> bool {
	secret_path(id).is_file()
}

/// Whether a bus caller may change the configuration.
///
/// Mirrors the daemon's own check (`netcfgd-daemon`'s `satisfies`): root
/// satisfies everything, `Any` is open, `User` compares uids. It stops short of
/// `Group`, and that is deliberate rather than unfinished -- the bus reports a
/// caller's uid and not its supplementary groups, so a group principal could
/// only be evaluated by guessing which groups that uid is usually in. Guessing
/// is not a thing to do in an authorization check, so it refuses and says which
/// tool does not have to guess.
///
/// # Errors
///
/// Returns the sentence to hand the client when the answer is no.
pub(crate) fn may_write(caller: u32, admin: &Principal) -> Result<(), String> {
	if caller == 0 {
		return Ok(());
	}
	match admin {
		Principal::Any => Ok(()),
		Principal::User(name) => {
			if user_id(name) == Some(caller) {
				Ok(())
			} else {
				Err(format!(
					"not permitted: changing netcfgd's configuration needs the `admin` tier, \
					 which this machine opens to the user `{name}`"
				))
			}
		}
		Principal::Root => Err(
			"not permitted: changing netcfgd's configuration needs the `admin` tier, which \
			 this machine keeps to root. Open it in the `control` block of netcfgd.conf, or \
			 edit the configuration directly"
				.to_owned(),
		),
		Principal::Group(name) => Err(format!(
			"not permitted here: the `admin` tier is open to the group `{name}`, and a \
			 message bus reports a caller's user but not its groups -- so this cannot tell \
			 whether you are in it, and will not guess. `ncfg` sees your groups over the \
			 socket and can do this"
		)),
	}
}

/// The numeric id of a user, by name.
///
/// The same `/etc/passwd` walk `netcfgd-sys` does, repeated here rather than
/// depended on: that crate is constraint 4's single audited `unsafe` exception
/// and links netlink, inotify and ncurses. Linking all of it into an adapter to
/// parse a text file would be the wrong trade in both directions.
///
/// It shares the daemon's limitation as well as its method -- a user that
/// exists only in LDAP is invisible to both -- which is the property that
/// matters, since the two must agree.
#[must_use]
fn user_id(name: &str) -> Option<u32> {
	let text = std::fs::read_to_string("/etc/passwd").ok()?;
	for line in text.lines() {
		let mut fields = line.split(':');
		if fields.next() == Some(name) {
			// name:passwd:uid:gid:...
			return fields.nth(1).and_then(|uid| uid.parse().ok());
		}
	}
	None
}

/// Write a profile and its secret.
///
/// # Errors
///
/// Returns a message naming the file and what went wrong. A permission error
/// is the one worth recognising: it means the shim is not running as something
/// that may write the operator's configuration, which is a deployment problem
/// with a specific answer.
pub(crate) fn write(emitted: &Emitted) -> Result<PathBuf, String> {
	if let Some((name, value)) = &emitted.secret {
		write_secret(name, value)?;
	}

	let path = path_for(&emitted.id);
	let directory = path.parent().unwrap_or_else(|| Path::new("."));
	create_dir(directory)?;
	write_atomically(&path, emitted.text.as_bytes(), 0o644)
		.map_err(|error| explain(&path, &error))?;
	Ok(path)
}

/// Remove a profile and its secret.
///
/// # Errors
///
/// Returns a message naming the file. An absent file is success: the state
/// being asked for is the state that holds.
pub(crate) fn remove(id: &str) -> Result<(), String> {
	let path = path_for(id);
	match std::fs::remove_file(&path) {
		Ok(()) => {}
		Err(error) if error.kind() == io::ErrorKind::NotFound => {}
		Err(error) => return Err(explain(&path, &error)),
	}

	// The credential goes with it. Leaving it behind would leave a passphrase
	// on disk for a network nothing refers to any more, which is the sort of
	// thing nobody ever notices to clean up.
	let secret = secret_path(id);
	match std::fs::remove_file(&secret) {
		Ok(()) => Ok(()),
		Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
		Err(error) => Err(explain(&secret, &error)),
	}
}

/// Where the `file` secret provider looks.
#[must_use]
fn secret_path(name: &str) -> PathBuf {
	config_dir().join("secrets").join(name)
}

/// Store a credential an agent supplied.
///
/// # Errors
///
/// Returns a message naming the file.
pub(crate) fn save_secret(name: &str, value: &str) -> Result<(), String> {
	write_secret(name, value)
}

fn write_secret(name: &str, value: &str) -> Result<(), String> {
	let path = secret_path(name);
	create_dir(path.parent().unwrap_or_else(|| Path::new(".")))?;
	// 0600, and set by the open rather than after it. The same reasoning as the
	// hostapd configuration in decision 0026: a mode applied afterwards is a
	// mode that was wrong once, and the window is exactly when the passphrase
	// is on disk and readable.
	write_atomically(&path, value.as_bytes(), 0o600).map_err(|error| explain(&path, &error))
}

fn create_dir(directory: &Path) -> Result<(), String> {
	std::fs::create_dir_all(directory).map_err(|error| explain(directory, &error))
}

/// Write, or leave what was there.
///
/// Through a temporary file in the same directory and a rename, so a reader --
/// and netcfgd's inotify watch is one -- sees either the old file or the new
/// one and never half of either. The temporary carries the final mode from the
/// moment it exists, so a secret is never briefly world-readable under another
/// name.
fn write_atomically(path: &Path, bytes: &[u8], mode: u32) -> io::Result<()> {
	use std::io::Write as _;
	use std::os::unix::fs::OpenOptionsExt as _;

	let directory = path.parent().unwrap_or_else(|| Path::new("."));
	let temporary = directory.join(format!(
		".{}.{}",
		path.file_name().map_or_else(
			|| "tmp".to_owned(),
			|name| name.to_string_lossy().into_owned()
		),
		std::process::id()
	));

	let mut file = std::fs::OpenOptions::new()
		.write(true)
		.create(true)
		.truncate(true)
		.mode(mode)
		.open(&temporary)?;
	file.write_all(bytes)?;
	// Durable before it is visible. A rename that beats the data to disk is a
	// truncated config file after a power cut, which on a router is the failure
	// that needs a serial cable.
	file.sync_all()?;
	drop(file);

	match std::fs::rename(&temporary, path) {
		Ok(()) => Ok(()),
		Err(error) => {
			let _ = std::fs::remove_file(&temporary);
			Err(error)
		}
	}
}

/// An io error, as something an operator can act on.
fn explain(path: &Path, error: &io::Error) -> String {
	if error.kind() == io::ErrorKind::PermissionDenied {
		format!(
			"cannot write {}: {error}. netcfgd-nm writes a GUI's networks into the \
			 operator's configuration (design section 9.4), so it needs write access to \
			 that directory -- which it does not have here",
			path.display()
		)
	} else {
		format!("cannot write {}: {error}", path.display())
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn a_filename_is_derived_and_marked() {
		let path = path_for("HomeFiber");
		assert!(path.ends_with("conf.d/nm-HomeFiber.conf"), "{path:?}");
	}

	/// An SSID may contain a slash, and a label is not a path. Without this a
	/// network called `a/b` would be written somewhere nobody asked for.
	#[test]
	fn a_label_that_is_not_a_filename_is_made_into_one() {
		let path = path_for("a/b c");
		assert!(path.ends_with("conf.d/nm-a_b_c.conf"), "{path:?}");
		assert_eq!(
			path.components().count(),
			path_for("plain").components().count()
		);
	}

	/// Root always may, whatever the policy says. Same reasoning as the
	/// daemon's: a configuration that named a group and locked root out would
	/// be unrecoverable without editing the file the daemon is refusing to let
	/// you reach.
	#[test]
	fn root_may_write_whatever_the_policy_says() {
		for principal in [
			Principal::Root,
			Principal::Any,
			Principal::User("nobody-real".to_owned()),
			Principal::Group("nobody-real".to_owned()),
		] {
			assert!(may_write(0, &principal).is_ok(), "for {principal:?}");
		}
	}

	#[test]
	fn a_default_machine_keeps_configuration_to_root() {
		let refusal = may_write(1000, &Principal::Root).expect_err("not root");
		assert!(refusal.contains("admin"), "{refusal}");
		assert!(refusal.contains("control"), "{refusal}");
	}

	#[test]
	fn an_open_policy_lets_anybody_write() {
		assert!(may_write(1000, &Principal::Any).is_ok());
	}

	/// A group principal is refused rather than guessed at. The bus reports a
	/// caller's user and not its groups, and an authorization check that
	/// assumes is worse than one that declines and names the tool which does
	/// not have to.
	#[test]
	fn a_group_policy_is_declined_rather_than_approximated() {
		let refusal =
			may_write(1000, &Principal::Group("netdev".to_owned())).expect_err("cannot tell");
		assert!(refusal.contains("not guess"), "{refusal}");
		assert!(refusal.contains("ncfg"), "{refusal}");
	}

	#[test]
	fn writing_is_atomic_and_leaves_no_temporary_behind() {
		let directory = netcfgd_testdir::TestDir::new("nm-store");
		let path = directory.join("thing.conf");
		write_atomically(&path, b"first\n", 0o644).expect("the first write");
		write_atomically(&path, b"second\n", 0o644).expect("the second");
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
		let _ = std::fs::remove_dir_all(&directory);
	}

	#[test]
	fn a_secret_is_never_readable_by_anybody_else() {
		use std::os::unix::fs::PermissionsExt as _;
		let directory = netcfgd_testdir::TestDir::new("nm-secret");
		let path = directory.join("credential");
		write_atomically(&path, b"hunter2hunter2", 0o600).expect("the write");
		let mode = std::fs::metadata(&path)
			.expect("readable")
			.permissions()
			.mode();
		assert_eq!(mode & 0o777, 0o600, "{mode:o}");
		let _ = std::fs::remove_dir_all(&directory);
	}
}
