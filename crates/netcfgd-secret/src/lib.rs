#![forbid(unsafe_code)]

//! Turning a [`SecretRef`] into the material it names.
//!
//! This is the only place in netcfgd where secret material exists at all. The
//! document carries indirections and never values (constraint 5), `/run` holds
//! none, and the plan carries none -- so a secret's whole life is: resolved
//! here, handed to a backend, dropped.
//!
//! Two rules the callers depend on:
//!
//! - **A secret is never in an error message.** Diagnostics name the
//!   reference, the provider and the reason, and stop there. A passphrase in a
//!   log is a passphrase in every log aggregator downstream.
//! - **Unsafe storage is refused rather than read.** A secret in a
//!   world-readable file is already disclosed; reading it anyway and carrying
//!   on tells the operator everything is fine.

use netcfgd_model::{CertSource, SecretProvider, SecretRef};
use std::fmt;
use std::path::{Path, PathBuf};

/// Secret material, which knows not to print itself.
///
/// `Debug` and `Display` are deliberately unhelpful. A struct holding a
/// passphrase will end up inside something derived, formatted into an error,
/// or dumped by a panic handler eventually -- and the one place to stop that
/// is the type.
#[derive(Clone, PartialEq, Eq)]
pub struct Secret(String);

impl Secret {
	/// Wrap material.
	#[must_use]
	pub fn new(value: String) -> Self {
		Self(value)
	}

	/// The material, for handing to a backend.
	///
	/// Named `expose` rather than `as_str` so that every use is visible in a
	/// grep and has to look deliberate at the call site.
	#[must_use]
	pub fn expose(&self) -> &str {
		&self.0
	}

	/// How long it is, which is safe to say and occasionally useful -- a
	/// passphrase of length zero is a common and confusing misconfiguration.
	#[must_use]
	pub fn len(&self) -> usize {
		self.0.len()
	}

	/// Whether it is empty.
	#[must_use]
	pub fn is_empty(&self) -> bool {
		self.0.is_empty()
	}
}

impl fmt::Debug for Secret {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		write!(f, "Secret(<{} bytes redacted>)", self.0.len())
	}
}

impl fmt::Display for Secret {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		write!(f, "<redacted>")
	}
}

/// Why a secret could not be resolved.
///
/// Every variant names the reference and the reason without quoting anything
/// that came out of the store.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
	/// Nothing of that name.
	NotFound {
		/// Which reference.
		name: String,
		/// Where it was looked for.
		where_: String,
	},
	/// It exists, but anybody can read it.
	Exposed {
		/// Which reference.
		name: String,
		/// The path.
		path: String,
		/// The mode it was found with.
		mode: u32,
	},
	/// The provider is not implemented in this build.
	Unsupported {
		/// Which provider.
		provider: &'static str,
		/// When it arrives.
		milestone: &'static str,
	},
	/// Something else went wrong.
	Failed {
		/// Which reference.
		name: String,
		/// What happened, from the operating system rather than from the store.
		reason: String,
	},
}

impl fmt::Display for Error {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self {
			Self::NotFound { name, where_ } => {
				// The command is named because this is exactly the moment
				// somebody needs it: the config refers to a credential and the
				// machine does not have it. Decision 0075.
				write!(
					f,
					"secret `{name}` was not found in {where_} -- \
					 `ncfg secret set {name}` stores one"
				)
			}
			Self::Exposed { name, path, mode } => write!(
				f,
				"secret `{name}` is readable by others: {path} has mode {mode:04o}. \
				 Refusing to use it -- run `chmod 600 {path}` once the value is \
				 no longer considered disclosed.",
			),
			Self::Unsupported {
				provider,
				milestone,
			} => write!(
				f,
				"the `{provider}` secret provider is not implemented in this build; \
				 it lands with {milestone}"
			),
			Self::Failed { name, reason } => write!(f, "secret `{name}`: {reason}"),
		}
	}
}

impl std::error::Error for Error {}

/// Where the `file` provider looks.
pub const DEFAULT_SECRETS_DIR: &str = "/etc/netcfgd/secrets";

/// Resolves references.
#[derive(Debug, Clone)]
pub struct Resolver {
	secrets_dir: PathBuf,
	/// Where [`Resolver::path_for`] writes stored certificates. `None` means
	/// it refuses rather than choosing somewhere.
	materialise_dir: Option<PathBuf>,
}

impl Default for Resolver {
	fn default() -> Self {
		Self {
			secrets_dir: PathBuf::from(DEFAULT_SECRETS_DIR),
			materialise_dir: None,
		}
	}
}

impl Resolver {
	/// Look for `file` secrets under this directory.
	#[must_use]
	pub fn with_secrets_dir(dir: impl Into<PathBuf>) -> Self {
		Self {
			secrets_dir: dir.into(),
			materialise_dir: None,
		}
	}

	/// Where stored certificates are written when something needs a path.
	///
	/// Absent by default, and a [`CertSource::Stored`] then fails rather than
	/// guessing a directory. A resolver that invented one would write key
	/// material somewhere its caller did not choose, which is the one thing
	/// this crate must not do quietly.
	#[must_use]
	pub fn materialising_into(mut self, dir: impl Into<PathBuf>) -> Self {
		self.materialise_dir = Some(dir.into());
		self
	}

	/// A filesystem path for a certificate or key, whichever kind it is.
	///
	/// **This is the function that made EAP-TLS work.** `wpa_supplicant` opens
	/// `ca_cert`, `client_cert` and `private_key` as files, so everything
	/// reaching it has to be a path -- and before 0127 the only way to have
	/// one was to put the file there yourself, which a desktop client cannot
	/// do. A `Stored` source is content netcfgd already holds; this writes it
	/// where the supplicant can read it and hands back that path.
	///
	/// **Written at 0600 under a 0700 directory**, and the mode is not chosen
	/// per kind. A CA certificate is public and could be 0644, but uniform is
	/// simpler to reason about and gives up nothing: the only reader is a
	/// process netcfgd started as root. The mode is set by the open rather
	/// than after it, so there is no instant at which a private key exists and
	/// is readable -- the rule 0026 states for hostapd's configuration and
	/// this file is a stronger case for it.
	///
	/// **Overwritten every time rather than cached.** The content is what the
	/// secret store says now, and a stale file would be a certificate that was
	/// rotated everywhere except on this machine.
	///
	/// # Errors
	///
	/// A source that cannot be resolved, a resolver with nowhere to write, or
	/// a write that failed.
	pub fn path_for(&self, source: &CertSource, name: &str) -> Result<PathBuf, Error> {
		let reference = match source {
			CertSource::Path(path) => return Ok(PathBuf::from(path)),
			CertSource::Stored(reference) => reference,
		};
		let secret = self.resolve(reference)?;

		let Some(directory) = self.materialise_dir.as_ref() else {
			return Err(Error::Failed {
				name: reference.name.clone(),
				reason: "this resolver has nowhere to materialise a stored certificate, \
				         so it cannot produce a path for one"
					.to_owned(),
			});
		};

		Self::write_private(directory, name, secret.expose().as_bytes()).map_err(|reason| {
			Error::Failed {
				name: reference.name.clone(),
				reason,
			}
		})
	}

	/// Write one materialised file, and the directory it needs, tightly.
	fn write_private(directory: &Path, name: &str, bytes: &[u8]) -> Result<PathBuf, String> {
		use std::io::Write as _;
		use std::os::unix::fs::{DirBuilderExt as _, OpenOptionsExt as _};

		if !directory.is_dir() {
			std::fs::DirBuilder::new()
				.recursive(true)
				.mode(0o700)
				.create(directory)
				.map_err(|error| format!("could not create {}: {error}", directory.display()))?;
		}

		let path = directory.join(name);
		let mut file = std::fs::OpenOptions::new()
			.write(true)
			.create(true)
			.truncate(true)
			.mode(0o600)
			.open(&path)
			.map_err(|error| format!("could not write {}: {error}", path.display()))?;
		file.write_all(bytes)
			.map_err(|error| format!("could not write {}: {error}", path.display()))?;
		file.sync_all()
			.map_err(|error| format!("could not flush {}: {error}", path.display()))?;
		Ok(path)
	}

	/// Resolve a reference.
	///
	/// # Errors
	///
	/// Returns why it could not be resolved, without disclosing anything.
	pub fn resolve(&self, reference: &SecretRef) -> Result<Secret, Error> {
		match reference.provider {
			SecretProvider::File => self.read_file(&reference.name),
			SecretProvider::Exec => Self::run_command(&reference.name),
			SecretProvider::Pass => Self::read_pass(&reference.name),
			SecretProvider::Keyring => Err(Error::Unsupported {
				provider: "keyring",
				// Not a milestone, because it is not scheduled, and naming one
				// that passes without the feature arriving is how a diagnostic
				// becomes a lie. The blocker is specific: the kernel keyring
				// is reached through `request_key(2)` and `keyctl(2)`, which
				// have no libc wrapper -- so it means either widening
				// constraint 4's single `unsafe` exception past netlink, or
				// shelling out to `keyctl`, which is a dependency on a tool
				// rather than on the kernel. Neither has been chosen.
				milestone: "no release yet; see the `keyring` note in netcfgd-secret",
			}),
		}
	}

	fn read_file(&self, name: &str) -> Result<Secret, Error> {
		// A name that escapes the directory would let a config read any file
		// on the machine as root. Names are a flat namespace on purpose.
		if name.is_empty() || name.contains('/') || name.contains("..") {
			return Err(Error::Failed {
				name: name.to_owned(),
				reason: "a file secret's name may not contain a path separator".to_owned(),
			});
		}
		let path = self.secrets_dir.join(name);

		let metadata = std::fs::metadata(&path).map_err(|_| Error::NotFound {
			name: name.to_owned(),
			where_: self.secrets_dir.display().to_string(),
		})?;

		check_mode(name, &path, &metadata)?;

		let body = std::fs::read_to_string(&path).map_err(|error| Error::Failed {
			name: name.to_owned(),
			reason: error.to_string(),
		})?;

		// One trailing newline is what an editor or `echo` leaves behind, and
		// a passphrase that silently includes it fails to associate with no
		// indication why. Anything further is the operator's.
		Ok(Secret::new(
			body.strip_suffix('\n').unwrap_or(&body).to_owned(),
		))
	}

	/// `pass show NAME`, from the standard password-store.
	///
	///
	/// A thin wrapper over the exec provider rather than a separate mechanism,
	/// and the difference from writing `@secret:exec:pass show NAME` by hand is
	/// the validation: `pass` takes a store path, and a name that looks like a
	/// flag or carries a second word would become an argument to `pass`
	/// itself. `pass --help` is harmless; the point is that a config file
	/// should not be able to choose what `pass` is asked to do.
	fn read_pass(name: &str) -> Result<Secret, Error> {
		if name.is_empty() || name.starts_with('-') || name.split_whitespace().count() != 1 {
			return Err(Error::Failed {
				name: name.to_owned(),
				reason: "a pass secret's name is one word naming an entry in the store".to_owned(),
			});
		}
		// `show` prints the first line and nothing else, which is the
		// convention password-store documents for exactly this.
		Ok(first_line(&Self::run_command(&format!(
			"pass show {name}"
		))?))
	}

	fn run_command(name: &str) -> Result<Secret, Error> {
		// The command is the name, run through no shell: a shell would make
		// the secrets directory a place where a config file becomes arbitrary
		// code with word splitting and globbing attached.
		let mut parts = name.split_whitespace();
		let program = parts.next().ok_or_else(|| Error::Failed {
			name: name.to_owned(),
			reason: "an exec secret needs a command".to_owned(),
		})?;

		let output = std::process::Command::new(program)
			.args(parts)
			.output()
			.map_err(|error| Error::Failed {
				name: name.to_owned(),
				reason: error.to_string(),
			})?;

		if !output.status.success() {
			// The command's stderr is not quoted: a failing secret helper
			// prints diagnostics that may contain the very thing it failed to
			// deliver.
			return Err(Error::Failed {
				name: name.to_owned(),
				reason: format!("the command exited with {}", output.status),
			});
		}

		let body = String::from_utf8(output.stdout).map_err(|_| Error::Failed {
			name: name.to_owned(),
			reason: "the command produced something that is not text".to_owned(),
		})?;
		Ok(Secret::new(
			body.strip_suffix('\n').unwrap_or(&body).to_owned(),
		))
	}
}

/// Refuse a secret anybody can read.
///
/// Design section 3.3 specifies mode 0600 for the file provider. Enforcing it
/// rather than documenting it is the difference between a rule and a
/// suggestion: a secret in a world-readable file is already disclosed, and
/// reading it anyway tells the operator everything is fine.
#[cfg(unix)]
/// The first line of a password-store entry.
///
/// A store entry conventionally holds the secret on line one and notes below
/// it -- a URL, a username, recovery codes. Taking the whole thing would hand
/// a supplicant a passphrase with somebody's recovery codes appended, and the
/// failure is an association that does not work for a reason the operator
/// cannot see, because nothing will print the value.
///
/// A free function rather than inline, so the rule can be tested without a
/// `pass` binary on the machine.
#[must_use]
pub fn first_line(secret: &Secret) -> Secret {
	let text = secret.expose();
	Secret::new(
		text.split_once('\n')
			.map_or(text, |(first, _)| first)
			.to_owned(),
	)
}

fn check_mode(name: &str, path: &Path, metadata: &std::fs::Metadata) -> Result<(), Error> {
	use std::os::unix::fs::PermissionsExt;
	let mode = metadata.permissions().mode() & 0o777;
	if mode & 0o077 != 0 {
		return Err(Error::Exposed {
			name: name.to_owned(),
			path: path.display().to_string(),
			mode,
		});
	}
	Ok(())
}

#[cfg(not(unix))]
fn check_mode(_name: &str, _path: &Path, _metadata: &std::fs::Metadata) -> Result<(), Error> {
	Ok(())
}
