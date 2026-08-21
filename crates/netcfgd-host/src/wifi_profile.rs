//! Writing a `network` block, for every caller allowed to.
//!
//! This was `ncfg wifi add`'s alone until [0117] gave the socket a typed
//! request that does the same thing for a client with no permission to write
//! the file itself. That request is the `wifi` tier since 0124, having been
//! `admin` until then. Two callers means the rendering, the
//! paths and the safety sequence have to live in one place or there are two
//! answers to "what a `network` block looks like" -- which is the shape this
//! tree keeps finding, most recently as three spellings of one access point's
//! name.
//!
//! **What is deliberately not here is the credential's provenance.** The CLI
//! prompts with echo off; the daemon takes it from a request. Both hand a
//! string to [`install`], which writes it through the provider and leaves an
//! `@secret:` reference in the block -- so the *document* stays free of secret
//! material (constraint 5) whichever caller asked.
//!
//! [0117]: ../../../docs/decisions/0117-adding-a-network-is-a-typed-request-not-a-written-file.md

use crate::config;
use netcfgd_model::Ssid;
use std::fmt::Write as _;
use std::path::{Path, PathBuf};

/// How a network is protected.
///
/// `Eap` carries paths, and that is why the socket request cannot construct
/// one: 0117 admits typed fields and refuses paths, because a path is a file
/// the daemon would hand to a supplicant running as root. The CLI builds these
/// from flags an operator typed on their own machine, which is a different
/// question. One renderer, two callers, and only one of them can reach the
/// arm that names a file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Security {
	/// No security at all, and no credential.
	Open,
	/// A passphrase, optionally pinned to one generation.
	Psk {
		/// `wpa2`, `wpa3`, or `None` to negotiate both.
		proto: Option<String>,
	},
	/// An enterprise network. Reachable from the CLI only.
	Eap {
		/// `peap`, `ttls`, `tls` or `pwd`.
		method: String,
		/// Who you are to the authentication server, often with a realm.
		identity: Option<String>,
		/// Who you are *outside* the tunnel, which is all the radio sees.
		anonymous_identity: Option<String>,
		/// The certificate the server is checked against.
		ca_cert: Option<String>,
		/// The certificate presented, for `tls`.
		client_cert: Option<String>,
		/// The inner method, such as `mschapv2`.
		phase2: Option<String>,
	},
}

impl Security {
	/// Whether a credential has to accompany this.
	#[must_use]
	pub fn wants_credential(&self) -> bool {
		!matches!(self, Self::Open)
	}
}

/// A network to write, with everything the block needs and nothing else.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Profile {
	/// The block's label, the filename and the secret's name, all three.
	pub id: String,
	/// The network's real name, which is 0..32 arbitrary octets.
	pub ssid: Ssid,
	/// Not broadcast, so it has to be probed for.
	pub hidden: bool,
	/// Higher wins when several are in range.
	pub priority: Option<u32>,
	/// How it is protected, and therefore what credential it wants.
	pub security: Security,
}

/// Whether an id can be a block label, a filename and a secret name at once.
///
/// It has to be all three and the strictest wins. The label rules keep a quote
/// or a backslash out of generated config and refuse a control character; the
/// rest are the secret provider's, and they are the reason this is checked
/// **inside [`install`]** rather than left to a caller.
///
/// A caller that forgot would be handing an id straight into two `join`s. With
/// the socket request of 0117 that caller is a remote client, and an id of
/// `../../../etc/cron.d/x` would be a file written wherever the daemon can
/// write. A validation a caller may skip is a validation a caller will skip.
///
/// # Errors
///
/// Returns why, as a fragment for a sentence.
pub fn usable_id(name: &str) -> Result<(), &'static str> {
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

/// The file a network's block goes in.
///
/// Flat, and `.conf`, because that is what the loader reads: it takes
/// `conf.d/*.conf` and does not descend, so a subdirectory per client would
/// configure nothing. The `wifi-` prefix says where the file came from without
/// claiming ownership of it -- there is no marker file and no registry, and a
/// block edited by hand afterwards is simply the configuration.
#[must_use]
pub fn profile_path(config_dir: &Path, id: &str) -> PathBuf {
	config_dir.join("conf.d").join(format!("wifi-{id}.conf"))
}

/// Where the `file` secret provider will look for the credential.
#[must_use]
pub fn secret_path(config_dir: &Path, id: &str) -> PathBuf {
	config_dir.join("secrets").join(id)
}

/// A value going into a quoted string in generated configuration.
///
/// An identity or a certificate path arrives from outside and goes into a file
/// the compiler reads back. A quote or a backslash in one would end the string
/// early and produce a file that does not compile -- which takes every other
/// interface on the machine with it, since the loader compiles the directory as
/// one document.
fn escape(value: &str) -> String {
	value.replace('\\', "\\\\").replace('"', "\\\"")
}

/// The block, as text.
///
/// Kept to what was asked for. netcfgd's defaults are the ones a laptop wants
/// -- `autoconnect` is on, `metered` is off, and a PSK negotiates WPA2 and WPA3
/// both -- and writing them out anyway would turn every generated file into a
/// list of things to wonder about.
#[must_use]
pub fn render(profile: &Profile) -> String {
	let id = &profile.id;
	let mut text = String::new();
	text.push_str(
		"# Written by netcfgd. This file is ordinary netcfgd configuration:\n\
		 # edit it, diff it, commit it, or delete it. Deleting it is how the\n\
		 # machine forgets this network.\n",
	);
	let _ = writeln!(text, "\nnetwork \"{id}\" {{");
	// The SSID as hex whenever it is not exactly the label, which is what makes
	// a separate id lossless: an SSID is 32 arbitrary octets and a label is
	// text, so a network whose name is not usable as a label still keeps its
	// exact name.
	if profile.ssid.as_bytes() != id.as_bytes() {
		let _ = writeln!(text, "\tssid = \"{}\"", profile.ssid.to_hex());
	}
	if profile.hidden {
		text.push_str("\thidden = true\n");
	}

	let mut keys: Vec<String> = Vec::new();
	match &profile.security {
		Security::Open => keys.push("open = true".to_owned()),
		Security::Eap {
			method,
			identity,
			anonymous_identity,
			ca_cert,
			client_cert,
			phase2,
		} => {
			keys.push(format!("eap = \"{method}\""));
			// Every value is quoted rather than interpolated bare: an identity
			// is `you@example.ac.uk` and a certificate is a path, and neither
			// is guaranteed to be a bare word the lexer reads back as itself.
			// `install` proves the round trip.
			for (value, key) in [
				(identity, "identity"),
				(anonymous_identity, "anonymous_identity"),
				(ca_cert, "ca_cert"),
				(client_cert, "client_cert"),
				(phase2, "phase2"),
			] {
				if let Some(value) = value {
					keys.push(format!("{key} = \"{}\"", escape(value)));
				}
			}
			// TLS presents a certificate and the rest present a password, and
			// the supplicant refuses the network outright if given the other
			// -- so which key the stored secret goes under is the same branch
			// the caller prompted through.
			if method == "tls" {
				keys.push(format!("private_key = \"@secret:{id}\""));
			} else {
				keys.push(format!("password = \"@secret:{id}\""));
			}
		}
		Security::Psk { proto } => {
			keys.push(format!("psk = \"@secret:{id}\""));
			if let Some(proto) = proto {
				keys.push(format!("proto = \"{proto}\""));
			}
		}
	}
	if let Some(priority) = profile.priority {
		keys.push(format!("priority = {priority}"));
	}
	// One key per line for an enterprise network. The single-line form reads
	// well for `psk` and `priority` and badly for seven keys, and this file is
	// meant to be edited by hand afterwards.
	if keys.len() > 3 {
		text.push_str("\twifi {\n");
		for key in &keys {
			let _ = writeln!(text, "\t\t{key}");
		}
		text.push_str("\t}\n");
	} else {
		let _ = writeln!(text, "\twifi {{ {} }}", keys.join("; "));
	}
	text.push_str("}\n");
	text
}

/// Why [`install`] refused.
///
/// A string was enough while the only caller was root. It stopped being enough
/// when 0124 put adding a network in the `wifi` tier: `ncfg wifi add` run by a
/// group member has the permission and not the access, and has to tell "the
/// kernel would not let me write this" apart from every other refusal so it
/// can ask the daemon instead. Matching on the words of the message would have
/// worked and would stop working the day somebody rewords one -- silently, by
/// turning the fallback off, which is the failure mode nobody notices.
///
/// `Display` renders exactly what this used to return, so no message changes.
#[derive(Debug, Clone)]
pub struct InstallError {
	/// The sentence to print.
	pub message: String,
	/// The filesystem refused this process, rather than the request being
	/// wrong. Set from `ErrorKind::PermissionDenied` and from nothing else.
	pub denied: bool,
}

impl std::fmt::Display for InstallError {
	fn fmt(&self, out: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		out.write_str(&self.message)
	}
}

impl From<String> for InstallError {
	fn from(message: String) -> Self {
		Self {
			message,
			denied: false,
		}
	}
}

impl InstallError {
	/// An error from the filesystem, carrying whether it was a refusal.
	fn from_io(message: String, error: &std::io::Error) -> Self {
		Self {
			message,
			denied: error.kind() == std::io::ErrorKind::PermissionDenied,
		}
	}
}

/// What [`install`] wrote, so a caller can say so.
#[derive(Debug, Clone)]
pub struct Installed {
	/// The `network` block that was written.
	pub file: PathBuf,
	/// `None` for an open network, which stores nothing.
	pub secret: Option<PathBuf>,
}

/// The secrets directory, at 0700 if it has to be made.
///
/// 0700 from the moment it exists rather than created and then tightened: a
/// directory that is briefly world-readable is briefly world-readable, and the
/// file inside it is a passphrase.
fn make_secret_dir(secret: &Path) -> Result<(), InstallError> {
	use std::os::unix::fs::DirBuilderExt as _;

	let directory = secret.parent().unwrap_or_else(|| Path::new("."));
	if directory.is_dir() {
		return Ok(());
	}
	std::fs::DirBuilder::new()
		.recursive(true)
		.mode(0o700)
		.create(directory)
		.map_err(|error| {
			InstallError::from_io(
				format!("could not create {}: {error}", directory.display()),
				&error,
			)
		})
}

fn remove(path: &Path) {
	let _ = std::fs::remove_file(path);
}

/// Write the credential and the block, then prove the machine can use them.
///
/// The order is the safety property and is not arbitrary:
///
/// 1. **Refuse first.** A second block with the same label is a compile error,
///    so writing one would break every interface on the machine to add one
///    network. An existing file or stored secret is refused rather than
///    overwritten -- this does not clobber what it did not write.
/// 2. **The credential, then the block.** A block referring to a secret that is
///    not there is a network that cannot join; the other order is a stored
///    passphrase for a network that does not exist.
/// 3. **Compile it back.** Through the same loader and compiler the daemon
///    uses, because a generated file that does not compile is worse than no
///    file at all -- it takes the whole directory with it. If the machine
///    cannot use what this wrote, both files are removed and the caller is told
///    why.
///
/// # Errors
///
/// Returns a sentence for a person. Nothing is left behind by a failure.
pub fn install(
	config_dir: &Path,
	factory_dir: &Path,
	profile: &Profile,
	credential: Option<&str>,
) -> Result<Installed, InstallError> {
	let id = &profile.id;
	// First, and inside rather than above: everything below joins this onto a
	// directory twice.
	usable_id(id).map_err(|why| format!("`{id}` cannot be used as a name here: {why}"))?;

	let file = profile_path(config_dir, id);
	let secret = secret_path(config_dir, id);

	if file.exists() {
		return Err(format!(
			"{} already exists -- refusing to overwrite a file this did not write",
			file.display()
		)
		.into());
	}
	if profile.security.wants_credential() {
		if credential.is_none() {
			return Err("this network needs a credential and none was given"
				.to_owned()
				.into());
		}
		if secret.exists() {
			return Err(format!(
				"{} already exists -- refusing to overwrite a stored credential. \
				 Remove it first if it is stale",
				secret.display()
			)
			.into());
		}
	}

	let stored = match credential {
		Some(value) if profile.security.wants_credential() => {
			make_secret_dir(&secret)?;
			config::write_atomically(&secret, value.as_bytes(), 0o600).map_err(|error| {
				InstallError::from_io(
					format!("could not write {}: {error}", secret.display()),
					&error,
				)
			})?;
			true
		}
		_ => false,
	};

	if let Err(error) = config::write_atomically(&file, render(profile).as_bytes(), 0o644) {
		if stored {
			remove(&secret);
		}
		return Err(InstallError::from_io(
			format!("could not write {}: {error}", file.display()),
			&error,
		));
	}

	if let Err(error) = compiles_back(config_dir, factory_dir, profile) {
		remove(&file);
		if stored {
			remove(&secret);
		}
		return Err(error.into());
	}

	Ok(Installed {
		file,
		secret: stored.then_some(secret),
	})
}

/// A certificate as it was written in the file, for comparing against it.
///
/// The round-trip check compares what this rendered with what the compiler
/// read back, so it has to undo the lowering rather than look at the meaning:
/// a stored reference was written as `@secret:name` and a path as itself.
/// Comparing a `CertSource` against the text would fail for every stored
/// certificate, and the failure would say netcfgd has a bug -- which is what
/// that message means and is exactly why it must not fire for a working case.
fn cert_as_written(source: Option<&netcfgd_model::CertSource>) -> Option<&str> {
	match source? {
		netcfgd_model::CertSource::Path(path) => Some(path.as_str()),
		// The reference's own text is not kept, so this cannot be compared by
		// value. It is a match by construction: `render` writes exactly the
		// `@secret:` form the compiler turns back into `Stored`.
		netcfgd_model::CertSource::Stored(_) => None,
	}
}

/// Compile the directory again and check the network arrived as asked.
///
/// Not a formality. It covers the two things that can go wrong between a
/// rendered block and a usable network -- a label the lexer reads differently
/// from the way it was written, and an SSID whose hex form did not round-trip
/// -- and it is the only check that sees the file as the daemon will, includes
/// and drop-in ordering and all.
fn compiles_back(config_dir: &Path, factory_dir: &Path, profile: &Profile) -> Result<(), String> {
	let id = &profile.id;
	let sources = config::load_layered(factory_dir, config_dir)
		.map_err(|error| format!("could not read {}: {error}", config_dir.display()))?;
	let document =
		netcfgd_compile::compile(&sources, &mut netcfgd_compile::NoHooks).map_err(|error| {
			format!(
				"what that would have written does not compile, so it was \
				 removed again:\n{error}"
			)
		})?;
	let Some(network) = document.networks.iter().find(|network| &network.id == id) else {
		return Err(format!(
			"the file was written and compiled, and the configuration still has \
			 no network `{id}`, so it was removed again. This is a bug in netcfgd"
		));
	};

	let secured = !matches!(network.security, netcfgd_model::Security::Open);
	if secured != profile.security.wants_credential() {
		return Err(format!(
			"network `{id}` compiled with the wrong security, so it was removed \
			 again. This is a bug in netcfgd"
		));
	}

	// An enterprise network is checked field by field, because its values went
	// through a quoted string on the way in: an identity with a realm, a
	// certificate path. `secured` is true for a `psk` network too, so without
	// this an `--eap` run that compiled to a passphrase network would pass --
	// and the operator would find out at association time, from a supplicant
	// log.
	//
	// Compared as the *compiler* parsed them rather than as they were written,
	// which is what makes this a round trip rather than a restatement of the
	// renderer. Breaking the comparison leaves every other check here green:
	// the compile step already catches a file that does not parse, and only
	// this catches one that parses into the wrong network.
	if let Security::Eap {
		method,
		identity,
		anonymous_identity,
		ca_cert,
		client_cert,
		phase2,
	} = &profile.security
	{
		let netcfgd_model::Security::Eap(eap) = &network.security else {
			return Err(format!(
				"network `{id}` asked for `{method}` and compiled to something \
				 else, so it was removed again. This is a bug in netcfgd"
			));
		};
		for (wrote, got, what) in [
			(identity.as_deref(), Some(eap.identity.as_str()), "identity"),
			(
				anonymous_identity.as_deref(),
				eap.anonymous_identity.as_deref(),
				"anonymous identity",
			),
			(
				ca_cert.as_deref(),
				cert_as_written(eap.ca_cert.as_ref()),
				"CA certificate",
			),
			(
				client_cert.as_deref(),
				cert_as_written(eap.client_cert.as_ref()),
				"client certificate",
			),
			(phase2.as_deref(), eap.phase2.as_deref(), "phase 2 method"),
		] {
			if wrote.is_some() && wrote != got {
				return Err(format!(
					"network `{id}`'s {what} did not survive being written and \
					 read back, so it was removed again. This is a bug in netcfgd"
				));
			}
		}
	}
	Ok(())
}

#[cfg(test)]
mod tests {
	/// The names the GUI's file chooser derives are ones this rule accepts.
	///
	/// **The point is that this side judges them.** `gui/tests/
	/// add_network_enterprise.cpp` derives a secret name from a chosen file
	/// and then checks it against a restatement of the rules below, written in
	/// C++ by the same hand -- which is one witness wearing two hats, and
	/// would go on passing if both were wrong together. These are the exact
	/// strings that test expects, put to the real [`usable_id`]: a rule change
	/// here fails this, and a derivation change there fails that, and the two
	/// cannot drift quietly in the same direction.
	///
	/// Keep the list in step with the probe. It is short on purpose -- one
	/// case per rule the derivation has to satisfy, not a corpus.
	#[test]
	fn the_names_the_file_chooser_derives_are_usable() {
		for name in [
			"corp-ca",       // the ordinary case
			"corp-ca-1",     // spaces and brackets replaced
			"hidden",        // a leading dot stripped
			"escape",        // `..` cannot survive
			"quote-slash",   // a quote and a backslash
			&"a".repeat(64), // exactly the length limit
		] {
			assert!(
				super::usable_id(name).is_ok(),
				"the file chooser would produce `{name}`, which this refuses: {:?}",
				super::usable_id(name)
			);
		}
	}

	use super::*;

	/// The round-trip check reads the enterprise fields back and compares them.
	///
	/// Moved here with the verifier it exercises, from `ncfg wifi add`, when
	/// the socket gained a second caller (0117).
	///
	/// The happy path cannot show this: the renderer and the verifier agree, so
	/// a working pair proves nothing about the check. So the file is written by
	/// the renderer and then verified against a *different* profile, which is
	/// what a future bug in the renderer would look like from here.
	///
	/// Written because breaking this comparison left every other test green:
	/// the compile step already catches a file that does not parse, and only
	/// this catches one that parses into the wrong network.
	#[test]
	fn the_round_trip_catches_a_field_that_did_not_survive() {
		let dir = netcfgd_testdir::TestDir::new("wifi-profile-eap");
		let config = dir.join("etc");
		std::fs::create_dir_all(config.join("conf.d")).expect("the directory is made");

		let profile = Profile {
			id: "Corp".to_owned(),
			ssid: Ssid::new(b"Corp".to_vec()).expect("a short ssid"),
			hidden: false,
			priority: None,
			security: Security::Eap {
				method: "peap".to_owned(),
				identity: Some("you@example.ac.uk".to_owned()),
				anonymous_identity: None,
				ca_cert: Some("/ca.pem".to_owned()),
				client_cert: None,
				phase2: None,
			},
		};
		std::fs::write(profile_path(&config, "Corp"), render(&profile))
			.expect("the block is written");

		let factory = dir.join("factory");
		compiles_back(&config, &factory, &profile).expect("the round trip holds");

		// And a mismatch is caught rather than reported as success.
		let mut drifted = profile.clone();
		drifted.security = Security::Eap {
			method: "peap".to_owned(),
			identity: Some("somebody.else@example.ac.uk".to_owned()),
			anonymous_identity: None,
			ca_cert: Some("/ca.pem".to_owned()),
			client_cert: None,
			phase2: None,
		};
		let error = compiles_back(&config, &factory, &drifted).expect_err("the identity moved");
		assert!(error.contains("identity"), "{error}");
	}

	/// An id that would leave the directory is refused inside `install`, not by
	/// a caller remembering to ask.
	///
	/// With 0117's socket request the caller is a remote client, so an id of
	/// `../../etc/cron.d/x` would otherwise be a file written wherever the
	/// daemon can write. Checked here rather than only in the CLI because the
	/// CLI is no longer the only caller.
	#[test]
	fn an_id_that_escapes_the_directory_is_refused() {
		let dir = netcfgd_testdir::TestDir::new("wifi-profile-traversal");
		let config = dir.join("etc");
		std::fs::create_dir_all(config.join("conf.d")).expect("the directory is made");

		for bad in ["../escape", "with/slash", ".hidden", "", "we\"ird"] {
			let profile = Profile {
				id: bad.to_owned(),
				ssid: Ssid::new(b"x".to_vec()).expect("a short ssid"),
				hidden: false,
				priority: None,
				security: Security::Open,
			};
			let error = install(&config, &dir.join("factory"), &profile, None)
				.expect_err("a name that is not usable is refused");
			assert!(
				error.message.contains("cannot be used as a name"),
				"{bad}: {error}"
			);
		}
	}
}
