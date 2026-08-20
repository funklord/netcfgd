//! `ncfg wifi add`: joining a network without opening an editor.
//!
//! Everything else under `ncfg wifi` asks the daemon a question or tells it to
//! do something. This one writes a file, and that is not an inconsistency: the
//! configuration is the only place a network can be remembered, `netcfgd.service`
//! mounts `/etc/netcfgd` read-only, and decision 0030 already established that a
//! client writes the operator's config directly rather than posting it through
//! the daemon. So `add` is a config-file generator that happens to live next to
//! the commands that use what it writes.
//!
//! What it produces is deliberately ordinary: one `network` block in
//! `conf.d/wifi-<id>.conf`, a passphrase in `secrets/<id>` at mode 0600, and a
//! `@secret:` reference between them. Nothing here is a format only this command
//! can read, and deleting the file is the whole of forgetting a network.

use crate::Options;
use netcfgd_host::{config, wifi_profile};
use netcfgd_model::Ssid;
use std::path::Path;
#[cfg(test)]
use std::path::PathBuf;
use std::process::ExitCode;

/// The parts of a `network` block the command line can say.
///
/// A deliberately short list. Every field of `WifiNetwork` is reachable by
/// editing the file this writes -- which the command prints the path of -- so
/// what earns a flag is what a network cannot be *joined* without (`hidden`,
/// and the security), what has to be decided while the passphrase is in hand
/// (`open`), and the one thing an operator adding a second network immediately
/// wants (`priority`).
#[derive(Debug, Default, Clone)]
pub(crate) struct Wanted {
	/// `--id`: the block's label, when the SSID is not usable as one.
	pub(crate) id: Option<String>,
	/// `--priority`: higher wins, and 0 is the model's default.
	pub(crate) priority: Option<u32>,
	/// `--open`: no security at all.
	pub(crate) open: bool,
	/// `--wpa2` or `--wpa3`, pinning one generation.
	pub(crate) proto: Option<&'static str>,
	/// `--hidden`: the SSID is not broadcast, so it has to be probed for.
	pub(crate) hidden: bool,
	/// `--eap`: the method, for an enterprise network.
	///
	/// A campus or corporate network is the one thing a laptop meets that this
	/// command could not add, and the reason it was left is that EAP is a form
	/// rather than a flag: which fields are needed depends on the method, and
	/// three of the four want a secret that must not be an argument.
	pub(crate) eap: Option<&'static str>,
	/// `--identity`: who you are to the authentication server.
	pub(crate) identity: Option<String>,
	/// `--anonymous-identity`: who you are *outside* the tunnel.
	///
	/// The whole point of a tunnelled method: the real identity goes inside the
	/// encrypted tunnel and this is what the radio and anyone listening see.
	/// eduroam's own guidance is `anonymous@realm`.
	pub(crate) anonymous_identity: Option<String>,
	/// `--ca-cert`: the certificate the server is checked against.
	pub(crate) ca_cert: Option<String>,
	/// `--client-cert`: the certificate presented, for EAP-TLS.
	pub(crate) client_cert: Option<String>,
	/// `--phase2`: the inner method, where the method tunnels one.
	pub(crate) phase2: Option<String>,
}

/// What an enterprise network needs, per method, before anything is written.
///
/// **This is the form part.** A flag list cannot express "TLS wants a client
/// certificate and PEAP wants a password", so the alternative to refusing here
/// is a file that compiles and a network that never joins -- which is 0017's
/// distinction between refusing what would work and refusing what cannot.
///
/// Each refusal names the flag to add rather than the field that is missing,
/// because the reader is at a command line and not in the model.
fn check_enterprise(wanted: &Wanted) -> Result<(), String> {
	let Some(method) = wanted.eap else {
		// The enterprise flags are meaningless without one, and silently
		// ignoring them would write a personal network for somebody who
		// believed they had written a corporate one.
		for (value, flag) in [
			(&wanted.identity, "--identity"),
			(&wanted.anonymous_identity, "--anonymous-identity"),
			(&wanted.ca_cert, "--ca-cert"),
			(&wanted.client_cert, "--client-cert"),
			(&wanted.phase2, "--phase2"),
		] {
			if value.is_some() {
				return Err(format!(
					"{flag} is for an enterprise network and this one has no method. \
					 Add `--eap peap`, `--eap ttls`, `--eap tls` or `--eap pwd`"
				));
			}
		}
		return Ok(());
	};

	if wanted.open {
		return Err(
			"--open and --eap contradict each other: one says there is no \
			 authentication and the other says which kind"
				.to_owned(),
		);
	}
	if wanted.proto.is_some() {
		return Err(
			"--wpa2/--wpa3 name a generation for a passphrase, and --eap says \
			 there is no passphrase. An enterprise network negotiates its own"
				.to_owned(),
		);
	}
	if wanted.identity.is_none() {
		return Err(format!(
			"--eap {method} needs `--identity`, which is who you are to the \
			 authentication server -- often your username, and often with a realm: \
			 `--identity you@example.ac.uk`"
		));
	}
	// TLS authenticates with a certificate and no password; the other three
	// authenticate with a password and no certificate of their own. Getting
	// this wrong is a network that will not join, and wpa_supplicant says so
	// only in its log.
	if method == "tls" && wanted.client_cert.is_none() {
		return Err("--eap tls authenticates with a certificate, so it needs \
			 `--client-cert PATH`. The private key is asked for, not passed"
			.to_owned());
	}
	if method != "tls" && wanted.client_cert.is_some() {
		return Err(format!(
			"--client-cert is for `--eap tls`, which authenticates with a \
			 certificate. `--eap {method}` authenticates with a password"
		));
	}
	Ok(())
}

/// Add a network to the configuration.
///
/// # Errors
///
/// Returns the sentence to print. Nothing is left behind by a failure: the two
/// files are written only after every check has passed, and are removed again if
/// what they compile to is not what was asked for.
pub(crate) fn add(positional: &[String], options: &Options) -> Result<ExitCode, String> {
	let [ssid_text] = positional else {
		return Err(
			"`ncfg wifi add` takes one SSID: `ncfg wifi add \"Cafe Wifi\"`. \
		            The passphrase is asked for, or read from standard input"
				.to_owned(),
		);
	};

	let wanted = &options.wifi;
	if wanted.open && wanted.proto.is_some() {
		return Err(
			"--open and --wpa2/--wpa3 contradict each other: one says there is no \
			 passphrase and the other says which generation protects it"
				.to_owned(),
		);
	}
	check_enterprise(wanted)?;

	let ssid = Ssid::new(ssid_text.as_bytes().to_vec())
		.map_err(|error| format!("that is not a usable ssid: {error}"))?;
	let id = wanted.id.clone().unwrap_or_else(|| ssid_text.clone());
	usable_label(&id)?;

	// Before anything is written. A second block with the same label is a
	// compile error, so writing it would break the whole configuration -- every
	// interface on the machine -- to add one network. A configuration that does
	// not compile is refused for the same reason from the other direction: an
	// error that was already there, reported after this wrote a file, is an
	// error the operator will spend the evening blaming on this command.
	let document = current(options)?;
	if let Some(existing) = document
		.as_ref()
		.and_then(|document| document.networks.iter().find(|network| network.id == id))
	{
		return Err(format!(
			"a network `{}` is already configured. Change it by editing the \
			 configuration, or remove it and add it again",
			existing.id
		));
	}

	let config_dir = config::resolve_dir(options.config_dir.as_deref());
	let factory_dir = config::resolve_factory_dir(options.factory_dir.as_deref());

	// An enterprise network cannot go over the socket, so a caller who cannot
	// write the file cannot add one at all -- and that has to be said *here*,
	// under the same rule as the credential below: a refusal that was going to
	// happen anyway should not happen after somebody has typed a password.
	//
	// This one does have to predict, because the alternative is to find out
	// after the prompt. It predicts by asking the directory the block would go
	// in rather than the config directory, which is the distinction the
	// fallback below got wrong first time.
	if wanted.eap.is_some() && !can_write(&wifi_profile::profile_path(&config_dir, &id)) {
		return Err(format!(
			"cannot write {} and an enterprise network cannot be added through \
			 the daemon: `--eap` carries certificate paths, which the socket \
			 deliberately does not accept (0117). Add this one as root",
			config_dir.display()
		));
	}

	// The credential last, because it is the only step that stops and waits for
	// a person: a refusal that was going to happen anyway should not happen
	// after the passphrase has been typed. `install` refuses an existing file
	// or stored credential before it writes either, so nothing below this
	// line can clobber what somebody else wrote.
	let credential = if wanted.open {
		None
	} else {
		Some(read_credential(&id, wanted)?)
	};

	// The rendering, the paths and the compile-it-back check are
	// netcfgd-host's, shared with the socket's `wifi_add` (0117). Two
	// implementations of "what a `network` block looks like" is the drift this
	// tree keeps finding, so there is one.
	let profile = wifi_profile::Profile {
		id: id.clone(),
		ssid,
		hidden: wanted.hidden,
		priority: wanted.priority,
		security: security_of(wanted),
	};
	let written =
		match wifi_profile::install(&config_dir, &factory_dir, &profile, credential.as_deref()) {
			Ok(written) => written,
			// `/etc/netcfgd` is root's, so a member of the `netcfgd` group running
			// this cannot write it and met `Permission denied` on a command the
			// tier system says is theirs (0124). Ask the daemon instead, which is
			// what the GUI and the TUI have always done and what `wifi_add` exists
			// for -- one outcome, reached by whichever route the caller can use.
			//
			// `denied` and not a writability probe. The first version of this asked
			// whether the *config directory* could be written, and a test caught it
			// answering for the wrong directory: the block goes in `conf.d`, so a
			// writable `conf.d` under an unwritable parent took the local path and
			// succeeded where the probe said it could not. The question worth
			// asking is the one the kernel already answered.
			Err(error) if error.denied => {
				return add_over_socket(
					&profile,
					credential.as_deref(),
					wanted,
					options,
					&error.message,
				);
			}
			Err(error) => return Err(error.message),
		};

	report(
		&written.file,
		&wifi_profile::secret_path(&config_dir, &id),
		&id,
		wanted,
		written.secret.is_some(),
		document.as_ref(),
	);
	Ok(ExitCode::SUCCESS)
}

/// Whether this process could create `target`.
///
/// Asked by writing, because that is the only answer that is true: a mode and
/// an owner have to be read against this process's uid and every supplementary
/// group, and a filesystem may be read-only or refuse for a reason neither
/// mentions. The probe is created and removed, so nothing is left behind.
///
/// Used for the one case that has to be answered *before* attempting anything,
/// which is the enterprise refusal above. Everywhere else the write is tried
/// and `InstallError::denied` carries the kernel's own answer, which is better
/// evidence than any prediction.
///
/// It probes the directory `target` would sit in, not `target` itself, and not
/// the config directory: the block goes in `conf.d`, and asking about the
/// parent of that is how the first version of this got a wrong answer.
fn can_write(target: &Path) -> bool {
	let Some(directory) = target.parent() else {
		return false;
	};
	if !directory.is_dir() {
		// `install` would create it, so the question becomes whether *its*
		// parent allows that.
		return directory.parent().is_some_and(can_write_dir);
	}
	can_write_dir(directory)
}

/// The probe itself, on a directory that exists.
fn can_write_dir(directory: &Path) -> bool {
	let probe = directory.join(".ncfg-write-probe");
	match std::fs::OpenOptions::new()
		.write(true)
		.create_new(true)
		.open(&probe)
	{
		Ok(_) => {
			let _ = std::fs::remove_file(&probe);
			true
		}
		Err(_) => false,
	}
}

/// Add the network through the daemon, for a caller who cannot write the file.
///
/// The credential travels inbound in the request, is written by the daemon
/// through the secret provider at 0600, and the block keeps an `@secret:`
/// reference -- so the desired-state document stays free of secret material
/// exactly as it does when this command writes the file itself (0117).
fn add_over_socket(
	profile: &wifi_profile::Profile,
	credential: Option<&str>,
	wanted: &Wanted,
	options: &Options,
	local_error: &str,
) -> Result<ExitCode, String> {
	// The socket has no enterprise arm: an 802.1X network carries certificate
	// *paths*, which are files the daemon would hand to a supplicant running as
	// root, and 0117 left how to carry those undecided. Saying so beats an
	// error about a field the reader never named.
	if wanted.eap.is_some() {
		return Err(format!(
			"could not write the configuration ({local_error}), and an enterprise \
			 network cannot be added through the daemon: `--eap` carries certificate \
			 paths, which the socket deliberately does not accept. Add this one as \
			 root, or from a machine where you can write /etc/netcfgd"
		));
	}

	let run_dir = crate::state::resolve_dir(options.run_dir.as_deref());
	let socket = crate::client::socket_path(&run_dir);
	let request = netcfgd_proto::Request::WifiAdd {
		ssid: profile.ssid.to_hex(),
		id: Some(profile.id.clone()),
		passphrase: credential.map(str::to_owned),
		proto: wanted.proto.map(str::to_owned),
		hidden: profile.hidden,
		priority: profile.priority,
	};

	match crate::client::ask(&socket, &request) {
		Ok(crate::client::Answer::Ok) => {
			println!("added `{}` through netcfgd", profile.id);
			println!(
				"the configuration is root's, so this went to the daemon rather than \
				 straight to a file"
			);
			println!("`ncfg wifi connect \"{}\"` joins it now", profile.id);
			Ok(ExitCode::SUCCESS)
		}
		Ok(crate::client::Answer::Error { message }) => Err(message),
		Ok(other) => Err(format!("the daemon sent {}", other.describe())),
		// Both halves failed, and reporting only the second sends the reader
		// after a daemon when the answer may be that they meant to run this as
		// root. Name what each one could not do.
		Err(message) => Err(format!(
			"could not write the configuration ({local_error}), and could not ask \
			 netcfgd to do it either: {message}"
		)),
	}
}

/// The configuration as it stands, or `None` if there is not one yet.
///
/// The distinction matters here and nowhere else in `ncfg`: every other command
/// has nothing to do without a configuration, and this one is what a machine
/// with no configuration at all runs first. Refusing to add the first network
/// because there is no network to add it to would be a fine joke and a useless
/// tool.
fn current(options: &Options) -> Result<Option<netcfgd_model::Document>, String> {
	let config_dir = config::resolve_dir(options.config_dir.as_deref());
	let factory_dir = config::resolve_factory_dir(options.factory_dir.as_deref());
	let sources = config::load_layered(&factory_dir, &config_dir)
		.map_err(|error| format!("could not read {}: {error}", config_dir.display()))?;
	if sources.is_empty() {
		return Ok(None);
	}
	// Loaded twice -- once here to ask whether there is anything, once inside
	// `compile` to compile it -- because `compile` is where hook materialising
	// and provenance live and a second implementation of it here would be a
	// second answer to what the configuration says.
	let (document, _) = super::compile(options)?;
	Ok(Some(document))
}

/// Whether an id can be a block label, a filename and a secret name at once.
///
/// It has to be all three, and the strictest of the three wins. The label rules
/// are `netcfgd-nm`'s (a quote or a backslash would have to be escaped in the
/// file, and a control character in a config file is never intentional); the
/// rest are the secret provider's, which refuses a name containing a path
/// separator or `..` because a config file that could name any path would let a
/// network read `/etc/shadow` as its passphrase.
fn usable_label(id: &str) -> Result<(), String> {
	crate::secret::usable_name(id).map_err(|why| {
		format!(
			"`{id}` cannot be used as a name here: {why}. Pass `--id` with a \
			 plainer one -- the SSID itself is kept exactly, as hex"
		)
	})
}

/// What the flags say about how the network is protected.
///
/// The CLI can reach the `Eap` arm and the socket's `wifi_add` cannot, which is
/// 0117's line: an enterprise network names certificate *paths*, and a path is
/// a file the daemon would hand to a supplicant running as root. Somebody
/// typing flags on their own machine is a different question from a client
/// asking a privileged daemon.
fn security_of(wanted: &Wanted) -> wifi_profile::Security {
	if wanted.open {
		return wifi_profile::Security::Open;
	}
	if let Some(method) = wanted.eap {
		return wifi_profile::Security::Eap {
			method: method.to_owned(),
			identity: wanted.identity.clone(),
			anonymous_identity: wanted.anonymous_identity.clone(),
			ca_cert: wanted.ca_cert.clone(),
			client_cert: wanted.client_cert.clone(),
			phase2: wanted.phase2.clone(),
		};
	}
	wifi_profile::Security::Psk {
		proto: wanted.proto.map(ToOwned::to_owned),
	}
}

/// Say what happened, and what it does not yet do.
fn report(
	file: &Path,
	secret: &Path,
	id: &str,
	wanted: &Wanted,
	stored: bool,
	before: Option<&netcfgd_model::Document>,
) {
	println!("wrote {}", file.display());
	if stored {
		println!("wrote {} (mode 0600)", secret.display());
	}
	if wanted.open {
		println!(
			"`{id}` has no security: anything sent over it is readable by \
			 anybody in range"
		);
	}

	// A network profile is not bound to a device, so a configuration with no
	// radio in it compiles perfectly and joins nothing. Saying so here is
	// decision 0061's rule -- a thing that compiles either does something or
	// says it does not -- applied to the file this just wrote.
	let radio =
		before.is_some_and(|document| document.devices.iter().any(|device| device.wifi.is_some()));
	if !radio {
		println!(
			"nothing will use it yet: no device in this configuration has a \
			 `wifi` block. Add one -- `device wlan0 {{ wifi {{ }} }}` -- and the \
			 radio can associate"
		);
	}

	// Quoted when it needs to be, because a copied line that does not run is
	// worse than no suggestion, and an SSID with a space in it is ordinary.
	let quoted = if id.contains(char::is_whitespace) {
		format!("\"{id}\"")
	} else {
		id.to_owned()
	};
	println!("`ncfg plan` shows what it changes; `ncfg wifi connect {quoted}` joins it now");
}

/// Ask for the passphrase, or read it from a pipe.
///
/// A passphrase is never an argument. `ps` shows one to every user on the
/// machine and the shell writes it to a history file, and neither is undone by
/// the operator noticing afterwards.
///
/// On a terminal it is prompted for with echo off; on a pipe it is one line on
/// standard input, which is what makes the command scriptable without a
/// passphrase ever reaching a command line.
fn read_passphrase(id: &str) -> Result<String, String> {
	let passphrase = crate::secret::read_without_echo(&format!("passphrase for `{id}`"))?;
	check_passphrase(&passphrase)?;
	Ok(passphrase)
}

/// The one secret this network needs, asked for by its own name.
///
/// Three different things live at `@secret:<id>` depending on the network, and
/// the prompt has to say which or the operator types the wrong one: a WPA
/// passphrase, an EAP password, or the private key an EAP-TLS certificate goes
/// with. Only the first has length rules -- an EAP password is whatever the
/// authentication server says it is, and checking it against WPA's 8-to-63 rule
/// would refuse valid credentials.
///
/// Never an argument, for the reason `ncfg secret set` exists (0075): an
/// argument is in the process table and in the shell's history.
fn read_credential(id: &str, wanted: &Wanted) -> Result<String, String> {
	match wanted.eap {
		None => read_passphrase(id),
		Some("tls") => crate::secret::read_without_echo(&format!(
			"private key for `{id}` (the path wpa_supplicant should load, or the key itself)"
		)),
		Some(_) => crate::secret::read_without_echo(&format!("EAP password for `{id}`")),
	}
}

/// The passphrase rules, refused here rather than by the supplicant.
///
/// The same two checks `netcfgd-supplicant` makes before it sends one, made
/// where the operator can still fix it: at association time the failure is a
/// bare `FAIL`, half an hour after the file was written.
///
/// The length is safe to report and the value is not, which is the rule
/// `netcfgd-secret` keeps everywhere.
fn check_passphrase(passphrase: &str) -> Result<(), String> {
	let length = passphrase.chars().count();
	if !(8..=63).contains(&length) {
		return Err(format!(
			"a WPA passphrase is 8 to 63 characters and that one is {length}. \
			 A 64-digit hex key -- a pre-computed PMK rather than a passphrase \
			 -- is not something netcfgd can send"
		));
	}
	if passphrase.chars().any(char::is_control) {
		return Err(
			"that passphrase contains a control character, which cannot be sent \
			 to the supplicant at all"
				.to_owned(),
		);
	}
	Ok(())
}

#[cfg(test)]
mod tests {

	/// The block these flags produce.
	///
	/// The renderer moved to `netcfgd_host::wifi_profile` when the socket
	/// gained a second caller (0117), so these tests go through the mapping
	/// this crate still owns -- flags to a `Security` -- and then through the
	/// shared renderer, which is the same path `ncfg wifi add` now takes.
	fn block(id: &str, ssid: &Ssid, wanted: &Wanted) -> String {
		wifi_profile::render(&wifi_profile::Profile {
			id: id.to_owned(),
			ssid: ssid.clone(),
			hidden: wanted.hidden,
			priority: wanted.priority,
			security: security_of(wanted),
		})
	}

	use super::*;

	fn wanted() -> Wanted {
		Wanted::default()
	}

	#[test]
	fn a_psk_network_becomes_a_block_and_a_reference() {
		let ssid = Ssid::new(b"HomeFiber".to_vec()).expect("a short ssid");
		let text = block("HomeFiber", &ssid, &wanted());
		assert!(text.contains("network \"HomeFiber\" {"), "{text}");
		assert!(text.contains("psk = \"@secret:HomeFiber\""), "{text}");
		// The label is the SSID, so there is nothing for the hex form to say.
		assert!(!text.contains("ssid ="), "{text}");
		// Neither default is written out.
		assert!(!text.contains("proto"), "{text}");
		assert!(!text.contains("priority"), "{text}");
	}

	#[test]
	fn a_label_that_is_not_the_ssid_keeps_the_ssid_as_hex() {
		let ssid = Ssid::new("Cafe Wifi".as_bytes().to_vec()).expect("a short ssid");
		let text = block("cafe", &ssid, &wanted());
		assert!(text.contains("network \"cafe\" {"), "{text}");
		assert!(
			text.contains(&format!("ssid = \"{}\"", ssid.to_hex())),
			"{text}"
		);
		// And it round-trips, which is the property `--id` depends on.
		assert_eq!(
			Ssid::from_hex(&ssid.to_hex()).expect("hex"),
			ssid,
			"the hex form must parse back to the same octets"
		);
	}

	#[test]
	fn the_flags_that_exist_reach_the_file() {
		let ssid = Ssid::new(b"h".to_vec()).expect("a short ssid");
		let text = block(
			"h",
			&ssid,
			&Wanted {
				id: None,
				priority: Some(30),
				open: false,
				proto: Some("wpa3"),
				hidden: true,
				eap: None,
				identity: None,
				anonymous_identity: None,
				ca_cert: None,
				client_cert: None,
				phase2: None,
			},
		);
		assert!(text.contains("hidden = true"), "{text}");
		assert!(text.contains("proto = \"wpa3\""), "{text}");
		assert!(text.contains("priority = 30"), "{text}");
	}

	/// An enterprise network reaches the file with the keys the supplicant
	/// needs, and the secret under the key its method uses.
	#[test]
	fn an_enterprise_network_writes_what_the_supplicant_wants() {
		let ssid = Ssid::new(b"eduroam".to_vec()).expect("a short ssid");
		let text = block(
			"eduroam",
			&ssid,
			&Wanted {
				eap: Some("peap"),
				identity: Some("you@example.ac.uk".to_owned()),
				anonymous_identity: Some("anonymous@example.ac.uk".to_owned()),
				ca_cert: Some("/etc/ssl/certs/ca.pem".to_owned()),
				phase2: Some("mschapv2".to_owned()),
				..Wanted::default()
			},
		);
		assert!(text.contains("eap = \"peap\""), "{text}");
		assert!(text.contains("identity = \"you@example.ac.uk\""), "{text}");
		assert!(
			text.contains("anonymous_identity = \"anonymous@example.ac.uk\""),
			"{text}"
		);
		assert!(text.contains("phase2 = \"mschapv2\""), "{text}");
		// A password, and never a psk: the two are different keys and a network
		// with both is refused by the compiler.
		assert!(text.contains("password = \"@secret:eduroam\""), "{text}");
		assert!(!text.contains("psk ="), "{text}");
	}

	/// EAP-TLS stores its secret under `private_key`, not `password`.
	///
	/// The supplicant refuses the network outright if it is given the other one
	/// -- `MissingEapField` for whichever it wanted -- and the failure arrives
	/// at association time in a log nobody is reading.
	#[test]
	fn eap_tls_stores_a_key_rather_than_a_password() {
		let ssid = Ssid::new(b"Corp".to_vec()).expect("a short ssid");
		let text = block(
			"Corp",
			&ssid,
			&Wanted {
				eap: Some("tls"),
				identity: Some("me".to_owned()),
				client_cert: Some("/etc/ssl/certs/me.pem".to_owned()),
				..Wanted::default()
			},
		);
		assert!(text.contains("private_key = \"@secret:Corp\""), "{text}");
		assert!(!text.contains("password ="), "{text}");
		assert!(
			text.contains("client_cert = \"/etc/ssl/certs/me.pem\""),
			"{text}"
		);
	}

	/// A value with a quote in it does not end the string early.
	///
	/// An identity comes off the command line and goes into a quoted string in
	/// a file the compiler reads back. Unescaped, `we"ird` closes the string and
	/// the file does not compile -- which takes every other interface on the
	/// machine with it, the loader compiling the directory as one document.
	///
	/// Asserted through the rendered block rather than on the escaping helper,
	/// which moved with the renderer. That is the stronger test anyway: it
	/// checks what ends up in the file, so it would still fail if the escaping
	/// were correct and the renderer stopped calling it.
	#[test]
	fn a_value_with_a_quote_in_it_is_escaped() {
		let ssid = Ssid::new(b"Corp".to_vec()).expect("a short ssid");
		let wanted = Wanted {
			eap: Some("peap"),
			identity: Some(r#"we"ird"#.to_owned()),
			ca_cert: Some(r"back\slash".to_owned()),
			..Wanted::default()
		};
		let text = block("Corp", &ssid, &wanted);
		assert!(text.contains(r#"identity = "we\"ird""#), "{text}");
		assert!(text.contains(r#"ca_cert = "back\\slash""#), "{text}");
	}

	/// The enterprise flags are refused where they would do nothing, and the
	/// combinations that cannot work are refused before a file exists.
	#[test]
	fn an_impossible_enterprise_network_is_refused_before_anything_is_written() {
		fn with(f: impl FnOnce(&mut Wanted)) -> Result<(), String> {
			let mut wanted = Wanted::default();
			f(&mut wanted);
			check_enterprise(&wanted)
		}

		// A method needs an identity, whichever method it is.
		for method in ["peap", "ttls", "tls", "pwd"] {
			let error = with(|w| w.eap = Some(method)).expect_err("no identity");
			assert!(error.contains("--identity"), "{method}: {error}");
		}
		// TLS presents a certificate; the others present a password.
		let error = with(|w| {
			w.eap = Some("tls");
			w.identity = Some("me".to_owned());
		})
		.expect_err("no client certificate");
		assert!(error.contains("--client-cert"), "{error}");
		let error = with(|w| {
			w.eap = Some("peap");
			w.identity = Some("me".to_owned());
			w.client_cert = Some("/x".to_owned());
		})
		.expect_err("a certificate on a password method");
		assert!(error.contains("--client-cert"), "{error}");

		// And the two kinds of security do not mix.
		for set in [
			(|w: &mut Wanted| w.open = true) as fn(&mut Wanted),
			|w: &mut Wanted| w.proto = Some("wpa3"),
		] {
			let error = with(|w| {
				w.eap = Some("peap");
				w.identity = Some("me".to_owned());
				set(w);
			})
			.expect_err("two kinds of security");
			assert!(error.contains("--eap"), "{error}");
		}

		// An enterprise flag with no method is a personal network somebody
		// believed was a corporate one.
		let error =
			with(|w| w.identity = Some("me".to_owned())).expect_err("an identity with no method");
		assert!(error.contains("--eap"), "{error}");

		// And an ordinary network still passes.
		assert!(with(|w| w.proto = Some("wpa3")).is_ok());
		assert!(with(|w| w.open = true).is_ok());
	}

	#[test]
	fn an_open_network_has_no_secret_reference() {
		let ssid = Ssid::new(b"Airport".to_vec()).expect("a short ssid");
		let text = block(
			"Airport",
			&ssid,
			&Wanted {
				open: true,
				..wanted()
			},
		);
		assert!(text.contains("open = true"), "{text}");
		assert!(!text.contains("@secret:"), "{text}");
	}

	#[test]
	fn a_label_that_would_be_a_path_is_refused() {
		for bad in ["", "a/b", "../etc", ".hidden", "a\"b", "a\\b", "a\nb"] {
			assert!(
				usable_label(bad).is_err(),
				"`{bad}` should not be usable as an id"
			);
		}
		// The last is non-ASCII, spelled as an escape because the source of this
		// project is ASCII: an SSID is octets and a label is text, and a label
		// outside ASCII has to be usable or half of Europe cannot name its
		// networks.
		for good in ["HomeFiber", "Cafe Wifi", "a.b-c_d", "hus#1", "\u{c5}lens"] {
			assert!(usable_label(good).is_ok(), "`{good}` should be usable");
		}
	}

	#[test]
	fn a_passphrase_is_checked_before_the_supplicant_sees_it() {
		assert!(check_passphrase("hunter2hunter2").is_ok());
		assert!(check_passphrase("short").is_err());
		assert!(check_passphrase(&"x".repeat(64)).is_err());
		assert!(check_passphrase("has\ttab").is_err());
		// Exactly the boundaries the backend enforces, so that a passphrase
		// this accepts is one it can send.
		assert!(check_passphrase(&"x".repeat(8)).is_ok());
		assert!(check_passphrase(&"x".repeat(63)).is_ok());
	}

	/// Make the config tree unwritable, and give back what undoes it.
	///
	/// **Both directories, not just the top one.** The first version of this
	/// chmodded `etc` and left `etc/conf.d` writable, which is not a shape any
	/// real machine has -- `/etc/netcfgd` and its `conf.d` are both root's --
	/// and it let a write succeed that the test was asserting could not happen.
	/// A fixture that does not model the situation tests a situation nobody is
	/// in.
	fn make_read_only(etc: &Path) -> impl FnOnce() + use<> {
		use std::os::unix::fs::PermissionsExt;

		let directories = [etc.to_path_buf(), etc.join("conf.d")];
		for directory in &directories {
			std::fs::set_permissions(directory, std::fs::Permissions::from_mode(0o555))
				.expect("read-only");
		}
		move || {
			// Deepest first, and always: a fixture left unwritable cannot be
			// removed, so the temporary directory would outlive the run.
			for directory in directories.iter().rev() {
				let _ = std::fs::set_permissions(directory, std::fs::Permissions::from_mode(0o755));
			}
		}
	}

	/// A config tree with one radio in it and nothing else.
	///
	/// A counter as well as the process id: cargo runs these in parallel
	/// threads of one process, and a shared path is one test wiping another's
	/// fixture from under it.
	fn fixture(tag: &str) -> (netcfgd_testdir::TestDir, Options) {
		let root = netcfgd_testdir::TestDir::new(&format!("wifi-add-{tag}"));
		std::fs::create_dir_all(root.join("etc/conf.d")).expect("a config directory");
		std::fs::create_dir_all(root.join("run")).expect("a run directory");
		std::fs::write(
			root.join("etc/netcfgd.conf"),
			"device wlan0 {\n\twifi { backend = \"wpa_supplicant\" }\n}\n",
		)
		.expect("a config file");

		let options = Options {
			config_dir: Some(root.join("etc").display().to_string()),
			factory_dir: Some(root.join("factory").display().to_string()),
			run_dir: Some(root.join("run").display().to_string()),
			..Options::default()
		};
		(root, options)
	}

	/// 0124 put adding a network in the `wifi` tier, and this command is the
	/// half of it that does not go over the socket: it writes `/etc/netcfgd`,
	/// which is root's. A group member therefore has the permission and not the
	/// access, and falls back to asking the daemon.
	///
	/// Checked on a directory made read-only rather than by a different uid,
	/// because a test cannot become one. That is enough for what is being
	/// asserted -- the *decision* is "can this process create a file here", and
	/// a read-only directory answers it the same way a root-owned one does for
	/// somebody who is not root.
	#[test]
	fn an_unwritable_config_directory_is_not_written_to() {
		// Open, so no passphrase is asked for. A PSK network legitimately
		// prompts before this point, because the credential is needed on
		// whichever route the add takes -- so prompting first is correct there
		// and would only obscure what this test is about.
		let (root, mut options) = fixture("unwritable");
		options.wifi.open = true;
		let etc = root.join("etc");
		let restore = make_read_only(&etc);

		assert!(
			!can_write(&wifi_profile::profile_path(&etc, "Cafe")),
			"the probe should not be able to write the block"
		);

		// No daemon is listening under this fixture's run directory, so the
		// fallback cannot complete -- and what matters is that it was *tried*
		// and that the message names both halves. Reporting only the socket
		// would send a reader after a daemon when the answer is to run this as
		// root; reporting only the write would hide that there is another way.
		let error = add(&["Cafe".to_owned()], &options).expect_err("it cannot be added");
		assert!(
			error.contains("could not write the configuration"),
			"the local failure is not named: {error}"
		);
		assert!(
			error.contains("could not ask netcfgd"),
			"the fallback was not attempted, or its failure is not named: {error}"
		);

		// Nothing was left behind by either half.
		assert!(!etc.join("conf.d/wifi-Cafe.conf").exists());
		assert!(!etc.join("secrets").exists());

		restore();
	}

	/// An enterprise network cannot cross the socket, so it is refused before
	/// the passphrase prompt rather than after it.
	///
	/// The ordering is the assertion. `--eap` reaches a prompt that stops and
	/// waits for a person, and a refusal that was always going to happen must
	/// not happen after they have typed. There is no stdin here, so a prompt
	/// would fail with a message about a missing password -- which is what this
	/// distinguishes.
	#[test]
	fn an_enterprise_network_is_refused_before_anyone_types_a_password() {
		let (root, mut options) = fixture("unwritable-eap");
		let etc = root.join("etc");
		options.wifi.eap = Some("peap");
		options.wifi.identity = Some("you@example.ac.uk".to_owned());
		let restore = make_read_only(&etc);

		let error = add(&["eduroam".to_owned()], &options).expect_err("it cannot be added");
		assert!(
			error.contains("cannot be added through the daemon"),
			"the reason is not the socket's missing enterprise arm: {error}"
		);
		assert!(
			!error.contains("password"),
			"it got as far as asking for a credential: {error}"
		);

		restore();
	}

	/// The ordinary case still writes the file and never asks the daemon.
	///
	/// The pair for the two above: a fallback that triggered when it should not
	/// would send every `ncfg wifi add` through a socket that need not be
	/// running, on the machine that has no network yet -- which is the case
	/// this command exists for.
	#[test]
	fn a_writable_config_directory_is_written_directly() {
		let (root, options) = fixture("writable");
		assert!(can_write(&root.join("etc")));
		options.config_dir.as_ref().expect("the fixture names one");
		add(&["Cafe".to_owned()], &{
			let mut options = options;
			options.wifi.open = true;
			options
		})
		.expect("it is added");
		assert!(root.join("etc/conf.d/wifi-Cafe.conf").exists());
	}

	#[test]
	fn an_open_network_is_written_and_compiles() {
		let (root, mut options) = fixture("open");
		options.wifi.open = true;
		add(&["Airport".to_owned()], &options).expect("it is added");

		let path = root.join("etc/conf.d/wifi-Airport.conf");
		let text = std::fs::read_to_string(&path).expect("the file it wrote");
		assert!(text.contains("network \"Airport\" {"), "{text}");
		// The whole point of the verify step: what it wrote is what the daemon
		// reads, through the same loader.
		let (document, _) = crate::compile(&options).expect("it compiles");
		assert_eq!(document.networks.len(), 1);
		assert_eq!(document.networks[0].id, "Airport");
		assert!(matches!(
			document.networks[0].security,
			netcfgd_model::Security::Open
		));
		// No passphrase was asked for, so no secret was written.
		assert!(!root.join("etc/secrets/Airport").exists());
		let _ = std::fs::remove_dir_all(&root);
	}

	#[test]
	fn a_network_that_is_already_configured_is_refused_and_nothing_changes() {
		let (root, mut options) = fixture("dup");
		options.wifi.open = true;
		add(&["Airport".to_owned()], &options).expect("the first one");

		let path = root.join("etc/conf.d/wifi-Airport.conf");
		let before = std::fs::read_to_string(&path).expect("the file");
		let error = add(&["Airport".to_owned()], &options).expect_err("the second one");
		assert!(error.contains("already configured"), "{error}");
		assert_eq!(
			std::fs::read_to_string(&path).expect("still there"),
			before,
			"a refusal must not touch the file that was already there"
		);
		let _ = std::fs::remove_dir_all(&root);
	}

	#[test]
	fn contradictory_security_is_refused_before_anything_is_written() {
		let (root, mut options) = fixture("contra");
		options.wifi.open = true;
		options.wifi.proto = Some("wpa3");
		let error = add(&["Airport".to_owned()], &options).expect_err("it is refused");
		assert!(error.contains("--open and --wpa2/--wpa3"), "{error}");
		assert!(!root.join("etc/conf.d/wifi-Airport.conf").exists());
		let _ = std::fs::remove_dir_all(&root);
	}

	/// And `add` is where the enterprise checks are made, not only the
	/// function that makes them.
	///
	/// Written after a break landed and nothing went red: the test above it
	/// calls `check_enterprise` directly, so deleting the call from `add`
	/// changed nothing any check could see. A refusal nobody reaches is not a
	/// refusal, and this one goes through the command with a real directory --
	/// which also proves the refusal happens *before* the prompt, since a test
	/// has no terminal to type a password at.
	#[test]
	fn an_enterprise_network_is_refused_by_the_command_and_not_only_the_check() {
		let (root, mut options) = fixture("contra-eap");
		options.wifi.eap = Some("peap");
		let error = add(&["Corp".to_owned()], &options).expect_err("it is refused");
		assert!(error.contains("--identity"), "{error}");
		assert!(!root.join("etc/conf.d/wifi-Corp.conf").exists());
		assert!(!root.join("etc/secrets/Corp").exists());
		let _ = std::fs::remove_dir_all(&root);
	}

	#[test]
	fn a_file_is_named_for_the_id_and_marked_as_generated() {
		let path = wifi_profile::profile_path(Path::new("/etc/netcfgd"), "HomeFiber");
		assert_eq!(
			path,
			PathBuf::from("/etc/netcfgd/conf.d/wifi-HomeFiber.conf")
		);
		assert_eq!(
			wifi_profile::secret_path(Path::new("/etc/netcfgd"), "HomeFiber"),
			PathBuf::from("/etc/netcfgd/secrets/HomeFiber")
		);
	}
}
