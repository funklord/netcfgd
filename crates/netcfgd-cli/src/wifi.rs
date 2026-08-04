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
use netcfgd_host::config;
use netcfgd_model::Ssid;
use std::fmt::Write as _;
use std::path::{Path, PathBuf};
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
	let file = profile_path(&config_dir, &id);
	if file.exists() {
		return Err(format!(
			"{} already exists but describes no network `{id}` -- refusing to \
			 overwrite a file this did not write",
			file.display()
		));
	}
	let secret = secret_path(&config_dir, &id);
	if !wanted.open && secret.exists() {
		return Err(format!(
			"{} already exists -- refusing to overwrite a stored passphrase. \
			 Remove it first if it is stale",
			secret.display()
		));
	}

	// Last, because it is the only step that stops and waits for a person: a
	// refusal that was going to happen anyway should not happen after the
	// passphrase has been typed.
	let stored = if wanted.open {
		false
	} else {
		let value = read_credential(&id, wanted)?;
		crate::secret::make_secrets_dir(&secret)?;
		config::write_atomically(&secret, value.as_bytes(), 0o600)
			.map_err(|error| format!("could not write {}: {error}", secret.display()))?;
		true
	};

	let text = block(&id, &ssid, wanted);
	if let Err(error) = config::write_atomically(&file, text.as_bytes(), 0o644) {
		remove(stored, &secret);
		return Err(format!("could not write {}: {error}", file.display()));
	}

	// Read back what was written, through the same loader and compiler the
	// daemon uses. A generated config file that does not compile is worse than
	// no file at all, because it takes every other interface with it -- so if
	// the machine cannot use what this wrote, this removes it and says why
	// rather than leaving the operator with a broken directory.
	if let Err(error) = verify(options, &id, wanted) {
		remove(true, &file);
		remove(stored, &secret);
		return Err(error);
	}

	report(&file, &secret, &id, wanted, stored, document.as_ref());
	Ok(ExitCode::SUCCESS)
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

/// The file a network's block goes in.
///
/// Flat, and `.conf`, because that is what the loader reads: it takes
/// `conf.d/*.conf` and does not descend, so a subdirectory per client would
/// configure nothing. The `wifi-` prefix says where the file came from without
/// claiming ownership of it -- there is no marker file and no registry, and a
/// block edited by hand afterwards is simply the configuration.
fn profile_path(config_dir: &Path, id: &str) -> PathBuf {
	config_dir.join("conf.d").join(format!("wifi-{id}.conf"))
}

/// Where the `file` secret provider will look for the passphrase.
fn secret_path(config_dir: &Path, id: &str) -> PathBuf {
	config_dir.join("secrets").join(id)
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

/// The block, as text.
///
/// Kept to what was asked for. netcfgd's defaults are the ones a laptop wants
/// -- `autoconnect` is on, `metered` is off, and a PSK negotiates WPA2 and WPA3
/// both -- and writing them out anyway would turn every generated file into a
/// list of things to wonder about.
fn block(id: &str, ssid: &Ssid, wanted: &Wanted) -> String {
	let mut text = String::new();
	text.push_str(
		"# Written by `ncfg wifi add`. This file is ordinary netcfgd\n\
		 # configuration: edit it, diff it, commit it, or delete it. Deleting it\n\
		 # is how the machine forgets this network.\n",
	);
	let _ = writeln!(text, "\nnetwork \"{id}\" {{");
	// The SSID as hex whenever it is not exactly the label, which is what makes
	// `--id` lossless: an SSID is 32 arbitrary octets and a label is text, so a
	// network whose name is not usable as a label still keeps its exact name.
	if ssid.as_bytes() != id.as_bytes() {
		let _ = writeln!(text, "\tssid = \"{}\"", ssid.to_hex());
	}
	if wanted.hidden {
		text.push_str("\thidden = true\n");
	}

	let mut keys: Vec<String> = Vec::new();
	if wanted.open {
		keys.push("open = true".to_owned());
	} else if let Some(method) = wanted.eap {
		keys.push(format!("eap = \"{method}\""));
		// Every value that came off the command line is quoted rather than
		// interpolated bare: an identity is `you@example.ac.uk` and a
		// certificate is a path, and neither is guaranteed to be a bare word
		// the lexer would read back as itself. `verify` below is what proves
		// it round-tripped, the way it already does for a hex SSID.
		for (value, key) in [
			(&wanted.identity, "identity"),
			(&wanted.anonymous_identity, "anonymous_identity"),
			(&wanted.ca_cert, "ca_cert"),
			(&wanted.client_cert, "client_cert"),
			(&wanted.phase2, "phase2"),
		] {
			if let Some(value) = value {
				keys.push(format!("{key} = \"{}\"", escape(value)));
			}
		}
		// TLS presents a certificate and the rest present a password, and the
		// supplicant refuses the network outright if it is given the other one
		// -- so which key the stored secret is written under is the same branch
		// `read_credential` prompts through.
		if method == "tls" {
			keys.push(format!("private_key = \"@secret:{id}\""));
		} else {
			keys.push(format!("password = \"@secret:{id}\""));
		}
	} else {
		keys.push(format!("psk = \"@secret:{id}\""));
		if let Some(proto) = wanted.proto {
			keys.push(format!("proto = \"{proto}\""));
		}
	}
	if let Some(priority) = wanted.priority {
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

/// A value going into a quoted string in generated configuration.
///
/// An identity or a certificate path comes off the command line and goes into a
/// file the compiler reads back. A quote or a backslash in one would end the
/// string early and produce a file that does not compile -- which takes every
/// other interface on the machine with it, since the loader compiles the
/// directory as one document.
fn escape(value: &str) -> String {
	value.replace('\\', "\\\\").replace('"', "\\\"")
}

/// Compile the configuration again and check the network arrived as asked.
///
/// Not a formality. It has caught the two things that can go wrong between a
/// rendered block and a usable network -- a label that the lexer reads
/// differently from the way it was written, and an SSID whose hex form did not
/// round-trip -- and it is the only check that covers the file as the daemon
/// will actually read it, includes and drop-in ordering and all.
fn verify(options: &Options, id: &str, wanted: &Wanted) -> Result<(), String> {
	let (document, _) = super::compile(options).map_err(|error| {
		format!(
			"what that would have written does not compile, so it was removed \
			 again:\n{error}"
		)
	})?;
	let Some(network) = document.networks.iter().find(|network| network.id == id) else {
		return Err(format!(
			"the file was written and compiled, and the configuration still has \
			 no network `{id}`, so it was removed again. This is a bug in \
			 `ncfg wifi add`"
		));
	};
	let secured = !matches!(network.security, netcfgd_model::Security::Open);
	if secured == wanted.open {
		return Err(format!(
			"network `{id}` compiled with the wrong security, so it was removed \
			 again. This is a bug in `ncfg wifi add`"
		));
	}

	// An enterprise network is checked further, because it has values that came
	// off the command line and went through a quoted string: an identity with a
	// realm, a certificate path. `secured` is true for a `psk` network too, so
	// without this an `--eap` run that compiled to a passphrase network would
	// pass -- and the operator would find out at association time, from a
	// supplicant log.
	if let Some(method) = wanted.eap {
		let netcfgd_model::Security::Eap(eap) = &network.security else {
			return Err(format!(
				"network `{id}` asked for `--eap {method}` and compiled to \
				 something else, so it was removed again. This is a bug in \
				 `ncfg wifi add`"
			));
		};
		// Compared as the compiler parsed them, not as they were written, which
		// is what makes this a round trip rather than a restatement.
		for (wrote, got, what) in [
			(
				wanted.identity.as_deref(),
				Some(eap.identity.as_str()),
				"identity",
			),
			(
				wanted.anonymous_identity.as_deref(),
				eap.anonymous_identity.as_deref(),
				"anonymous identity",
			),
			(
				wanted.ca_cert.as_deref(),
				eap.ca_cert.as_deref(),
				"CA certificate",
			),
			(
				wanted.client_cert.as_deref(),
				eap.client_cert.as_deref(),
				"client certificate",
			),
			(
				wanted.phase2.as_deref(),
				eap.phase2.as_deref(),
				"phase 2 method",
			),
		] {
			if wrote.is_some() && wrote != got {
				return Err(format!(
					"network `{id}`'s {what} did not survive being written and read \
					 back, so it was removed again. This is a bug in \
					 `ncfg wifi add`"
				));
			}
		}
	}
	Ok(())
}

/// Remove a file this command wrote, if it wrote one.
///
/// Only ever called on the two paths above, and only with `ours` true when this
/// command created them: both are refused up front if they already exist, so a
/// rollback cannot delete anything of the operator's.
fn remove(ours: bool, path: &Path) {
	if ours {
		let _ = std::fs::remove_file(path);
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
	#[test]
	fn a_value_with_a_quote_in_it_is_escaped() {
		assert_eq!(escape(r#"we"ird"#), r#"we\"ird"#);
		assert_eq!(escape(r"back\slash"), r"back\\slash");
		assert_eq!(escape("ordinary@example.ac.uk"), "ordinary@example.ac.uk");
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

	/// `verify` reads the enterprise fields back and compares them.
	///
	/// The happy path cannot show this: `block` and `verify` agree, so a
	/// working pair proves nothing about the check. So the file is written by
	/// `block` and then verified against a *different* identity, which is what
	/// a future bug in `block` would look like from here.
	///
	/// Written because breaking this comparison left every other test green:
	/// the compile step already catches a file that does not parse, and only
	/// this catches one that parses into the wrong network.
	#[test]
	fn verify_catches_a_field_that_did_not_survive_the_round_trip() {
		let (root, options) = fixture("verify-eap");
		let wanted = Wanted {
			eap: Some("peap"),
			identity: Some("you@example.ac.uk".to_owned()),
			ca_cert: Some("/ca.pem".to_owned()),
			..Wanted::default()
		};
		let ssid = Ssid::new(b"Corp".to_vec()).expect("a short ssid");
		std::fs::write(
			profile_path(Path::new(&root.join("etc")), "Corp"),
			block("Corp", &ssid, &wanted),
		)
		.expect("the block is written");

		// What was written is what was asked for.
		verify(&options, "Corp", &wanted).expect("the round trip holds");

		// And a mismatch is caught rather than reported as success.
		let drifted = Wanted {
			identity: Some("somebody.else@example.ac.uk".to_owned()),
			..wanted.clone()
		};
		let error = verify(&options, "Corp", &drifted).expect_err("the identity moved");
		assert!(error.contains("identity"), "{error}");

		let drifted = Wanted {
			phase2: Some("mschapv2".to_owned()),
			..wanted.clone()
		};
		let error = verify(&options, "Corp", &drifted).expect_err("a phase 2 that is not there");
		assert!(error.contains("phase 2"), "{error}");
		let _ = std::fs::remove_dir_all(&root);
	}

	#[test]
	fn a_file_is_named_for_the_id_and_marked_as_generated() {
		let path = profile_path(Path::new("/etc/netcfgd"), "HomeFiber");
		assert_eq!(
			path,
			PathBuf::from("/etc/netcfgd/conf.d/wifi-HomeFiber.conf")
		);
		assert_eq!(
			secret_path(Path::new("/etc/netcfgd"), "HomeFiber"),
			PathBuf::from("/etc/netcfgd/secrets/HomeFiber")
		);
	}
}
