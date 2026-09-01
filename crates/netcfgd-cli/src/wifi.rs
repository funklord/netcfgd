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
	/// `--interface`: which radio, on a machine with more than one.
	///
	/// Absent is the ordinary case and means "the one radio there is". A
	/// laptop has one, and making every invocation on every such machine name
	/// it would be ceremony for the common case to serve the rare one. Two
	/// radios is where the question is real, and there this is required rather
	/// than guessed -- one of the two is often somebody else's.
	pub(crate) interface: Option<String>,
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

/// Refuse a certificate given as a path when the network must go to netcfgd.
///
/// Split out of [`add`] for its line budget, and it is the right piece to
/// take: every line of it is about one question, asked before the prompt for
/// the reason the rest of that function keeps repeating -- a refusal that was
/// going to happen anyway must not happen after somebody has typed a password.
///
/// # Errors
///
/// Names the flag, the path, and the two commands that fix it.
fn cert_paths_can_cross(wanted: &Wanted, config_dir: &Path, id: &str) -> Result<(), String> {
	// An enterprise network *can* go over the socket now, so the refusal that
	// used to stand here is gone. What replaced it is narrower and is checked
	// before the prompt for the same reason that one was: a certificate given
	// as a path cannot cross, and finding that out after somebody has typed a
	// password is the thing to avoid.
	if wanted.eap.is_some() && !can_write(&wifi_profile::profile_path(config_dir, id)) {
		for (given, flag) in [
			(&wanted.ca_cert, "--ca-cert"),
			(&wanted.client_cert, "--client-cert"),
		] {
			if let Some(path) = given {
				if !path.starts_with("@secret:") {
					return Err(format!(
						"`{flag} {path}` names a file, and this cannot write \
					 {} -- so the network has to go to netcfgd, which does not \
					 accept a path. Store the contents first:\n  \
					 ncfg secret set NAME < {path}\n\
					 then pass `{flag} @secret:NAME`",
						config_dir.display()
					));
				}
			}
		}
	}
	Ok(())
}

/// The radios netcfgd has already been given, according to the document.
///
/// The document's answer *and* the kernel's, both: a `device` block naming an
/// interface that is not a radio says nothing about hardware that is here, and
/// a radio with no block is not netcfgd's yet.
fn activated_radios(root: &Path, document: Option<&netcfgd_model::Document>) -> Vec<String> {
	document.map_or_else(Vec::new, |document| {
		document
			.devices
			.iter()
			.filter(|device| device.managed && device.wifi.is_some())
			.filter(|device| netcfgd_sys::radio::is_wireless(root, &device.name))
			.map(|device| device.name.clone())
			.collect()
	})
}

/// Which radio this network needs handed over, if any.
///
/// **Adding a network to a machine whose radio nobody activated writes a
/// configuration that does nothing**, which is what this exists to stop: a
/// `network` block alone plans nothing at all, and with only an `interface`
/// block it plans a DHCP client on a radio that never associates. Both were
/// measured, and the second is the worse of the two because it looks
/// configured.
///
/// Returns the radio to activate, or `None` when there is nothing to do.
///
/// **Decides and writes nothing**, so that it can run before the credential
/// prompt. This file's rule is that a refusal which was going to happen anyway
/// must not happen after somebody has typed a passphrase -- and refusing to
/// choose between two radios is exactly such a refusal. The write happens
/// afterwards, next to the one that adds the network.
///
/// # Errors
///
/// A machine with no radio, or one with several and no `--interface` to say
/// which. The second is refused rather than guessed: one of two radios is
/// often somebody else's, and picking it would take hardware nobody offered.
fn choose_radio(
	root: &Path,
	document: Option<&netcfgd_model::Document>,
	wanted: &Wanted,
) -> Result<Option<String>, String> {
	let already = activated_radios(root, document);

	if let Some(named) = &wanted.interface {
		// Present and not a radio is a mistake worth refusing: somebody named
		// the wrong interface. **Absent is not**, and the difference matters
		// here more than anywhere else in this command -- writing
		// configuration for hardware that is not plugged in yet is what
		// `ncfg wifi add` on a machine being prepared is for, and the planner
		// skips an interface that is not there.
		if root.join(named).exists() && !netcfgd_sys::radio::is_wireless(root, named) {
			return Err(format!(
				"`{named}` is an interface on this machine and is not a radio. The \
				 radios are: {}",
				list(&netcfgd_sys::radio::wireless_links(root))
			));
		}
		if already.iter().any(|name| name == named) {
			return Ok(None);
		}
		return Ok(Some(named.clone()));
	}

	// Something is already netcfgd's, so this command has no reason to choose.
	// That matters most on the machine that would otherwise be refused: two
	// radios, one already activated, and nothing ambiguous about it.
	if !already.is_empty() {
		return Ok(None);
	}

	let radios = netcfgd_sys::radio::wireless_links(root);
	match radios.as_slice() {
		// **Not a refusal.** A machine with no radio is one being prepared
		// before the hardware arrives, which is the case this command was
		// written for -- somebody at a console with no network. The network
		// block is written, and the report says nothing will use it yet.
		[] => Ok(None),
		[only] => Ok(Some(only.clone())),
		several => Err(format!(
			"this machine has {} radios ({}), and none of them is netcfgd's yet -- so \
		 this cannot tell which one the network is for. Say which with \
		 `--interface`, or hand one over first with `ncfg wifi activate <radio>`",
			several.len(),
			list(several)
		)),
	}
}

/// Interface names as a person reads them.
fn list(names: &[String]) -> String {
	if names.is_empty() {
		return "none".to_owned();
	}
	names.join(", ")
}

/// Hand a radio to netcfgd, by whichever route is open.
///
/// The daemon where one is listening, because 0127 makes it the writer; the
/// files directly where none is, because that is the machine `ncfg wifi add`
/// was written for -- somebody at a console, as root, with no network. Both
/// write the same text, from `netcfgd-host`, so the two routes cannot drift.
fn activate(interface: &str, options: &Options) -> Result<(), String> {
	let socket = crate::client::socket_path(&crate::state::resolve_dir(options.run_dir.as_deref()));
	if socket.exists() {
		let request = netcfgd_proto::Request::RadioSet {
			interface: interface.to_owned(),
			activate: true,
		};
		return match crate::client::ask(&socket, &request) {
			Ok(crate::client::Answer::Ok) => Ok(()),
			Ok(crate::client::Answer::Error { message }) | Err(message) => Err(message),
			Ok(other) => Err(format!("the daemon sent {}", other.describe())),
		};
	}

	let config_dir = netcfgd_host::config::resolve_dir(options.config_dir.as_deref());
	let factory_dir = netcfgd_host::config::resolve_factory_dir(options.factory_dir.as_deref());
	netcfgd_host::config::install_drop_in(
		&config_dir,
		&factory_dir,
		&netcfgd_host::config::radio_drop_in(interface),
		&netcfgd_host::config::radio_blocks(interface),
		// Replacing is right: this is a switch, so turning on something
		// already on is the state being asked for rather than a collision.
		true,
	)
	.map(|_| ())
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

	cert_paths_can_cross(wanted, &config_dir, &id)?;

	// **Nowhere to send it is a refusal, and it belongs before the prompt.**
	// Found by a test that hung rather than failed: a network with a stored
	// certificate reached the credential prompt on a machine with an
	// unwritable config directory and no daemon, and would have asked for a
	// password before saying it had nowhere to put the answer. The rule below
	// says a refusal that was going to happen anyway must not happen after
	// somebody has typed, and this is that rule applied to the case the
	// earlier checks did not cover.
	let socket = crate::client::socket_path(&crate::state::resolve_dir(options.run_dir.as_deref()));
	if !socket.exists() && !can_write(&wifi_profile::profile_path(&config_dir, &id)) {
		return Err(format!(
			"cannot write {} and nothing is listening on {} -- so there is nowhere \
			 to put this network. Start netcfgd, or run this as somebody who can \
			 write the configuration",
			config_dir.display(),
			socket.display()
		));
	}

	// Which radio, before the prompt and for the same reason as the refusal
	// above: a machine with two radios and neither activated cannot be chosen
	// for, and being told so after typing a passphrase is the thing this file
	// keeps refusing to do. Nothing is written yet.
	let sys_class_net = options
		.sys_class_net
		.as_deref()
		.map_or_else(netcfgd_sys::radio::class_net, std::path::PathBuf::from);
	let hand_over = choose_radio(&sys_class_net, document.as_ref(), wanted)?;

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

	// **The radio before the network, because it is the prerequisite.** If
	// this fails there is an unactivated radio and no network, which is the
	// state the machine was already in; the other order would leave a network
	// nothing can join, which looks configured and is not. Both routes write
	// the same text, from `netcfgd-host`, so they cannot drift.
	if let Some(interface) = &hand_over {
		activate(interface, options)?;
	}
	// **The daemon first, and the local write is the exception** -- inverted by
	// 0127, which makes netcfgd the only writer of /etc/netcfgd. Until then
	// this wrote the files itself and asked the daemon when the kernel refused,
	// which had the exception and the rule the wrong way round: the ordinary
	// case on a running machine is a client with no permission to write
	// system files, because that is what a client is.
	//
	// What the local write is still for is the case this command was written
	// for and the daemon cannot serve: a machine being configured before
	// netcfgd runs on it, which has no socket to ask. That is somebody at a
	// console, as root, with no network -- and they can write the file.
	let socket = crate::client::socket_path(&crate::state::resolve_dir(options.run_dir.as_deref()));
	if socket.exists() {
		return add_over_socket(
			&profile,
			credential.as_deref(),
			wanted,
			options,
			"",
			hand_over.as_deref(),
		);
	}

	// An enterprise network cannot cross the socket -- `--eap` carries
	// certificate *paths*, which 0127 will turn into content and has not yet --
	// so it takes the local path whether or not a daemon is listening, and
	// needs the rights to write the file. The refusal above says so before
	// anybody types a password.
	let written =
		match wifi_profile::install(&config_dir, &factory_dir, &profile, credential.as_deref()) {
			Ok(written) => written,
			// Both halves named, because they are two different things to do
			// about it. The kernel refused this process, *and* there is no
			// daemon to ask instead -- a reader told only the first goes
			// looking for a permission to grant, when starting netcfgd would
			// have done.
			Err(error) if error.denied => {
				return Err(format!(
					"could not write the configuration ({}), and could not ask \
					 netcfgd to do it either: nothing is listening on {}",
					error.message,
					socket.display()
				))
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
		hand_over.as_deref(),
	);
	Ok(ExitCode::SUCCESS)
}

/// A `@secret:name` reference reduced to the name the socket carries.
///
/// The two spellings exist for a reason rather than by accident: a
/// configuration file says `@secret:corp-ca` because that is the language's
/// syntax for an indirection, and the socket carries `corp-ca` because a
/// request that could hold the other spelling could hold a path. The prefix
/// goes back on in the daemon, which is the only place it can.
fn stored_name(reference: &str) -> String {
	reference
		.strip_prefix("@secret:")
		.unwrap_or(reference)
		.to_owned()
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
	activated: Option<&str>,
) -> Result<ExitCode, String> {
	// The socket has no enterprise arm: an 802.1X network carries certificate
	// *paths*, which are files the daemon would hand to a supplicant running as
	// root, and 0117 left how to carry those undecided. Saying so beats an
	// error about a field the reader never named.
	// A certificate given as a *path* still cannot cross: the socket carries
	// the names of stored certificates and has no field a path fits in, which
	// is what makes accepting an enterprise network safe at all. The way to
	// use a file already on the machine is to store its contents first.
	for (given, flag) in [
		(&wanted.ca_cert, "--ca-cert"),
		(&wanted.client_cert, "--client-cert"),
	] {
		if let Some(path) = given {
			if !path.starts_with("@secret:") {
				return Err(format!(
					"could not write the configuration ({local_error}), and \
					 `{flag} {path}` names a file, which the socket does not accept: \
					 a path is an instruction to open a file as root. Store the \
					 contents instead --\n  ncfg secret set NAME < {path}\n\
					 and pass `{flag} @secret:NAME`"
				));
			}
		}
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
		eap: wanted.eap.map(|method| {
			Box::new(netcfgd_proto::EapRequest {
				method: method.to_owned(),
				identity: wanted.identity.clone().unwrap_or_default(),
				anonymous_identity: wanted.anonymous_identity.clone(),
				phase2: wanted.phase2.clone(),
				// Already checked above to be `@secret:` references; the socket
				// carries the bare name and the daemon puts the prefix back.
				ca_cert: wanted.ca_cert.as_ref().map(|value| stored_name(value)),
				client_cert: wanted.client_cert.as_ref().map(|value| stored_name(value)),
			})
		}),
	};

	match crate::client::ask(&socket, &request) {
		Ok(crate::client::Answer::Ok) => {
			say_activated(activated);
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
/// What activating a radio did, said the same way by both routes.
///
/// **Said rather than done quietly.** Adding a network can now hand a radio to
/// netcfgd, which is a change to what hardware netcfgd owns -- a bigger thing
/// than the network that prompted it, and not what somebody typing
/// `ncfg wifi add` asked for in so many words. A command that takes hardware
/// silently is one whose next surprise is worse.
fn say_activated(interface: Option<&str>) {
	if let Some(interface) = interface {
		println!(
			"activated `{interface}`: netcfgd manages that radio now, which is what \
			 lets it join anything. `ncfg wifi deactivate {interface}` hands it back"
		);
	}
}

fn report(
	file: &Path,
	secret: &Path,
	id: &str,
	wanted: &Wanted,
	stored: bool,
	before: Option<&netcfgd_model::Document>,
	activated: Option<&str>,
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
	// radio in it compiles perfectly and joins nothing. Decision 0061's rule
	// -- a thing that compiles either does something or says it does not --
	// applied to the file this just wrote.
	//
	// **It used to end here, with advice.** It said "no device in this
	// configuration has a `wifi` block. Add one" and left the operator to
	// write it, which is the wall the whole of this milestone was spent
	// against: the advice was correct, incomplete (an `interface` block is
	// needed too), and given by a command that could have done it. Now the
	// radio is handed over above and this says which.
	say_activated(activated);
	let radio =
		before.is_some_and(|document| document.devices.iter().any(|device| device.wifi.is_some()));
	if !radio && activated.is_none() {
		println!(
			"nothing will use it yet: no device in this configuration has a \
			 `wifi` block, and no radio was activated for it"
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
		// **A path, and not the key.** The prompt used to offer "or the key
		// itself", which cannot work: wpa_supplicant's `private_key` names a
		// file it opens, so key material there is a filename that does not
		// exist -- and a PEM is multi-line, which terminates the control
		// socket's command in the middle. Offering an option that cannot work
		// is worse than not offering it, because the failure arrives in
		// wpa_supplicant's log rather than here.
		Some("tls") => crate::secret::read_without_echo(&format!(
			"path to the private key for `{id}`, which wpa_supplicant will open"
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

	/// What `ncfg wifi add` writes on a fresh machine plans a supplicant.
	///
	/// **The end of the chain this milestone was spent on.** A `network` block
	/// alone plans nothing; with an `interface` block it plans a DHCP client on
	/// a radio that never associates; only with the `device` block too does a
	/// supplicant appear. Every one of those compiles, and the middle one looks
	/// configured, so nothing short of asking the planner tells them apart.
	///
	/// The radio is a fixture directory rather than the machine's own: a test
	/// that read `/sys/class/net` would pass on a laptop and do something else
	/// on a build machine, which is not a test.
	#[test]
	fn what_add_writes_on_a_fresh_machine_plans_a_supplicant() {
		let root = netcfgd_testdir::TestDir::new("wifi-add-plans");
		std::fs::create_dir_all(root.join("sys/wlan0/wireless")).expect("a fake radio");
		std::fs::create_dir_all(root.join("etc/conf.d")).expect("a config directory");
		std::fs::create_dir_all(root.join("run")).expect("a run directory");
		std::fs::write(root.join("etc/netcfgd.conf"), "").expect("an empty config");

		let options = Options {
			config_dir: Some(root.join("etc").display().to_string()),
			factory_dir: Some(root.join("factory").display().to_string()),
			run_dir: Some(root.join("run").display().to_string()),
			// The radio comes from this fixture rather than the machine, so
			// the test says the same thing on a laptop and on a build host.
			sys_class_net: Some(root.join("sys").display().to_string()),
			wifi: Wanted {
				open: true,
				..Wanted::default()
			},
			..Options::default()
		};
		add(&["Cafe".to_owned()], &options).expect("a fresh machine can add a network");

		// Compile what it wrote and ask the planner, rather than comparing the
		// files against expected text: the broken version wrote perfectly good
		// text too.
		let sources = netcfgd_host::config::load_layered(
			std::path::Path::new(&root.join("factory")),
			std::path::Path::new(&root.join("etc")),
		)
		.expect("the configuration it wrote is readable");
		let document = netcfgd_compile::compile(&sources, &mut netcfgd_compile::NoHooks)
			.unwrap_or_else(|d| {
				panic!(
					"it wrote something that does not compile:\n{}",
					d.render(&sources)
				)
			});

		let observed = netcfgd_model::Observed {
			links: vec![radio_link("wlan0")],
			..Default::default()
		};
		let plan = netcfgd_plan::plan(&document, &observed, &netcfgd_plan::PlanOptions::default());
		let names: Vec<&str> = plan.actions.iter().map(|a| a.op.name()).collect();
		assert!(
			names.contains(&"backend.start"),
			"one `wifi add` on a fresh machine still plans no supplicant: {names:?}"
		);
	}

	/// A link the kernel calls a radio, for the planner.
	fn radio_link(name: &str) -> netcfgd_model::ObservedLink {
		netcfgd_model::ObservedLink {
			name: name.to_owned(),
			index: 2,
			kind: String::new(),
			wireless: true,
			network: None,
			up: false,
			carrier: true,
			reachable: None,
			probe_detail: None,
			mtu: 1500,
			mac: None,
			master: None,
			parent: None,
			offloads: Vec::new(),
			ipv6_token: None,
			qdisc: None,
			qdisc_bandwidth_bits: None,
			qdisc_ingress: false,
			ingress_redirect: None,
			forwarding: None,
			privacy: None,
			accept_ra: None,
			rfkill: None,
			ownership: netcfgd_model::Ownership::Unknown,
			private_key_loaded: false,
			wireguard: None,
			bond: None,
			bridge: None,
			macvlan: None,
			vlan: None,
			tunnel: None,
			vxlan: None,
		}
	}

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
				interface: None,
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
		// A radio of its own, matching the `device wlan0` above, so these
		// tests describe "a machine whose radio is already netcfgd's" and not
		// "whatever hardware the developer has". Without it `add` reads the
		// host's `/sys/class/net`, finds a real radio that no fixture mentions,
		// and activates it -- which on a laptop turns one socket request into
		// two and fails a test about routing for a reason that has nothing to
		// do with routing.
		std::fs::create_dir_all(root.join("sys/wlan0/wireless")).expect("a fixture radio");

		let options = Options {
			config_dir: Some(root.join("etc").display().to_string()),
			factory_dir: Some(root.join("factory").display().to_string()),
			run_dir: Some(root.join("run").display().to_string()),
			sys_class_net: Some(root.join("sys").display().to_string()),
			..Options::default()
		};
		(root, options)
	}

	/// The case with no way through: no daemon to ask, and no permission to
	/// write. Since 0127 the daemon is the ordinary path, so reaching the
	/// local write at all means nothing was listening -- and then the kernel
	/// refuses too. Both halves have to be named, because they are two
	/// different things to do about it, and a reader told only about the
	/// permission goes looking for one to grant when starting netcfgd would
	/// have done.
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
		// Both halves, which is the point: two different things to do about
		// it, and a reader told only about the permission goes looking for one
		// to grant when starting netcfgd would have done.
		assert!(
			error.contains(&etc.display().to_string()),
			"the directory it cannot write is not named: {error}"
		);
		assert!(
			error.contains("netcfgd.sock"),
			"the socket nothing is listening on is not named: {error}"
		);

		// Nothing was left behind by either half.
		assert!(!etc.join("conf.d/wifi-Cafe.conf").exists());
		assert!(!etc.join("secrets").exists());

		restore();
	}

	/// A certificate given as a path is refused before anyone types a password.
	///
	/// **This replaces a test that refused enterprise networks outright.** They
	/// cross the socket now: a certificate is content netcfgd stores, so
	/// `EapRequest` carries the *names* of stored ones and has no field a path
	/// fits in. What is left to refuse is the narrower thing -- a caller who
	/// cannot write the file and named a file anyway -- and the ordering rule
	/// is the one the old test was really about: a refusal that was always
	/// going to happen must not happen after somebody has typed a password.
	#[test]
	fn a_certificate_path_is_refused_before_anyone_types_a_password() {
		let (root, mut options) = fixture("unwritable-eap");
		let etc = root.join("etc");
		options.wifi.eap = Some("peap");
		options.wifi.identity = Some("you@example.ac.uk".to_owned());
		options.wifi.ca_cert = Some("/etc/ssl/certs/corp.pem".to_owned());
		let restore = make_read_only(&etc);

		let error = add(&["eduroam".to_owned()], &options).expect_err("it cannot be added");
		assert!(
			error.contains("ncfg secret set"),
			"the refusal does not say how to fix it: {error}"
		);
		assert!(
			!error.contains("password for"),
			"it got as far as asking for a credential: {error}"
		);

		restore();
	}

	/// A stored certificate is not refused, which is what makes the above a
	/// bound on paths rather than on enterprise networks.
	#[test]
	fn a_stored_certificate_is_not_refused_for_being_a_certificate() {
		let (root, mut options) = fixture("unwritable-eap-stored");
		let etc = root.join("etc");
		options.wifi.eap = Some("peap");
		options.wifi.identity = Some("you@example.ac.uk".to_owned());
		options.wifi.ca_cert = Some("@secret:corp-ca".to_owned());
		let restore = make_read_only(&etc);

		// No daemon in this fixture, so it still cannot finish -- but it fails
		// for want of somewhere to send it, not for naming a certificate, and
		// it fails *before* the prompt.
		//
		// That last part is why this test exists in the form it does: the
		// first version hung here rather than failing, because the code
		// reached the credential prompt and blocked on standard input. A test
		// that hangs stalls the suite instead of reporting, and the fix was in
		// the code rather than the test -- there is nowhere to put the network,
		// and saying so after somebody has typed a password is the ordering
		// this command's own comments forbid.
		let error = add(&["eduroam".to_owned()], &options).expect_err("no daemon is listening");
		assert!(
			!error.contains("ncfg secret set"),
			"a stored certificate was refused as though it were a path: {error}"
		);
		assert!(
			error.contains("nowhere to put this network"),
			"the refusal is not the one expected: {error}"
		);

		restore();
	}

	/// Activating a radio goes over the socket too, and writes no file.
	///
	/// **Two requests now, where there was one**, and both must take the same
	/// route: 0127 makes netcfgd the only writer, and a client that sent the
	/// network to the daemon and wrote the radio's own blocks itself would be
	/// obeying the rule for half of what it does. That is the failure the
	/// operator saw as "read-only file system" -- from the daemon's side of it
	/// -- and the shape is easy to reintroduce, because the local write is
	/// still there for the machine with no daemon.
	#[test]
	fn activating_a_radio_goes_over_the_socket_as_well() {
		use std::io::{BufRead, BufReader, Write};

		let (root, mut options) = fixture("activate-over-socket");
		options.wifi.open = true;
		// A radio the configuration does *not* mention, so `add` has to hand
		// it over before it can add anything for it.
		std::fs::write(root.join("etc/netcfgd.conf"), "").expect("an empty config");
		std::fs::create_dir_all(root.join("sys/wlan7/wireless")).expect("a fixture radio");
		std::fs::remove_dir_all(root.join("sys/wlan0")).expect("only one radio");

		let socket = root.join("run/netcfgd.sock");
		let listener = std::os::unix::net::UnixListener::bind(&socket).expect("it binds");

		// Two connections, answered in turn. Bounded and reported through a
		// channel for the reason the sibling test records: a version of this
		// that joined a thread would *hang* if the second request stopped
		// being made, and a hanging test stalls the suite instead of failing.
		let (sender, asked) = std::sync::mpsc::channel();
		std::thread::spawn(move || {
			for _ in 0..2 {
				let Ok((stream, _)) = listener.accept() else {
					return;
				};
				let Ok(clone) = stream.try_clone() else {
					return;
				};
				let mut line = String::new();
				let _ = BufReader::new(clone).read_line(&mut line);
				let mut writer = stream;
				let _ = writer.write_all(b"{\"response\":\"ok\"}\n");
				let _ = writer.flush();
				if sender.send(line).is_err() {
					return;
				}
			}
		});

		add(&["Cafe".to_owned()], &options).expect("the daemon answers ok");

		let first = asked
			.recv_timeout(std::time::Duration::from_secs(5))
			.expect("nothing connected within 5s, so the daemon was not asked");
		let second = asked
			.recv_timeout(std::time::Duration::from_secs(5))
			.expect("only one request crossed, so half of this went to a file");

		// The radio first, because it is the prerequisite: a network added
		// for a radio netcfgd does not have is a network nothing can join.
		assert!(first.contains("radio_set"), "first request was {first}");
		assert!(
			first.contains("wlan7"),
			"it activated something else: {first}"
		);
		assert!(second.contains("wifi_add"), "second request was {second}");

		// The property 0127 exists for, and the one the operator's report was
		// about: nothing was written here.
		assert!(
			!root.join("etc/conf.d/radio-wlan7.conf").exists(),
			"the client wrote the radio's configuration itself"
		);
		assert!(!root.join("etc/conf.d/wifi-Cafe.conf").exists());
	}

	/// With a daemon listening, the request goes to it and no file is written.
	///
	/// The property 0127 inverted, and one nothing tested until now: before,
	/// the local write was the rule and the socket the exception. The fixture
	/// stands up a real listener answering `ok`, so this asserts the *route*
	/// rather than the outcome -- what proves it went to the daemon is that
	/// `conf.d` is empty afterwards.
	#[test]
	fn with_a_daemon_listening_the_request_goes_to_it() {
		use std::io::{BufRead, BufReader, Write};

		let (root, mut options) = fixture("daemon-preferred");
		options.wifi.open = true;
		let socket = root.join("run/netcfgd.sock");
		let listener = std::os::unix::net::UnixListener::bind(&socket).expect("it binds");

		// A channel and not a join, because the first version of this *hung*
		// when the behaviour regressed: with the local write preferred again
		// nothing ever connects, `accept` blocks for ever, and `join` blocks
		// behind it. A test that hangs is worse than one that fails -- it
		// stalls the suite rather than reporting -- and this is the shape that
		// does it, so the wait is bounded and the timeout is the assertion.
		let (sender, asked) = std::sync::mpsc::channel();
		std::thread::spawn(move || {
			let Ok((stream, _)) = listener.accept() else {
				return;
			};
			let Ok(clone) = stream.try_clone() else {
				return;
			};
			let mut reader = BufReader::new(clone);
			let mut line = String::new();
			let _ = reader.read_line(&mut line);
			let mut writer = stream;
			let _ = writer.write_all(b"{\"response\":\"ok\"}\n");
			let _ = writer.flush();
			let _ = sender.send(line);
		});

		add(&["Cafe".to_owned()], &options).expect("the daemon answers ok");

		let asked = asked
			.recv_timeout(std::time::Duration::from_secs(5))
			.expect("nothing connected to the socket within 5s, so the daemon was not asked");
		assert!(
			asked.contains("wifi_add"),
			"the daemon was sent something else: {asked}"
		);
		assert!(
			!root.join("etc/conf.d/wifi-Cafe.conf").exists(),
			"a file was written even though the daemon answered"
		);
	}

	/// With no daemon, the file is written locally.
	///
	/// The case the command was written for and the one 0127's inversion had
	/// to keep: a machine being configured before netcfgd runs on it, by
	/// somebody at a console with no network. The fixture's run directory
	/// holds no socket, so the local write is the only path left.
	#[test]
	fn with_no_daemon_the_file_is_written_locally() {
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
