//! A network from the document, as control-socket commands.
//!
//! Decision 0015: `wpa_supplicant` holds no state, so every network it knows
//! about arrives this way. This module is the translation, and it is pure --
//! it produces the command list without a socket in sight, which is what makes
//! "does netcfgd configure WPA3 correctly?" a question a test can answer on a
//! machine with no radio.

use crate::protocol::{passphrase_argument, passphrase_is_sendable, ssid_argument};
use netcfgd_model::device::MacPolicy;
use netcfgd_model::security::PskProto;
use netcfgd_model::{EapMethod, Security, WifiNetwork};
use netcfgd_secret::{Resolver, Secret};

/// A `SET_NETWORK` variable and its already-quoted value.
///
/// The value carries its own quoting because the two kinds are not
/// interchangeable: `ssid` is hex and must not be quoted, `psk` is a quoted
/// string. Deciding that here rather than at the call site means there is one
/// place to be right.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Setting {
	/// The variable name, such as `ssid` or `key_mgmt`.
	pub variable: String,
	/// The value as it goes on the wire.
	pub value: String,
	/// Whether the value is a secret and must not be logged.
	pub sensitive: bool,
}

impl Setting {
	fn plain(variable: &str, value: impl Into<String>) -> Self {
		Self {
			variable: variable.to_owned(),
			value: value.into(),
			sensitive: false,
		}
	}

	fn secret(variable: &str, value: impl Into<String>) -> Self {
		Self {
			variable: variable.to_owned(),
			value: value.into(),
			sensitive: true,
		}
	}

	/// The command line, with secrets intact. Never log this.
	#[must_use]
	pub fn command(&self, id: u32) -> String {
		format!("SET_NETWORK {id} {} {}", self.variable, self.value)
	}

	/// The command line as it is safe to print.
	#[must_use]
	pub fn redacted(&self, id: u32) -> String {
		let value = if self.sensitive {
			"<redacted>"
		} else {
			&self.value
		};
		format!("SET_NETWORK {id} {} {value}", self.variable)
	}
}

/// Something about the network `wpa_supplicant` cannot be asked to do.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Unsupported {
	/// A network whose SSID was never resolved.
	///
	/// A document may name access points instead of an SSID, and something has
	/// to have read the name off a scan before this point. Reaching here with
	/// `None` is a caller that skipped that step, not an operator mistake --
	/// so it says so rather than inventing an empty SSID, which would
	/// associate with anything.
	UnresolvedSsid,
	/// A passphrase containing a character that would end the command.
	PassphraseNotSendable,
	/// A passphrase outside WPA's 8..=63 character range.
	PassphraseLength {
		/// How long it was.
		len: usize,
	},
	/// An EAP method needing a field the config did not provide.
	MissingEapField {
		/// Which one.
		field: &'static str,
	},
	/// A BSSID that is not six colon-separated hex octets.
	MalformedBssid {
		/// What was given.
		given: String,
	},
}

impl std::fmt::Display for Unsupported {
	fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		match self {
			Self::UnresolvedSsid => formatter.write_str(
				"this network names access points instead of an SSID, and the name was \
				 never read off a scan",
			),
			Self::PassphraseNotSendable => formatter.write_str(
				"the passphrase contains a newline or NUL, which the control protocol cannot carry",
			),
			Self::PassphraseLength { len } => write!(
				formatter,
				"a WPA passphrase is 8 to 63 characters; this one is {len}"
			),
			Self::MissingEapField { field } => {
				write!(formatter, "this EAP method needs `{field}`")
			}
			Self::MalformedBssid { given } => {
				write!(formatter, "`{given}` is not a MAC address")
			}
		}
	}
}

impl std::error::Error for Unsupported {}

/// Whether a string is six colon-separated hex octets.
///
/// A BSSID reaches the command line unquoted, so this is the same injection
/// surface as an SSID with a narrower answer available: the set of valid
/// values is small enough to check exactly.
fn is_bssid(text: &str) -> bool {
	let mut octets = 0;
	for part in text.split(':') {
		if part.len() != 2 || !part.bytes().all(|byte| byte.is_ascii_hexdigit()) {
			return false;
		}
		octets += 1;
	}
	octets == 6
}

/// How a [`MacPolicy`] is spelled in the control protocol.
///
/// `wpa_supplicant`'s `mac_addr` is a small integer whose meanings are not
/// guessable from the number, so the mapping is here, once, next to the words
/// it maps from:
///
/// | Model | `mac_addr` | What the supplicant does |
/// |---|---|---|
/// | `Permanent` | 0 | uses the hardware address |
/// | `PerNetwork` | 1 | a random address per ESS |
/// | `PerConnection` | 2 | a random address per association |
///
/// The values match `wpa_supplicant.conf`'s documented meanings for the
/// per-network `mac_addr` key. There is a global of the same name; netcfgd
/// sets the per-network one, so that a single network can be exempted -- which
/// is the case that matters, since MAC-based admission control is the usual
/// reason to need the permanent address on exactly one network.
#[must_use]
pub fn mac_addr_value(policy: MacPolicy) -> &'static str {
	match policy {
		MacPolicy::Permanent => "0",
		MacPolicy::PerNetwork => "1",
		MacPolicy::PerConnection => "2",
	}
}

/// The settings for one network, in the order they should be sent.
///
/// # Errors
///
/// Returns [`Unsupported`] for a network `wpa_supplicant` cannot be given, and
/// propagates secret resolution failures as a rendered message.
pub fn settings(
	network: &WifiNetwork,
	policy: MacPolicy,
	resolver: &Resolver,
) -> Result<Vec<Setting>, Box<dyn std::error::Error>> {
	// The SSID has to be known by now. A document may leave it out and name
	// access points instead, and `add_network` resolves it from a scan before
	// getting here -- because WPA derives its key from the passphrase *and* the
	// SSID, so there is nothing to send without one.
	let ssid = network.ssid.as_ref().ok_or(Unsupported::UnresolvedSsid)?;
	let mut out = vec![Setting::plain("ssid", ssid_argument(ssid))];

	// Sent always, including for `Permanent`. Leaving it unset would inherit
	// whatever the supplicant's global happens to be, which on a distribution
	// that sets one would make netcfgd's `permanent` mean something else --
	// and a privacy property that depends on somebody else's default is not a
	// property. Decision 0015's rule applied to one more setting.
	out.push(Setting::plain("mac_addr", mac_addr_value(policy)));

	if network.hidden {
		// Without this a hidden network is never probed for, so it simply
		// never appears -- with no error anywhere to say why.
		out.push(Setting::plain("scan_ssid", "1"));
	}

	for bssid in &network.bssid {
		if !is_bssid(bssid) {
			return Err(Box::new(Unsupported::MalformedBssid {
				given: bssid.clone(),
			}));
		}
	}
	match network.bssid.as_slice() {
		[] => {}
		// One is a pin: `bssid` refuses every other access point outright.
		[only] => out.push(Setting::plain("bssid", only.clone())),
		// Several is a choice. `bssid_accept` limits selection to the set and
		// lets the supplicant pick among them by signal, which is what "any of
		// these, whichever is best" means -- and it composes with a roam
		// policy, where a pin does not.
		//
		// Space separated, each with an exact mask: the masked form is what
		// `wpa_supplicant` parses, and every-bit-set is one specific address.
		several => out.push(Setting::plain(
			"bssid_accept",
			several
				.iter()
				.map(|bssid| format!("{bssid}/ff:ff:ff:ff:ff:ff"))
				.collect::<Vec<String>>()
				.join(" "),
		)),
	}

	if let Some(roam) = &network.roam {
		// `simple`, not `learn`. The learn module keeps a database file of
		// which channels this network uses, which is a second piece of state
		// on disk that netcfgd would then own the lifetime of -- and its
		// benefit is fewer scans, not better roaming. The module name is
		// chosen here and not in the document for the reason every other
		// backend detail is: a `bgscan="simple:30:-70:300"` in netcfgd.conf
		// would be netcfgd asking the operator which supplicant is underneath.
		//
		// Quoted, because wpa_supplicant parses this one as a string and
		// takes the whole quoted value as the module specification.
		out.push(Setting::plain(
			"bgscan",
			format!(
				"\"simple:{}:{}:{}\"",
				roam.interval, roam.signal, roam.slow_interval
			),
		));
	}

	// `wpa_supplicant`'s priority is unsigned and higher wins, which matches the
	// model's ordering but not its range.
	if network.priority != 0 {
		out.push(Setting::plain("priority", network.priority.to_string()));
	}

	match &network.security {
		Security::Open => {
			out.push(Setting::plain("key_mgmt", "NONE"));
		}
		Security::Psk(psk) => {
			let passphrase = resolver.resolve(&psk.passphrase)?;
			out.extend(psk_settings(&passphrase, psk.proto)?);
		}
		Security::Eap(eap) => {
			out.extend(eap_settings(eap, resolver)?);
		}
		Security::Owe => {
			// Opportunistic Wireless Encryption: unauthenticated but
			// encrypted. `ieee80211w` is required rather than optional here --
			// OWE without management frame protection is not OWE.
			out.push(Setting::plain("key_mgmt", "OWE"));
			out.push(Setting::plain("ieee80211w", "2"));
		}
	}

	Ok(out)
}

fn psk_settings(passphrase: &Secret, proto: PskProto) -> Result<Vec<Setting>, Unsupported> {
	let text = passphrase.expose();
	if !passphrase_is_sendable(text) {
		return Err(Unsupported::PassphraseNotSendable);
	}
	// Checked here rather than left to the supplicant because `FAIL` with no
	// detail is what it answers otherwise, and a passphrase with a stray space
	// is a common enough mistake to deserve a real message. The length is safe
	// to report; the value is not.
	if !(8..=63).contains(&text.chars().count()) {
		return Err(Unsupported::PassphraseLength {
			len: text.chars().count(),
		});
	}

	let mut out = vec![Setting::secret("psk", passphrase_argument(text))];
	match proto {
		PskProto::Wpa2 => {
			out.push(Setting::plain("key_mgmt", "WPA-PSK"));
			out.push(Setting::plain("proto", "RSN"));
			out.push(Setting::plain("ieee80211w", "1"));
		}
		PskProto::Wpa3 => {
			// SAE only, with management frame protection required -- WPA3
			// personal is not WPA3 without it.
			out.push(Setting::plain("key_mgmt", "SAE"));
			out.push(Setting::plain("proto", "RSN"));
			out.push(Setting::plain("ieee80211w", "2"));
		}
		PskProto::Wpa2Wpa3 => {
			// Transitional: offer both and let the access point choose.
			// `ieee80211w=1` is the only value that works against both, since
			// 2 excludes WPA2 access points and 0 excludes SAE.
			out.push(Setting::plain("key_mgmt", "WPA-PSK SAE"));
			out.push(Setting::plain("proto", "RSN"));
			out.push(Setting::plain("ieee80211w", "1"));
		}
	}
	Ok(out)
}

fn eap_settings(
	eap: &netcfgd_model::EapConfig,
	resolver: &Resolver,
) -> Result<Vec<Setting>, Box<dyn std::error::Error>> {
	let mut out = vec![
		Setting::plain("key_mgmt", "WPA-EAP"),
		Setting::plain("eap", eap_name(eap.method)),
		Setting::secret("identity", quote(&eap.identity)),
	];

	if let Some(anonymous) = &eap.anonymous_identity {
		out.push(Setting::plain("anonymous_identity", quote(anonymous)));
	}
	if let Some(ca_cert) = &eap.ca_cert {
		// Everything wpa_supplicant is given here is a path, because it opens
		// all three as files. `path_for` passes a `Path` through and writes a
		// `Stored` one under /run first -- which is what lets a client that
		// cannot write /etc supply a certificate at all (0127).
		let path = resolver.path_for(ca_cert, "ca.pem")?;
		out.push(Setting::plain(
			"ca_cert",
			quote(&path.display().to_string()),
		));
	} else {
		// No CA certificate means the supplicant will accept any server that
		// speaks the protocol, which is the whole attack. Refusing outright
		// would break real deployments that pin nothing, so this is left to
		// the compile stage to warn about -- but it is noted here so the next
		// reader does not conclude it was never considered.
		out.push(Setting::plain("ca_cert", "\"\""));
	}
	if let Some(client_cert) = &eap.client_cert {
		let path = resolver.path_for(client_cert, "client.pem")?;
		out.push(Setting::plain(
			"client_cert",
			quote(&path.display().to_string()),
		));
	}
	if let Some(phase2) = &eap.phase2 {
		out.push(Setting::plain("phase2", quote(phase2)));
	}

	match eap.method {
		EapMethod::Tls => {
			let key = eap
				.private_key
				.as_ref()
				.ok_or(Unsupported::MissingEapField {
					field: "private_key",
				})?;
			// **A path, always, because wpa_supplicant opens it as a file.**
			// Its own README says `private_key="/etc/cert/user.prv"`.
			//
			// This used to resolve the secret and send its *value*, which
			// could not work: key material there is a filename that does not
			// exist, and a PEM is multi-line, so it terminated the line-based
			// `SET_NETWORK` command in the middle and corrupted the rest of
			// the conversation with the supplicant. Nothing caught it because
			// the only EAP-TLS test asserted a missing-field error and never
			// looked at what a complete network renders to.
			//
			// `path_for` gives a path either way: a `Path` source passes
			// through, and a `Stored` one is written under /run at 0600 first.
			// The second is the case that matters -- it is how a client with
			// no permission to write /etc supplies a key at all.
			let path = resolver.path_for(key, "client.key")?;
			out.push(Setting::plain(
				"private_key",
				quote(&path.display().to_string()),
			));
		}
		EapMethod::Peap | EapMethod::Ttls | EapMethod::Pwd => {
			let password = eap
				.password
				.as_ref()
				.ok_or(Unsupported::MissingEapField { field: "password" })?;
			let secret = resolver.resolve(password)?;
			if !passphrase_is_sendable(secret.expose()) {
				return Err(Box::new(Unsupported::PassphraseNotSendable));
			}
			out.push(Setting::secret("password", quote(secret.expose())));
		}
	}

	Ok(out)
}

fn eap_name(method: EapMethod) -> &'static str {
	match method {
		EapMethod::Peap => "PEAP",
		EapMethod::Ttls => "TTLS",
		EapMethod::Tls => "TLS",
		EapMethod::Pwd => "PWD",
	}
}

/// Quote a value for the control protocol.
///
/// The same escaping as [`passphrase_argument`], which this delegates to --
/// identities and certificate paths are attacker-influenced often enough
/// (a RADIUS realm, a path from a config) that treating them as trusted text
/// would be a distinction without a reason.
fn quote(value: &str) -> String {
	passphrase_argument(value)
}

/// The settings for a wired 802.1X port.
///
/// Not the same as a wifi EAP network, and the difference is the one that
/// matters: wired uses `key_mgmt = IEEE8021X`, bare EAPOL with no WPA
/// handshake wrapped around it. Sending `WPA-EAP` to a `wired` driver produces
/// a network the supplicant accepts and never authenticates with, which is the
/// worst available outcome -- everything looks configured and the port stays
/// blocked.
///
/// Decision 0008 puts wired 802.1X on this supplicant precisely so the EAP
/// method handling is shared; this function is the part that must not be.
///
/// # Errors
///
/// The same failures as [`settings`]: an unusable credential, or a secret that
/// will not resolve.
pub fn wired_settings(
	eap: &netcfgd_model::EapConfig,
	resolver: &Resolver,
) -> Result<Vec<Setting>, Box<dyn std::error::Error>> {
	let mut out = eap_settings(eap, resolver)?;

	// eap_settings speaks wifi. Replace the two things that differ rather than
	// duplicating the method, identity and certificate handling.
	for setting in &mut out {
		if setting.variable == "key_mgmt" {
			"IEEE8021X".clone_into(&mut setting.value);
		}
	}
	// Without this the supplicant tries to install WEP keys the switch never
	// sends, and the port authenticates and then goes quiet.
	out.push(Setting::plain("eapol_flags", "0"));

	Ok(out)
}
