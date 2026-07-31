//! An access point from the document, as a hostapd configuration file.
//!
//! Pure, and deliberately so. hostapd has no way to be handed a network over
//! its control socket the way `wpa_supplicant` takes one (decision 0015) -- the
//! configuration is a file it reads once at startup -- so the file *is* the
//! interface, and getting a key name or a value spelling wrong is the whole
//! failure mode. Keeping the rendering here means every variant can be checked
//! on a machine with no radio, and `tests/live/ap.sh` then feeds the same
//! output to a real hostapd, which parses it and says which line it dislikes.
//!
//! The resolved passphrase arrives as an argument rather than through a
//! [`netcfgd_secret::Resolver`]. That is what keeps this testable without
//! fixtures: a test that has to lay out a secrets directory to check that WPA3
//! spells its key management `SAE` is a test nobody writes twelve of.

use netcfgd_model::security::PskProto;
use netcfgd_model::{AccessPoint, AclPolicy, Security};
use std::path::Path;

/// One `key=value` line of the file.
///
/// Carrying `sensitive` per line rather than redacting the whole file: an
/// operator debugging an access point wants to see `hw_mode` and `channel`,
/// and a blanket "the configuration contains a secret, so here is nothing" is
/// how people end up reading the real file with `cat` instead.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Line {
	/// The configuration key, such as `ssid2` or `wpa_key_mgmt`.
	pub key: String,
	/// The value, exactly as it goes in the file.
	pub value: String,
	/// Whether the value is secret material and must not be logged.
	pub sensitive: bool,
}

impl Line {
	fn plain(key: &str, value: impl Into<String>) -> Self {
		Self {
			key: key.to_owned(),
			value: value.into(),
			sensitive: false,
		}
	}

	fn secret(key: &str, value: impl Into<String>) -> Self {
		Self {
			key: key.to_owned(),
			value: value.into(),
			sensitive: true,
		}
	}
}

/// Something the document asks for that this build cannot render.
///
/// Each of these is a refusal by name. The alternative -- rendering something
/// close and letting hostapd fail -- puts the operator in front of a message
/// about a configuration file they did not write.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Unsupported {
	/// `Security::Eap` on an access point.
	EnterpriseNeedsRadius,
	/// A `Psk` network with no passphrase resolved for it.
	MissingPassphrase,
	/// A passphrase outside WPA's 8..=63 character range.
	PassphraseLength {
		/// How long it was.
		len: usize,
	},
	/// A passphrase carrying a byte that would not survive the file.
	PassphraseNotWritable,
	/// A `band` this build has no spelling for.
	UnknownBand {
		/// What the document said.
		given: String,
	},
	/// The 6 GHz band, which needs more than the document can say.
	SixGigahertz,
	/// A channel that is not in the band it was given with.
	ChannelNotInBand {
		/// The channel number.
		channel: u16,
		/// The band it would have to be in.
		band: &'static str,
	},
	/// A regulatory domain that is not two letters.
	MalformedRegdom {
		/// What the document said.
		given: String,
	},
	/// A control directory whose path is not UTF-8.
	NonUtf8CtrlDir,
}

impl std::fmt::Display for Unsupported {
	fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		match self {
			Self::EnterpriseNeedsRadius => formatter.write_str(
				"an access point using EAP authenticates against a RADIUS server, and the \
				 document has no field for one -- an `eap` block on an `access_point` \
				 describes a client's credentials, which is the wrong end of the exchange. \
				 Use `psk` or `owe` here",
			),
			Self::MissingPassphrase => {
				formatter.write_str("this access point needs a passphrase and none was resolved")
			}
			Self::PassphraseLength { len } => write!(
				formatter,
				"a WPA passphrase is 8 to 63 characters; this one is {len}"
			),
			Self::PassphraseNotWritable => formatter.write_str(
				"the passphrase contains a newline or NUL, which cannot go in a hostapd \
				 configuration file -- the file is one key per line",
			),
			Self::UnknownBand { given } => write!(
				formatter,
				"`{given}` is not a band this build knows. Use \"2.4\" or \"5\", or leave \
				 `band` out and let the channel number say which"
			),
			Self::SixGigahertz => formatter.write_str(
				"the 6 GHz band needs an operating class and HE parameters, which the \
				 document has no fields for and which this build has never run against a \
				 radio. Use \"2.4\" or \"5\"",
			),
			Self::ChannelNotInBand { channel, band } => {
				write!(formatter, "channel {channel} is not in the {band} GHz band")
			}
			Self::MalformedRegdom { given } => write!(
				formatter,
				"`{given}` is not a regulatory domain; it is an ISO 3166-1 alpha-2 country \
				 code, such as \"SE\""
			),
			Self::NonUtf8CtrlDir => {
				formatter.write_str("the control directory's path is not UTF-8")
			}
		}
	}
}

impl std::error::Error for Unsupported {}

/// Where the station list for one device is written.
///
/// Beside the generated configuration and named after the device, so that an
/// operator who finds one file knows what the other is. Taking the directory
/// as text rather than a `Path` because this is going into a configuration
/// file, and the caller has already established that the path is UTF-8.
#[must_use]
pub fn acl_file(ctrl_dir: &str, device: &str) -> String {
	format!("{ctrl_dir}/{device}.acl")
}

/// The station list, one address per line, as hostapd reads it.
///
/// hostapd accepts an optional VLAN id after the address, which nothing here
/// writes: putting a station on a VLAN is an `interface` question and the
/// document says it there.
#[must_use]
pub fn acl_contents(stations: &[String]) -> String {
	let mut out = String::new();
	for station in stations {
		out.push_str(station);
		out.push('\n');
	}
	out
}

/// The 2.4 GHz band, as hostapd spells the mode and the document spells the
/// band.
const BAND_24: (&str, &str) = ("2.4", "g");
/// The 5 GHz band, likewise.
const BAND_5: (&str, &str) = ("5", "a");

/// Whether a channel number exists in a band.
///
/// The 5 GHz list is a range rather than the exact set because which of those
/// channels are usable is a regulatory question the kernel answers, not a
/// spelling question this can answer -- 149 is legal in one country and not in
/// the next, and hostapd and the regulatory domain settle that between them.
/// What this rejects is a number that is in no band at all, which is a typo
/// rather than a regulatory refusal.
fn channel_in(band: (&str, &str), channel: u16) -> bool {
	if band == BAND_24 {
		(1..=14).contains(&channel)
	} else {
		(36..=177).contains(&channel)
	}
}

/// Which band and hardware mode to operate in.
///
/// The channel number alone is ambiguous in one direction only: 1..=14 is 2.4
/// GHz and nothing else, while the numbers above it belong to 5 GHz -- but
/// channel 6 exists in both 6 GHz and 2.4 GHz, which is exactly why the model
/// carries `band` at all. So `band` decides when it is present, the channel
/// decides when it is not, and a channel that belongs to neither band is
/// refused either way rather than passed to hostapd to fail on later.
fn band_of(access_point: &AccessPoint) -> Result<(&'static str, &'static str), Unsupported> {
	let declared = match access_point.band.as_deref() {
		None => None,
		Some("2.4") => Some(BAND_24),
		Some("5") => Some(BAND_5),
		Some("6") => return Err(Unsupported::SixGigahertz),
		Some(other) => {
			return Err(Unsupported::UnknownBand {
				given: other.to_owned(),
			})
		}
	};

	let Some(channel) = access_point.channel else {
		// No channel: the band as declared, or 2.4 GHz, which every radio has
		// and which the automatic channel selection can then choose within.
		return Ok(declared.unwrap_or(BAND_24));
	};

	// An undeclared band is inferred from the channel, and then checked the
	// same way a declared one is. Inferring and skipping the check is how
	// channel 20 would have become `hw_mode=a`, which is a band it is not in.
	let band = declared.unwrap_or(if channel <= 14 { BAND_24 } else { BAND_5 });
	if channel_in(band, channel) {
		Ok(band)
	} else {
		Err(Unsupported::ChannelNotInBand {
			channel,
			band: band.0,
		})
	}
}

/// Whether a passphrase can go in the file at all.
///
/// Only two bytes are a problem, and neither is one hostapd rejects -- they
/// end the line, so hostapd would read a *different* passphrase, or a stray
/// key, without either end noticing. `#`, spaces and quotes are all fine:
/// hostapd splits on the first `=` and takes the rest of the line verbatim,
/// which was checked against hostapd 2.10 rather than assumed.
fn is_writable(passphrase: &str) -> bool {
	!passphrase.contains(['\n', '\0'])
}

/// The `wpa_*` lines for a pre-shared key network.
fn psk_lines(proto: PskProto, passphrase: &str) -> Result<Vec<Line>, Unsupported> {
	if !is_writable(passphrase) {
		return Err(Unsupported::PassphraseNotWritable);
	}
	// hostapd enforces this itself, at parse time, with a clear message. It is
	// checked here anyway so the operator hears it from netcfgd naming their
	// `access_point` block, rather than from a daemon naming a line number in a
	// file under /run that netcfgd wrote.
	if !(8..=63).contains(&passphrase.chars().count()) {
		return Err(Unsupported::PassphraseLength {
			len: passphrase.chars().count(),
		});
	}

	// `wpa=2` for all three: it selects RSN, which is what WPA2 and WPA3 both
	// are. WPA3 is not `wpa=3` -- there is no such value, and the generation is
	// carried by the key management and the management frame protection below.
	let mut lines = vec![Line::plain("wpa", "2")];
	match proto {
		PskProto::Wpa2 => {
			lines.push(Line::plain("wpa_key_mgmt", "WPA-PSK"));
			lines.push(Line::plain("rsn_pairwise", "CCMP"));
			lines.push(Line::secret("wpa_passphrase", passphrase));
		}
		PskProto::Wpa3 => {
			lines.push(Line::plain("wpa_key_mgmt", "SAE"));
			lines.push(Line::plain("rsn_pairwise", "CCMP"));
			// Management frame protection is required for WPA3, not optional.
			lines.push(Line::plain("ieee80211w", "2"));
			lines.push(Line::secret("sae_password", passphrase));
		}
		PskProto::Wpa2Wpa3 => {
			lines.push(Line::plain("wpa_key_mgmt", "WPA-PSK SAE"));
			lines.push(Line::plain("rsn_pairwise", "CCMP"));
			// Optional, because a WPA2 client cannot do it and the point of
			// transition mode is that such a client can still associate.
			lines.push(Line::plain("ieee80211w", "1"));
			// But a client that negotiates SAE must use it, which is what stops
			// transition mode being a downgrade to WPA2 for everybody.
			lines.push(Line::plain("sae_require_mfp", "1"));
			lines.push(Line::secret("wpa_passphrase", passphrase));
			lines.push(Line::secret("sae_password", passphrase));
		}
	}
	Ok(lines)
}

/// Render one access point.
///
/// `passphrase` is the already-resolved secret, or `None` for a network that
/// needs none.
///
/// # Errors
///
/// Returns [`Unsupported`] for anything the document can say and this build
/// cannot render.
pub fn config(
	access_point: &AccessPoint,
	ctrl_dir: &Path,
	passphrase: Option<&str>,
) -> Result<Vec<Line>, Unsupported> {
	let ctrl_dir = ctrl_dir
		.to_str()
		.ok_or(Unsupported::NonUtf8CtrlDir)?
		.to_owned();
	let (_, hw_mode) = band_of(access_point)?;

	let mut lines = vec![
		Line::plain("interface", access_point.device.clone()),
		Line::plain("driver", "nl80211"),
		Line::plain("ctrl_interface", ctrl_dir.clone()),
		// `ssid2` rather than `ssid`, because an SSID is 0..32 arbitrary octets
		// (section 2.1) and `ssid=` is text. `ssid2=` takes bare hex, which is
		// exactly what the model already holds -- verified against hostapd 2.10,
		// which decodes the hex and then rejects 33 octets as an invalid SSID.
		Line::plain("ssid2", access_point.ssid.to_hex()),
		Line::plain("hw_mode", hw_mode),
		// Channel 0 is not a channel; it asks hostapd to survey the band and
		// pick one. That is what "absent means the implementation chooses"
		// means here, and it beats naming a default that would put every
		// netcfgd access point in the country on the same channel.
		Line::plain(
			"channel",
			access_point
				.channel
				.map_or_else(|| "0".to_owned(), |channel| channel.to_string()),
		),
	];

	if let Some(regdom) = &access_point.regdom {
		if regdom.len() != 2 || !regdom.bytes().all(|byte| byte.is_ascii_alphabetic()) {
			return Err(Unsupported::MalformedRegdom {
				given: regdom.clone(),
			});
		}
		lines.push(Line::plain("country_code", regdom.to_ascii_uppercase()));
		// Without this the country code is recorded and not advertised, so
		// clients never learn which regulatory domain they are in. hostapd
		// accepts the one without the other; it is not useful.
		lines.push(Line::plain("ieee80211d", "1"));
	}

	if access_point.hidden {
		// 1 rather than 2: the beacon carries an empty SSID field. Mode 2 sends
		// a beacon whose SSID is the right length and all zeroes, which some
		// clients handle worse and which hides nothing extra.
		lines.push(Line::plain("ignore_broadcast_ssid", "1"));
	}

	if let Some(acl) = &access_point.access_control {
		// The list goes in its own file rather than inline, because hostapd has
		// no inline form -- `macaddr_acl` selects which file to read. Naming
		// the file unconditionally, even for an empty list, keeps hostapd from
		// starting with the previous run's list still on disk and unreferenced.
		lines.push(Line::plain("macaddr_acl", acl.policy.macaddr_acl()));
		let key = match acl.policy {
			AclPolicy::Deny => "deny_mac_file",
			AclPolicy::Allow => "accept_mac_file",
		};
		lines.push(Line::plain(key, acl_file(&ctrl_dir, &access_point.device)));
	}

	match &access_point.security {
		Security::Open => {}
		Security::Psk(psk) => {
			let passphrase = passphrase.ok_or(Unsupported::MissingPassphrase)?;
			lines.extend(psk_lines(psk.proto, passphrase)?);
		}
		Security::Owe => {
			lines.push(Line::plain("wpa", "2"));
			lines.push(Line::plain("wpa_key_mgmt", "OWE"));
			lines.push(Line::plain("rsn_pairwise", "CCMP"));
			lines.push(Line::plain("ieee80211w", "2"));
		}
		Security::Eap(_) => return Err(Unsupported::EnterpriseNeedsRadius),
	}

	Ok(lines)
}

/// The file, with secrets in it. Never log this.
#[must_use]
pub fn to_file(id: &str, lines: &[Line]) -> String {
	render(id, lines, false)
}

/// The file as it is safe to print.
#[must_use]
pub fn to_redacted(id: &str, lines: &[Line]) -> String {
	render(id, lines, true)
}

fn render(id: &str, lines: &[Line], redact: bool) -> String {
	let mut text = format!(
		"# hostapd configuration for the `{id}` access point.\n\
		 # Written by netcfgd from /etc/netcfgd. Regenerated on every apply, so\n\
		 # editing it changes nothing that survives.\n"
	);
	for line in lines {
		let value = if redact && line.sensitive {
			"<redacted>"
		} else {
			&line.value
		};
		text.push_str(&line.key);
		text.push('=');
		text.push_str(value);
		text.push('\n');
	}
	text
}

#[cfg(test)]
mod tests {
	use super::*;
	use netcfgd_model::secret::{SecretProvider, SecretRef};
	use netcfgd_model::security::PskConfig;
	use netcfgd_model::{AccessControl, Ssid};

	fn access_point(security: Security) -> AccessPoint {
		AccessPoint {
			id: "guest".to_owned(),
			ssid: Ssid::new(b"guest".to_vec()).expect("a valid ssid"),
			device: "wlan0".to_owned(),
			security,
			channel: Some(6),
			band: None,
			hidden: false,
			regdom: None,
			access_control: None,
		}
	}

	fn psk(proto: PskProto) -> Security {
		Security::Psk(PskConfig {
			passphrase: SecretRef {
				provider: SecretProvider::File,
				name: "guest".to_owned(),
			},
			proto,
		})
	}

	fn value_of<'a>(lines: &'a [Line], key: &str) -> Option<&'a str> {
		lines
			.iter()
			.find(|line| line.key == key)
			.map(|line| line.value.as_str())
	}

	fn rendered(access_point: &AccessPoint, passphrase: Option<&str>) -> Vec<Line> {
		config(access_point, Path::new("/run/netcfgd/hostapd"), passphrase)
			.expect("this access point renders")
	}

	#[test]
	fn an_open_network_carries_no_wpa_lines() {
		let lines = rendered(&access_point(Security::Open), None);
		assert_eq!(value_of(&lines, "ssid2"), Some("6775657374"));
		assert_eq!(value_of(&lines, "hw_mode"), Some("g"));
		assert_eq!(value_of(&lines, "channel"), Some("6"));
		assert!(value_of(&lines, "wpa").is_none());
		assert!(value_of(&lines, "wpa_key_mgmt").is_none());
	}

	#[test]
	fn wpa2_uses_a_passphrase_and_wpa3_uses_sae() {
		let two = rendered(&access_point(psk(PskProto::Wpa2)), Some("hunter2hunter2"));
		assert_eq!(value_of(&two, "wpa_key_mgmt"), Some("WPA-PSK"));
		assert_eq!(value_of(&two, "wpa_passphrase"), Some("hunter2hunter2"));
		assert!(value_of(&two, "sae_password").is_none());
		// WPA2 must not require management frame protection: a client that
		// cannot do it is the entire reason somebody chose WPA2.
		assert!(value_of(&two, "ieee80211w").is_none());

		let three = rendered(&access_point(psk(PskProto::Wpa3)), Some("hunter2hunter2"));
		assert_eq!(value_of(&three, "wpa_key_mgmt"), Some("SAE"));
		assert_eq!(value_of(&three, "sae_password"), Some("hunter2hunter2"));
		assert!(value_of(&three, "wpa_passphrase").is_none());
		assert_eq!(value_of(&three, "ieee80211w"), Some("2"));
	}

	#[test]
	fn transition_mode_offers_both_and_still_protects_sae() {
		let lines = rendered(
			&access_point(psk(PskProto::Wpa2Wpa3)),
			Some("hunter2hunter2"),
		);
		assert_eq!(value_of(&lines, "wpa_key_mgmt"), Some("WPA-PSK SAE"));
		assert_eq!(value_of(&lines, "wpa_passphrase"), Some("hunter2hunter2"));
		assert_eq!(value_of(&lines, "sae_password"), Some("hunter2hunter2"));
		// Optional overall, required for whoever negotiates SAE. Without the
		// second line transition mode would let an attacker downgrade every
		// client to WPA2, which is the thing transition mode is accused of.
		assert_eq!(value_of(&lines, "ieee80211w"), Some("1"));
		assert_eq!(value_of(&lines, "sae_require_mfp"), Some("1"));
	}

	#[test]
	fn owe_needs_no_secret() {
		let lines = rendered(&access_point(Security::Owe), None);
		assert_eq!(value_of(&lines, "wpa_key_mgmt"), Some("OWE"));
		assert_eq!(value_of(&lines, "ieee80211w"), Some("2"));
	}

	#[test]
	fn an_ssid_that_is_not_text_survives_as_hex() {
		let mut point = access_point(Security::Open);
		point.ssid = Ssid::new(vec![0x00, 0xff, 0x20]).expect("a valid ssid");
		let lines = rendered(&point, None);
		assert_eq!(value_of(&lines, "ssid2"), Some("00ff20"));
	}

	#[test]
	fn the_band_follows_the_channel_when_nothing_says_otherwise() {
		let mut point = access_point(Security::Open);
		point.channel = Some(36);
		assert_eq!(value_of(&rendered(&point, None), "hw_mode"), Some("a"));
		point.channel = Some(11);
		assert_eq!(value_of(&rendered(&point, None), "hw_mode"), Some("g"));
	}

	#[test]
	fn no_channel_asks_hostapd_to_choose() {
		let mut point = access_point(Security::Open);
		point.channel = None;
		let lines = rendered(&point, None);
		assert_eq!(value_of(&lines, "channel"), Some("0"));
		assert_eq!(value_of(&lines, "hw_mode"), Some("g"));

		// A band with no channel picks within that band.
		point.band = Some("5".to_owned());
		let lines = rendered(&point, None);
		assert_eq!(value_of(&lines, "channel"), Some("0"));
		assert_eq!(value_of(&lines, "hw_mode"), Some("a"));
	}

	#[test]
	fn a_channel_that_contradicts_its_band_is_refused() {
		let mut point = access_point(Security::Open);
		point.band = Some("5".to_owned());
		point.channel = Some(6);
		assert_eq!(
			config(&point, Path::new("/run"), None),
			Err(Unsupported::ChannelNotInBand {
				channel: 6,
				band: "5"
			})
		);
	}

	/// The gap between the bands is nobody's channel.
	///
	/// Inferring a band from the channel and then not checking it is how
	/// channel 20 became `hw_mode=a`: a 5 GHz mode on a channel that only
	/// exists in 2.4 GHz, which hostapd would have refused much later and much
	/// less clearly.
	#[test]
	fn a_channel_in_no_band_is_refused_even_with_no_band_declared() {
		let mut point = access_point(Security::Open);
		point.channel = Some(20);
		assert_eq!(
			config(&point, Path::new("/run"), None),
			Err(Unsupported::ChannelNotInBand {
				channel: 20,
				band: "5"
			})
		);
		point.channel = Some(200);
		assert_eq!(
			config(&point, Path::new("/run"), None),
			Err(Unsupported::ChannelNotInBand {
				channel: 200,
				band: "5"
			})
		);
	}

	#[test]
	fn six_gigahertz_and_unknown_bands_are_refused_differently() {
		let mut point = access_point(Security::Open);
		point.band = Some("6".to_owned());
		assert_eq!(
			config(&point, Path::new("/run"), None),
			Err(Unsupported::SixGigahertz)
		);
		point.band = Some("5g".to_owned());
		assert_eq!(
			config(&point, Path::new("/run"), None),
			Err(Unsupported::UnknownBand {
				given: "5g".to_owned()
			})
		);
	}

	#[test]
	fn a_regdom_is_advertised_as_well_as_recorded() {
		let mut point = access_point(Security::Open);
		point.regdom = Some("se".to_owned());
		let lines = rendered(&point, None);
		assert_eq!(value_of(&lines, "country_code"), Some("SE"));
		assert_eq!(value_of(&lines, "ieee80211d"), Some("1"));

		point.regdom = Some("SWE".to_owned());
		assert_eq!(
			config(&point, Path::new("/run"), None),
			Err(Unsupported::MalformedRegdom {
				given: "SWE".to_owned()
			})
		);
	}

	#[test]
	fn enterprise_is_refused_by_name() {
		let eap = Security::Eap(netcfgd_model::EapConfig {
			method: netcfgd_model::EapMethod::Peap,
			identity: "someone".to_owned(),
			anonymous_identity: None,
			password: None,
			ca_cert: None,
			client_cert: None,
			private_key: None,
			phase2: None,
		});
		assert_eq!(
			config(&access_point(eap), Path::new("/run"), None),
			Err(Unsupported::EnterpriseNeedsRadius)
		);
	}

	#[test]
	fn a_passphrase_that_would_break_the_file_is_refused() {
		let point = access_point(psk(PskProto::Wpa2));
		assert_eq!(
			config(
				&point,
				Path::new("/run"),
				Some("good enough\nssid2=deadbeef")
			),
			Err(Unsupported::PassphraseNotWritable)
		);
		assert_eq!(
			config(&point, Path::new("/run"), Some("short")),
			Err(Unsupported::PassphraseLength { len: 5 })
		);
		// A `#` is not a comment once the line has a key, and a space is not a
		// separator. Both are ordinary passphrase characters and both are kept.
		let lines = rendered(&point, Some("a pass#word"));
		assert_eq!(value_of(&lines, "wpa_passphrase"), Some("a pass#word"));
	}

	#[test]
	fn the_redacted_form_keeps_everything_that_is_not_the_secret() {
		let lines = rendered(&access_point(psk(PskProto::Wpa2)), Some("hunter2hunter2"));
		let safe = to_redacted("guest", &lines);
		assert!(safe.contains("wpa_passphrase=<redacted>"));
		assert!(!safe.contains("hunter2hunter2"));
		assert!(safe.contains("hw_mode=g"));
		assert!(safe.contains("channel=6"));

		let real = to_file("guest", &lines);
		assert!(real.contains("wpa_passphrase=hunter2hunter2"));
	}

	#[test]
	fn a_deny_list_selects_the_deny_file_and_an_allow_list_the_accept_file() {
		let mut point = access_point(Security::Open);
		point.access_control = Some(AccessControl {
			policy: AclPolicy::Deny,
			stations: vec!["aa:bb:cc:dd:ee:ff".to_owned()],
		});
		let lines = rendered(&point, None);
		assert_eq!(value_of(&lines, "macaddr_acl"), Some("0"));
		assert_eq!(
			value_of(&lines, "deny_mac_file"),
			Some("/run/netcfgd/hostapd/wlan0.acl")
		);
		// The two files are alternatives in hostapd, so naming both would leave
		// one of them silently unread.
		assert_eq!(value_of(&lines, "accept_mac_file"), None);

		point.access_control = Some(AccessControl {
			policy: AclPolicy::Allow,
			stations: vec!["aa:bb:cc:dd:ee:ff".to_owned()],
		});
		let lines = rendered(&point, None);
		assert_eq!(value_of(&lines, "macaddr_acl"), Some("1"));
		assert_eq!(
			value_of(&lines, "accept_mac_file"),
			Some("/run/netcfgd/hostapd/wlan0.acl")
		);
		assert_eq!(value_of(&lines, "deny_mac_file"), None);
	}

	#[test]
	fn no_access_control_block_says_nothing_about_acls() {
		let lines = rendered(&access_point(Security::Open), None);
		// Not `macaddr_acl=0`: an access point that never mentions an ACL and
		// one whose deny list is empty behave the same, but only the second
		// should leave a file behind for somebody to find and believe.
		assert_eq!(value_of(&lines, "macaddr_acl"), None);
	}

	#[test]
	fn the_station_file_is_one_address_per_line() {
		assert_eq!(acl_contents(&[]), "");
		assert_eq!(
			acl_contents(&[
				"aa:bb:cc:dd:ee:ff".to_owned(),
				"00:11:22:33:44:55".to_owned()
			]),
			"aa:bb:cc:dd:ee:ff\n00:11:22:33:44:55\n"
		);
	}
}
