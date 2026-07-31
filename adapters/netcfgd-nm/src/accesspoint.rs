//! `org.freedesktop.NetworkManager.AccessPoint`: one entry from a scan.
//!
//! The interesting work here is not the D-Bus object, it is the three
//! translations underneath it. netcfgd reports what a scan found in its own
//! terms -- dBm, a boolean, an SSID as octets -- and NM's clients want a
//! percentage, a pair of bitfields and a byte array with particular meanings.
//! All three are pure functions and all three are tested against numbers a
//! real `NetworkManager` produced.

use crate::enums::{ap_flag, ap_security, wifi_mode};
use crate::state::State;
use netcfgd_model::Security;
use netcfgd_proto::ScanEntry;
use std::sync::Arc;
use zbus::zvariant::OwnedObjectPath;

/// The object path for an access point number.
#[must_use]
pub(crate) fn path_for(number: u32) -> OwnedObjectPath {
	OwnedObjectPath::try_from(format!(
		"/org/freedesktop/NetworkManager/AccessPoint/{number}"
	))
	.expect("an access point path built from a number is always valid")
}

/// A signal level as NM's clients want it.
///
/// netcfgd reports dBm, because that is what the supplicant reports and it is
/// the honest unit. NM's `Strength` is a percentage, and it is not a linear
/// map of anything physical -- it is `nm_wifi_utils_level_to_quality`, which
/// treats -40 dBm as perfect and -100 as hopeless and interpolates between.
/// Reimplementing it rather than inventing a scale matters because every
/// applet's signal-bars widget is calibrated to those numbers.
///
/// It could not be checked by reading a dBm and a `Strength` for the same
/// access point, because NM does not expose the level it converted. What it
/// could be checked against is consistency: the daemon on the machine this was
/// written on reported `Strength` 79 for an access point, and 79 is what this
/// returns for -53 dBm, which is an ordinary beacon level for a nearby router.
#[must_use]
pub(crate) fn strength(dbm: i32) -> u8 {
	let clamped = dbm.clamp(-100, -40);
	// Distance below the best level, in dB: 0 at -40, 60 at -100.
	let below = (clamped + 40).abs();
	let quality = 100 - (100 * below) / 60;
	u8::try_from(quality.clamp(0, 100)).unwrap_or(0)
}

/// What an access point advertises, and what it will negotiate.
///
/// Returns `(flags, wpa_flags, rsn_flags)`.
///
/// The security a scan reports is a boolean on netcfgd's socket: an entry is
/// secured or it is not. The supplicant knows more -- it parses
/// `[WPA2-PSK-CCMP][ESS]` and keeps the string -- but the daemon collapses it
/// before the socket, so the shim cannot have it without a socket change.
/// Constraint 6 forbids making that change for an adapter's benefit, and this
/// is not the commit to argue it on its own merits, so the shim does two
/// things instead.
///
/// For a network the *configuration* describes, the answer is exact: the
/// document says whether it is `psk` with which generation, `eap`, or `owe`,
/// and that is strictly better information than a scan flags string. That also
/// covers the case that matters most, since it is the network an applet is
/// about to be asked to join.
///
/// For everything else, WPA2-PSK with CCMP: the overwhelmingly common shape of
/// a secured network, and the one an applet handles by prompting for a
/// passphrase. A wrong guess here costs a prompt for the wrong credential
/// type; refusing to answer costs the network not appearing at all.
#[must_use]
pub(crate) fn security_flags(secured: bool, configured: Option<&Security>) -> (u32, u32, u32) {
	let ciphers = ap_security::PAIR_CCMP | ap_security::GROUP_CCMP;
	match configured {
		Some(Security::Psk(psk)) => {
			let key_mgmt = match psk.proto {
				netcfgd_model::security::PskProto::Wpa2 => ap_security::KEY_MGMT_PSK,
				netcfgd_model::security::PskProto::Wpa3 => ap_security::KEY_MGMT_SAE,
				netcfgd_model::security::PskProto::Wpa2Wpa3 => {
					ap_security::KEY_MGMT_PSK | ap_security::KEY_MGMT_SAE
				}
			};
			(ap_flag::PRIVACY, ap_security::NONE, ciphers | key_mgmt)
		}
		Some(Security::Eap(_)) => (
			ap_flag::PRIVACY,
			ap_security::NONE,
			ciphers | ap_security::KEY_MGMT_802_1X,
		),
		// OWE encrypts without a credential, and NM still sets PRIVACY: the
		// flag means "this is not an open network", not "you will be asked for
		// a passphrase".
		Some(Security::Owe) => (
			ap_flag::PRIVACY,
			ap_security::NONE,
			ciphers | ap_security::KEY_MGMT_OWE,
		),
		None if secured => (
			ap_flag::PRIVACY,
			ap_security::NONE,
			ciphers | ap_security::KEY_MGMT_PSK,
		),
		// An open network, whether the document says so or the scan does.
		Some(Security::Open) | None => (ap_flag::NONE, ap_security::NONE, ap_security::NONE),
	}
}

/// Seconds since boot, which is the clock NM's `LastSeen` is on.
///
/// `CLOCK_BOOTTIME`, read from `/proc/uptime` rather than through `clock_gettime`
/// -- the syscall would be an `unsafe` FFI call, and constraint 4 puts those in
/// one audited crate that an adapter has no business linking for a timestamp.
#[must_use]
pub(crate) fn boot_seconds() -> i32 {
	// The whole-seconds part taken as text, rather than parsed as a float and
	// cast back. `/proc/uptime` is "12345.67 8901.23", so the integer is
	// already sitting there, and going through an `f64` would introduce a
	// truncating cast for a number that was never fractional to begin with.
	std::fs::read_to_string("/proc/uptime")
		.ok()
		.and_then(|text| {
			text.split_whitespace()
				.next()
				.and_then(|seconds| seconds.split('.').next().map(str::to_owned))
		})
		.and_then(|seconds| seconds.parse::<i32>().ok())
		.unwrap_or(0)
}

/// One access point.
pub(crate) struct AccessPoint {
	state: Arc<State>,
	interface: String,
	bssid: String,
}

impl AccessPoint {
	/// An access point object for one scan entry.
	#[must_use]
	pub(crate) fn new(state: Arc<State>, interface: String, bssid: String) -> Self {
		Self {
			state,
			interface,
			bssid,
		}
	}

	/// The scan entry this object stands for, as last seen.
	fn entry(&self) -> Option<ScanEntry> {
		self.state.scan_entry(&self.interface, &self.bssid)
	}

	/// What the configuration says about this network, if anything.
	fn configured(&self) -> Option<Security> {
		let entry = self.entry()?;
		let id = entry.configured.as_ref()?;
		self.state.security_of(id)
	}

	/// The three security bitfields, computed together because they are one
	/// answer split across three properties.
	fn security(&self) -> (u32, u32, u32) {
		let Some(entry) = self.entry() else {
			return (ap_flag::NONE, ap_security::NONE, ap_security::NONE);
		};
		security_flags(entry.secured, self.configured().as_ref())
	}
}

#[zbus::interface(name = "org.freedesktop.NetworkManager.AccessPoint")]
impl AccessPoint {
	/// The network name, as octets.
	///
	/// `ay` and not a string, which is the one place NM's API is more honest
	/// than most: an SSID is 0..32 arbitrary bytes and need not be text. It
	/// lines up exactly with netcfgd's own `Ssid`, so nothing is lost in either
	/// direction.
	#[zbus(property)]
	fn ssid(&self) -> Vec<u8> {
		self.entry()
			.and_then(|entry| decode_hex(&entry.ssid))
			.unwrap_or_default()
	}

	#[zbus(property)]
	fn hw_address(&self) -> String {
		self.bssid.to_uppercase()
	}

	#[zbus(property)]
	fn frequency(&self) -> u32 {
		self.entry().map_or(0, |entry| entry.frequency)
	}

	#[zbus(property)]
	fn strength(&self) -> u8 {
		self.entry().map_or(0, |entry| strength(entry.signal))
	}

	#[zbus(property)]
	fn flags(&self) -> u32 {
		self.security().0
	}

	#[zbus(property)]
	fn wpa_flags(&self) -> u32 {
		self.security().1
	}

	#[zbus(property)]
	fn rsn_flags(&self) -> u32 {
		self.security().2
	}

	#[zbus(property)]
	fn mode(&self) -> u32 {
		// A scan reports infrastructure networks. netcfgd's supplicant does not
		// report ad-hoc cells separately, so claiming to distinguish them would
		// be inventing a distinction the data does not carry.
		wifi_mode::INFRA
	}

	#[zbus(property)]
	fn max_bitrate(&self) -> u32 {
		// Not known. The supplicant's scan results do not carry it, and NM
		// clients use it for a tooltip rather than for a decision.
		0
	}

	#[zbus(property)]
	fn bandwidth(&self) -> u32 {
		0
	}

	#[zbus(property)]
	fn last_seen(&self) -> i32 {
		self.state.last_scan_seconds(&self.interface).unwrap_or(-1)
	}
}

/// Hex back to octets.
///
/// netcfgd puts SSIDs on the wire as hex because that is the only lossless
/// form. `None` rather than a partial decode for malformed input: half an SSID
/// is a different network.
#[must_use]
pub(crate) fn decode_hex(text: &str) -> Option<Vec<u8>> {
	if text.len() % 2 != 0 {
		return None;
	}
	(0..text.len())
		.step_by(2)
		.map(|index| u8::from_str_radix(&text[index..index + 2], 16).ok())
		.collect()
}

#[cfg(test)]
mod tests {
	use super::*;
	use netcfgd_model::secret::{SecretProvider, SecretRef};
	use netcfgd_model::security::{PskConfig, PskProto};

	fn psk(proto: PskProto) -> Security {
		Security::Psk(PskConfig {
			passphrase: SecretRef {
				provider: SecretProvider::File,
				name: "home".to_owned(),
			},
			proto,
		})
	}

	/// The endpoints, and the number a real daemon produced.
	#[test]
	fn dbm_becomes_the_percentage_nm_clients_draw_bars_from() {
		assert_eq!(strength(-40), 100);
		assert_eq!(strength(-100), 0);
		assert_eq!(strength(-70), 50);
		// Anything stronger than -40 or weaker than -100 is clamped rather
		// than allowed off the end of the scale.
		assert_eq!(strength(-10), 100);
		assert_eq!(strength(-120), 0);
		// NetworkManager 1.52 reported 79 for a nearby router while this was
		// being written. -53 dBm is an ordinary level for one, and it is what
		// produces 79 here -- which is the only cross-check available, since
		// NM does not expose the level it converted.
		assert_eq!(strength(-53), 79);
	}

	/// Monotonic across the whole range.
	///
	/// The first version of this looped over `-40..=-100`, which is an empty
	/// range: it asserted nothing and passed. Clippy noticed; the test had
	/// been written the way the sentence reads rather than the way a range
	/// does.
	#[test]
	fn strength_never_increases_as_the_signal_weakens() {
		let mut previous = 101;
		for dbm in (-100..=-40).rev() {
			let value = i32::from(strength(dbm));
			assert!(value <= previous, "{dbm} dBm gave {value} after {previous}");
			previous = value;
		}
	}

	/// The four constants this depends on, confirmed by one number from a
	/// running daemon: a WPA2/WPA3 transition access point reports `RsnFlags`
	/// 1416.
	#[test]
	fn a_transition_network_matches_what_a_real_daemon_reports() {
		let (flags, wpa, rsn) = security_flags(true, Some(&psk(PskProto::Wpa2Wpa3)));
		assert_eq!(flags, ap_flag::PRIVACY);
		assert_eq!(wpa, ap_security::NONE);
		assert_eq!(rsn, 1416);
	}

	#[test]
	fn each_generation_asks_for_the_key_management_it_uses() {
		assert_eq!(
			security_flags(true, Some(&psk(PskProto::Wpa2))).2,
			ap_security::PAIR_CCMP | ap_security::GROUP_CCMP | ap_security::KEY_MGMT_PSK
		);
		assert_eq!(
			security_flags(true, Some(&psk(PskProto::Wpa3))).2,
			ap_security::PAIR_CCMP | ap_security::GROUP_CCMP | ap_security::KEY_MGMT_SAE
		);
		assert_eq!(
			security_flags(true, Some(&Security::Owe)).2,
			ap_security::PAIR_CCMP | ap_security::GROUP_CCMP | ap_security::KEY_MGMT_OWE
		);
	}

	/// OWE needs no passphrase and still sets `PRIVACY`. The flag means "not an
	/// open network", not "you will be asked for a credential" -- an applet
	/// that read it the second way would prompt for a passphrase that does not
	/// exist.
	#[test]
	fn owe_is_private_without_being_a_prompt() {
		assert_eq!(
			security_flags(true, Some(&Security::Owe)).0,
			ap_flag::PRIVACY
		);
		assert_eq!(
			security_flags(false, Some(&Security::Open)).0,
			ap_flag::NONE
		);
	}

	/// An unconfigured network is guessed at, and the guess is the common
	/// case. Getting it wrong costs a prompt for the wrong credential; not
	/// answering costs the network not being shown at all.
	#[test]
	fn an_unconfigured_secured_network_is_assumed_to_want_a_passphrase() {
		let (flags, _, rsn) = security_flags(true, None);
		assert_eq!(flags, ap_flag::PRIVACY);
		assert_eq!(rsn & ap_security::KEY_MGMT_PSK, ap_security::KEY_MGMT_PSK);

		let (open_flags, _, open_rsn) = security_flags(false, None);
		assert_eq!(open_flags, ap_flag::NONE);
		assert_eq!(open_rsn, ap_security::NONE);
	}

	/// The configuration outranks the scan. A network the operator wrote down
	/// as WPA3 is WPA3 even if the scan only managed to say "secured".
	#[test]
	fn the_configuration_wins_over_the_boolean() {
		assert_eq!(
			security_flags(true, Some(&psk(PskProto::Wpa3))).2 & ap_security::KEY_MGMT_SAE,
			ap_security::KEY_MGMT_SAE
		);
	}

	#[test]
	fn an_ssid_survives_the_round_trip_through_hex() {
		assert_eq!(decode_hex("6775657374"), Some(b"guest".to_vec()));
		assert_eq!(decode_hex("00ff20"), Some(vec![0x00, 0xff, 0x20]));
		assert_eq!(decode_hex(""), Some(Vec::new()));
		// Half an octet is half an SSID, which is a different network.
		assert_eq!(decode_hex("677565737"), None);
		assert_eq!(decode_hex("zz"), None);
	}
}
