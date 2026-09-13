//! Link security: EAP, and the wifi-only mechanisms wrapped around it.

use crate::secret::SecretRef;
use serde::{Deserialize, Serialize};

/// EAP method.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EapMethod {
	/// PEAP.
	Peap,
	/// EAP-TTLS.
	Ttls,
	/// EAP-TLS.
	Tls,
	/// EAP-PWD.
	Pwd,
}

/// Where a certificate or key comes from.
///
/// **Two sources, and the difference is who has to be able to read the file.**
///
/// - `Path` names a file already on this machine. It is what worked before
///   there was anything else, and it stays: an operator with a certificate in
///   `/etc/ssl` should not have to hand it to netcfgd to use it.
/// - `Stored` is content netcfgd holds, put there by a client that cannot
///   write system files ([0127](../../../doc/decision/0127-netcfgd-is-the-only-writer-and-the-socket-carries-the-rest.md)).
///   netcfgd materialises it under `/run` when a supplicant needs it and hands
///   over that path.
///
/// The distinction is a security property and not a convenience. A `Path` in a
/// configuration is an instruction to open a file **as root**, so it is
/// classified privileged and a caller who is not root cannot send one. A
/// `Stored` reference names something netcfgd already has, so it grants
/// nothing the caller did not already give it -- which is what makes an
/// enterprise network reachable from a desktop client at all.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CertSource {
	/// A file on this machine, opened by whatever netcfgd runs.
	Path(String),
	/// Content netcfgd stores, materialised when it is needed.
	Stored(SecretRef),
}

/// An 802.1X supplicant configuration.
///
/// Top-level, not nested under wifi security, because 802.1X is port-based
/// access control that predates its use on radios and is ordinary on wired
/// campus and corporate networks (`doc/decision/0008`). Nesting it under an
/// SSID profile made the wired case inexpressible.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EapConfig {
	/// Which method.
	pub method: EapMethod,
	/// Outer identity.
	pub identity: String,
	/// Anonymous outer identity, where the method tunnels one.
	#[serde(skip_serializing_if = "Option::is_none", default)]
	pub anonymous_identity: Option<String>,
	/// Password, for methods that use one.
	#[serde(skip_serializing_if = "Option::is_none", default)]
	pub password: Option<SecretRef>,
	/// Which server name the certificate must carry.
	///
	/// **`ca_cert` alone answers "who signed this", not "who is this".** It
	/// accepts any certificate the pinned issuer signed, which is exactly right
	/// when the issuer is the organisation's own CA and nearly worthless when
	/// it is a public one -- and a commercial certificate on a RADIUS server is
	/// ordinary. There, anyone who can buy a certificate from the same CA can
	/// stand up an access point with the right SSID, be trusted, and collect
	/// whatever the inner method hands over: an `MSCHAPv2` exchange to crack
	/// offline, or the password itself.
	///
	/// This is `wpa_supplicant`'s `domain_suffix_match`, a suffix match against
	/// the certificate's names -- `radius.example.com` matches that host, and
	/// `example.com` matches any host under it. Absent means netcfgd sends
	/// nothing and the supplicant keeps its own default, which is to check the
	/// issuer and not the name. Decision 0206.
	#[serde(skip_serializing_if = "Option::is_none", default)]
	pub domain_suffix_match: Option<String>,
	/// The certificate the server is checked against.
	#[serde(skip_serializing_if = "Option::is_none", default)]
	pub ca_cert: Option<CertSource>,
	/// The certificate presented, for EAP-TLS.
	#[serde(skip_serializing_if = "Option::is_none", default)]
	pub client_cert: Option<CertSource>,
	/// The private key that certificate goes with.
	///
	/// A `CertSource` and no longer a bare `SecretRef`, which is the change
	/// that made EAP-TLS possible rather than merely expressible. `wpa_supplicant`
	/// opens `private_key` as a **file**, so a secret holding key material was
	/// emitted as a filename that did not exist -- and being multi-line, it
	/// terminated the control socket's command in the middle. Now the two
	/// cases are different types: a path is passed through, and stored content
	/// is written under `/run` at 0600 and *that* path is passed.
	#[serde(skip_serializing_if = "Option::is_none", default)]
	pub private_key: Option<CertSource>,
	/// Inner (phase 2) method, where the method tunnels one.
	#[serde(skip_serializing_if = "Option::is_none", default)]
	pub phase2: Option<String>,
}

/// Whether a `phase2` value pins an inner method at all.
///
/// **`wpa_supplicant` accepts anything here and acts on almost none of it.**
/// Asked directly, it answers `OK` to `phase2="nonsense"` and reads the string
/// straight back; it selects an inner method by scanning for `auth=` and
/// `autheap=` tokens, so a value carrying neither constrains nothing and the
/// server proposes whatever it likes.
///
/// That is not cosmetic. Pinning `auth=MSCHAPV2` is what stops a server asking
/// for `GTC`, which sends the password in clear inside the tunnel -- and the
/// tunnel is only as trustworthy as `ca_cert` and `domain_suffix_match` make
/// it (0206).
///
/// **netcfgd's own example told operators to write the inert form**, `phase2 =
/// "mschapv2"`, which is why this is a question worth asking of a document
/// rather than a hypothetical.
///
/// The *shape* decides and the key names do not: a token is meaningful if it
/// is `key=value` with both halves present. Judging by a closed list would
/// make netcfgd the reason a working configuration started complaining when
/// `wpa_supplicant` grew a key it had never heard of.
///
/// Here beside [`EapConfig`] rather than in the compiler, because the planner
/// is what says it and must not depend on the compiler to ask.
#[must_use]
pub fn phase2_pins_nothing(phase2: &str) -> bool {
	!phase2.split_whitespace().any(|token| {
		token
			.split_once('=')
			.is_some_and(|(key, value)| !key.is_empty() && !value.is_empty())
	})
}

/// WPA protocol generation for a pre-shared key network.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PskProto {
	/// WPA2 only.
	Wpa2,
	/// WPA3 only.
	Wpa3,
	/// Transitional mode accepting both.
	#[default]
	Wpa2Wpa3,
}

/// The `wpa_key_mgmt` line a security choice produces in an access point's file.
///
/// **hostapd's spelling, kept here because two crates have to agree on it.**
/// `netcfgd-hostapd` writes this line; the observation reads it back out of the
/// file, into [`crate::ObservedAccessPoint::key_mgmt`]; and the planner compares
/// the two to notice an access point whose *generation* changed under a running
/// hostapd, which reads its configuration once. A second copy of the mapping
/// could disagree with the first, and the disagreement would look like an
/// access point that restarts on every reconcile.
///
/// It lives beside `Security` rather than in the backend because the planner
/// must not depend on a backend crate to ask this, and the observed value it is
/// compared against is already part of this model.
///
/// `None` for an open network, which writes no key management at all: absent in
/// the file says the same thing, so the two compare equal with no special case.
///
/// Takes no passphrase, and must not: the planner has no secret in hand, and an
/// observation may not read one out of `/run`.
#[must_use]
pub fn key_mgmt_of(security: &Security) -> Option<&'static str> {
	match security {
		Security::Open => None,
		Security::Owe => Some("OWE"),
		// Never actually written: the renderer refuses an enterprise access
		// point, because hostapd needs a RADIUS server the document cannot
		// describe. Named so the match is exhaustive by the compiler rather
		// than by a wildcard that would silently absorb a variant added later.
		Security::Eap(_) => Some("WPA-EAP"),
		Security::Psk(psk) => Some(match psk.proto {
			PskProto::Wpa2 => "WPA-PSK",
			PskProto::Wpa3 => "SAE",
			PskProto::Wpa2Wpa3 => "WPA-PSK SAE",
		}),
	}
}

/// The range of a passphrase, in octets, that `psk` and `wpa_passphrase` take.
///
/// **Octets, not characters, and that is the whole point of writing it down
/// (0229).** Four places in this tree checked `chars().count()` against this
/// range and both daemons count bytes, so a passphrase of accented characters
/// was accepted by netcfgd and refused by the thing it was handed to.
///
/// Measured against `wpa_supplicant` 2.10 and `hostapd` 2.10 on the reporting
/// machine:
///
/// ```text
/// 63 x "a"     63 chars  63 bytes  SET_NETWORK psk -> OK
/// 64 x "a"     64 chars  64 bytes  SET_NETWORK psk -> FAIL
/// 32 x "e-acute"  32 chars  64 bytes  SET_NETWORK psk -> FAIL
/// 31 x "e-acute"  31 chars  62 bytes  SET_NETWORK psk -> OK
///  4 x "e-acute"   4 chars   8 bytes  SET_NETWORK psk -> OK
/// ```
///
/// ```text
/// hostapd, wpa_passphrase of 32 accented characters:
///   Line 8: invalid WPA passphrase length 64 (expected 8..63)
/// ```
///
/// The last row of the first block is the direction people miss: four
/// characters is a legitimate passphrase to both daemons if they are four
/// two-octet characters, and netcfgd refused it.
///
/// **It is not WPA's range either.** It belongs to the field: a network sent
/// as `sae_password` has no such limit, which is 0205 and why every caller
/// asks this only for the generations that use `psk`.
pub const PASSPHRASE_OCTETS: std::ops::RangeInclusive<usize> = 8..=63;

/// Whether a passphrase fits the field that will carry it.
///
/// Counted the way both daemons count it. See [`PASSPHRASE_OCTETS`] for the
/// measurements, and use `passphrase.len()` for the number to report -- that
/// is the same count, and it is the one the daemon's own message will use.
#[must_use]
pub fn passphrase_fits(passphrase: &str) -> bool {
	PASSPHRASE_OCTETS.contains(&passphrase.len())
}

/// A pre-shared key network's parameters.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PskConfig {
	/// The passphrase, by reference.
	pub passphrase: SecretRef,
	/// Which WPA generation to negotiate.
	#[serde(default)]
	pub proto: PskProto,
}

/// How a wifi network is secured.
///
/// Wifi only. A wired port carries [`EapConfig`] directly on its interface, so
/// that `Psk` and `Owe` are not reachable in a context where they mean
/// nothing -- a type that cannot express the wrong thing beats a validation
/// rule that rejects it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Security {
	/// No encryption.
	Open,
	/// WPA2/WPA3 personal.
	Psk(PskConfig),
	/// WPA enterprise.
	Eap(EapConfig),
	/// Opportunistic Wireless Encryption.
	Owe,
}

#[cfg(test)]
mod tests {
	use super::{passphrase_fits, PASSPHRASE_OCTETS};

	/// The rule, in the unit both daemons actually count in.
	///
	/// **Every case here was measured against the daemon it is about**, not
	/// derived from the code: `wpa_supplicant` 2.10 over its control socket on
	/// the `none` driver, and hostapd 2.10 reading a configuration file. Four
	/// places in this tree counted characters instead, so a passphrase of
	/// accented letters was accepted here and refused there -- and, at the
	/// short end, refused here and accepted there. 0229.
	#[test]
	fn a_passphrase_is_measured_in_octets_not_characters() {
		// Pure ASCII, where characters and octets agree and the old check was
		// right. The boundaries either side of each end.
		assert!(!passphrase_fits(&"a".repeat(7)), "7 octets: FAIL on both");
		assert!(passphrase_fits(&"a".repeat(8)), "8 octets: OK on both");
		assert!(passphrase_fits(&"a".repeat(63)), "63 octets: OK on both");
		assert!(!passphrase_fits(&"a".repeat(64)), "64 octets: FAIL on both");

		// **Where they disagree.** Each of these is two octets per character.
		let accented = |n: usize| "\u{e9}".repeat(n);

		// 32 characters, 64 octets. The supplicant answered FAIL and hostapd
		// said "invalid WPA passphrase length 64 (expected 8..63)"; a check
		// counting characters saw 32 and let it through.
		assert_eq!(accented(32).chars().count(), 32);
		assert_eq!(accented(32).len(), 64);
		assert!(!passphrase_fits(&accented(32)), "too long, by octets");

		// 31 characters, 62 octets: the supplicant took it.
		assert!(passphrase_fits(&accented(31)));

		// **And the direction that is easy to miss.** Four characters is a
		// passphrase both daemons accept when it is eight octets, and a check
		// counting characters refused it.
		assert_eq!(accented(4).len(), 8);
		assert!(passphrase_fits(&accented(4)), "long enough, by octets");

		// Three is seven octets, which neither daemon takes.
		assert_eq!(accented(3).len(), 6);
		assert!(!passphrase_fits(&accented(3)));

		// The range itself, so a caller reporting `passphrase.len()` beside
		// this is quoting the same numbers.
		assert_eq!(*PASSPHRASE_OCTETS.start(), 8);
		assert_eq!(*PASSPHRASE_OCTETS.end(), 63);
	}
}
