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
