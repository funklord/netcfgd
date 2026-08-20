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
///   write system files ([0127](../../../docs/decisions/0127-netcfgd-is-the-only-writer-and-the-socket-carries-the-rest.md)).
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
/// campus and corporate networks (`docs/decisions/0008`). Nesting it under an
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
