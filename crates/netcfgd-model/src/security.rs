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
	/// CA certificate path.
	#[serde(skip_serializing_if = "Option::is_none", default)]
	pub ca_cert: Option<String>,
	/// Client certificate path.
	#[serde(skip_serializing_if = "Option::is_none", default)]
	pub client_cert: Option<String>,
	/// Client private key.
	#[serde(skip_serializing_if = "Option::is_none", default)]
	pub private_key: Option<SecretRef>,
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
