//! Indirections to secret material. This type cannot hold a value.

use serde::{Deserialize, Serialize};

/// Where a secret is stored.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SecretProvider {
	/// A mode-0600 file under the secrets directory. The no-dependency
	/// default.
	#[default]
	File,
	/// The kernel keyring.
	Keyring,
	/// `pass(1)`.
	Pass,
	/// An external command that prints the secret.
	Exec,
}

/// A reference to secret material, never the material itself.
///
/// The desired-state document is written to `/run`, read by adapters and may
/// eventually be transmitted. Making the *type* incapable of carrying a
/// passphrase closes that door structurally rather than by policy, which is
/// the same reasoning that makes hooks references rather than inline shell.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecretRef {
	/// Which provider resolves `name`.
	#[serde(default)]
	pub provider: SecretProvider,
	/// The provider-scoped name of the secret.
	pub name: String,
}
