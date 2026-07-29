//! Curve25519 keys, as the config writes them and as the kernel wants them.
//!
//! `WireGuard` keys are 32 raw octets. Every tool that shows one to a human --
//! `wg`, every config example, every wiki page -- shows base64, so that is
//! what the config holds. The conversion happens once, here, and the type
//! makes an invalid key a compile-time error rather than a `wg` command that
//! fails at apply with the interface already created.
//!
//! No base64 crate. Constraint 3 keeps dependencies to libc and the kernel,
//! and a fixed-length decoder is thirty lines.

use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// How long a Curve25519 key is.
pub const KEY_LEN: usize = 32;

/// The base64 length of [`KEY_LEN`] octets, including the one pad character.
const KEY_BASE64_LEN: usize = 44;

const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// A 32-octet key.
///
/// Holds the octets, not the text: two spellings of the same key -- and base64
/// has more than one, since the final character carries only four significant
/// bits -- compare equal, which they must for a plan to be able to tell
/// "unchanged" from "different".
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Key([u8; KEY_LEN]);

impl Key {
	/// Wrap raw octets.
	#[must_use]
	pub fn from_bytes(bytes: [u8; KEY_LEN]) -> Self {
		Self(bytes)
	}

	/// The octets, for the wire.
	#[must_use]
	pub fn as_bytes(&self) -> &[u8; KEY_LEN] {
		&self.0
	}

	/// Parse the base64 spelling every `WireGuard` tool uses.
	///
	/// # Errors
	///
	/// Returns [`crate::Error::BadKey`] for anything that is not exactly 44
	/// characters of standard base64 decoding to 32 octets.
	pub fn parse(text: &str) -> Result<Self, crate::Error> {
		let bytes = text.as_bytes();
		if bytes.len() != KEY_BASE64_LEN || bytes[KEY_BASE64_LEN - 1] != b'=' {
			return Err(crate::Error::BadKey {
				len: text.chars().count(),
			});
		}

		let mut out = [0_u8; KEY_LEN];
		let mut accumulator: u32 = 0;
		let mut bits = 0_u32;
		let mut written = 0_usize;

		// The pad is not decoded: 43 significant characters carry 258 bits, of
		// which the low two are discarded. A key whose last character sets
		// them is still a valid key -- `wg` emits them -- so they are ignored
		// rather than rejected.
		for &byte in &bytes[..KEY_BASE64_LEN - 1] {
			let Some(value) = decode_char(byte) else {
				return Err(crate::Error::BadKey {
					len: text.chars().count(),
				});
			};
			accumulator = (accumulator << 6) | u32::from(value);
			bits += 6;
			if bits >= 8 {
				bits -= 8;
				if written < KEY_LEN {
					// The cast is exact: the shift leaves at most 8 bits.
					#[allow(clippy::cast_possible_truncation)]
					{
						out[written] = ((accumulator >> bits) & 0xff) as u8;
					}
					written += 1;
				}
			}
		}

		if written != KEY_LEN {
			return Err(crate::Error::BadKey {
				len: text.chars().count(),
			});
		}
		Ok(Self(out))
	}

	/// The base64 spelling.
	#[must_use]
	pub fn render(&self) -> String {
		let mut out = String::with_capacity(KEY_BASE64_LEN);
		for chunk in self.0.chunks(3) {
			let mut block = 0_u32;
			for (index, byte) in chunk.iter().enumerate() {
				block |= u32::from(*byte) << (16 - 8 * index);
			}
			// One output character per six bits, and one pad per missing
			// input byte -- 32 is not a multiple of 3, so the last chunk is
			// short and this is where the single `=` comes from.
			let produced = chunk.len() + 1;
			for index in 0..4 {
				if index < produced {
					let value = (block >> (18 - 6 * index)) & 0x3f;
					out.push(char::from(ALPHABET[value as usize]));
				} else {
					out.push('=');
				}
			}
		}
		out
	}
}

fn decode_char(byte: u8) -> Option<u8> {
	match byte {
		b'A'..=b'Z' => Some(byte - b'A'),
		b'a'..=b'z' => Some(byte - b'a' + 26),
		b'0'..=b'9' => Some(byte - b'0' + 52),
		b'+' => Some(62),
		b'/' => Some(63),
		_ => None,
	}
}

/// Rendered rather than dumped, so a key in a diagnostic is the spelling the
/// operator has in their config.
///
/// A *public* key is not a secret -- it is published to every peer -- so
/// unlike [`crate::SecretRef`] this does print itself. A private key never
/// reaches this type from a config: it is a secret reference, and the octets
/// exist only between resolution and the netlink socket.
impl std::fmt::Display for Key {
	fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		formatter.write_str(&self.render())
	}
}

impl Serialize for Key {
	fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
		serializer.serialize_str(&self.render())
	}
}

impl<'de> Deserialize<'de> for Key {
	fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
		use serde::de::Error;
		let text = String::deserialize(deserializer)?;
		Self::parse(&text).map_err(D::Error::custom)
	}
}
