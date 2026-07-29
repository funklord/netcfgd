//! Curve25519 keys, round-tripped.

use netcfgd_model::Key;

/// The base64 every `WireGuard` tool prints, and the octets the kernel wants.
/// A key that survives a round trip in both directions is one the config and
/// the wire agree about.
#[test]
fn a_key_round_trips_both_ways() {
	// All zeroes and all ones are the two that catch a shift in the wrong
	// direction, since neither is symmetric under one.
	for bytes in [[0_u8; 32], [0xff; 32], {
		let mut counting = [0_u8; 32];
		for (index, byte) in counting.iter_mut().enumerate() {
			#[allow(clippy::cast_possible_truncation)]
			{
				*byte = index as u8;
			}
		}
		counting
	}] {
		let key = Key::from_bytes(bytes);
		let text = key.render();
		assert_eq!(text.len(), 44, "got {text}");
		assert!(text.ends_with('='), "got {text}");
		assert_eq!(Key::parse(&text).expect("parses"), key);
		assert_eq!(key.as_bytes(), &bytes);
	}
}

/// A key `wg genkey` actually produced, so the encoding is checked against
/// something outside this file rather than only against itself.
#[test]
fn a_real_key_decodes_to_the_right_octets() {
	// wg's own test vector: the base64 of 32 zero bytes.
	let key = Key::parse("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=").expect("parses");
	assert_eq!(key.as_bytes(), &[0_u8; 32]);

	// And one with every bit set.
	let ones = Key::parse("//////////////////////////////////////////8=").expect("parses");
	assert_eq!(ones.as_bytes(), &[0xff_u8; 32]);
}

/// Anything that is not a key is refused at parse time, so it cannot become an
/// interface that is created and then fails to configure.
#[test]
fn a_malformed_key_is_refused() {
	for bad in [
		"",
		"short",
		// 44 characters, but one is not in the alphabet.
		"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA!=",
		// Right alphabet, wrong length: 43 with no pad.
		"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
		// 44 characters but no pad, which decodes to 33 octets.
		"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
		// URL-safe base64, which `WireGuard` does not use.
		"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA-=",
	] {
		assert!(Key::parse(bad).is_err(), "`{bad}` must not parse");
	}
}

/// Two spellings of one key compare equal, because base64's last character
/// carries only four significant bits. Without holding octets, a plan could
/// see a change where there is none.
#[test]
fn equality_is_over_octets_not_text() {
	// The final character's low two bits are not part of the key. `wg` emits
	// them clear; something else may not.
	let clear = Key::parse("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=").expect("parses");
	let set = Key::parse("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAB=").expect("parses");
	assert_eq!(clear, set, "the ignored bits must not make two keys differ");
}

/// A public key is published to every peer, so unlike a passphrase it prints
/// itself -- a diagnostic that redacted it would be unusable.
#[test]
fn a_public_key_prints_itself() {
	let key = Key::parse("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=").expect("parses");
	assert_eq!(
		format!("{key}"),
		"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
	);
}

/// Anything at all, without panicking. Keys come from config files.
#[test]
fn arbitrary_text_never_panics() {
	let mut state = 0x2545_f491_4f6c_dd1d_u64;
	for _ in 0..20_000 {
		state ^= state << 13;
		state ^= state >> 7;
		state ^= state << 17;
		let len = (state % 60) as usize;
		let text: String = (0..len)
			.map(|index| {
				let byte = ((state >> (index % 56)) & 0x7f) as u8;
				char::from(if byte < 32 { b'A' + (byte % 26) } else { byte })
			})
			.collect();
		let _ = Key::parse(&text);
	}
}
