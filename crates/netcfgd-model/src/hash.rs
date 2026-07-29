//! SHA-256.
//!
//! Here rather than in one of the crates that uses it, because two of them do:
//! the CLI computes a hook's content hash when it materialises the body, and
//! the executor checks that hash before running it. Two implementations of the
//! same digest is two chances for them to disagree, and the failure mode is
//! every hook being refused as modified.
//!
//! Pure arithmetic, so it does not compromise this crate's no-I/O rule. It
//! hashes local files that netcfgd itself wrote; it is not a boundary against
//! a chosen-prefix attacker.

/// The SHA-256 of `input`, as lowercase hex.
#[must_use]
#[allow(clippy::many_single_char_names, clippy::too_many_lines)]
pub fn sha256_hex(input: &[u8]) -> String {
	const K: [u32; 64] = [
		0x428a_2f98,
		0x7137_4491,
		0xb5c0_fbcf,
		0xe9b5_dba5,
		0x3956_c25b,
		0x59f1_11f1,
		0x923f_82a4,
		0xab1c_5ed5,
		0xd807_aa98,
		0x1283_5b01,
		0x2431_85be,
		0x550c_7dc3,
		0x72be_5d74,
		0x80de_b1fe,
		0x9bdc_06a7,
		0xc19b_f174,
		0xe49b_69c1,
		0xefbe_4786,
		0x0fc1_9dc6,
		0x240c_a1cc,
		0x2de9_2c6f,
		0x4a74_84aa,
		0x5cb0_a9dc,
		0x76f9_88da,
		0x983e_5152,
		0xa831_c66d,
		0xb003_27c8,
		0xbf59_7fc7,
		0xc6e0_0bf3,
		0xd5a7_9147,
		0x06ca_6351,
		0x1429_2967,
		0x27b7_0a85,
		0x2e1b_2138,
		0x4d2c_6dfc,
		0x5338_0d13,
		0x650a_7354,
		0x766a_0abb,
		0x81c2_c92e,
		0x9272_2c85,
		0xa2bf_e8a1,
		0xa81a_664b,
		0xc24b_8b70,
		0xc76c_51a3,
		0xd192_e819,
		0xd699_0624,
		0xf40e_3585,
		0x106a_a070,
		0x19a4_c116,
		0x1e37_6c08,
		0x2748_774c,
		0x34b0_bcb5,
		0x391c_0cb3,
		0x4ed8_aa4a,
		0x5b9c_ca4f,
		0x682e_6ff3,
		0x748f_82ee,
		0x78a5_636f,
		0x84c8_7814,
		0x8cc7_0208,
		0x90be_fffa,
		0xa450_6ceb,
		0xbef9_a3f7,
		0xc671_78f2,
	];
	let mut state: [u32; 8] = [
		0x6a09_e667,
		0xbb67_ae85,
		0x3c6e_f372,
		0xa54f_f53a,
		0x510e_527f,
		0x9b05_688c,
		0x1f83_d9ab,
		0x5be0_cd19,
	];

	let mut message = input.to_vec();
	let bit_len = (input.len() as u64).wrapping_mul(8);
	message.push(0x80);
	while message.len() % 64 != 56 {
		message.push(0);
	}
	message.extend_from_slice(&bit_len.to_be_bytes());

	for chunk in message.chunks_exact(64) {
		let mut w = [0_u32; 64];
		for (index, word) in w.iter_mut().enumerate().take(16) {
			let start = index * 4;
			*word = u32::from_be_bytes([
				chunk[start],
				chunk[start + 1],
				chunk[start + 2],
				chunk[start + 3],
			]);
		}
		for index in 16..64 {
			let s0 = w[index - 15].rotate_right(7)
				^ w[index - 15].rotate_right(18)
				^ (w[index - 15] >> 3);
			let s1 = w[index - 2].rotate_right(17)
				^ w[index - 2].rotate_right(19)
				^ (w[index - 2] >> 10);
			w[index] = w[index - 16]
				.wrapping_add(s0)
				.wrapping_add(w[index - 7])
				.wrapping_add(s1);
		}

		let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = state;
		for index in 0..64 {
			let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
			let ch = (e & f) ^ ((!e) & g);
			let temp1 = h
				.wrapping_add(s1)
				.wrapping_add(ch)
				.wrapping_add(K[index])
				.wrapping_add(w[index]);
			let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
			let maj = (a & b) ^ (a & c) ^ (b & c);
			let temp2 = s0.wrapping_add(maj);

			h = g;
			g = f;
			f = e;
			e = d.wrapping_add(temp1);
			d = c;
			c = b;
			b = a;
			a = temp1.wrapping_add(temp2);
		}

		for (slot, value) in state.iter_mut().zip([a, b, c, d, e, f, g, h]) {
			*slot = slot.wrapping_add(value);
		}
	}

	state
		.iter()
		.fold(String::with_capacity(64), |mut out, word| {
			use std::fmt::Write as _;
			let _ = write!(out, "{word:08x}");
			out
		})
}
