//! A randomised smoke test for the wire parsers, on stable.
//!
//! Not a substitute for `fuzz/fuzz_targets/netlink_wire.rs`, which explores
//! far more with coverage feedback. This exists because that target needs
//! nightly and cargo-fuzz, and a check nobody can run on the machine they are
//! committing from is a check that rots. Seeds are fixed, so a failure here is
//! reproducible rather than a flaky CI run.

use netcfgd_sys::dump::{decode_address, decode_link, decode_route};
use netcfgd_sys::genl::{payload_attrs, GenlHeader};
use netcfgd_sys::wire::{
	error_code, ifla, msg_type, AttrBuf, Attrs, Header, IfAddr, IfInfo, Messages, RtMsg,
};

/// xorshift64*, so the generator is four lines and needs no dependency.
struct Rng(u64);

impl Rng {
	fn next(&mut self) -> u64 {
		self.0 ^= self.0 << 13;
		self.0 ^= self.0 >> 7;
		self.0 ^= self.0 << 17;
		self.0
	}

	fn byte(&mut self) -> u8 {
		u8::try_from(self.next() & 0xff).unwrap_or(0)
	}

	fn below(&mut self, bound: usize) -> usize {
		if bound == 0 {
			0
		} else {
			usize::try_from(self.next() % bound as u64).unwrap_or(0)
		}
	}
}

/// Run every entry point over `data` and require only that nothing panics and
/// no iterator runs away.
fn exercise(data: &[u8]) {
	let _ = Header::decode(data);
	let _ = IfInfo::decode(data);
	let _ = IfAddr::decode(data);
	let _ = RtMsg::decode(data);
	let _ = error_code(data);
	let _ = decode_link(data);
	let _ = decode_address(data);
	let _ = decode_route(data);

	assert!(
		Attrs::new(data).take(10_000).count() < 10_000,
		"attribute iteration did not terminate"
	);
	assert!(
		netcfgd_sys::inotify::Events::new(data).take(10_000).count() < 10_000,
		"inotify event iteration did not terminate"
	);
	for message in Messages::new(data).take(10_000) {
		let _ = decode_link(message.payload);
		let _ = decode_address(message.payload);
		let _ = decode_route(message.payload);
		assert!(
			Attrs::new(message.payload).take(10_000).count() < 10_000,
			"nested attribute iteration did not terminate"
		);
	}

	// Generic netlink replies come from the kernel on the same terms. The
	// family parser is the entry point every future family shares, so a hang
	// here would be a hang in whatever uses nl80211 or wireguard next.
	let _ = GenlHeader::decode(data);
	assert!(
		payload_attrs(data).take(10_000).count() < 10_000,
		"generic netlink attribute iteration did not terminate"
	);
	for message in Messages::new(data).take(10_000) {
		let _ = GenlHeader::decode(message.payload);
		for attr in payload_attrs(message.payload).take(10_000) {
			// The nested arrays a family list uses: an attribute whose value
			// is itself a run of attributes, which is where a length that
			// makes no progress hides.
			assert!(
				Attrs::new(attr.value).take(10_000).count() < 10_000,
				"nested generic netlink iteration did not terminate"
			);
		}
	}
}

/// Uniform random bytes. Finds the shallow cases: truncation, absurd lengths.
#[test]
fn random_bytes_never_panic() {
	let mut rng = Rng(0x2026_0729_0000_0001);
	for _ in 0..2_000 {
		let length = rng.below(300);
		let data: Vec<u8> = (0..length).map(|_| rng.byte()).collect();
		exercise(&data);
	}
}

/// Mutations of a well-formed message, which is where the interesting states
/// are: uniform noise almost never produces a valid header, so it never
/// reaches the code past one.
#[test]
fn mutated_valid_messages_never_panic() {
	let mut attrs = AttrBuf::new();
	attrs.push_str(ifla::IFNAME, "eth0");
	attrs.push_u32(ifla::MTU, 1500);
	attrs.push(ifla::ADDRESS, &[1, 2, 3, 4, 5, 6]);
	let mut nest = AttrBuf::new();
	nest.push_str(ifla::INFO_KIND, "bridge");
	attrs.push(ifla::LINKINFO, nest.as_bytes());

	let mut body = Vec::new();
	IfInfo::default().encode(&mut body);
	let template = netcfgd_sys::wire::build_request(msg_type::RTM_NEWLINK, 0, 1, &body, &attrs);

	let mut rng = Rng(0x2026_0729_0000_0002);
	for _ in 0..4_000 {
		let mut data = template.clone();
		// One to four single-byte edits, biased towards the length fields at
		// the front where the termination hazards live.
		for _ in 0..=rng.below(4) {
			let index = if rng.below(2) == 0 {
				rng.below(8.min(data.len()))
			} else {
				rng.below(data.len())
			};
			data[index] = rng.byte();
		}
		// And sometimes a truncation, which is what a short read looks like.
		if rng.below(3) == 0 {
			let keep = rng.below(data.len());
			data.truncate(keep);
		}
		exercise(&data);
	}
}

/// The values random search will not find, tried on purpose.
///
/// `random_bytes_never_panic` draws two thousand strings, so a specific
/// four-byte value turns up with probability about two in ten billion. That is
/// how `error_code` kept `-raw` on `i32::MIN` -- a real crash, found by
/// `cargo fuzz` and not by this file, which had been calling `error_code` on
/// random bytes the whole time.
///
/// Coverage feedback finds these because a boundary sits on a branch edge;
/// undirected random draws do not. So they are enumerated: the extremes of
/// each width, at every aligned offset in a buffer long enough to reach the
/// scalar fields, with the rest of the buffer left as both zeroes and ones so
/// a value is not neutralised by whatever surrounds it.
#[test]
fn boundary_scalars_never_panic() {
	// Written as bit patterns rather than as `i32::MIN as u32`, which is the
	// same number and a sign-losing cast clippy is right to refuse: what these
	// are is four bytes on a wire, and a signed name for them would suggest the
	// parser has already decided how to read them.
	const EXTREMES: [u32; 8] = [
		0,
		1,
		0x7fff_ffff, // i32::MAX
		0x8000_0000, // i32::MIN -- the one with no positive counterpart
		0xffff_ffff, // u32::MAX, and -1 read signed
		0x0000_8000,
		0x0001_0000,
		0xffff_0000,
	];

	for filler in [0x00u8, 0xff] {
		for length in [4usize, 9, 16, 20, 32, 64] {
			for offset in (0..length).step_by(4) {
				if offset + 4 > length {
					continue;
				}
				for value in EXTREMES {
					let mut data = vec![filler; length];
					data[offset..offset + 4].copy_from_slice(&value.to_ne_bytes());
					exercise(&data);
				}
			}
		}
	}
}
