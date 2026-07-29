//! A randomised smoke test for the wire parsers, on stable.
//!
//! Not a substitute for `fuzz/fuzz_targets/netlink_wire.rs`, which explores
//! far more with coverage feedback. This exists because that target needs
//! nightly and cargo-fuzz, and a check nobody can run on the machine they are
//! committing from is a check that rots. Seeds are fixed, so a failure here is
//! reproducible rather than a flaky CI run.

use netcfgd_netlink::dump::{decode_address, decode_link, decode_route};
use netcfgd_netlink::wire::{
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
		netcfgd_netlink::inotify::Events::new(data)
			.take(10_000)
			.count() < 10_000,
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
	let template = netcfgd_netlink::wire::build_request(msg_type::RTM_NEWLINK, 0, 1, &body, &attrs);

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
