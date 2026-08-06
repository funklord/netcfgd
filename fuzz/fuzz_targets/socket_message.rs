//! The control socket's parser, which is the only one an unprivileged local
//! process can drive directly.
//!
//! Everything else here is a file netcfgd wrote itself or a message from the
//! kernel. This one reads bytes from whoever can open the socket -- and the
//! control tiers let a site open `observe`, and therefore the socket mode, to
//! `any`. The daemon holds `CAP_NET_ADMIN` while doing it.
//!
//! Both directions are driven. The request path is the privilege boundary; the
//! response path matters because a client may be pointed at something that is
//! not netcfgd, and `client/`'s hand-written reader is a second implementation
//! of the same job.
//!
//! `crates/netcfgd-proto/tests/random.rs` is the stable counterpart and runs on
//! every `make check`, seeded from the witness. This one needs nightly and
//! cargo-fuzz, and goes further into the byte space than a seeded mutator can.

#![no_main]

use libfuzzer_sys::fuzz_target;
use netcfgd_proto::{codec, Request, Response};
use std::io::BufReader;

fuzz_target!(|data: &[u8]| {
	let mut reader = BufReader::new(data);
	while let Ok(Some(request)) = codec::read_message::<Request, _>(&mut reader) {
		// A message that parsed must survive its own encoder. Framing and
		// parsing are one contract, and a round trip is the only assertion
		// that holds both ends of it.
		let mut encoded = Vec::new();
		codec::write_message(&mut encoded, &request).expect("a parsed request encodes");
		let mut back = BufReader::new(&encoded[..]);
		let again = codec::read_message::<Request, _>(&mut back)
			.expect("its own output frames")
			.expect("its own output parses");
		assert_eq!(request, again);
	}

	let mut reader = BufReader::new(data);
	while let Ok(Some(response)) = codec::read_message::<Response, _>(&mut reader) {
		let mut encoded = Vec::new();
		codec::write_message(&mut encoded, &response).expect("a parsed response encodes");
	}
});
