//! A randomised smoke test for the control socket's parser, on stable.
//!
//! The counterpart to `fuzz/fuzz_targets/socket_message.rs`, for the reason
//! the config and netlink ones give: the real target needs nightly and
//! cargo-fuzz, and this runs on every `make check`. Seeds are fixed so a
//! failure is reproducible.
//!
//! **This is the surface that reads bytes from a stranger.** The daemon holds
//! `CAP_NET_ADMIN`, and the control tiers let a site open `observe` -- and
//! therefore the socket -- to `any`. Everything else netcfgd fuzzes is a file
//! it wrote itself or a kernel message; this is the only parser an
//! unprivileged local process can drive directly, and it was the last one with
//! nothing pointed at it.
//!
//! Two things are taken from `fuzzypickles`' wire fuzzing, both of which it
//! records having got wrong first:
//!
//! - **Seeded with real frames, then mutated.** Synthetic bytes almost never
//!   form a valid message, so a purely generated run spends itself on the
//!   outermost checks. The seeds here are the witness -- every line of
//!   `docs/schema/socket.json` is a real frame -- so a mutation lands on real
//!   structure.
//! - **The acceptance rate is asserted, not just printed.** A mutation scheme
//!   that degenerates into garbage still passes every "does not panic" check
//!   while testing nothing. If nothing survives to a complete parse, this test
//!   has stopped being evidence and says so.

use netcfgd_proto::{codec, Request, Response};
use std::io::BufReader;
use std::path::PathBuf;

struct Rng(u64);

impl Rng {
	fn next(&mut self) -> u64 {
		self.0 ^= self.0 << 13;
		self.0 ^= self.0 >> 7;
		self.0 ^= self.0 << 17;
		self.0
	}

	fn below(&mut self, bound: usize) -> usize {
		if bound == 0 {
			0
		} else {
			usize::try_from(self.next() % bound as u64).unwrap_or(0)
		}
	}
}

fn witness() -> Vec<String> {
	let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
		.join("../..")
		.join("docs/schema/socket.json");
	let text = std::fs::read_to_string(path).expect("the witness is readable");
	text.lines()
		.map(str::trim_end)
		.filter(|line| !line.is_empty() && !line.starts_with('#'))
		.map(ToOwned::to_owned)
		.collect()
}

/// Drive both parsers over one buffer, exactly as the daemon and a client do.
///
/// Returns whether anything parsed all the way. Any outcome but a panic is
/// acceptable -- a refusal is the parser working.
fn exercise(bytes: &[u8]) -> bool {
	let mut accepted = false;

	let mut reader = BufReader::new(bytes);
	while let Ok(Some(request)) = codec::read_message::<Request, _>(&mut reader) {
		accepted = true;
		// A message that parsed must survive its own encoder, or the codec is
		// not the function the witness says it is.
		let mut encoded = Vec::new();
		codec::write_message(&mut encoded, &request).expect("a parsed request encodes");
		let mut back = BufReader::new(&encoded[..]);
		let again = codec::read_message::<Request, _>(&mut back)
			.expect("its own output frames")
			.expect("its own output parses");
		assert_eq!(request, again, "a request did not survive a round trip");
	}

	// The other direction, because a client parses these and a client may be
	// talking to something that is not netcfgd.
	let mut reader = BufReader::new(bytes);
	while let Ok(Some(response)) = codec::read_message::<Response, _>(&mut reader) {
		accepted = true;
		let mut encoded = Vec::new();
		codec::write_message(&mut encoded, &response).expect("a parsed response encodes");
	}
	accepted
}

/// Byte flips, truncations, splices and injected newlines, over a real frame.
fn mutate(rng: &mut Rng, seed: &str) -> Vec<u8> {
	let mut bytes = seed.as_bytes().to_vec();
	match rng.below(6) {
		0 => {
			// A flipped byte, which is where an escape or a digit becomes
			// something the parser has to decide about.
			if !bytes.is_empty() {
				let at = rng.below(bytes.len());
				bytes[at] ^= 1u8 << rng.below(8);
			}
		}
		1 => {
			// Truncation: half a frame, which is what a peer that died
			// mid-write leaves behind.
			let keep = rng.below(bytes.len() + 1);
			bytes.truncate(keep);
		}
		2 => {
			// An injected newline, which frames one message as two and is the
			// case `MAX_LINE` and the newline refusal are both about.
			if !bytes.is_empty() {
				let at = rng.below(bytes.len());
				bytes.insert(at, b'\n');
			}
		}
		3 => {
			// Trailing rubbish after a complete frame.
			for _ in 0..rng.below(16) {
				bytes.push((rng.next() & 0xff) as u8);
			}
		}
		4 => {
			// Deep nesting, which is what a recursive-descent reader is asked
			// about and the one shape a byte flip will never produce.
			let depth = rng.below(64);
			let mut nested = Vec::new();
			nested.extend_from_slice(b"{\"request\":\"status\",\"x\":");
			nested.extend(std::iter::repeat_n(b'[', depth));
			nested.extend(std::iter::repeat_n(b']', depth));
			nested.extend_from_slice(b"}");
			bytes = nested;
		}
		_ => {
			// Two frames in one buffer, which is what a client that pipelines
			// produces and where a line reader loses the second.
			bytes.push(b'\n');
			bytes.extend_from_slice(seed.as_bytes());
		}
	}
	bytes.push(b'\n');
	bytes
}

#[test]
fn a_mutated_witness_never_panics_and_still_reaches_the_parser() {
	let seeds = witness();
	assert!(
		seeds.len() > 20,
		"the witness is too small to seed from, so this test would prove nothing"
	);

	let mut rng = Rng(0x5eed_50c1_e700_0001);
	let rounds = 20_000;
	let mut accepted = 0u32;

	for _ in 0..rounds {
		let seed = &seeds[rng.below(seeds.len())];
		if exercise(&mutate(&mut rng, seed)) {
			accepted += 1;
		}
	}

	let rate = f64::from(accepted) * 100.0 / f64::from(rounds);
	println!("socket parser: {accepted}/{rounds} mutations reached a complete parse ({rate:.1}%)");

	// The number is asserted rather than reported, because a mutation scheme
	// that stopped producing parseable frames would keep passing the
	// does-not-panic half while testing nothing at all.
	//
	// **The threshold is calibrated, and `> 0` was measured to be useless.**
	// Replacing every seed with `?` bytes -- destroying the seeding entirely --
	// still scores 16.4%, because the deep-nesting case above builds its own
	// frame and parses whatever the seed was. Against 33.4% with the real
	// witness, a floor of 25% is the one that tells those apart. A floor of
	// zero passed the degenerate mutator, which is how this number came to be
	// measured rather than chosen.
	assert!(
		rate > 25.0,
		"only {rate:.1}% of mutations reached a complete parse; below 25% the seeding \
		 has stopped working and this is testing the outermost checks only"
	);
}

#[test]
fn arbitrary_bytes_never_panic_and_the_bound_holds() {
	let mut rng = Rng(0x5eed_50c1_e700_0002);

	for _ in 0..2_000 {
		let length = rng.below(512);
		// Terminated as part of the construction rather than appended: it is
		// one buffer of random bytes ending in a newline, and saying so in one
		// expression is both clearer and what stops clippy reading a per-round
		// terminator as a repeated push into one vector.
		let bytes: Vec<u8> = (0..length)
			.map(|_| (rng.next() & 0xff) as u8)
			.chain(std::iter::once(b'\n'))
			.collect();
		let _ = exercise(&bytes);
	}

	// A stream with no newline at all must be refused rather than absorbed:
	// the daemon holds CAP_NET_ADMIN, and being killed by the OOM killer is a
	// denial of service with extra steps. Checked just past the limit, which
	// is the boundary the constant exists to draw.
	let oversized = vec![b'x'; codec::MAX_LINE + 1];
	let mut reader = BufReader::new(&oversized[..]);
	let refused = codec::read_message::<Request, _>(&mut reader);
	let error = refused.expect_err("a line past MAX_LINE with no newline was not refused");
	// Asserted on *which* refusal, not merely that there was one. `xxxx...` is
	// not valid JSON either, so a bound that had been deleted would still come
	// back as an error and this check would pass for a reason that has nothing
	// to do with the bound -- which is the shape of every gate this tree has
	// caught passing vacuously.
	assert!(
		error.to_string().contains(&codec::MAX_LINE.to_string()),
		"the refusal did not name the limit, so this may not be the bound firing: {error}"
	);
}
