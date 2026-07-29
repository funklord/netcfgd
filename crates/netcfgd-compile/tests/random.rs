//! A randomised smoke test for the config parser, on stable.
//!
//! The counterpart to `fuzz/fuzz_targets/config_parse.rs`, for the same reason
//! as the netlink one: the real target needs nightly and cargo-fuzz, and this
//! runs on every `make check`. Seeds are fixed so a failure is reproducible.

use netcfgd_compile::{compile, NoHooks, SourceMap};

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

	fn pick<'a>(&mut self, choices: &[&'a str]) -> &'a str {
		choices[self.below(choices.len())]
	}
}

fn exercise(text: &str) {
	let mut sources = SourceMap::new();
	sources.add("fuzz.conf", text);
	// Any outcome but a panic is acceptable. The canonicalise path is only
	// reachable through a successful compile, so it is driven here too.
	if let Ok(document) = compile(&sources, &mut NoHooks) {
		let _ = document.to_json_canonical();
	}
}

/// Tokens drawn from the grammar rather than from the whole byte space. Random
/// bytes almost never form a block, so they never reach the interesting code.
const PIECES: &[&str] = &[
	"interface",
	"global",
	"device",
	"network",
	"override",
	"include",
	"eth0",
	"config",
	"routes",
	"dns",
	"mtu",
	"guard",
	"vlan",
	"bridge",
	"bond",
	"post_up",
	"on",
	"lease",
	"{",
	"}",
	"[",
	"]",
	"=",
	",",
	";",
	"\n",
	"\t",
	" ",
	"\"",
	"\"dhcp\"",
	"\"192.168.0.1/24\"",
	"\"default via 1.1.1.1\"",
	"1500",
	"-1",
	"true",
	"false",
	"#",
	"@pd:wan0",
	"@secret:x",
	"\\",
	"$",
	"(",
	")",
];

#[test]
fn random_token_soup_never_panics() {
	let mut rng = Rng(0x2026_0729_0000_0011);
	for _ in 0..3_000 {
		let length = rng.below(40);
		let mut text = String::new();
		for _ in 0..length {
			text.push_str(rng.pick(PIECES));
		}
		exercise(&text);
	}
}

/// Mutations of a valid config, which reach lowering rather than stopping at
/// the parser.
#[test]
fn mutated_valid_configs_never_panic() {
	const TEMPLATE: &str = "interface eth0 {\n\
		\tconfig = \"192.168.0.2/24 192.168.0.3/24\"\n\
		\troutes = \"default via 192.168.0.1 metric 100\"\n\
		\tdns    = \"192.168.0.1\"\n\
		\tmtu    = 1500\n\
		\tguard  = \"nfs root\"\n\
		\tvlan   { parent = \"eth1\"; id = 10 }\n\
		}\n";

	let mut rng = Rng(0x2026_0729_0000_0012);
	for _ in 0..3_000 {
		let mut bytes = TEMPLATE.as_bytes().to_vec();
		for _ in 0..=rng.below(5) {
			let index = rng.below(bytes.len());
			match rng.below(3) {
				// Replace with another printable byte.
				0 => bytes[index] = u8::try_from(0x20 + rng.below(0x5f)).unwrap_or(b' '),
				// Delete.
				1 => {
					bytes.remove(index);
				}
				// Duplicate, which is how unbalanced braces and quotes appear.
				_ => {
					let byte = bytes[index];
					bytes.insert(index, byte);
				}
			}
			if bytes.is_empty() {
				break;
			}
		}
		if let Ok(text) = std::str::from_utf8(&bytes) {
			exercise(text);
		}
	}
}
