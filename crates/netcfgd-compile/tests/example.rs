//! `netcfgd.conf.example` is checked by compiling it, not by reading it.
//!
//! The file is shipped to `/etc/netcfgd/netcfgd.conf.example` and is the first
//! thing an operator with no network and no manual has to read. netifrc's
//! `net.example` is the model, and its one weakness is the one worth fixing
//! here: a commented example is documentation nothing executes, so it goes
//! stale silently and the reader cannot tell. A key renamed in the compiler
//! leaves the example describing a language that no longer exists, and the
//! person reading it has no network to look anything up with.
//!
//! So every example in it is compiled. The convention is netifrc's, which
//! already distinguishes the two kinds of comment by eye:
//!
//! - `# ` (hash, space) is prose. Ignored here.
//! - `#` immediately followed by anything else is **config**, and is stripped
//!   of the leading hash and compiled.
//!
//! Each contiguous run of config lines is compiled **on its own**, so an
//! example has to be a complete top-level block. That is deliberate: a
//! fragment a reader cannot paste somewhere is a fragment that does not
//! belong in a file whose whole purpose is to be pasted from. It is also why
//! the file may show two different `interface eth0` blocks in two places --
//! separate snippets never meet, so redefining a block across them is not an
//! error, while redefining one *inside* a snippet still is.

use netcfgd_compile::{compile, HookSink, SourceMap};
use netcfgd_model::{HookPhase, HookRef};

/// A hook sink that records instead of writing.
///
/// `NoHooks` refuses to materialise, so every hook example failed with "this
/// caller cannot materialise hooks" -- which is the compiler being right and
/// the gate asking the wrong thing. A hook body is arbitrary shell and the
/// one production the grammar treats irregularly, so it is the part of the
/// language an example is most likely to get wrong and the last part that
/// should go unchecked.
#[derive(Default)]
struct FakeHooks;

impl HookSink for FakeHooks {
	fn record(&mut self, phase: HookPhase, owner: &str, _body: &str) -> Result<HookRef, String> {
		Ok(HookRef {
			phase,
			path: format!("/run/netcfgd/hooks/{owner}"),
			sha256: "0".repeat(64),
			run_as: None,
			timeout: None,
		})
	}
}

/// Where the example lives in the source tree.
///
/// The installed copy is `/etc/netcfgd/netcfgd.conf.example`; the loader reads
/// `netcfgd.conf` by exact name and `conf.d/*.conf` by extension, so the
/// installed file is inert by construction rather than by a rule somebody has
/// to remember. `installed_name_is_not_one_the_loader_reads` pins that.
const EXAMPLE: &str = concat!(
	env!("CARGO_MANIFEST_DIR"),
	"/../../doc/netcfgd.conf.example"
);

/// One example: the line it starts on, and its text with the hashes removed.
struct Snippet {
	line: usize,
	text: String,
}

/// Split the example file into compilable snippets.
fn snippets(source: &str) -> Vec<Snippet> {
	let mut found: Vec<Snippet> = Vec::new();
	let mut current: Option<Snippet> = None;

	for (index, line) in source.lines().enumerate() {
		// Config is `#` followed by something that is not a space. A blank
		// line, a prose line, or anything else closes the run -- so two
		// examples separated by a sentence are two snippets, which is what
		// lets each be complete on its own.
		let is_config = line
			.strip_prefix('#')
			.is_some_and(|rest| !rest.is_empty() && !rest.starts_with(' '));

		if is_config {
			let body = &line[1..];
			match current.as_mut() {
				Some(snippet) => {
					snippet.text.push_str(body);
					snippet.text.push('\n');
				}
				None => {
					current = Some(Snippet {
						line: index + 1,
						text: format!("{body}\n"),
					});
				}
			}
		} else if let Some(snippet) = current.take() {
			found.push(snippet);
		}
	}
	if let Some(snippet) = current.take() {
		found.push(snippet);
	}
	found
}

/// Every example in the file compiles.
///
/// This is the whole gate. A key that is renamed, a block that is removed, a
/// value spelling that stops being accepted -- each fails here, naming the
/// line of the example that has to change, rather than shipping a manual that
/// describes a language the compiler does not speak.
#[test]
fn every_example_compiles() {
	let source = std::fs::read_to_string(EXAMPLE)
		.unwrap_or_else(|error| panic!("cannot read {EXAMPLE}: {error}"));
	let found = snippets(&source);

	// The gate is worthless if the split found nothing -- an example file
	// rewritten in a way this parser does not recognise would otherwise report
	// success over zero snippets, which is exactly the vacuous pass this tree
	// keeps finding. The number is a floor rather than an equality so that
	// adding an example does not fail the suite, but losing them all does.
	assert!(
		found.len() >= 20,
		"only {} examples were found in {EXAMPLE}; config lines are `#` followed by \
		 a non-space, and finding none looks exactly like every one of them passing",
		found.len()
	);

	let mut failures = String::new();
	for snippet in &found {
		let mut sources = SourceMap::new();
		sources.add("netcfgd.conf.example", &snippet.text);
		if let Err(diagnostics) = compile(&sources, &mut FakeHooks) {
			failures.push_str(&format!(
				"\n{EXAMPLE}:{}: this example does not compile:\n{}\n{}\n",
				snippet.line,
				snippet
					.text
					.lines()
					.map(|line| format!("    {line}"))
					.collect::<Vec<_>>()
					.join("\n"),
				diagnostics.render(&sources)
			));
		}
	}
	assert!(failures.is_empty(), "{failures}");
}

/// Every example renders back as configuration, and recompiles to itself.
///
/// **A corpus somebody else curated**, which is what makes this worth having
/// beside the renderer's own unit tests. Those use documents their author
/// chose; this file claims to carry every feature with the syntax to use it,
/// so it is the nearest thing to the whole language -- and `ncfg profile save`
/// renders a running document, so a feature the renderer never learned is a
/// machine that can save no profile at all. That failure has arrived four
/// times: a wifi policy, a routing rule, an access point, and an
/// ingress-shaped line.
///
/// **The exception is named rather than counted.** A snippet may be refused
/// only if every reason names `hooks`, and nothing else: a `HookRef` holds a
/// path and a sha256 rather than the shell, so the body is not in the document
/// to write back. Naming it this way means a *new* refusal -- a key somebody
/// adds to the parser and not to the renderer -- fails here with its own
/// wording, instead of being absorbed into a tolerance.
///
/// The waiver is also asserted non-empty, because a list of permitted
/// failures that has quietly stopped matching anything is the vacuous pass
/// again: it would report success whether or not the renderer still refused
/// hooks, and whether or not this test still reached them.
#[test]
fn every_example_renders_and_round_trips() {
	let source = std::fs::read_to_string(EXAMPLE)
		.unwrap_or_else(|error| panic!("cannot read {EXAMPLE}: {error}"));
	let found = snippets(&source);
	assert!(found.len() >= 20, "only {} examples found", found.len());

	let mut failures = String::new();
	let mut waived = 0usize;
	let mut rendered_count = 0usize;
	for snippet in &found {
		let mut sources = SourceMap::new();
		sources.add("netcfgd.conf.example", &snippet.text);
		let Ok(document) = compile(&sources, &mut FakeHooks) else {
			// `every_example_compiles` owns that failure and reports it
			// better; reporting it twice would make one defect read as two.
			continue;
		};
		let overrides = netcfgd_compile::render::Overrides::new();
		let text = match netcfgd_compile::render::render(&document, &overrides) {
			Ok(text) => text,
			Err(missing) => {
				if missing.iter().all(|what| what.contains("hooks")) {
					waived += 1;
				} else {
					failures.push_str(&format!(
						"\n{EXAMPLE}:{}: renders only partly, and not because of hooks:\n    {}\n",
						snippet.line,
						missing.join("\n    ")
					));
				}
				continue;
			}
		};
		rendered_count += 1;

		// The round trip, which is what a profile save actually depends on:
		// the daemon proves a snapshot reproduces the running document before
		// keeping it, so a renderer that writes something subtly different
		// refuses the save rather than producing a wrong file.
		let mut back = SourceMap::new();
		back.add("rendered.conf", &text);
		match compile(&back, &mut FakeHooks) {
			Ok(again) if again == document => {}
			Ok(_) => failures.push_str(&format!(
				"\n{EXAMPLE}:{}: renders to a different document:\n{}\n",
				snippet.line, text
			)),
			Err(diagnostics) => failures.push_str(&format!(
				"\n{EXAMPLE}:{}: renders to something that does not compile:\n{}\n{}\n",
				snippet.line,
				text,
				diagnostics.render(&back)
			)),
		}
	}

	assert!(failures.is_empty(), "{failures}");
	assert!(
		waived > 0,
		"no example was refused for hooks, so the waiver above is checking nothing -- \
		 either the renderer learned them, in which case delete it, or this test has \
		 stopped reaching them"
	);
	assert!(
		rendered_count >= 20,
		"only {rendered_count} examples rendered, which is too few for this to be a \
		 measurement of the language"
	);
}

/// xorshift, seeded fixed by the caller, because a randomised failure nobody
/// can reproduce is a sighting rather than a finding. The same generator as
/// `tests/random.rs`, deliberately: a second one would be a second thing to be
/// wrong about.
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

/// One to four byte edits of `text`.
///
/// **The digit arm is the one that reaches a VALUE rather than the grammar**,
/// and it was added because a sabotage proved the sweep could not find one:
/// dropping `mtu` unless it was exactly 1492 -- the only value the corpus
/// contains -- left every assertion green. A random printable byte lands on a
/// digit position about 14% of the time and is itself a digit 10 times in 95,
/// so reaching a specific number's digits was a once-or-twice-per-run accident.
/// This makes it ordinary, and it keeps the document valid while doing it,
/// which is what gets a mutation past the parser and into the renderer.
fn mutate(rng: &mut Rng, text: &str) -> Vec<u8> {
	let mut bytes = text.as_bytes().to_vec();
	for _ in 0..=rng.below(4) {
		if bytes.is_empty() {
			break;
		}
		let index = rng.below(bytes.len());
		match rng.below(4) {
			0 => bytes[index] = u8::try_from(0x20 + rng.below(0x5f)).unwrap_or(b' '),
			1 => {
				bytes.remove(index);
			}
			2 if bytes[index].is_ascii_digit() => {
				bytes[index] = b'0' + u8::try_from(rng.below(10)).unwrap_or(0);
			}
			// Duplicating a byte is how unbalanced braces and quotes arrive,
			// which is the mutation that reaches the parser's recovery rather
			// than its happy path.
			_ => bytes.insert(index, bytes[index]),
		}
	}
	bytes
}

/// How many mutations each example gets.
///
/// Per snippet rather than a flat budget, so a block type cannot be starved by
/// the file happening to carry more examples of another. Raised from 120 when
/// the digit arm went into `mutate`: the point of both changes is to reach
/// values, and 120 was chosen before there was any evidence about what reaching
/// them costs. Measured at about 4 seconds for the whole test, which is
/// affordable in `make check` and is the reason it is not higher.
const PER_SNIPPET: usize = 600;

/// Mutations of every example, not of one hand-written block.
///
/// **`tests/random.rs` mutates a single `interface` template.** It is a good
/// test and it reaches lowering for exactly one block shape: `config`,
/// `routes`, `dns`, `mtu`, `guard` and a `vlan`. The language has `network`,
/// `device`, `bluetooth`, `access_point`, `rule`, `linkset`, `tunnel`,
/// `wireguard`, `openvpn`, `pppoe`, `advertise`, `ethtool` and `qdisc` besides,
/// and mutation reached none of their lowering paths -- so the shapes most
/// recently taught to the compiler were the ones a mutating test never saw.
///
/// The corpus is already here, already complete enough to be a gate, and
/// already extracted by `snippets`, so this lives beside it rather than
/// carrying a second copy of that extraction.
///
/// **Two properties, and the second is the stronger one.** No mutation may
/// panic, which is what a fuzz target asserts. And any mutation that still
/// *compiles* must round-trip through the renderer, which is the invariant
/// `every_example_renders_and_round_trips` checks on unmutated text -- it has
/// nothing to do with the input being an example, so it must hold for every
/// document the compiler accepts. A mutated-but-valid document is a document.
///
/// The hooks waiver is carried for the same reason as above, and so is the
/// requirement that it fire: a mutation that produces a hook must not be read
/// as a renderer failure.
#[test]
fn mutating_every_example_round_trips_or_is_refused() {
	let source = std::fs::read_to_string(EXAMPLE)
		.unwrap_or_else(|error| panic!("cannot read {EXAMPLE}: {error}"));
	let found = snippets(&source);
	assert!(found.len() >= 20, "only {} examples found", found.len());

	let mut rng = Rng(0x2026_1008_0000_0001);
	let mut failures = String::new();
	let mut compiled = 0usize;
	let mut round_tripped = 0usize;
	let mut waived = 0usize;

	for snippet in &found {
		for _ in 0..PER_SNIPPET {
			let bytes = mutate(&mut rng, &snippet.text);
			let Ok(text) = std::str::from_utf8(&bytes) else {
				continue;
			};

			let mut sources = SourceMap::new();
			sources.add("mutated.conf", text);
			// Any refusal is a correct outcome: this asserts about what the
			// compiler ACCEPTS, and a mutation is far likelier to be invalid.
			let Ok(document) = compile(&sources, &mut FakeHooks) else {
				continue;
			};
			compiled += 1;

			// Canonicalisation is reachable only through a successful compile,
			// so it is driven here as `random.rs` drives it.
			let _ = document.to_json_canonical();

			let overrides = netcfgd_compile::render::Overrides::new();
			let rendered = match netcfgd_compile::render::render(&document, &overrides) {
				Ok(rendered) => rendered,
				Err(missing) => {
					if missing.iter().all(|what| what.contains("hooks")) {
						waived += 1;
					} else {
						failures.push_str(&format!(
							"\na mutation of {EXAMPLE}:{} compiles but renders only \
							 partly, and not because of hooks: {}\n{text}\n",
							snippet.line,
							missing.join(", ")
						));
					}
					continue;
				}
			};

			let mut back = SourceMap::new();
			back.add("rendered.conf", &rendered);
			match compile(&back, &mut FakeHooks) {
				Ok(again) if again == document => round_tripped += 1,
				Ok(_) => failures.push_str(&format!(
					"\na mutation of {EXAMPLE}:{} renders to a different \
					 document.\nmutated:\n{text}\nrendered:\n{rendered}\n",
					snippet.line
				)),
				Err(diagnostics) => failures.push_str(&format!(
					"\na mutation of {EXAMPLE}:{} renders to something that does \
					 not compile.\nmutated:\n{text}\nrendered:\n{rendered}\n{}\n",
					snippet.line,
					diagnostics.render(&back)
				)),
			}

			// One finding is enough to act on, and a mutation storm would
			// bury it.
			if failures.len() > 4_000 {
				break;
			}
		}
	}

	assert!(failures.is_empty(), "{failures}");
	// **The controls, because a mutation sweep that reached nothing would be
	// silent in exactly the same way as one that found nothing.** Mutations
	// are far likelier to be invalid than valid, so the number that compile is
	// the measure of whether this test examined the renderer at all.
	// Measured when this was written: 3182 compiled, 3065 round-tripped, and
	// the 117 between them are the hooks waiver firing. The floors are set at
	// roughly half, so a collapse fails while ordinary movement in the corpus
	// does not -- `found.len() >= 20` above already guards the corpus itself.
	assert!(
		compiled >= 1_500,
		"only {compiled} mutations compiled, against 3182 when this was written -- \
		 too few for the round-trip assertions to be a measurement, so either the \
		 mutation has become too destructive or the language stopped accepting \
		 something it did"
	);
	assert!(
		round_tripped >= 1_200,
		"only {round_tripped} mutations reached the renderer and came back, against \
		 3065 when this was written, so this test is asserting much less about it \
		 than it did"
	);
	// The hooks waiver has to fire, for the reason the test above it says: a
	// waiver that never fires is either dead or hiding something.
	assert!(
		waived > 0,
		"no mutation was refused for hooks, so the waiver is checking nothing"
	);
}

/// The installed example must not be a file the loader reads.
///
/// The whole safety of shipping a configuration file full of examples is that
/// netcfgd never loads it: `netcfgd-host`'s loader takes `netcfgd.conf` by
/// exact name and `conf.d/*.conf` by extension. `netcfgd.conf.example` is
/// neither. If that ever changed, a default install would apply every example
/// in this file at once, so the property is asserted rather than assumed.
#[test]
fn installed_name_is_not_one_the_loader_reads() {
	let name = "netcfgd.conf.example";
	assert_ne!(name, "netcfgd.conf");
	assert!(
		!std::path::Path::new(name)
			.extension()
			.is_some_and(|ext| ext.eq_ignore_ascii_case("conf")),
		"the loader takes conf.d/*.conf by extension, and this would match"
	);
}
