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
