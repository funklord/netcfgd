#![forbid(unsafe_code)]

//! The netcfgd config language: text in, desired-state document out.
//!
//! Pure, like `netcfgd-model`. This crate opens no files -- the caller reads
//! the config directory and hands the text over as a [`SourceMap`], and
//! resolves `include` statements before compiling. That is what lets the whole
//! front end be exercised from fixtures with no filesystem, which is the
//! property project.md section 5 asks for.
//!
//! The pipeline is four passes, each with one job:
//!
//! 1. [`parse`] -- text to an AST that says what was written, not what it
//!    means. Every node carries a span.
//! 2. [`merge`] -- drop-in precedence, and the `override` rule that makes
//!    redefinition an error rather than a silent last-wins.
//! 3. [`lower`] -- AST to model, where the interpretation happens and where
//!    diagnostics can still point at the text that caused them.
//! 4. Validation, in `netcfgd-model`, of the invariants the language cannot
//!    express structurally.

pub mod ast;
pub mod diag;
pub mod hook;
pub mod lex;
pub mod lower;
pub mod merge;
pub mod parse;
pub mod provenance;

pub use diag::{Diagnostic, Diagnostics, SourceId, SourceMap, Span};
pub use hook::{HookSink, NoHooks};
pub use provenance::Provenance;

use netcfgd_model::Document;

/// Compile a set of config files, in precedence order, into a document.
///
/// # Errors
///
/// Returns every diagnostic found. A config with four mistakes should take one
/// edit round rather than four.
pub fn compile(sources: &SourceMap, hooks: &mut dyn HookSink) -> Result<Document, Diagnostics> {
	compile_with_provenance(sources, hooks).map(|(document, _)| document)
}

/// Compile, and report where each field came from.
///
/// The provenance is a side table rather than part of the document, because
/// the document is the frozen schema and has to encode identically for two
/// compiles of one config. See `provenance`.
///
/// # Errors
///
/// As [`compile`].
pub fn compile_with_provenance(
	sources: &SourceMap,
	hooks: &mut dyn HookSink,
) -> Result<(Document, Provenance), Diagnostics> {
	let mut files = Vec::with_capacity(sources.len());
	let mut diagnostics = Diagnostics::new();

	for id in sources.ids() {
		match parse::parse(id, sources.text(id)) {
			Ok(file) => files.push(file),
			Err(more) => diagnostics.0.extend(more.0),
		}
	}
	if !diagnostics.is_empty() {
		return Err(diagnostics);
	}

	let merged = merge::merge(&files, sources)?;
	let mut provenance = Provenance::default();
	let mut document = lower::lower(&merged, hooks, sources, &mut provenance)?;
	provenance.canonicalize();

	// Canonicalise before validating so that a diagnostic about, say, a
	// duplicate interface names the same entry every time regardless of which
	// drop-in file introduced it.
	document.canonicalize();
	document.validate().map_err(|error| {
		let mut diagnostics = Diagnostics::new();
		diagnostics.push(Diagnostic::new(Span::start(SourceId(0)), error.to_string()));
		diagnostics
	})?;

	Ok((document, provenance))
}
