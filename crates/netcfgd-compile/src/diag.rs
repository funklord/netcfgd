//! Source positions and the diagnostics that carry them.

use std::fmt;

/// Index into a [`SourceMap`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SourceId(pub usize);

/// A position in a source file.
///
/// Carried on every AST node, because design section 17 requires a parse error
/// to name the file and the line. An error that says only what was wrong makes
/// the reader search a directory of drop-ins for it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Span {
	/// Which file.
	pub source: SourceId,
	/// One-based line.
	pub line: u32,
	/// One-based column, counted in characters.
	pub column: u32,
}

impl Span {
	/// The position at the start of a file.
	#[must_use]
	pub fn start(source: SourceId) -> Self {
		Self {
			source,
			line: 1,
			column: 1,
		}
	}
}

/// The set of files being compiled together, in precedence order.
///
/// The compiler never opens a file. The caller reads the config directory and
/// hands the text in, which is what keeps this crate pure and what lets the
/// whole front end be tested from fixtures with no filesystem at all.
#[derive(Debug, Clone, Default)]
pub struct SourceMap {
	files: Vec<(String, String)>,
}

impl SourceMap {
	/// An empty map.
	#[must_use]
	pub fn new() -> Self {
		Self::default()
	}

	/// Append a file. Order is precedence order: `netcfgd.conf` first, then
	/// `conf.d/*.conf` in lexical filename order.
	pub fn add(&mut self, name: impl Into<String>, text: impl Into<String>) -> SourceId {
		self.files.push((name.into(), text.into()));
		SourceId(self.files.len() - 1)
	}

	/// The name of a file, for diagnostics.
	#[must_use]
	pub fn name(&self, id: SourceId) -> &str {
		self.files
			.get(id.0)
			.map_or("<unknown>", |(n, _)| n.as_str())
	}

	/// The text of a file.
	#[must_use]
	pub fn text(&self, id: SourceId) -> &str {
		self.files.get(id.0).map_or("", |(_, t)| t.as_str())
	}

	/// Every file id, in precedence order.
	pub fn ids(&self) -> impl Iterator<Item = SourceId> {
		(0..self.files.len()).map(SourceId)
	}

	/// How many files.
	#[must_use]
	pub fn len(&self) -> usize {
		self.files.len()
	}

	/// Whether there are no files.
	#[must_use]
	pub fn is_empty(&self) -> bool {
		self.files.is_empty()
	}
}

/// One compilation failure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Diagnostic {
	/// Where it happened.
	pub span: Span,
	/// What was wrong, as a sentence.
	pub message: String,
	/// What to do about it, where that is not obvious from the message.
	pub help: Option<String>,
}

impl Diagnostic {
	/// A diagnostic with no help text.
	#[must_use]
	pub fn new(span: Span, message: impl Into<String>) -> Self {
		Self {
			span,
			message: message.into(),
			help: None,
		}
	}

	/// Attach a suggestion.
	#[must_use]
	pub fn with_help(mut self, help: impl Into<String>) -> Self {
		self.help = Some(help.into());
		self
	}

	/// Render as `file:line:column: message`, with any help on a second line.
	#[must_use]
	pub fn render(&self, sources: &SourceMap) -> String {
		let mut out = format!(
			"{}:{}:{}: {}",
			sources.name(self.span.source),
			self.span.line,
			self.span.column,
			self.message
		);
		if let Some(help) = &self.help {
			out.push_str("\n  help: ");
			out.push_str(help);
		}
		out
	}
}

/// Every failure found, rather than only the first.
///
/// A config with four mistakes should take one edit round, not four.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Diagnostics(pub Vec<Diagnostic>);

impl Diagnostics {
	/// An empty set.
	#[must_use]
	pub fn new() -> Self {
		Self::default()
	}

	/// Record a failure.
	pub fn push(&mut self, diagnostic: Diagnostic) {
		self.0.push(diagnostic);
	}

	/// Whether anything was recorded.
	#[must_use]
	pub fn is_empty(&self) -> bool {
		self.0.is_empty()
	}

	/// How many failures.
	#[must_use]
	pub fn len(&self) -> usize {
		self.0.len()
	}

	/// Render every diagnostic, one per line.
	#[must_use]
	pub fn render(&self, sources: &SourceMap) -> String {
		self.0
			.iter()
			.map(|d| d.render(sources))
			.collect::<Vec<_>>()
			.join("\n")
	}
}

impl fmt::Display for Diagnostics {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		for (index, diagnostic) in self.0.iter().enumerate() {
			if index > 0 {
				writeln!(f)?;
			}
			write!(
				f,
				"{}:{}: {}",
				diagnostic.span.line, diagnostic.span.column, diagnostic.message
			)?;
		}
		Ok(())
	}
}

impl std::error::Error for Diagnostics {}
