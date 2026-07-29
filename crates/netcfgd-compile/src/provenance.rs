//! Where each part of the document came from.
//!
//! The document itself deliberately carries no spans: it is the frozen schema
//! (section 2), it gets written to `/run` and eventually transmitted, and
//! putting file offsets in it would make two compiles of one config differ
//! whenever a comment moved. So provenance is a side table, keyed by the same
//! dotted paths the planner already uses in [`netcfgd_plan::Reason`].
//!
//! This is what lets `ncfg explain` answer "because
//! `/etc/netcfgd/conf.d/10-lan.conf` line 4 says so" rather than "because the
//! configuration says so", which is the difference between an explanation and
//! a restatement.

use crate::diag::{SourceMap, Span};
use serde::{Deserialize, Serialize};

/// One field, and where it was written.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Entry {
	/// Dotted path into the document, for example
	/// `interfaces[eth0].addressing[0]`.
	pub path: String,
	/// The file it came from.
	pub file: String,
	/// One-based line.
	pub line: u32,
	/// One-based column.
	pub column: u32,
}

impl Entry {
	/// `file:line:column`, which is what an editor and a human both want.
	#[must_use]
	pub fn location(&self) -> String {
		format!("{}:{}:{}", self.file, self.line, self.column)
	}
}

/// Every recorded field.
///
/// Sorted by path, so the file is stable across compiles for the same reason
/// the document is.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Provenance {
	/// The entries.
	pub entries: Vec<Entry>,
}

impl Provenance {
	/// Record a field's position.
	pub fn record(&mut self, sources: &SourceMap, path: impl Into<String>, span: Span) {
		self.entries.push(Entry {
			path: path.into(),
			file: sources.name(span.source).to_owned(),
			line: span.line,
			column: span.column,
		});
	}

	/// Where a field was written.
	#[must_use]
	pub fn lookup(&self, path: &str) -> Option<&Entry> {
		self.entries.iter().find(|entry| entry.path == path)
	}

	/// Everything recorded beneath a path prefix, for explaining a whole
	/// interface at once.
	pub fn under<'a>(&'a self, prefix: &'a str) -> impl Iterator<Item = &'a Entry> {
		self.entries
			.iter()
			.filter(move |entry| entry.path.starts_with(prefix))
	}

	/// Put the entries in a stable order.
	pub fn canonicalize(&mut self) {
		self.entries.sort_by(|a, b| a.path.cmp(&b.path));
		self.entries.dedup_by(|a, b| a.path == b.path);
	}
}

/// The dotted path of an interface.
#[must_use]
pub fn interface_path(name: &str) -> String {
	format!("interfaces[{name}]")
}

/// The dotted path of one of its fields.
#[must_use]
pub fn field_path(interface: &str, field: &str) -> String {
	format!("interfaces[{interface}].{field}")
}
