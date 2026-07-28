//! The shape of a parsed config file, before it means anything.
//!
//! Deliberately dumb: this is what was written, not what it implies. Every
//! interpretation happens in `lower`, so a diagnostic can always point at the
//! text that caused it.

use crate::diag::Span;

/// A value on the right of an `=`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Value {
	/// A quoted string.
	Str(String),
	/// An integer.
	Number(i64),
	/// `true` or `false`.
	Bool(bool),
	/// A bracketed list.
	List(Vec<Spanned<Value>>),
}

impl Value {
	/// A name for this kind of value, for "expected X, found Y" messages.
	#[must_use]
	pub fn describe(&self) -> &'static str {
		match self {
			Self::Str(_) => "a string",
			Self::Number(_) => "a number",
			Self::Bool(_) => "a boolean",
			Self::List(_) => "a list",
		}
	}
}

/// Anything carrying a source position.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Spanned<T> {
	/// The thing.
	pub node: T,
	/// Where it was written.
	pub span: Span,
}

impl<T> Spanned<T> {
	/// Pair a node with a span.
	pub fn new(node: T, span: Span) -> Self {
		Self { node, span }
	}
}

/// A `key = value` line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Assignment {
	/// The key.
	pub key: String,
	/// The value.
	pub value: Spanned<Value>,
	/// Position of the key.
	pub span: Span,
}

/// A `phase { ... }` block whose body is raw shell.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hook {
	/// The phase name as written: `post_up`, or the event after `on`.
	pub phase: String,
	/// The shell, verbatim, without the closing line.
	pub body: String,
	/// Position of the phase keyword.
	pub span: Span,
}

/// A `head label { ... }` block.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Block {
	/// The block keyword: `interface`, `global`, `vlan` and so on.
	pub head: String,
	/// The label, where the block takes one.
	pub label: Option<String>,
	/// Whether `override` preceded it.
	pub overrides: bool,
	/// What is inside.
	pub items: Vec<Item>,
	/// Position of the head keyword.
	pub span: Span,
}

impl Block {
	/// `interface eth0` or `global`, for diagnostics.
	#[must_use]
	pub fn describe(&self) -> String {
		match &self.label {
			Some(label) => format!("{} {label}", self.head),
			None => self.head.clone(),
		}
	}

	/// The key a redefinition check compares on.
	#[must_use]
	pub fn key(&self) -> (String, Option<String>) {
		(self.head.clone(), self.label.clone())
	}
}

/// One statement.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Item {
	/// A nested or top-level block.
	Block(Block),
	/// A key and a value.
	Assignment(Assignment),
	/// A hook block.
	Hook(Hook),
	/// `include "path"`. Resolution is the caller's job; the compiler opens no
	/// files.
	Include(Spanned<String>),
}

/// One parsed file.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct File {
	/// Its statements, in the order written.
	pub items: Vec<Item>,
}
