//! The grammar in project.md section 3, as a recursive descent parser.

use crate::ast::{Assignment, Block, File, Hook, Item, Spanned, Value};
use crate::diag::{Diagnostic, Diagnostics, SourceId, Span};
use crate::lex::{Lexer, Spanned as SpannedToken, Token};

/// The phases a hook block may name directly. `on <event>` covers the rest.
const HOOK_PHASES: &[&str] = &["pre_up", "up", "post_up", "pre_down", "down", "post_down"];

/// Blocks that take a label, and therefore are not hook blocks even when the
/// name collides.
const LABELLED_BLOCKS: &[&str] = &["interface", "network", "device", "peer"];

/// Parse one file.
///
/// # Errors
///
/// Returns every diagnostic found rather than only the first, so a config with
/// four mistakes takes one edit round.
pub fn parse(source: SourceId, text: &str) -> Result<File, Diagnostics> {
	let mut parser = Parser::new(source, text);
	let file = parser.parse_file();
	if parser.diagnostics.is_empty() {
		Ok(file)
	} else {
		Err(parser.diagnostics)
	}
}

/// How deeply blocks may nest before the parser refuses.
///
/// The parser descends once per `{`, so without a bound a file of nothing but
/// open braces exhausts the stack -- a crash rather than a diagnostic, in a
/// daemon that re-reads its configuration directory whenever anything in it
/// changes. Found by `cargo fuzz` on the `config_parse` target, which reported
/// an `AddressSanitizer` stack-overflow on 3679 bytes containing 1238 `{`.
///
/// Thirty-two is roughly ten times the deepest nesting the language actually
/// has -- `interface` holds `qdisc` holds its keys, and that is three -- so no
/// real configuration comes near it, and a file that does is a mistake worth
/// naming rather than a shape worth supporting.
const MAX_BLOCK_DEPTH: usize = 32;

struct Parser<'a> {
	lexer: Lexer<'a>,
	lookahead: Option<SpannedToken>,
	diagnostics: Diagnostics,
	source: SourceId,
	/// How many blocks are currently open. See [`MAX_BLOCK_DEPTH`].
	depth: usize,
}

impl<'a> Parser<'a> {
	fn new(source: SourceId, text: &'a str) -> Self {
		Self {
			depth: 0,
			lexer: Lexer::new(source, text),
			lookahead: None,
			diagnostics: Diagnostics::new(),
			source,
		}
	}

	fn peek(&mut self) -> SpannedToken {
		if self.lookahead.is_none() {
			self.lookahead = Some(self.pull());
		}
		self.lookahead.clone().unwrap_or(SpannedToken {
			token: Token::Eof,
			span: self.lexer.span(),
		})
	}

	fn next(&mut self) -> SpannedToken {
		match self.lookahead.take() {
			Some(token) => token,
			None => self.pull(),
		}
	}

	/// Pull a token, turning a lexer failure into a diagnostic and an `Eof` so
	/// the parser can keep going and find more than one problem.
	fn pull(&mut self) -> SpannedToken {
		match self.lexer.next_token() {
			Ok(token) => token,
			Err(diagnostic) => {
				let span = diagnostic.span;
				self.diagnostics.push(diagnostic);
				SpannedToken {
					token: Token::Eof,
					span,
				}
			}
		}
	}

	fn skip_terminators(&mut self) {
		while self.peek().token == Token::Terminator {
			self.next();
		}
	}

	fn parse_file(&mut self) -> File {
		let mut items = Vec::new();
		loop {
			self.skip_terminators();
			if self.peek().token == Token::Eof {
				break;
			}
			match self.parse_item() {
				Some(item) => items.push(item),
				None => {
					if !self.recover() {
						break;
					}
				}
			}
		}
		File { items }
	}

	/// Skip to the next statement boundary after an error.
	///
	/// Returns false at end of input. Without this the parser reports one
	/// problem and stops, which is the behaviour that makes people fix configs
	/// one line per compile.
	fn recover(&mut self) -> bool {
		loop {
			match self.next().token {
				Token::Eof => return false,
				Token::Terminator => return true,
				_ => {}
			}
		}
	}

	fn parse_item(&mut self) -> Option<Item> {
		let head = self.peek();
		let Token::Ident(name) = &head.token else {
			self.diagnostics.push(Diagnostic::new(
				head.span,
				format!("expected a statement, found {}", head.token.describe()),
			));
			return None;
		};
		let name = name.clone();

		if name == "include" {
			return self.parse_include();
		}
		if name == "override" {
			self.next();
			let mut block = self.parse_block()?;
			block.overrides = true;
			return Some(Item::Block(block));
		}
		if Self::is_hook_head(&name) {
			return self.parse_hook();
		}

		// An assignment and a block differ only after the key, so decide by
		// what follows rather than by keyword tables: `dns = ...` and
		// `dns { ... }` are both legitimate spellings for different things.
		let checkpoint = self.next();
		let next = self.peek();
		match next.token {
			Token::Equals => {
				self.next();
				let value = self.parse_value()?;
				self.expect_terminator();
				Some(Item::Assignment(Assignment {
					key: name,
					value,
					span: checkpoint.span,
				}))
			}
			Token::LBrace | Token::Ident(_) | Token::Str(_) => {
				let block = self.parse_block_after_head(name, checkpoint.span)?;
				Some(Item::Block(block))
			}
			other => {
				self.diagnostics.push(Diagnostic::new(
					next.span,
					format!(
						"expected `=` or `{{` after `{name}`, found {}",
						other.describe()
					),
				));
				None
			}
		}
	}

	fn is_hook_head(name: &str) -> bool {
		if name == "on" {
			return true;
		}
		HOOK_PHASES.contains(&name) && !LABELLED_BLOCKS.contains(&name)
	}

	fn parse_include(&mut self) -> Option<Item> {
		let keyword = self.next();
		let value = self.next();
		let Token::Str(path) = value.token else {
			self.diagnostics.push(Diagnostic::new(
				value.span,
				format!(
					"expected a quoted path after `include`, found {}",
					value.token.describe()
				),
			));
			return None;
		};
		self.expect_terminator();
		Some(Item::Include(Spanned::new(path, keyword.span)))
	}

	fn parse_hook(&mut self) -> Option<Item> {
		let keyword = self.next();
		let Token::Ident(mut phase) = keyword.token else {
			return None;
		};

		if phase == "on" {
			let event = self.next();
			let Token::Ident(name) = event.token else {
				self.diagnostics.push(Diagnostic::new(
					event.span,
					format!(
						"expected an event name after `on`, found {}",
						event.token.describe()
					),
				));
				return None;
			};
			phase = name;
		}

		let brace = self.next();
		if brace.token != Token::LBrace {
			self.diagnostics.push(Diagnostic::new(
				brace.span,
				format!(
					"expected `{{` after `{phase}`, found {}",
					brace.token.describe()
				),
			));
			return None;
		}

		// The lexer may have buffered the newline after `{`. Drop it, then
		// hand the raw remainder of the file to the body scanner.
		if self.peek().token == Token::Terminator {
			self.next();
		}
		self.lookahead = None;

		match self.lexer.take_hook_body() {
			Ok(body) => Some(Item::Hook(Hook {
				phase,
				body,
				span: keyword.span,
			})),
			Err(diagnostic) => {
				self.diagnostics.push(diagnostic);
				None
			}
		}
	}

	fn parse_block(&mut self) -> Option<Block> {
		let head = self.next();
		let Token::Ident(name) = head.token else {
			self.diagnostics.push(Diagnostic::new(
				head.span,
				format!(
					"expected a block after `override`, found {}",
					head.token.describe()
				),
			));
			return None;
		};
		self.parse_block_after_head(name, head.span)
	}

	fn parse_block_after_head(&mut self, head: String, span: Span) -> Option<Block> {
		let label = match self.peek().token {
			Token::Ident(name) => {
				self.next();
				Some(name)
			}
			Token::Str(text) => {
				self.next();
				Some(text)
			}
			_ => None,
		};

		let brace = self.next();
		if brace.token != Token::LBrace {
			self.diagnostics.push(Diagnostic::new(
				brace.span,
				format!(
					"expected `{{` to open `{head}`, found {}",
					brace.token.describe()
				),
			));
			return None;
		}

		// Bounded here rather than at the recursive call, because this is the
		// one place a block body is entered from -- `parse_block` and
		// `parse_item` both arrive through it.
		if self.depth >= MAX_BLOCK_DEPTH {
			self.diagnostics.push(
				Diagnostic::new(
					brace.span,
					format!("`{head}` nests more than {MAX_BLOCK_DEPTH} blocks deep"),
				)
				.with_help("this is almost always an unclosed block earlier in the file"),
			);
			return None;
		}
		self.depth += 1;
		let block = self.parse_block_items(head, label, span);
		self.depth -= 1;
		block
	}

	/// The body of a block, once its head, label and `{` are consumed.
	///
	/// Split from [`Self::parse_block_after_head`] so the depth counter has one
	/// place to go up and one to come back down, rather than a decrement before
	/// each of several early returns.
	fn parse_block_items(
		&mut self,
		head: String,
		label: Option<String>,
		span: Span,
	) -> Option<Block> {
		let mut items = Vec::new();
		loop {
			self.skip_terminators();
			match self.peek().token {
				Token::RBrace => {
					self.next();
					break;
				}
				Token::Eof => {
					self.diagnostics.push(
						Diagnostic::new(span, format!("unclosed block `{head}`"))
							.with_help("every block needs a closing `}`"),
					);
					return None;
				}
				_ => match self.parse_item() {
					Some(item) => items.push(item),
					None => {
						if !self.recover() {
							return None;
						}
					}
				},
			}
		}
		self.expect_terminator();

		Some(Block {
			head,
			label,
			overrides: false,
			items,
			span,
		})
	}

	fn parse_value(&mut self) -> Option<Spanned<Value>> {
		let token = self.next();
		let value = match token.token {
			Token::Str(text) => Value::Str(text),
			Token::Number(number) => Value::Number(number),
			Token::Bool(flag) => Value::Bool(flag),
			Token::LBracket => return self.parse_list(token.span),
			other => {
				self.diagnostics.push(Diagnostic::new(
					token.span,
					format!("expected a value, found {}", other.describe()),
				));
				return None;
			}
		};
		Some(Spanned::new(value, token.span))
	}

	fn parse_list(&mut self, span: Span) -> Option<Spanned<Value>> {
		let mut entries = Vec::new();
		loop {
			// A list may span lines, so terminators inside it are whitespace.
			self.skip_terminators();
			if self.peek().token == Token::RBracket {
				self.next();
				break;
			}
			let entry = self.parse_value()?;
			entries.push(entry);
			self.skip_terminators();
			match self.peek().token {
				Token::Comma => {
					self.next();
				}
				Token::RBracket => {
					self.next();
					break;
				}
				other => {
					let span = self.peek().span;
					self.diagnostics.push(Diagnostic::new(
						span,
						format!("expected `,` or `]` in list, found {}", other.describe()),
					));
					return None;
				}
			}
		}
		Some(Spanned::new(Value::List(entries), span))
	}

	fn expect_terminator(&mut self) {
		match self.peek().token {
			Token::Terminator => {
				self.next();
			}
			Token::Eof | Token::RBrace => {}
			other => {
				let span = self.peek().span;
				self.diagnostics.push(Diagnostic::new(
					span,
					format!("expected end of statement, found {}", other.describe()),
				));
			}
		}
	}

	#[allow(dead_code)]
	fn source(&self) -> SourceId {
		self.source
	}
}
