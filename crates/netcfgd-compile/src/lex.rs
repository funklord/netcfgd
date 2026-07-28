//! Tokenising, plus the one escape the grammar needs for hook bodies.

use crate::diag::{Diagnostic, SourceId, Span};

/// A token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Token {
	/// A bare word.
	Ident(String),
	/// A quoted string, with escapes already resolved.
	Str(String),
	/// An integer. There are no floats in this language.
	Number(i64),
	/// `true` or `false`.
	Bool(bool),
	/// `{`
	LBrace,
	/// `}`
	RBrace,
	/// `[`
	LBracket,
	/// `]`
	RBracket,
	/// `=`
	Equals,
	/// `,`
	Comma,
	/// A statement terminator: a newline or a semicolon.
	Terminator,
	/// End of input.
	Eof,
}

impl Token {
	/// A name for this token, for "expected X, found Y" messages.
	#[must_use]
	pub fn describe(&self) -> String {
		match self {
			Self::Ident(name) => format!("`{name}`"),
			Self::Str(_) => "a string".to_owned(),
			Self::Number(_) => "a number".to_owned(),
			Self::Bool(_) => "a boolean".to_owned(),
			Self::LBrace => "`{`".to_owned(),
			Self::RBrace => "`}`".to_owned(),
			Self::LBracket => "`[`".to_owned(),
			Self::RBracket => "`]`".to_owned(),
			Self::Equals => "`=`".to_owned(),
			Self::Comma => "`,`".to_owned(),
			Self::Terminator => "end of statement".to_owned(),
			Self::Eof => "end of file".to_owned(),
		}
	}
}

/// A token together with where it came from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Spanned {
	/// The token.
	pub token: Token,
	/// Its position.
	pub span: Span,
}

/// A cursor over one file.
///
/// Hand-written rather than table-driven because of [`Lexer::take_hook_body`]:
/// a hook body is raw shell that must not be tokenised at all, and the cleanest
/// way to express that is a lexer the parser can step out of and back into.
pub struct Lexer<'a> {
	text: &'a [u8],
	position: usize,
	line: u32,
	column: u32,
	source: SourceId,
}

impl<'a> Lexer<'a> {
	/// Start at the beginning of `text`.
	#[must_use]
	pub fn new(source: SourceId, text: &'a str) -> Self {
		Self {
			text: text.as_bytes(),
			position: 0,
			line: 1,
			column: 1,
			source,
		}
	}

	/// The current position.
	#[must_use]
	pub fn span(&self) -> Span {
		Span {
			source: self.source,
			line: self.line,
			column: self.column,
		}
	}

	fn peek_byte(&self) -> Option<u8> {
		self.text.get(self.position).copied()
	}

	fn bump(&mut self) -> Option<u8> {
		let byte = self.peek_byte()?;
		self.position += 1;
		if byte == b'\n' {
			self.line += 1;
			self.column = 1;
		} else {
			self.column += 1;
		}
		Some(byte)
	}

	/// Skip spaces, tabs, carriage returns and comments, but never newlines:
	/// a newline is a statement terminator and the parser needs to see it.
	fn skip_trivia(&mut self) {
		loop {
			match self.peek_byte() {
				Some(b' ' | b'\t' | b'\r') => {
					self.bump();
				}
				Some(b'#') => {
					while let Some(byte) = self.peek_byte() {
						if byte == b'\n' {
							break;
						}
						self.bump();
					}
				}
				_ => return,
			}
		}
	}

	/// The next token.
	///
	/// # Errors
	///
	/// Returns a diagnostic for an unterminated string, an unknown escape, a
	/// number that does not fit an `i64`, or a character the grammar has no
	/// production for.
	pub fn next_token(&mut self) -> Result<Spanned, Diagnostic> {
		self.skip_trivia();
		let span = self.span();
		let Some(byte) = self.peek_byte() else {
			return Ok(Spanned {
				token: Token::Eof,
				span,
			});
		};

		let token = match byte {
			b'\n' | b';' => {
				self.bump();
				Token::Terminator
			}
			b'{' => {
				self.bump();
				Token::LBrace
			}
			b'}' => {
				self.bump();
				Token::RBrace
			}
			b'[' => {
				self.bump();
				Token::LBracket
			}
			b']' => {
				self.bump();
				Token::RBracket
			}
			b'=' => {
				self.bump();
				Token::Equals
			}
			b',' => {
				self.bump();
				Token::Comma
			}
			b'"' => self.lex_string(span)?,
			b'-' | b'0'..=b'9' => self.lex_number(span)?,
			b if is_ident_start(b) => self.lex_ident(),
			other => {
				self.bump();
				return Err(Diagnostic::new(
					span,
					format!("unexpected character {:?}", char::from(other)),
				));
			}
		};

		Ok(Spanned { token, span })
	}

	fn lex_ident(&mut self) -> Token {
		let start = self.position;
		while let Some(byte) = self.peek_byte() {
			if is_ident_continue(byte) {
				self.bump();
			} else {
				break;
			}
		}
		let text = String::from_utf8_lossy(&self.text[start..self.position]).into_owned();
		match text.as_str() {
			"true" => Token::Bool(true),
			"false" => Token::Bool(false),
			_ => Token::Ident(text),
		}
	}

	fn lex_number(&mut self, span: Span) -> Result<Token, Diagnostic> {
		let start = self.position;
		if self.peek_byte() == Some(b'-') {
			self.bump();
		}
		let digits_start = self.position;
		while let Some(byte) = self.peek_byte() {
			if byte.is_ascii_digit() {
				self.bump();
			} else {
				break;
			}
		}
		if self.position == digits_start {
			return Err(Diagnostic::new(span, "expected digits after `-`"));
		}
		// A trailing `.` would be a float, and section 2 forbids floats
		// outright. Catching it here gives a better message than letting the
		// `.` surface as an unexpected character on the next token.
		if self.peek_byte() == Some(b'.') {
			return Err(
				Diagnostic::new(span, "numbers in this language are integers")
					.with_help("no value in the desired-state document is a float"),
			);
		}
		let text = String::from_utf8_lossy(&self.text[start..self.position]).into_owned();
		text.parse::<i64>()
			.map(Token::Number)
			.map_err(|_| Diagnostic::new(span, format!("number {text} does not fit in 64 bits")))
	}

	/// Lex a quoted string.
	///
	/// A string may span lines. The grammar in section 3 says so -- `char -
	/// '"'` excludes only the quote -- and it has to, because the netifrc
	/// spelling puts several addresses or routes in one quoted value, one per
	/// line. The cost is that a missing closing quote swallows everything up
	/// to the next one, so every diagnostic here points at the opening quote
	/// rather than at wherever the lexer eventually gave up.
	fn lex_string(&mut self, span: Span) -> Result<Token, Diagnostic> {
		self.bump(); // opening quote
		let mut out = String::new();
		loop {
			let Some(byte) = self.bump() else {
				return Err(Diagnostic::new(span, "unterminated string")
					.with_help("a string runs to its closing quote, across lines if need be"));
			};
			match byte {
				b'"' => return Ok(Token::Str(out)),
				b'\\' => {
					let escape_span = self.span();
					let Some(escaped) = self.bump() else {
						return Err(Diagnostic::new(span, "unterminated string"));
					};
					match escaped {
						b'"' => out.push('"'),
						b'\\' => out.push('\\'),
						b'n' => out.push('\n'),
						b't' => out.push('\t'),
						other => {
							return Err(Diagnostic::new(
								escape_span,
								format!("unknown escape `\\{}`", char::from(other)),
							)
							.with_help("the escapes are \\\" \\\\ \\n and \\t"))
						}
					}
				}
				other => {
					// Push the raw byte through UTF-8 reconstruction: the
					// source may legitimately contain non-ASCII inside a
					// string, for an SSID or a search domain.
					let mut buffer = [0_u8; 4];
					let len = utf8_continuation_len(other);
					buffer[0] = other;
					for slot in buffer.iter_mut().take(len).skip(1) {
						match self.bump() {
							Some(next) => *slot = next,
							None => return Err(Diagnostic::new(span, "unterminated string")),
						}
					}
					match std::str::from_utf8(&buffer[..len]) {
						Ok(text) => out.push_str(text),
						Err(_) => {
							return Err(Diagnostic::new(span, "string is not valid UTF-8"));
						}
					}
				}
			}
		}
	}

	/// Consume raw lines up to and including the first line consisting solely
	/// of `}`, and return everything before it.
	///
	/// This is the one irregular production in the grammar (section 3). A hook
	/// body is arbitrary shell, so brace counting would mean parsing shell;
	/// terminating on a lone `}` line needs no shell knowledge and is
	/// explainable in one sentence of documentation. Braces nested inside the
	/// shell are irrelevant.
	///
	/// # Errors
	///
	/// Returns a diagnostic if the file ends before the closing line.
	pub fn take_hook_body(&mut self) -> Result<String, Diagnostic> {
		let open = self.span();
		let mut body = String::new();
		loop {
			if self.position >= self.text.len() {
				return Err(Diagnostic::new(open, "unterminated hook body").with_help(
					"a hook body ends at the first line containing only a closing brace",
				));
			}
			let line_start = self.position;
			while let Some(byte) = self.peek_byte() {
				self.bump();
				if byte == b'\n' {
					break;
				}
			}
			let raw = String::from_utf8_lossy(&self.text[line_start..self.position]).into_owned();
			if raw.trim_end_matches(['\n', '\r']).trim() == "}" {
				return Ok(body);
			}
			body.push_str(&raw);
		}
	}
}

fn is_ident_start(byte: u8) -> bool {
	byte.is_ascii_alphabetic() || byte == b'_'
}

fn is_ident_continue(byte: u8) -> bool {
	byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-'
}

/// How many bytes this UTF-8 lead byte introduces, including itself.
fn utf8_continuation_len(lead: u8) -> usize {
	if lead < 0x80 {
		1
	} else if lead >> 5 == 0b110 {
		2
	} else if lead >> 4 == 0b1110 {
		3
	} else if lead >> 3 == 0b11110 {
		4
	} else {
		// A stray continuation byte. Take it alone and let the UTF-8 check
		// reject it with a real message.
		1
	}
}
