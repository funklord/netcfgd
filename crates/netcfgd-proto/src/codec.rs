//! Framing: one JSON object per line, in both directions.
//!
//! The interesting part is not the encoding, it is the bound. A control socket
//! is reachable by anything that can open it, so a client that sends a
//! gigabyte without a newline must be refused rather than absorbed -- the
//! daemon holds `CAP_NET_ADMIN` and being killed by the OOM killer is a denial
//! of service with extra steps.

use serde::de::DeserializeOwned;
use serde::Serialize;
use std::io::{self, BufRead, Read, Write};

/// The longest line the daemon will accept.
///
/// Generous for anything the protocol actually carries -- a whole document
/// compiles to a few tens of kilobytes -- and small enough that a hostile
/// client cannot make the daemon allocate its way to death.
pub const MAX_LINE: usize = 1024 * 1024;

/// Read one message.
///
/// Returns `Ok(None)` at a clean end of stream, which is how a client
/// disconnecting is distinguished from a client misbehaving.
///
/// # Errors
///
/// Returns `InvalidData` for a line over [`MAX_LINE`] or one that is not the
/// expected message, and the underlying `io::Error` otherwise.
pub fn read_message<T: DeserializeOwned, R: BufRead>(reader: &mut R) -> io::Result<Option<T>> {
	let mut line = Vec::new();
	// A reborrow rather than a bare `read_until`, because `read_until` grows
	// without bound and the bound is the point. `&mut R` is itself `BufRead`,
	// so the reader stays usable for the next message.
	let read = Read::by_ref(reader)
		.take(MAX_LINE as u64)
		.read_until(b'\n', &mut line)?;
	if read == 0 {
		return Ok(None);
	}
	if !line.ends_with(b"\n") {
		return Err(io::Error::new(
			io::ErrorKind::InvalidData,
			format!("message exceeded {MAX_LINE} bytes without a newline"),
		));
	}
	let message = serde_json::from_slice(&line)
		.map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
	Ok(Some(message))
}

/// Write one message, terminated and flushed.
///
/// # Errors
///
/// Returns the underlying `io::Error`, or `InvalidData` if the value will not
/// serialise.
pub fn write_message<T: Serialize>(writer: &mut impl Write, message: &T) -> io::Result<()> {
	let mut line = serde_json::to_vec(message)
		.map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
	// A message containing a newline would frame as two, so refuse rather than
	// send something the peer will mis-parse. serde_json escapes newlines
	// inside strings, so this can only fire on a bug here.
	if line.contains(&b'\n') {
		return Err(io::Error::new(
			io::ErrorKind::InvalidData,
			"encoded message contains a newline",
		));
	}
	line.push(b'\n');
	writer.write_all(&line)?;
	writer.flush()
}

/// A reader and writer paired over one connection.
pub struct Framed<R, W> {
	reader: R,
	writer: W,
}

impl<R: BufRead, W: Write> Framed<R, W> {
	/// Pair the two halves.
	pub fn new(reader: R, writer: W) -> Self {
		Self { reader, writer }
	}

	/// Read one message.
	///
	/// # Errors
	///
	/// As [`read_message`].
	pub fn read<T: DeserializeOwned>(&mut self) -> io::Result<Option<T>> {
		read_message(&mut self.reader)
	}

	/// Write one message.
	///
	/// # Errors
	///
	/// As [`write_message`].
	pub fn write<T: Serialize>(&mut self, message: &T) -> io::Result<()> {
		write_message(&mut self.writer, message)
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::{Request, Response, Subject};

	/// Written out because clippy reads the obvious filter-count as a naive
	/// byte count and suggests `bytecount`, which is a dependency this project
	/// will not take for one assertion in one test.
	fn bytecount_newlines(buffer: &[u8]) -> usize {
		buffer
			.iter()
			.fold(0, |count, byte| count + usize::from(*byte == b'\n'))
	}

	fn round_trip(request: &Request) -> Request {
		let mut buffer = Vec::new();
		write_message(&mut buffer, request).expect("writes");
		let mut cursor = std::io::Cursor::new(buffer);
		read_message(&mut cursor).expect("reads").expect("present")
	}

	#[test]
	fn requests_round_trip() {
		for request in [
			Request::Hello,
			Request::Status,
			Request::Plan,
			Request::Apply {
				confirm: Some(120),
				allow_disruption: vec!["eth0".to_owned()],
			},
			Request::Confirm,
			Request::Reload,
			Request::Explain {
				subject: Subject::Address {
					interface: "eth0".to_owned(),
					address: "10.0.0.1/24".to_owned(),
				},
			},
		] {
			assert_eq!(round_trip(&request), request);
		}
	}

	/// Several messages in one buffer are read one at a time, which is what a
	/// pipelining client produces.
	#[test]
	fn messages_are_framed_one_per_line() {
		let mut buffer = Vec::new();
		write_message(&mut buffer, &Request::Status).expect("writes");
		write_message(&mut buffer, &Request::Plan).expect("writes");
		assert_eq!(bytecount_newlines(&buffer), 2);

		let mut cursor = std::io::Cursor::new(buffer);
		assert_eq!(
			read_message::<Request, _>(&mut cursor).unwrap(),
			Some(Request::Status)
		);
		assert_eq!(
			read_message::<Request, _>(&mut cursor).unwrap(),
			Some(Request::Plan)
		);
		assert_eq!(read_message::<Request, _>(&mut cursor).unwrap(), None);
	}

	/// A closed connection is not an error. Distinguishing it from a
	/// misbehaving client is the reason `read` returns an Option.
	#[test]
	fn a_clean_end_of_stream_is_not_an_error() {
		let mut cursor = std::io::Cursor::new(Vec::new());
		assert_eq!(read_message::<Request, _>(&mut cursor).unwrap(), None);
	}

	/// The bound that stops a hostile client allocating the daemon to death.
	#[test]
	fn an_unterminated_flood_is_refused_rather_than_absorbed() {
		let flood = vec![b'x'; MAX_LINE + 1024];
		let mut cursor = std::io::Cursor::new(flood);
		let error = read_message::<Request, _>(&mut cursor).expect_err("must refuse");
		assert_eq!(error.kind(), io::ErrorKind::InvalidData);
		assert!(error.to_string().contains("without a newline"));
	}

	/// Garbage is a parse error, not a panic. The socket is reachable by
	/// anything that can open it.
	#[test]
	fn malformed_input_is_an_error_not_a_panic() {
		for junk in ["{", "]", "null\n", "{\"request\":\"nope\"}\n", "\n", "\0\n"] {
			let mut cursor = std::io::Cursor::new(junk.as_bytes().to_vec());
			let _ = read_message::<Request, _>(&mut cursor);
		}
	}

	/// An unknown request is refused rather than silently treated as some
	/// other one -- the same rule section 2 applies to documents.
	#[test]
	fn an_unknown_request_is_refused() {
		let mut cursor = std::io::Cursor::new(b"{\"request\":\"format_the_disk\"}\n".to_vec());
		assert!(read_message::<Request, _>(&mut cursor).is_err());
	}

	#[test]
	fn responses_round_trip_too() {
		let response = Response::error("something went wrong");
		let mut buffer = Vec::new();
		write_message(&mut buffer, &response).expect("writes");
		let mut cursor = std::io::Cursor::new(buffer);
		let back: Response = read_message(&mut cursor).unwrap().unwrap();
		assert_eq!(back, response);
	}
}
