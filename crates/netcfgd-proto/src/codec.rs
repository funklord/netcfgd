//! Framing: one JSON object per line, in both directions.
//!
//! The interesting part is not the encoding, it is the bound. A control socket
//! is reachable by anything that can open it, so a client that sends a
//! gigabyte without a newline must be refused rather than absorbed -- the
//! daemon holds `CAP_NET_ADMIN` and being killed by the OOM killer is a denial
//! of service with extra steps.

use crate::Request;
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
	let Some(line) = read_line(reader)? else {
		return Ok(None);
	};
	let message = serde_json::from_slice(&line)
		.map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
	Ok(Some(message))
}

/// One bounded line, or `None` at a clean end of stream.
fn read_line<R: BufRead>(reader: &mut R) -> io::Result<Option<Vec<u8>>> {
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
	Ok(Some(line))
}

/// Read one request, refusing a member the protocol does not define.
///
/// Separate from [`read_message`] because the two directions want opposite
/// answers. A request is untrusted input to a process holding `CAP_NET_ADMIN`,
/// and section 7 of `docs/socket-protocol.md` tells every implementation to
/// refuse unknown members -- a rule the daemon was not keeping, because
/// `deny_unknown_fields` cannot be applied to an internally-tagged enum, so the
/// payloads were strict and the envelope was not. A *response* is read by a
/// client that may be older than the daemon, where refusing a member it does
/// not know is how a working client breaks on an upgrade. So the strictness is
/// here and not in the shared path.
///
/// # Errors
///
/// As [`read_message`], plus `InvalidData` for a member the request's variant
/// does not define.
pub fn read_request<R: BufRead>(reader: &mut R) -> io::Result<Option<Request>> {
	let Some(line) = read_line(reader)? else {
		return Ok(None);
	};
	// The request first, so a malformed message keeps serde's own message
	// rather than being reported as an unknown member.
	let request: Request = serde_json::from_slice(&line)
		.map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;

	// It parsed as a request, so it is an object; a failure here cannot happen
	// and denies rather than guessing if it somehow does.
	let map: serde_json::Map<String, serde_json::Value> = serde_json::from_slice(&line)
		.map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;

	let allowed = request.members();
	if let Some(unknown) = map
		.keys()
		.find(|key| key.as_str() != "request" && !allowed.contains(&key.as_str()))
	{
		return Err(io::Error::new(
			io::ErrorKind::InvalidData,
			format!("unknown member `{unknown}` on this request"),
		));
	}
	Ok(Some(request))
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

	/// One line in, through the strict reader.
	fn strict(line: &str) -> io::Result<Option<Request>> {
		let mut cursor = std::io::Cursor::new(format!("{line}\n").into_bytes());
		read_request(&mut cursor)
	}

	/// Section 7 item 6 of docs/socket-protocol.md, which the daemon was not
	/// keeping: the payloads refused an unknown member and the envelope did
	/// not, so the permissive half was the one reading untrusted bytes.
	#[test]
	fn an_unknown_member_on_a_request_is_refused() {
		let error = strict(r#"{"request":"status","bogus":1}"#).expect_err("refused");
		assert_eq!(error.kind(), io::ErrorKind::InvalidData);
		assert!(
			error.to_string().contains("bogus"),
			"the refusal must name the member: {error}"
		);
	}

	/// The case that rules out the cheaper implementation.
	///
	/// Refusing any member a re-serialisation drops needs no table and cannot
	/// drift -- and it would refuse this, because `confirm` is
	/// `skip_serializing_if = "Option::is_none"`. Item 5 of the same checklist
	/// is "tell absent from null", so a client is entitled to send it.
	#[test]
	fn a_known_member_sent_as_null_is_accepted() {
		let request = strict(r#"{"request":"apply","confirm":null}"#)
			.expect("accepted")
			.expect("present");
		assert_eq!(
			request,
			Request::Apply {
				confirm: None,
				allow_disruption: Vec::new(),
				strand_credentials: Vec::new(),
			}
		);
	}

	/// The other direction stays lenient, deliberately.
	///
	/// A response is read by a client that may be older than the daemon, where
	/// refusing an unknown member is how an upgrade breaks a working client. So
	/// the strictness is in `read_request` and not in the shared path -- which
	/// this asserts by sending the same bytes the test above refuses.
	#[test]
	fn the_shared_reader_is_still_lenient() {
		let mut cursor =
			std::io::Cursor::new(b"{\"request\":\"status\",\"bogus\":1}\n".to_vec());
		let request: Request = read_message(&mut cursor).expect("reads").expect("present");
		assert_eq!(request, Request::Status);
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
				strand_credentials: vec!["wg0".to_owned()],
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
