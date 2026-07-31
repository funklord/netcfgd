//! Talking to the daemon.
//!
//! Only where the daemon is genuinely required. `ncfg plan` and `ncfg status`
//! work without one -- design section 4.4 makes daemon-optional a property
//! rather than a fallback -- but a commit-confirm window has to outlive the
//! process that opened it, so those commands need somebody still running.

use netcfgd_apply::Journal;
use netcfgd_proto::{read_message, write_message, Request};
use serde::Deserialize;
use std::io::{BufReader, BufWriter};
use std::os::unix::net::UnixStream;
use std::path::Path;

/// The three answers the CLI ever asks the daemon for.
///
/// A narrow mirror of `netcfgd_proto::Response` rather than the type itself,
/// and the reason is measured rather than aesthetic: deserialising the full
/// `Response` pulls in `Plan`, which pulls in `Op`, whose derived
/// `Deserialize` is 42 KB of monomorphised serde -- the single largest symbol
/// in the binary, for a variant `ncfg` never receives. It computes plans
/// locally (design section 4.4: daemon-optional) and only needs the daemon for
/// confirm, revert, and an apply that opens a window.
///
/// The tags must match the wire type. That is a real coupling, so it is
/// checked by a test rather than by hoping.
#[derive(Debug, Deserialize)]
#[serde(tag = "response", rename_all = "snake_case")]
pub(crate) enum Answer {
	/// The request succeeded and had nothing to return.
	Ok,
	/// What an apply did.
	Journal(Box<Journal>),
	/// What a scan found.
	WifiScan(Box<netcfgd_proto::ScanReport>),
	/// What a radio is doing.
	WifiStatus(Box<netcfgd_proto::WifiState>),
	/// Who is associated with an access point.
	ApStations(Box<netcfgd_proto::StationReport>),
	/// The request failed.
	Error {
		/// What went wrong.
		message: String,
	},
	/// Anything else the daemon can send. Named rather than silently ignored,
	/// because a client that quietly treats an unexpected answer as success is
	/// the bug this whole project keeps refusing to write.
	#[serde(untagged)]
	Unexpected(serde_json::Value),
}

impl Answer {
	/// What arrived, for an error message. Truncated, because a whole document
	/// in a diagnostic is not a diagnostic.
	pub(crate) fn describe(&self) -> String {
		match self {
			Self::Ok => "ok".to_owned(),
			Self::Journal(_) => "a journal".to_owned(),
			Self::WifiScan(_) => "a scan".to_owned(),
			Self::WifiStatus(_) => "a radio status".to_owned(),
			Self::ApStations(_) => "a station list".to_owned(),
			Self::Error { message } => format!("an error: {message}"),
			Self::Unexpected(value) => {
				let rendered = value.to_string();
				let head: String = rendered.chars().take(120).collect();
				format!("an unexpected answer: {head}")
			}
		}
	}
}

/// Send one request and read one response.
///
/// # Errors
///
/// Returns a message naming what could not be reached, which for a missing
/// daemon is the useful half: "connection refused" alone sends the reader
/// looking for a network problem.
pub(crate) fn ask(socket: &Path, request: &Request) -> Result<Answer, String> {
	let stream = UnixStream::connect(socket).map_err(|error| {
		format!(
			"cannot reach the daemon at {}: {error}\n\
			 this command needs netcfgd running, because the window has to \
			 outlive `ncfg`",
			socket.display()
		)
	})?;
	let write_half = stream
		.try_clone()
		.map_err(|error| format!("cannot use the socket: {error}"))?;

	let mut reader = BufReader::new(stream);
	let mut writer = BufWriter::new(write_half);

	write_message(&mut writer, request).map_err(|error| format!("cannot send: {error}"))?;
	match read_message::<Answer, _>(&mut reader) {
		Ok(Some(response)) => Ok(response),
		Ok(None) => Err("the daemon closed the connection without answering".to_owned()),
		Err(error) => Err(format!("cannot read the answer: {error}")),
	}
}

/// Ask, and return the answer as raw JSON.
///
/// Used by the TUI, which draws four fields out of a document and would
/// otherwise pull in the derived deserialiser for the whole thing -- hundreds
/// of kilobytes, for a pane that prints a name and an address.
///
/// # Errors
///
/// Returns a message naming what could not be reached.
pub(crate) fn ask_value(socket: &Path, request: &Request) -> Result<serde_json::Value, String> {
	let stream = UnixStream::connect(socket)
		.map_err(|error| format!("cannot reach the daemon at {}: {error}", socket.display()))?;
	let write_half = stream
		.try_clone()
		.map_err(|error| format!("cannot use the socket: {error}"))?;
	let mut reader = BufReader::new(stream);
	let mut writer = BufWriter::new(write_half);

	write_message(&mut writer, request).map_err(|error| format!("cannot send: {error}"))?;
	match read_message::<serde_json::Value, _>(&mut reader) {
		Ok(Some(value)) => Ok(value),
		Ok(None) => Err("the daemon closed the connection without answering".to_owned()),
		Err(error) => Err(format!("cannot read the answer: {error}")),
	}
}

/// Subscribe, and hand each event to `sink` as a rendered line.
///
/// The same subscription `stream` makes, without the assumption that the
/// destination is standard output.
///
/// # Errors
///
/// Returns a message naming what could not be reached.
pub(crate) fn stream_lines(socket: &Path, sink: &dyn Fn(String)) -> Result<(), String> {
	let stream = UnixStream::connect(socket)
		.map_err(|error| format!("cannot reach the daemon at {}: {error}", socket.display()))?;
	let write_half = stream
		.try_clone()
		.map_err(|error| format!("cannot use the socket: {error}"))?;
	let mut reader = BufReader::new(stream);
	let mut writer = BufWriter::new(write_half);

	write_message(&mut writer, &Request::Monitor)
		.map_err(|error| format!("cannot subscribe: {error}"))?;

	loop {
		match read_message::<serde_json::Value, _>(&mut reader) {
			Ok(Some(value)) => sink(render_event(&value)),
			Ok(None) => return Ok(()),
			Err(error) => return Err(error.to_string()),
		}
	}
}

/// Where the socket is, for a given run directory.
#[must_use]
pub(crate) fn socket_path(run_dir: &Path) -> std::path::PathBuf {
	run_dir.join("netcfgd.sock")
}

/// Subscribe to the daemon's event stream and print until interrupted.
///
/// # Errors
///
/// Returns a message naming what could not be reached.
pub(crate) fn stream(socket: &Path, json: bool) -> Result<std::process::ExitCode, String> {
	let stream = UnixStream::connect(socket)
		.map_err(|error| format!("cannot reach the daemon at {}: {error}", socket.display()))?;
	let write_half = stream
		.try_clone()
		.map_err(|error| format!("cannot use the socket: {error}"))?;
	let mut reader = BufReader::new(stream);
	let mut writer = BufWriter::new(write_half);

	write_message(&mut writer, &Request::Monitor)
		.map_err(|error| format!("cannot subscribe: {error}"))?;

	// Events arrive until the daemon stops or the terminal goes away. There is
	// no exit condition on this side by design: `monitor` is something you
	// leave running in another window and interrupt when you are done.
	loop {
		match read_message::<serde_json::Value, _>(&mut reader) {
			Ok(Some(value)) => {
				if json {
					println!("{value}");
				} else {
					println!("{}", render_event(&value));
				}
			}
			Ok(None) => return Ok(std::process::ExitCode::SUCCESS),
			Err(error) => return Err(format!("the stream ended: {error}")),
		}
	}
}

/// One line per event.
///
/// Rendered from the JSON rather than a typed enum for the same reason the
/// response type is narrow: pulling the full `Response` in costs several
/// hundred kilobytes, and a monitor that prints an event it does not recognise
/// is more useful than one that refuses to parse it.
fn render_event(value: &serde_json::Value) -> String {
	let event = value.get("event").and_then(serde_json::Value::as_str);
	let field = |name: &str| {
		value
			.get(name)
			.map(|found| match found.as_str() {
				Some(text) => text.to_owned(),
				None => found.to_string(),
			})
			.unwrap_or_default()
	};
	match event {
		Some("observed") => format!("observed  {}", field("summary")),
		Some("reloaded") => {
			if value.get("ok").and_then(serde_json::Value::as_bool) == Some(true) {
				"reloaded  the configuration compiled".to_owned()
			} else {
				format!("reloaded  FAILED\n{}", field("diagnostics"))
			}
		}
		Some("drift") => format!(
			"drift     {}: {} ({})",
			field("interface"),
			field("summary"),
			field("action")
		),
		Some("confirm_armed") => format!("confirm   window open for {}s", field("seconds")),
		Some("confirm_resolved") => {
			if value.get("confirmed").and_then(serde_json::Value::as_bool) == Some(true) {
				"confirm   confirmed; the change stands".to_owned()
			} else {
				"confirm   reverted to the last-good configuration".to_owned()
			}
		}
		_ => value.to_string(),
	}
}

#[cfg(test)]
mod tests {
	use super::Answer;
	use netcfgd_proto::{write_message, Response};

	/// `Answer` mirrors `Response`'s tags by hand, which is a real coupling
	/// and therefore checked rather than trusted. If a tag is ever renamed on
	/// the wire, this fails instead of the CLI silently reporting every answer
	/// as unexpected.
	#[test]
	fn the_narrow_mirror_matches_the_wire_tags() {
		for (response, expected) in [
			(Response::Ok, "ok"),
			(
				Response::error("something went wrong"),
				"an error: something went wrong",
			),
		] {
			let mut buffer = Vec::new();
			write_message(&mut buffer, &response).expect("writes");
			let answer: Answer = serde_json::from_slice(&buffer).expect("the mirror parses it");
			assert_eq!(answer.describe(), expected);
		}
	}

	/// A response the CLI does not handle is reported as unexpected rather
	/// than failing to parse, so a newer daemon does not make an older `ncfg`
	/// useless for the commands it does understand.
	#[test]
	fn an_unhandled_response_is_reported_not_fatal() {
		let mut buffer = Vec::new();
		write_message(
			&mut buffer,
			&Response::Hello {
				protocol: netcfgd_proto::PROTOCOL_VERSION,
				schema: netcfgd_model::SCHEMA_VERSION,
			},
		)
		.expect("writes");
		let answer: Answer = serde_json::from_slice(&buffer).expect("parses as unexpected");
		assert!(answer.describe().starts_with("an unexpected answer"));
	}
}
