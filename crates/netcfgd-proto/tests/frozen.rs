//! The socket API freeze, as a test.
//!
//! M4 freezes the socket contract alongside the document schema. Nothing
//! speaks it yet, so a change breaks nothing today -- the witness is here to
//! make a change visible, and because the socket is the surface most likely to
//! be reshaped by whatever is written against it next.
//!
//! Same mechanism as `netcfgd-model`'s witness: every request, response and
//! event serialised into `docs/schema/socket.json`, and any change to the wire
//! form moves those bytes.
//!
//! Only the envelope is pinned here. A `Status` response carries an `Observed`
//! and a `Plan`, and those are pinned by their own crates -- repeating them
//! would mean two witnesses to update for one change, and the second would
//! eventually be the one nobody did.

use netcfgd_proto::{
	Event, Explanation, Fact, Request, Response, ScanEntry, ScanReport, Subject, WifiState,
};
use std::path::PathBuf;

fn witness_path() -> PathBuf {
	PathBuf::from(env!("CARGO_MANIFEST_DIR"))
		.join("../..")
		.join("docs/schema/socket.json")
}

fn every_request() -> Vec<Request> {
	vec![
		Request::Hello,
		Request::Status,
		Request::Plan,
		Request::Apply {
			confirm: Some(90),
			allow_disruption: vec!["eth0".to_owned()],
			strand_credentials: vec!["wg0".to_owned()],
		},
		Request::Confirm,
		Request::Revert,
		Request::Reload,
		Request::Show,
		Request::Explain {
			subject: Subject::Interface {
				name: "eth0".to_owned(),
			},
		},
		Request::Explain {
			subject: Subject::Address {
				interface: "eth0".to_owned(),
				address: "192.0.2.1/24".to_owned(),
			},
		},
		Request::Explain {
			subject: Subject::Route {
				interface: "eth0".to_owned(),
				destination: "default".to_owned(),
			},
		},
		Request::Monitor,
		Request::WifiScan {
			interface: "wlan0".to_owned(),
		},
		Request::WifiStatus {
			interface: "wlan0".to_owned(),
		},
		Request::WifiConnect {
			interface: "wlan0".to_owned(),
			network: "home".to_owned(),
		},
		Request::WifiDisconnect {
			interface: "wlan0".to_owned(),
		},
	]
}

fn every_response() -> Vec<Response> {
	vec![
		Response::Hello {
			protocol: netcfgd_proto::PROTOCOL_VERSION,
			schema: netcfgd_model::SCHEMA_VERSION,
		},
		Response::Explanation(Box::new(Explanation {
			subject: "eth0".to_owned(),
			facts: vec![Fact {
				topic: "desired".to_owned(),
				detail: "static 192.0.2.1/24".to_owned(),
				source: Some("netcfgd.conf:3".to_owned()),
			}],
		})),
		Response::WifiScan(Box::new(ScanReport {
			interface: "wlan0".to_owned(),
			access_points: vec![ScanEntry {
				bssid: "00:11:22:33:44:55".to_owned(),
				frequency: 2412,
				signal: -40,
				secured: true,
				ssid: "686f6d65".to_owned(),
				name: Some("home".to_owned()),
				configured: Some("home".to_owned()),
			}],
		})),
		Response::WifiStatus(Box::new(WifiState {
			interface: "wlan0".to_owned(),
			state: "COMPLETED".to_owned(),
			ssid: Some("686f6d65".to_owned()),
			name: Some("home".to_owned()),
			bssid: Some("00:11:22:33:44:55".to_owned()),
			network: Some("home".to_owned()),
		})),
		Response::Ok,
		Response::Error {
			message: "not permitted".to_owned(),
		},
	]
}

fn every_event() -> Vec<Event> {
	vec![
		Event::Observed {
			summary: "eth0 gained an address".to_owned(),
		},
		Event::Reloaded {
			ok: false,
			diagnostics: Some("netcfgd.conf:3: unknown key".to_owned()),
		},
		Event::Drift {
			interface: "eth0".to_owned(),
			summary: "an address we installed is gone".to_owned(),
			action: "reconciled".to_owned(),
		},
		Event::ConfirmArmed { seconds: 90 },
		Event::ConfirmResolved { confirmed: true },
	]
}

/// Every message, in the framing the socket actually uses.
///
/// One JSON object per line, because that is the wire form -- pinning a pretty
/// rendering would leave the framing itself unpinned, and the framing is what
/// a client parses.
fn witness() -> String {
	let mut out = String::new();
	for request in every_request() {
		out.push_str(&serde_json::to_string(&request).expect("a request serialises"));
		out.push('\n');
	}
	for response in every_response() {
		out.push_str(&serde_json::to_string(&response).expect("a response serialises"));
		out.push('\n');
	}
	for event in every_event() {
		out.push_str(&serde_json::to_string(&event).expect("an event serialises"));
		out.push('\n');
	}
	out
}

/// The frozen socket contract, byte for byte.
#[test]
fn the_socket_api_matches_its_witness() {
	let rendered = witness();

	if std::env::var_os("NCFG_BLESS").is_some() {
		let path = witness_path();
		std::fs::create_dir_all(path.parent().expect("a parent")).expect("mkdir");
		std::fs::write(&path, &rendered).expect("write the witness");
		println!("blessed {}", path.display());
		return;
	}

	let expected = std::fs::read_to_string(witness_path())
		.unwrap_or_else(|error| panic!("cannot read the socket witness ({error})"));

	if rendered != expected {
		let mismatch = expected
			.lines()
			.zip(rendered.lines())
			.enumerate()
			.find(|(_, (left, right))| left != right);
		let detail = mismatch.map_or_else(
			|| {
				format!(
					"a message was added or removed ({} lines, was {})",
					rendered.lines().count(),
					expected.lines().count()
				)
			},
			|(index, (left, right))| format!("line {}:\n  was: {left}\n  now: {right}", index + 1),
		);
		panic!(
			"the socket API has changed.\n\
			 \n\
			 {detail}\n\
			 \n\
			 Nothing speaks this protocol yet, so the change is cheap. Run\n\
			 `make schema-bless` and say in the commit what moved.\n\
			 \n\
			 Worth a moment's thought all the same: this is the surface a client\n\
			 is written against, and the first one written will fix its shape\n\
			 harder than any version number would."
		);
	}
}

/// Every message has to survive the round trip a client performs.
#[test]
fn every_message_round_trips() {
	for request in every_request() {
		let text = serde_json::to_string(&request).expect("serialises");
		let parsed: Request = serde_json::from_str(&text).expect("parses");
		assert_eq!(parsed, request, "request did not round trip: {text}");
	}
	for response in every_response() {
		let text = serde_json::to_string(&response).expect("serialises");
		let parsed: Response = serde_json::from_str(&text).expect("parses");
		assert_eq!(parsed, response, "response did not round trip: {text}");
	}
	for event in every_event() {
		let text = serde_json::to_string(&event).expect("serialises");
		let parsed: Event = serde_json::from_str(&text).expect("parses");
		assert_eq!(parsed, event, "event did not round trip: {text}");
	}
}

/// Every message is one line, because the framing is one JSON object per line.
/// A message containing a newline would frame as two and desynchronise the
/// stream -- the codec refuses to write one, and this is the other half of
/// that guarantee.
#[test]
fn no_message_spans_two_lines() {
	for line in witness().lines() {
		assert!(!line.is_empty());
		assert!(
			serde_json::from_str::<serde_json::Value>(line).is_ok(),
			"each line must be a complete message: {line}"
		);
	}
}

/// `Hello` reports both versions, so a client that asks can tell.
///
/// Not an assertion about what the numbers are -- there is nothing to be
/// compatible with yet. What is worth pinning is that the handshake exists and
/// carries both, because a client written before the first real change is the
/// one that will need it.
#[test]
fn the_handshake_reports_both_versions() {
	let hello = Response::Hello {
		protocol: netcfgd_proto::PROTOCOL_VERSION,
		schema: netcfgd_model::SCHEMA_VERSION,
	};
	let text = serde_json::to_string(&hello).expect("serialises");
	assert!(text.contains("\"protocol\""), "got: {text}");
	assert!(text.contains("\"schema\""), "got: {text}");
}
