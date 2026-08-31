//! The socket API freeze, as a test.
//!
//! M4 freezes the socket contract alongside the document schema. Nothing
//! speaks it yet, so a change breaks nothing today -- the witness is here to
//! make a change visible, and because the socket is the surface most likely to
//! be reshaped by whatever is written against it next.
//!
//! Same mechanism as `netcfgd-model`'s witness: every request, response and
//! event serialised into `doc/schema/socket.json`, and any change to the wire
//! form moves those bytes.
//!
//! Only the envelope is pinned here, for the payloads that are pinned
//! elsewhere. A `Status` response carries an `Observed` and a `Plan`, and
//! repeating them would mean two witnesses to update for one change, with the
//! second eventually being the one nobody did -- so those variants appear with
//! an empty payload, which pins the tag and the framing and leaves the contents
//! to `doc/schema/observed.json`, `plan.json` and `document.json`. A payload
//! *nothing else* pins carries a real sample: a journal record and a station
//! report are only ever described here.
//!
//! An empty payload is not a payload-free one -- an `Observed::default()` still
//! spells every field name, so adding a field to `Observed` moves this witness
//! as well as its own. That is the price of pinning the tag at all, there being
//! no way to serialise a `Status` response without an `Observed` inside it, and
//! `make schema-bless` moves all four together. Leaving the variant out instead
//! would leave the tag and the framing pinned by nothing, which is the failure
//! this file has now had twice.
//!
//! That sentence used to end "those are pinned by their own crates", which was
//! not true of either of them. `netcfgd-model` pinned a `Document` and nothing
//! pinned an `Observed`, so a field could be added to the thing this socket
//! actually sends and no gate anywhere moved -- which is how
//! `ObservedReport::routes` arrived. Both are pinned now, at
//! `doc/schema/observed.json` and `doc/schema/plan.json`, and the sentence is
//! true because those files exist rather than because it says so.
//!
//! **And the same disease had a second host, in this file.** The header above
//! said "every request, response and event", and the lists below were plain
//! `vec![]`s that nobody had to add to: `Request::ApStations`,
//! `Response::ApStations` and `Response::Journal` were never in them, so
//! `StationReport`, `StationEntry` and the journal's `Record` -- three types the
//! socket sends and no other witness mentions -- were pinned by nothing at all.
//! The three lists now go through the exhaustive match the model's witness
//! arrived at, which stops this file compiling when a variant appears. A sample
//! is a sample; only the compiler can count variants.

use netcfgd_apply::{Journal, Outcome, Record};
use netcfgd_plan::Reason;
use netcfgd_proto::{
	Event, Explanation, Fact, Request, Response, ScanEntry, ScanReport, StationEntry,
	StationReport, Subject, WifiState,
};
use std::path::PathBuf;

fn witness_path() -> PathBuf {
	PathBuf::from(env!("CARGO_MANIFEST_DIR"))
		.join("../..")
		.join("doc/schema/socket.json")
}

/// Every request, so none can be added or renamed unnoticed.
///
/// Two checks, and they catch different things. The match is a *compile* error
/// when a variant appears, which is the half that catches an addition -- never a
/// `_` arm, because the wildcard is what would take that half away. The
/// assertion catches a sample that went away or a name that moved, and does not
/// catch an arm written with no sample beside it: neither list would mention the
/// new name and the two would agree. `crates/netcfgd-plan/tests/frozen.rs` is
/// exact about the same division.
fn every_request() -> Vec<Request> {
	let all = every_request_sample();
	let name = |request: &Request| match request {
		Request::Hello => "hello",
		Request::Status => "status",
		Request::Plan => "plan",
		Request::Apply { .. } => "apply",
		Request::Confirm => "confirm",
		Request::Revert => "revert",
		Request::Reload => "reload",
		Request::Show => "show",
		Request::Explain { .. } => "explain",
		Request::Monitor => "monitor",
		Request::WifiScan { .. } => "wifi_scan",
		Request::WifiStatus { .. } => "wifi_status",
		Request::WifiAdd { .. } => "wifi_add",
		Request::WifiConnect { .. } => "wifi_connect",
		Request::WifiDisconnect { .. } => "wifi_disconnect",
		Request::ApStations { .. } => "ap_stations",
		Request::ConfigPut { .. } => "config_put",
		Request::ProbePut { .. } => "probe_put",
		Request::SecretPut { .. } => "secret_put",
		Request::ConfigDelete { .. } => "config_delete",
		Request::SecretDelete { .. } => "secret_delete",
		Request::Radios => "radios",
		Request::ProbeList => "probe_list",
		Request::ProfileList => "profile_list",
		Request::ProfileSet { .. } => "profile_set",
		Request::RadioSet { .. } => "radio_set",
	};
	let mut present: Vec<&str> = all.iter().map(name).collect();
	present.sort_unstable();
	present.dedup();
	assert_eq!(
		present,
		[
			"ap_stations",
			"apply",
			"config_delete",
			"config_put",
			"confirm",
			"explain",
			"hello",
			"monitor",
			"plan",
			"probe_list",
			"probe_put",
			"profile_list",
			"profile_set",
			"radio_set",
			"radios",
			"reload",
			"revert",
			"secret_delete",
			"secret_put",
			"show",
			"status",
			"wifi_add",
			"wifi_connect",
			"wifi_disconnect",
			"wifi_scan",
			"wifi_status",
		],
		"the witness is missing a sample for a request, so the frozen surface \
		 would not move when that request changed"
	);
	all
}

/// The link-detection requests.
///
/// A helper for `enterprise_samples`' reason: `every_request_sample` has a line
/// limit, and these are a group rather than an arbitrary cut. The scripts are
/// the shortest thing that is still a probe -- a witness is committed, read and
/// diffed, and one carrying a real address would be copied by somebody, which
/// is the whole reason netcfgd ships no default target.
fn probe_samples() -> Vec<Request> {
	vec![
		Request::ProbeList,
		Request::ProfileList,
		// Two, because `name` is skip_serializing_if and one that sets it
		// pins only the present form. The absent one is "no profile chosen",
		// which is a real state rather than a missing argument.
		Request::ProfileSet {
			name: Some("office".to_owned()),
		},
		Request::ProfileSet { name: None },
		// Two, because `replace` is skip_serializing_if and one that sets it
		// pins only the present form.
		Request::ProbePut {
			name: "office".to_owned(),
			text: "#!/bin/sh\nexit 0\n".to_owned(),
			replace: true,
		},
		Request::ProbePut {
			name: "home".to_owned(),
			text: "#!/bin/sh\nexit 1\n".to_owned(),
			replace: false,
		},
	]
}

/// The requests that write, and the two that take something away.
///
/// Grouped out of `every_request_sample` because that function has a line
/// limit, and these belong together: every one of them changes the machine.
fn writer_samples() -> Vec<Request> {
	vec![
		// Two samples, for `wifi_add`'s reason: `replace` is
		// skip_serializing_if, so one that sets it pins only the present form.
		// The absent one is what a client sends when it means "do not
		// overwrite anything", which is the shape that must stay the default.
		Request::ConfigPut {
			name: "from-a-client".to_owned(),
			text: "interface eth0 {\n\tconfig = \"dhcp\"\n}\n".to_owned(),
			replace: true,
		},
		Request::ConfigPut {
			name: "cafe".to_owned(),
			text: "network \"Cafe\" {\n\twifi { open = true }\n}\n".to_owned(),
			replace: false,
		},
		// Two, for the reason the others have two: `replace` is
		// skip_serializing_if. The value is a placeholder and looks like one
		// on purpose -- a witness is committed, read and diffed, and a sample
		// that looked like a credential would be copied by somebody.
		Request::SecretPut {
			name: "vpn".to_owned(),
			value: "NOT-A-REAL-SECRET".to_owned(),
			replace: true,
		},
		Request::SecretPut {
			name: "cafe".to_owned(),
			value: "NOT-A-REAL-SECRET".to_owned(),
			replace: false,
		},
		// One each: neither has an optional member, so one sample pins the
		// whole shape.
		Request::ConfigDelete {
			name: "nm-cafe".to_owned(),
		},
		Request::SecretDelete {
			name: "cafe".to_owned(),
		},
	]
}

fn every_request_sample() -> Vec<Request> {
	let mut samples = enterprise_samples();
	samples.extend(probe_samples());
	samples.extend(writer_samples());
	samples.extend(vec![
		Request::Hello,
		Request::Status,
		Request::Plan,
		Request::Radios,
		Request::RadioSet {
			interface: "wlan0".to_owned(),
			activate: true,
		},
		Request::Apply {
			confirm: Some(90),
			allow_disruption: vec!["eth0".to_owned()],
			strand_credentials: vec!["wg0".to_owned()],
			restart_wedged: Vec::new(),
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
		// Two samples, because `id`, `passphrase`, `proto`, `hidden` and
		// `priority` are all skip_serializing_if and one that fills them pins
		// only the present form. The second is an open network: every optional
		// absent, which is `wifi_add` at its smallest and the shape a client
		// is most likely to send.
		Request::WifiAdd {
			ssid: "686f6d65".to_owned(),
			id: Some("home".to_owned()),
			passphrase: Some("hunter2".to_owned()),
			proto: Some("wpa3".to_owned()),
			hidden: true,
			priority: Some(10),
			eap: None,
		},
		Request::WifiAdd {
			ssid: "63616665".to_owned(),
			id: None,
			passphrase: None,
			proto: None,
			hidden: false,
			priority: None,
			eap: None,
		},
		Request::WifiDisconnect {
			interface: "wlan0".to_owned(),
		},
		Request::ApStations {
			interface: "wlan0".to_owned(),
		},
	]);
	samples
}

/// The 802.1X requests, in their own function.
///
/// Split out because the list above went over its line budget, and these are
/// the group that reads as one subject.
fn enterprise_samples() -> Vec<Request> {
	vec![
		// The arm that exists because a certificate stopped being a path.
		// Every certificate here is the *name* of a stored secret and there is
		// no field a path fits in, so this sample is also the shape of what
		// cannot be sent.
		Request::WifiAdd {
			ssid: "656475726f616d".to_owned(),
			id: Some("eduroam".to_owned()),
			passphrase: Some("NOT-A-REAL-SECRET".to_owned()),
			proto: None,
			hidden: false,
			priority: None,
			eap: Some(Box::new(netcfgd_proto::EapRequest {
				method: "peap".to_owned(),
				identity: "you@corp.example".to_owned(),
				anonymous_identity: Some("anonymous@corp.example".to_owned()),
				phase2: Some("mschapv2".to_owned()),
				ca_cert: Some("corp-ca".to_owned()),
				client_cert: None,
			})),
		},
	]
}

/// Every response, on the same terms.
fn every_response() -> Vec<Response> {
	let all = every_response_sample();
	// One of each kind, because the pair is the point: a shipped example is not
	// editable in place, and the operator's copy of the same name is what
	// shadows it. A witness carrying only one would not pin that. Out of the
	// list above because that function has a line limit.
	let all: Vec<Response> = all
		.into_iter()
		.chain([Response::Profiles {
			// Two, one from each layer, because a witness carrying only the
			// operator's would not pin how a shipped one reports.
			profiles: vec![
				netcfgd_proto::ProfileEntry {
					name: "offline".to_owned(),
					shipped: true,
				},
				netcfgd_proto::ProfileEntry {
					name: "office".to_owned(),
					shipped: false,
				},
			],
			chosen: Some("office".to_owned()),
		}])
		.chain([Response::Probes {
			probes: vec![
				netcfgd_proto::ProbeScript {
					name: "default".to_owned(),
					directory: "/usr/share/netcfgd/probe".to_owned(),
					text: "#!/bin/sh\nexit 0\n".to_owned(),
					editable: false,
				},
				netcfgd_proto::ProbeScript {
					name: "office".to_owned(),
					directory: "/etc/netcfgd/probe".to_owned(),
					text: "#!/bin/sh\nexit 1\n".to_owned(),
					editable: true,
				},
			],
		}])
		.collect();

	let name = |response: &Response| match response {
		Response::Hello { .. } => "hello",
		Response::Status(_) => "status",
		Response::Plan(_) => "plan",
		Response::Document(_) => "document",
		Response::Journal(_) => "journal",
		Response::Explanation(_) => "explanation",
		Response::Event(_) => "event",
		Response::WifiScan(_) => "wifi_scan",
		Response::WifiStatus(_) => "wifi_status",
		Response::ApStations(_) => "ap_stations",
		Response::Radios { .. } => "radios",
		Response::Probes { .. } => "probes",
		Response::Profiles { .. } => "profiles",
		Response::Ok => "ok",
		Response::Error { .. } => "error",
	};
	let mut present: Vec<&str> = all.iter().map(name).collect();
	present.sort_unstable();
	present.dedup();
	assert_eq!(
		present,
		[
			"ap_stations",
			"document",
			"error",
			"event",
			"explanation",
			"hello",
			"journal",
			"ok",
			"plan",
			"probes",
			"profiles",
			"radios",
			"status",
			"wifi_scan",
			"wifi_status",
		],
		"the witness is missing a sample for a response, so the frozen surface \
		 would not move when that response changed"
	);
	all
}

/// The scan response, lifted out of [`every_response_sample`] so that list
/// stays inside its line budget.
///
/// It is the longest sample by a distance, and for a reason worth keeping: the
/// fields that matter here are the ones where two entries differ, so a
/// single-entry sample would pin none of them.
fn wifi_scan_sample() -> Response {
	Response::WifiScan(Box::new(ScanReport {
		interface: "wlan0".to_owned(),
		access_points: vec![
			ScanEntry {
				bssid: "00:11:22:33:44:55".to_owned(),
				frequency: 2412,
				signal: -40,
				secured: true,
				enterprise: false,
				ssid: "686f6d65".to_owned(),
				name: Some("home".to_owned()),
				configured: Some("home".to_owned()),
				// One sample carries a mobility domain and the others do
				// not, which pins both forms: the field is
				// skip_serializing_if, so a witness where every entry had
				// one would never show its absence.
				mobility_domain: Some("a1b2".to_owned()),
			},
			// Hidden: the SSID is not broadcast, so it arrives empty
			// and the name arrives *present and empty*. Not the same
			// answer as absent, and a client that renders them alike
			// merges two networks.
			ScanEntry {
				bssid: "00:11:22:33:44:66".to_owned(),
				frequency: 5180,
				signal: -58,
				secured: false,
				enterprise: false,
				ssid: String::new(),
				name: Some(String::new()),
				configured: None,
				mobility_domain: None,
			},
			// An SSID that is not UTF-8: no `name` at all, and the hex
			// is the only name it has.
			ScanEntry {
				bssid: "00:11:22:33:44:77".to_owned(),
				frequency: 2437,
				signal: -71,
				secured: true,
				// The one enterprise entry, so the witness pins all
				// three combinations: passphrase, open, and 802.1X.
				enterprise: true,
				ssid: "ff00ff".to_owned(),
				name: None,
				configured: None,
				mobility_domain: None,
			},
		],
	}))
}

fn every_response_sample() -> Vec<Response> {
	vec![
		Response::Hello {
			protocol: netcfgd_proto::PROTOCOL_VERSION,
			schema: netcfgd_model::SCHEMA_VERSION,
			// Two rather than all three, and not in the order the enum
			// declares them: the tiers are three separate group memberships
			// and not a ladder, so a sample holding a prefix of them would
			// pin a shape that happens to look like one.
			tiers: vec![netcfgd_model::Tier::Observe, netcfgd_model::Tier::Admin],
		},
		Response::Explanation(Box::new(Explanation {
			subject: "eth0".to_owned(),
			facts: vec![Fact {
				topic: "desired".to_owned(),
				detail: "static 192.0.2.1/24".to_owned(),
				source: Some("netcfgd.conf:3".to_owned()),
			}],
		})),
		// Three entries and not one, because `name` and `configured` are
		// `skip_serializing_if` and a sample that fills both pins only the
		// present form. The absent form is a *different* set of bytes, it is
		// what the daemon sends for an unprintable SSID and for a network
		// nobody has written config for, and until these arrived it was
		// pinned by nothing -- which a second client implementation then
		// disagreed about without any gate noticing.
		wifi_scan_sample(),
		// Both states, because the pair is the point: a radio netcfgd holds
		// and one another manager does, which a client renders differently.
		Response::Radios {
			radios: vec![
				netcfgd_proto::Radio {
					interface: "wlan0".to_owned(),
					activated: true,
					supplicant: true,
				},
				netcfgd_proto::Radio {
					interface: "wlan1".to_owned(),
					activated: false,
					supplicant: true,
				},
			],
		},
		Response::WifiStatus(Box::new(WifiState {
			interface: "wlan0".to_owned(),
			state: "COMPLETED".to_owned(),
			ssid: Some("686f6d65".to_owned()),
			name: Some("home".to_owned()),
			bssid: Some("00:11:22:33:44:55".to_owned()),
			network: Some("home".to_owned()),
		})),
		// A radio that is associated with nothing, which is every one of
		// this response's optional fields in its absent form. Four
		// `skip_serializing_if` members that the sample above spells and
		// this one does not.
		Response::WifiStatus(Box::new(WifiState {
			interface: "wlan0".to_owned(),
			state: "SCANNING".to_owned(),
			ssid: None,
			name: None,
			bssid: None,
			network: None,
		})),
		// Empty payloads, deliberately: the tag and the framing are this
		// witness's business and the contents belong to `observed.json`,
		// `plan.json` and `document.json`. An empty one still moves these bytes
		// if the envelope is renamed or the box goes away.
		Response::Status(Box::<netcfgd_model::Observed>::default()),
		Response::Plan(Box::<netcfgd_plan::Plan>::default()),
		Response::Document(Box::<netcfgd_model::Document>::default()),
		// And a full one here, because nothing else in the repository pins a
		// journal record or a station: this is the only description of either.
		Response::Journal(Box::new(Journal {
			records: vec![Record {
				id: 1,
				op: "addr.add".to_owned(),
				interface: Some("eth0".to_owned()),
				reason: Reason::differs("eth0", "addressing[0]", "192.0.2.1/24", "<absent>"),
				outcome: Outcome::Done,
				error: None,
			}],
		})),
		Response::Event(Box::new(Event::ConfirmArmed { seconds: 90 })),
		Response::ApStations(Box::new(StationReport {
			interface: "wlan0".to_owned(),
			access_point: "home".to_owned(),
			access_control: Some(netcfgd_model::AclPolicy::Deny),
			stations: vec![StationEntry {
				address: "00:11:22:33:44:55".to_owned(),
				authorized: true,
				listed: true,
				signal: Some(-52),
				connected_seconds: Some(184),
				inactive_msec: Some(120),
				rx_bytes: Some(4096),
				tx_bytes: Some(8192),
			}],
		})),
		Response::Ok,
		Response::Error {
			message: "not permitted".to_owned(),
		},
	]
}

/// Every event, on the same terms.
fn every_event() -> Vec<Event> {
	let all = every_event_sample();
	let name = |event: &Event| match event {
		Event::Observed { .. } => "observed",
		Event::Reloaded { .. } => "reloaded",
		Event::Drift { .. } => "drift",
		Event::ConfirmArmed { .. } => "confirm_armed",
		Event::ConfirmResolved { .. } => "confirm_resolved",
	};
	let mut present: Vec<&str> = all.iter().map(name).collect();
	present.sort_unstable();
	present.dedup();
	assert_eq!(
		present,
		[
			"confirm_armed",
			"confirm_resolved",
			"drift",
			"observed",
			"reloaded",
		],
		"the witness is missing a sample for an event, so the frozen surface \
		 would not move when that event changed"
	);
	all
}

fn every_event_sample() -> Vec<Event> {
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

/// The exact bytes the C client emits are bytes this decoder accepts.
///
/// **The one seam neither side's tests cover.** `client/tests/client_test.c`
/// asserts the JSON its encoder produces, character for character, against a
/// staged server that answers `ok` to anything -- so it proves what the C
/// client *writes* and nothing about whether netcfgd can read it. This side's
/// witness proves what Rust emits and accepts. Between them sits the question
/// that actually matters, and until a real daemon is on the other end of a
/// real C client, nothing asks it.
///
/// So these are copied from the C test's expectations verbatim. A member
/// renamed on either side breaks one of the two, and a member renamed on both
/// breaks this -- which is the case the two independent suites would otherwise
/// agree about while netcfgd refused every request.
#[test]
fn the_c_client_writes_requests_this_decoder_accepts() {
	for line in [
		r#"{"request":"wifi_add","ssid":"686f6d65","id":"home","passphrase":"hunter2","proto":"wpa3","hidden":true,"priority":10}"#,
		r#"{"request":"wifi_add","ssid":"63616665"}"#,
		r#"{"request":"wifi_add","ssid":"656475726f616d","id":"eduroam","passphrase":"hunter2","eap":{"method":"peap","identity":"you@corp.example","phase2":"mschapv2","ca_cert":"corp-ca"}}"#,
		r#"{"request":"secret_put","name":"corp-ca","value":"hunter2"}"#,
		r#"{"request":"secret_put","name":"corp-ca","value":"hunter2","replace":true}"#,
	] {
		let parsed: Result<Request, _> = serde_json::from_str(line);
		assert!(
			parsed.is_ok(),
			"netcfgd would refuse what the C client sends: {line}\n{:?}",
			parsed.err()
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
		tiers: vec![netcfgd_model::Tier::Observe],
	};
	let text = serde_json::to_string(&hello).expect("serialises");
	assert!(text.contains("\"protocol\""), "got: {text}");
	// And what this connection may do, which is the third thing a client needs
	// before it draws anything (0092).
	assert!(text.contains("\"tiers\""), "got: {text}");
	assert!(text.contains("\"schema\""), "got: {text}");
}
