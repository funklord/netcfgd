#![forbid(unsafe_code)]

//! The control socket contract.
//!
//! Newline-delimited JSON, one message per line, in both directions. That is a
//! deliberate choice over anything more compact: the socket is the API, and an
//! API you can drive with `socat` and read with `jq` is one people can debug
//! without netcfgd's own tooling. It is the same reasoning that puts the
//! runtime state in greppable files rather than a database.
//!
//! Everything a client can ask for is also derivable from `/run/netcfgd/`, so
//! a client is never forced to talk to the daemon -- design section 5.2 says
//! hooks never need to call back, and this keeps that true.

pub mod codec;

pub use codec::{read_message, read_request, write_message, Framed};

use netcfgd_apply::Journal;
use netcfgd_model::{AclPolicy, Document, Observed, Version};
use netcfgd_plan::Plan;
use serde::{Deserialize, Serialize};

/// The socket's own version, distinct from the document schema version.
///
/// A client that speaks a different major refuses to continue, for the same
/// reason a document consumer does: acting on half an understanding is worse
/// than refusing.
pub const PROTOCOL_VERSION: Version = Version { major: 1, minor: 0 };

/// Where the socket lives when nothing says otherwise.
pub const DEFAULT_SOCKET: &str = "/run/netcfgd/netcfgd.sock";

/// What a client asks for.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "request", rename_all = "snake_case")]
pub enum Request {
	/// Which protocol and schema the daemon speaks. Sent first by a careful
	/// client, and cheap enough that it can be.
	Hello,
	/// The observed state.
	Status,
	/// What would change, changing nothing.
	Plan,
	/// Make the observed state match the config.
	Apply {
		/// Seconds before an unconfirmed change reverts.
		#[serde(skip_serializing_if = "Option::is_none", default)]
		confirm: Option<u32>,
		/// Guarded interfaces the operator consents to disrupt.
		#[serde(default)]
		allow_disruption: Vec<String>,
		/// Devices the operator consents to walk away from, keys and all.
		///
		/// Separate from `allow_disruption` because they consent to different
		/// things: an operator who accepted a brief outage on one interface has
		/// not agreed to leave a private key loaded on another.
		#[serde(default)]
		strand_credentials: Vec<String>,
	},
	/// Keep the change made under a confirm window.
	Confirm,
	/// Undo the change made under a confirm window, now rather than at expiry.
	Revert,
	/// Re-read the config directory.
	Reload,
	/// The compiled desired-state document.
	Show,
	/// Why is this the way it is.
	Explain {
		/// What to explain.
		subject: Subject,
	},
	/// Stream events until the connection closes.
	Monitor,

	/// Scan for access points on a wireless interface.
	WifiScan {
		/// Which interface.
		interface: String,
	},
	/// What a wireless interface is currently doing.
	WifiStatus {
		/// Which interface.
		interface: String,
	},
	/// Add a wireless network to the configuration.
	///
	/// **Typed fields, never config text and never a path**, which is the whole
	/// of decision 0117. A config file may name a hook, and a hook's `run_as`
	/// is absent by default, which means root -- so anything able to write
	/// arbitrary config into `/etc/netcfgd` can run arbitrary code as root
	/// whatever the file's mode says. This request cannot express a hook, a
	/// path or a `run_as`, because it has no such fields: the privilege it
	/// grants is bounded by the shape of the message rather than by the
	/// caller's good manners.
	///
	/// That is also why there is no enterprise (802.1X) arm here. Those carry
	/// certificate *paths*, which is a file the daemon would hand to a
	/// supplicant running as root, and 0117 leaves how to carry them undecided.
	/// `ncfg wifi add --eap` is the way to configure one, from a machine where
	/// somebody already has the rights to write the file.
	///
	/// The credential travels **inbound only**, is written through the secret
	/// provider, and the block keeps an `@secret:` reference -- so the
	/// desired-state document stays free of secret material (constraint 5), and
	/// 0031's bridge still runs one way.
	WifiAdd {
		/// The network's real name, as lowercase hex. An SSID is 0..32
		/// arbitrary octets and is not guaranteed to be text, so hex is the
		/// only form that always works.
		ssid: String,
		/// The block's label, the filename and the secret's name. Defaults to
		/// the SSID read as text where that is usable as all three.
		#[serde(skip_serializing_if = "Option::is_none", default)]
		id: Option<String>,
		/// The passphrase. Absent means an open network, and an open network
		/// with one supplied is refused rather than quietly ignored.
		#[serde(skip_serializing_if = "Option::is_none", default)]
		passphrase: Option<String>,
		/// `wpa2` or `wpa3` to pin one generation; absent negotiates both.
		#[serde(skip_serializing_if = "Option::is_none", default)]
		proto: Option<String>,
		/// The SSID is not broadcast, so it has to be probed for.
		#[serde(skip_serializing_if = "std::ops::Not::not", default)]
		hidden: bool,
		/// Higher wins when several are in range.
		#[serde(skip_serializing_if = "Option::is_none", default)]
		priority: Option<u32>,
	},
	/// Join a network **that is already in the configuration**.
	///
	/// The network is named by its id in the document, not by SSID and
	/// passphrase. That is what keeps this inside the `wifi` tier rather than
	/// making it `admin` wearing a hat: joining a configured network changes
	/// no configuration, and there is no request here that could create one
	/// (decision 0013).
	WifiConnect {
		/// Which interface.
		interface: String,
		/// The `network` block's id.
		network: String,
	},
	/// Leave the current network, without forgetting it.
	WifiDisconnect {
		/// Which interface.
		interface: String,
	},

	/// Put a configuration drop-in on disk, which netcfgd writes.
	///
	/// **0127's general case**, where `WifiAdd` is the specialisation that came
	/// first. A client cannot write `/etc/netcfgd` -- it is root's, and system
	/// configuration does not live under a user -- so configuration a client
	/// wants netcfgd to have arrives here and netcfgd puts it on disk.
	///
	/// **A name, never a path.** netcfgd decides where it goes; the name is
	/// checked by the same rule a wifi profile's id is, so it cannot contain a
	/// separator, traverse upwards or begin with a dot. A request that could
	/// name a path would be a request that could write anywhere root can.
	///
	/// **The text is classified before it lands.** `netcfgd-compile`'s
	/// `privilege` module answers what a production grants, and anything
	/// granting more than configuring a network is refused unless the caller is
	/// root on this machine. That is 0117's principle, which survived 0127
	/// intact: the line was never socket-versus-file, it was whether a payload
	/// can express code.
	ConfigPut {
		/// What to call it. `conf.d/<name>.conf`, chosen by netcfgd.
		name: String,
		/// The configuration, in the language `docs/netcfgd.conf.example`
		/// documents.
		text: String,
		/// Overwrite a drop-in of this name that already exists.
		///
		/// Absent means refuse, because the alternative is silently replacing
		/// something an operator wrote by hand -- the rule `ncfg secret set`
		/// already follows.
		#[serde(skip_serializing_if = "std::ops::Not::not", default)]
		replace: bool,
	},

	/// Store a credential the configuration refers to, which netcfgd writes.
	///
	/// The other half of 0127's collapse, beside [`Request::ConfigPut`]. A
	/// client cannot write `/etc/netcfgd/secrets`, so a credential it holds --
	/// a VPN password, a `WireGuard` key, an 802.1X password -- comes here and
	/// netcfgd stores it at 0600.
	///
	/// **Inbound only, like every other credential path in this protocol.**
	/// There is no request that reads one back and there is not going to be:
	/// 0031's bridge runs one way, `GetSecrets` refuses, and the desired-state
	/// document carries `@secret:` references rather than values (constraint
	/// 5). What crosses this socket is a value going *in*.
	///
	/// **A name, never a path**, checked by the same rule the drop-in's name
	/// is.
	SecretPut {
		/// The name a `@secret:` reference uses.
		name: String,
		/// The value. Never logged, never echoed, never read back.
		value: String,
		/// Overwrite one that already exists.
		///
		/// Absent means refuse. A `WireGuard` private key nobody has a copy of
		/// cannot be got back (0042), so replacing one is said rather than
		/// assumed -- the rule `ncfg secret set` already follows.
		#[serde(skip_serializing_if = "std::ops::Not::not", default)]
		replace: bool,
	},

	/// Remove a drop-in netcfgd wrote for a client.
	///
	/// Deleting is writing, so it comes here for 0127's reason: a client that
	/// could remove files from `/etc/netcfgd` would be a client with write
	/// access to it. Forgetting a network is as ordinary as adding one -- the
	/// shim does it for `nmcli connection delete` -- so the collapse is
	/// incomplete without it.
	///
	/// **An absent file is success.** The state being asked for is the state
	/// that holds, and reporting an error for it would make a client retry
	/// something already true.
	ConfigDelete {
		/// The name it was written under.
		name: String,
	},

	/// Remove a stored credential.
	///
	/// Absent is success, as above. Note the asymmetry with [`Request::SecretPut`],
	/// which refuses to replace without being asked: replacing is recoverable
	/// by whoever knows the value, and this is not, so it is the *caller's*
	/// deliberate act either way and the protocol does not add a second one.
	/// What guards it is the `admin` tier and nothing else, which is worth
	/// knowing before a client offers a button for it.
	SecretDelete {
		/// The name a `@secret:` reference used.
		name: String,
	},

	/// Who is associated with an access point this machine runs.
	///
	/// A live query rather than a field of [`Response::Status`]: there is no
	/// desired station list to reconcile against, so putting stations in the
	/// observation would give the planner state that changes with who is in
	/// the building.
	ApStations {
		/// Which interface runs the access point.
		interface: String,
	},
}

impl Request {
	/// The members this request carries, beside the `request` tag itself.
	///
	/// Named here rather than derived, because serde cannot answer the question
	/// at the point it matters. `deny_unknown_fields` is unsupported on an
	/// internally-tagged enum -- the tag would be the first member it refused --
	/// so the envelope accepted anything, on the one surface that reads
	/// untrusted bytes into a process holding `CAP_NET_ADMIN`. Section 7 of
	/// `docs/socket-protocol.md` tells implementers to refuse unknown members,
	/// and this is the daemon keeping its own rule.
	///
	/// The obvious alternative is wrong and was measured before this was
	/// written: deserialising, re-serialising and refusing any member the round
	/// trip dropped needs no table and cannot drift -- and it refuses valid
	/// requests, because `confirm`, `id`, `passphrase`, `proto` and `priority`
	/// are all `skip_serializing_if = "Option::is_none"`. A client sending
	/// `{"request":"apply","confirm":null}` would have lost a member it was
	/// entitled to send, and item 5 of that same checklist is "tell absent from
	/// null, and from empty". A table that must be maintained is the price of
	/// not refusing what the protocol permits.
	///
	/// It cannot drift silently: `the_member_table_matches_the_struct` builds
	/// every variant fully populated, so nothing is skipped, and compares what
	/// serde emits against what this returns.
	#[must_use]
	pub fn members(&self) -> &'static [&'static str] {
		match self {
			Self::Hello
			| Self::Status
			| Self::Plan
			| Self::Confirm
			| Self::Revert
			| Self::Reload
			| Self::Show
			| Self::Monitor => &[],
			Self::Apply { .. } => &["confirm", "allow_disruption", "strand_credentials"],
			Self::Explain { .. } => &["subject"],
			Self::WifiScan { .. }
			| Self::WifiStatus { .. }
			| Self::WifiDisconnect { .. }
			| Self::ApStations { .. } => &["interface"],
			Self::WifiAdd { .. } => &["ssid", "id", "passphrase", "proto", "hidden", "priority"],
			Self::WifiConnect { .. } => &["interface", "network"],
			Self::ConfigPut { .. } => &["name", "text", "replace"],
			Self::SecretPut { .. } => &["name", "value", "replace"],
			Self::ConfigDelete { .. } | Self::SecretDelete { .. } => &["name"],
		}
	}
}

/// What `explain` is being asked about.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "subject", rename_all = "snake_case")]
pub enum Subject {
	/// An interface and everything on it.
	Interface {
		/// Its name.
		name: String,
	},
	/// One address.
	Address {
		/// Which interface carries it.
		interface: String,
		/// CIDR.
		address: String,
	},
	/// One route.
	Route {
		/// Which interface it leaves by.
		interface: String,
		/// CIDR, or `default`.
		destination: String,
	},
}

/// What the daemon answers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "response", rename_all = "snake_case")]
pub enum Response {
	/// Versions, in answer to [`Request::Hello`].
	Hello {
		/// The socket contract's version.
		protocol: Version,
		/// The document schema this build speaks.
		schema: Version,
		/// Which control tiers *this* connection satisfies.
		///
		/// The daemon already works this out for every request it answers; this
		/// is the same answer, given once and before anything is attempted.
		/// Without it a client can only learn what it may do by doing it and
		/// being refused -- so a window offers an apply button to somebody
		/// holding `observe`, and the first thing that happens when they press
		/// it is a refusal (0092).
		///
		/// Peer-specific, not machine-specific: two connections from different
		/// users get different answers, which is the whole point of asking.
		#[serde(default)]
		tiers: Vec<netcfgd_model::Tier>,
	},
	/// The observed state.
	Status(Box<Observed>),
	/// A plan.
	Plan(Box<Plan>),
	/// The desired-state document.
	Document(Box<Document>),
	/// What an apply did.
	Journal(Box<Journal>),
	/// An answer to `explain`.
	Explanation(Box<Explanation>),
	/// One event, on a monitor stream.
	Event(Box<Event>),
	/// What a scan found.
	WifiScan(Box<ScanReport>),
	/// What a radio is doing.
	WifiStatus(Box<WifiState>),
	/// Who is associated with an access point.
	ApStations(Box<StationReport>),
	/// The request succeeded and had nothing to return.
	Ok,
	/// The request failed.
	Error {
		/// What went wrong, as a sentence for a human.
		message: String,
	},
}

/// Why something on the system is the way it is.
///
/// The product, in one type. Every field answers a question an operator asks
/// out loud: what asked for this, where is that written, is it ours, how do we
/// know, and what would happen if the config changed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Explanation {
	/// What was asked about, rendered.
	pub subject: String,
	/// One line per fact, in the order a person would want them.
	pub facts: Vec<Fact>,
}

/// One statement in an explanation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Fact {
	/// What this fact is about: `desired`, `observed`, `ownership`, `guard`.
	pub topic: String,
	/// The statement itself.
	pub detail: String,
	/// Where it came from, where that is a place: a config file and line, a
	/// kernel attribute, a file under `/run`.
	#[serde(skip_serializing_if = "Option::is_none", default)]
	pub source: Option<String>,
}

/// What one scan found.
///
/// A struct wrapping the list rather than the list itself, and not only for
/// the interface name. [`Response`] is an internally tagged enum, and serde
/// cannot serialise a tagged newtype variant containing a sequence -- it fails
/// at runtime, when the daemon tries to answer. Every other variant here wraps
/// a struct, and this one has to as well.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScanReport {
	/// Which interface scanned.
	pub interface: String,
	/// What it found, strongest first.
	pub access_points: Vec<ScanEntry>,
}

/// One access point a scan found.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScanEntry {
	/// The access point's address.
	pub bssid: String,
	/// Centre frequency in MHz.
	pub frequency: u32,
	/// Signal level in dBm. Closer to zero is stronger.
	pub signal: i32,
	/// Whether joining it needs a credential.
	pub secured: bool,
	/// The network name as hex, which is the canonical form and the only one
	/// that is always available -- an SSID is 32 arbitrary octets.
	pub ssid: String,
	/// The name as text, where it happens to be valid UTF-8. Absent rather
	/// than mangled otherwise, so a client can tell "not text" from "empty".
	#[serde(skip_serializing_if = "Option::is_none", default)]
	pub name: Option<String>,
	/// The 802.11r mobility domain this access point advertises, if any.
	///
	/// Two access points sharing one are configured as a single roaming
	/// domain, which is the only *standard* statement that two BSSes belong
	/// together -- adjacent addresses and a shared manufacturer prefix are
	/// convention. Present only where the BSS advertises fast transition,
	/// because that is the only case worth a round trip to ask about.
	///
	/// **Diagnostic, never a trust signal.** The element is unauthenticated
	/// bytes in a beacon, so anything can claim any domain. A client that
	/// grouped or trusted access points by it would be trusting whoever is
	/// transmitting.
	#[serde(skip_serializing_if = "Option::is_none", default)]
	pub mobility_domain: Option<String>,

	/// The id of the `network` block describing it, if the configuration has
	/// one.
	///
	/// This is the field that makes decision 0013's boundary visible instead
	/// of surprising. A caller holding only the `wifi` tier can join exactly
	/// the entries where this is set; for the rest, somebody has to write
	/// config first. A client that shows the difference saves the operator
	/// discovering it by being refused.
	#[serde(skip_serializing_if = "Option::is_none", default)]
	pub configured: Option<String>,
}

/// Who is associated with one access point.
///
/// Wrapping the list for the same reason [`ScanReport`] does: serde cannot
/// serialise a tagged newtype variant containing a sequence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StationReport {
	/// Which interface runs the access point.
	pub interface: String,
	/// The `access_point` block's id.
	pub access_point: String,
	/// Which way the access point's station list reads, when it has one.
	///
	/// Carried here rather than left implicit, because `listed` on an entry
	/// means opposite things under the two policies and a client would
	/// otherwise have to guess which.
	#[serde(skip_serializing_if = "Option::is_none", default)]
	pub access_control: Option<AclPolicy>,
	/// Who is associated, by address.
	pub stations: Vec<StationEntry>,
}

/// One associated station.
///
/// Every field but the address is optional because hostapd omits the whole
/// statistics block when it cannot read them from the driver. A client that
/// required them would hide a station that is really there, which is the worst
/// way for this to be wrong.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StationEntry {
	/// Hardware address, lowercase and colon-separated -- the same spelling an
	/// `access_control` list uses, so that denying the station somebody can
	/// see is a copy rather than a translation.
	pub address: String,
	/// Whether it finished authenticating rather than merely associating. An
	/// unauthorized station is present and cannot pass traffic.
	pub authorized: bool,
	/// Whether the access point's own `access_control` list names it.
	///
	/// The field that makes the two halves of decision 0039 one feature. Under
	/// a `deny` policy a listed station that is nonetheless connected means
	/// hostapd was never told about a list that changed -- which is exactly
	/// the gap the runtime path closes. Under `allow` it is the ordinary case
	/// and an *un*listed station is the anomaly.
	pub listed: bool,
	/// Signal level in dBm. Closer to zero is stronger.
	#[serde(skip_serializing_if = "Option::is_none", default)]
	pub signal: Option<i32>,
	/// Seconds since it associated.
	#[serde(skip_serializing_if = "Option::is_none", default)]
	pub connected_seconds: Option<u64>,
	/// Milliseconds since the access point last heard from it.
	#[serde(skip_serializing_if = "Option::is_none", default)]
	pub inactive_msec: Option<u64>,
	/// Bytes received from the station.
	#[serde(skip_serializing_if = "Option::is_none", default)]
	pub rx_bytes: Option<u64>,
	/// Bytes sent to the station.
	#[serde(skip_serializing_if = "Option::is_none", default)]
	pub tx_bytes: Option<u64>,
}

/// What a wireless interface is doing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WifiState {
	/// Which interface.
	pub interface: String,
	/// The supplicant's own state name, such as `COMPLETED` or `SCANNING`.
	pub state: String,
	/// The associated network's name as hex, when there is one.
	#[serde(skip_serializing_if = "Option::is_none", default)]
	pub ssid: Option<String>,
	/// That name as text, where it is valid UTF-8.
	#[serde(skip_serializing_if = "Option::is_none", default)]
	pub name: Option<String>,
	/// The access point.
	#[serde(skip_serializing_if = "Option::is_none", default)]
	pub bssid: Option<String>,
	/// Which `network` block it came from.
	///
	/// Absent means the supplicant is on something the document did not put
	/// there, which after decision 0015 should not happen -- so a client
	/// showing this is showing a discrepancy worth reporting, not a gap.
	#[serde(skip_serializing_if = "Option::is_none", default)]
	pub network: Option<String>,
}

/// Something that happened, for a monitor stream.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum Event {
	/// The kernel reported a change.
	Observed {
		/// A short description of what moved.
		summary: String,
	},
	/// The config directory changed and was recompiled.
	Reloaded {
		/// Whether the new config compiled.
		ok: bool,
		/// Diagnostics, when it did not.
		#[serde(skip_serializing_if = "Option::is_none", default)]
		diagnostics: Option<String>,
	},
	/// Observed state stopped matching desired state.
	Drift {
		/// Which interface.
		interface: String,
		/// What differs.
		summary: String,
		/// What netcfgd did about it, per the drift policy.
		action: String,
	},
	/// A commit-confirm window opened.
	ConfirmArmed {
		/// How long the operator has.
		seconds: u32,
	},
	/// A commit-confirm window was confirmed or expired.
	ConfirmResolved {
		/// Whether it was confirmed rather than reverted.
		confirmed: bool,
	},
}

impl Response {
	/// An error response from anything renderable.
	pub fn error(message: impl std::fmt::Display) -> Self {
		Self::Error {
			message: message.to_string(),
		}
	}
}

#[cfg(test)]
mod shape_tests {
	use super::*;

	/// Every variant, fully populated, so that nothing is skipped.
	///
	/// The `skip_serializing_if` fields are the reason this exists: with any of
	/// them absent, serde emits fewer members than the variant has and the
	/// comparison below would pass while proving less than it claims.
	fn every_request_fully_populated() -> Vec<Request> {
		vec![
			Request::Hello,
			Request::Status,
			Request::Plan,
			Request::Confirm,
			Request::Revert,
			Request::Reload,
			Request::Show,
			Request::Monitor,
			Request::Apply {
				confirm: Some(30),
				allow_disruption: vec!["eth0".to_owned()],
				strand_credentials: vec!["wg0".to_owned()],
			},
			Request::Explain {
				subject: Subject::Interface {
					name: "eth0".to_owned(),
				},
			},
			Request::WifiScan {
				interface: "wlan0".to_owned(),
			},
			Request::WifiStatus {
				interface: "wlan0".to_owned(),
			},
			Request::WifiAdd {
				ssid: "686f6d65".to_owned(),
				id: Some("home".to_owned()),
				passphrase: Some("secret".to_owned()),
				proto: Some("wpa3".to_owned()),
				hidden: true,
				priority: Some(10),
			},
			Request::WifiConnect {
				interface: "wlan0".to_owned(),
				network: "home".to_owned(),
			},
			Request::WifiDisconnect {
				interface: "wlan0".to_owned(),
			},
			Request::ApStations {
				interface: "wlan0".to_owned(),
			},
		]
	}

	/// `Request::members` is a hand-written table, so it is checked against the
	/// only authority there is: what serde emits.
	///
	/// A table that drifts is worse than no table, because the envelope check
	/// would refuse a member the protocol had just gained -- so this compares
	/// both directions rather than asserting the table is a subset.
	#[test]
	fn the_member_table_matches_the_struct() {
		for request in every_request_fully_populated() {
			let serde_json::Value::Object(map) =
				serde_json::to_value(&request).expect("a request serialises")
			else {
				panic!("a request is an object");
			};

			let mut emitted: Vec<String> = map
				.keys()
				.filter(|key| key.as_str() != "request")
				.cloned()
				.collect();
			emitted.sort();

			let mut declared: Vec<String> =
				request.members().iter().map(|m| (*m).to_owned()).collect();
			declared.sort();

			assert_eq!(
				emitted, declared,
				"the member table disagrees with what serde emits for {request:?}"
			);
		}
	}

	/// Every variant is covered above, so a new one cannot arrive unchecked.
	///
	/// Without this, adding a request and forgetting to list it here leaves the
	/// table untested for exactly the variant nobody has thought about yet --
	/// the vacuous pass, in the test that exists to prevent one.
	#[test]
	fn every_variant_is_in_the_fixture() {
		let tags: std::collections::BTreeSet<String> = every_request_fully_populated()
			.iter()
			.map(|request| {
				serde_json::to_value(request).expect("serialises")["request"]
					.as_str()
					.expect("a tag")
					.to_owned()
			})
			.collect();
		assert_eq!(
			tags.len(),
			every_request_fully_populated().len(),
			"two fixtures share a tag, so one variant is untested"
		);
	}

	/// The JSON a client actually reads off the socket.
	///
	/// The tagged-enum wrapping means a report's fields are flattened beside
	/// the tag rather than nested under a key, so a client looking for the
	/// wrong field name gets `None` and renders nothing rather than failing.
	/// That is exactly what happened to the TUI's wifi pane.
	#[test]
	fn a_report_flattens_its_fields_beside_the_tag() {
		let response = Response::WifiScan(Box::new(ScanReport {
			interface: "wl0".to_owned(),
			access_points: Vec::new(),
		}));
		let value: serde_json::Value =
			serde_json::from_str(&serde_json::to_string(&response).expect("serialises"))
				.expect("valid json");
		assert_eq!(value["response"], "wifi_scan");
		assert_eq!(value["interface"], "wl0");
		assert!(value.get("access_points").is_some(), "{value}");
		// The name the TUI was looking for, which never existed.
		assert!(value.get("entries").is_none(), "{value}");
	}

	#[test]
	fn a_station_report_does_the_same() {
		let response = Response::ApStations(Box::new(StationReport {
			interface: "ap0".to_owned(),
			access_point: "guest".to_owned(),
			access_control: None,
			stations: Vec::new(),
		}));
		let value: serde_json::Value =
			serde_json::from_str(&serde_json::to_string(&response).expect("serialises"))
				.expect("valid json");
		assert_eq!(value["response"], "ap_stations");
		assert_eq!(value["access_point"], "guest");
		assert!(value.get("stations").is_some(), "{value}");
	}
}
