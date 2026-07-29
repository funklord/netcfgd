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

pub use codec::{read_message, write_message, Framed};

use netcfgd_apply::Journal;
use netcfgd_model::{Document, Observed, Version};
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
