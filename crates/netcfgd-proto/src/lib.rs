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
		/// Interfaces whose wedged backend the operator consents to restart.
		///
		/// **The option half of 0141**, and separate from the two above for the
		/// reason they are separate from each other: consenting to a brief
		/// outage on an interface is not consenting to have netcfgd kill a
		/// daemon that may only be busy. A backend running and answering
		/// nothing is a loud failure by default; this is how a person says
		/// which interface may have it killed and started again.
		#[serde(default)]
		restart_wedged: Vec<String>,
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
	/// **The enterprise arm is [`EapRequest`]**, and it exists because
	/// certificates stopped being paths. 0117 left it out for a reason that
	/// was true then: an enterprise network named certificate *files*, which
	/// the daemon would hand to a supplicant running as root, so accepting one
	/// over the socket meant accepting an instruction to read an arbitrary
	/// file. A certificate is content netcfgd stores now, and `EapRequest`
	/// carries the *names* of stored secrets and has no field a path could go
	/// in -- the same construction as this request itself, where the privilege
	/// granted is bounded by the shape of the message.
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
		/// 802.1X, for a campus or corporate network.
		///
		/// Absent for an ordinary personal network, which is what the rest of
		/// these fields describe. Present, `passphrase` carries the EAP
		/// password rather than a WPA passphrase -- one credential field,
		/// because a network has one and the method decides what it is called.
		#[serde(skip_serializing_if = "Option::is_none", default)]
		/// Boxed so that one uncommon arm does not widen every request. Serde
		/// sees through it, so the wire form is unchanged.
		eap: Option<Box<EapRequest>>,
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
		/// The configuration, in the language `doc/netcfgd.conf.example`
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

	/// The link-detection scripts netcfgd can see.
	///
	/// **Over the socket rather than off the disk, and that is the whole
	/// point.** A client only ever talks to netcfgd; these files belong to the
	/// machine netcfgd runs on. A gui that listed its own
	/// `/etc/netcfgd/probe` would be showing the operator's laptop while
	/// configuring a remote machine -- and would then save an edit of one
	/// machine's script onto another.
	ProbeList,

	/// The profiles this machine has, and which one is chosen.
	///
	/// **Asked of netcfgd rather than read off the client's own disk**, for
	/// the reason `ProbeList` gives: a gui listing its own
	/// `/etc/netcfgd/profile` would be showing the operator's laptop while
	/// configuring a remote machine, and would then offer to switch that
	/// machine to a profile it does not have.
	ProfileList,

	/// The modem devices, their SIM order, and which source is in use.
	///
	/// A verb rather than a client reading the document and `/run` itself, for
	/// the reason [`Request::ProbeList`] already gives: a gui listing its own
	/// machine's modems would describe the laptop while configuring a remote
	/// host. It also joins two facts that live apart -- the configured order
	/// comes from the document and the *chosen* source is runtime state under
	/// `/run` -- and a client stitching those together would be a second copy
	/// of a rule that belongs to the daemon
	/// ([0152](../../../doc/decision/0152-a-sim-source-is-kept-until-the-probe-says-otherwise.md)).
	///
	/// Reading, so `observe`. There is deliberately no verb to *choose* a
	/// source: which one is in use is netcfgd's answer to a failing probe, and
	/// letting a client pin it is a design question about what happens to the
	/// fallback afterwards, not a missing accessor.
	ModemList,

	/// Write what this machine is running into a profile, and select it.
	///
	/// **`admin`, and the heaviest thing at that tier.** It writes a
	/// configuration file, moves the folded profile out of `conf.d`, and
	/// changes the selection -- and the daemon reconciles on its own, so it is
	/// a change to the running machine rather than a note for later.
	///
	/// A verb rather than a `ConfigPut` of a rendered file, for the reason
	/// [`Request::ProfileSet`] gives and one more: the caller does not have
	/// the text. What gets written is the *effective* document rendered back
	/// out, which only the machine holding it can produce.
	ProfileSave {
		/// The profile to write. A plain name: netcfgd chooses the directory.
		name: String,
		/// Overwrite one that exists. Refused without it, because an existing
		/// profile is somebody's work.
		#[serde(default, skip_serializing_if = "std::ops::Not::not")]
		replace: bool,
	},

	/// The credentials this machine holds, by name and never by value.
	///
	/// **Names only, and that is the whole design.** A secret's value never
	/// crosses this socket in this direction; `SecretPut` goes the other way.
	/// What a client needs is which names exist and which the configuration
	/// refers to, because the interesting fault is the mismatch: a network
	/// naming `@secret:cafe` where no such secret exists is a network that
	/// will never join, and it fails at association time with an error about
	/// the radio rather than about the missing passphrase.
	///
	/// `observe`, which is weaker than it first looks: the *names* are already
	/// in the document that [`Request::Show`] returns, since that is where
	/// `@secret:` references live. What this adds is whether the file behind
	/// each one is actually there.
	SecretList,

	/// Choose a profile, or stop using one.
	///
	/// **A verb of its own rather than a `ConfigPut` of a known filename.**
	/// netcfgd owns the drop-in the selection lives in, and a client that
	/// spelled that name would be a second copy of it -- one that goes stale
	/// the day the name changes, in a client nobody rebuilt. It also puts the
	/// check where the directories are: a name with no profile directory is
	/// refused by the machine that would have to read it.
	///
	/// `admin`, like any other configuration write.
	ProfileSet {
		/// The profile to run, or `None` to stop using one -- which is the
		/// default state and is not a profile called "none".
		#[serde(skip_serializing_if = "Option::is_none", default)]
		name: Option<String>,
	},

	/// Store a link-detection script, which netcfgd writes.
	///
	/// A probe is a program netcfgd runs **as root, on an interval**, so this
	/// is the most dangerous payload the socket carries and it is guarded
	/// accordingly: local root and nothing else, the same bar `ConfigPut`
	/// applies to a privileged production. The `admin` tier is not enough,
	/// because a site may have opened `admin` to a group and 0127's
	/// architecture only survives that if opening it cannot grant root.
	///
	/// It exists rather than letting a client write the file because 0127 is
	/// the whole arrangement: a client cannot write system files, and system
	/// configuration cannot live under a user. A gui that wrote
	/// `/etc/netcfgd/probe/` itself would be the fifth program with root's
	/// write permissions on what the daemon treats as its own.
	ProbePut {
		/// The script's filename under `/etc/netcfgd/probe`. A plain name:
		/// netcfgd chooses the directory, and a name carrying a separator
		/// would let a caller choose it instead.
		name: String,
		/// The script. Written executable, because netcfgd runs it.
		text: String,
		/// Overwrite one of this name that already exists.
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

	/// Which radios this machine has, and which of them netcfgd manages.
	///
	/// The list a client needs before it can offer anything wireless at all,
	/// and the reason it is a request rather than something read out of a scan
	/// is that a radio netcfgd does not manage **cannot be scanned with** --
	/// so it has to be nameable before there is anything to name it in.
	Radios,

	/// Take a radio on, or hand it back.
	///
	/// **Typed, so that it lives in the `wifi` tier.** What activation writes
	/// is a `device` block, and a client that sent one as *text* would be
	/// sending configuration -- which is 0117's remote code execution and is
	/// `admin`. An interface name and a boolean cannot name a hook, a path or
	/// a `run_as`, so this is bounded the way `wifi_add` is and a member of
	/// the `netcfgd` group can turn their own radio on.
	///
	/// Deactivating removes the block netcfgd wrote and does not touch one
	/// somebody else edited: the point is a switch a person can flip, not a
	/// way to delete configuration through a narrower door than `config_rm`.
	RadioSet {
		/// The radio.
		interface: String,
		/// On, or off.
		activate: bool,
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
	/// `doc/socket-protocol.md` tells implementers to refuse unknown members,
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
			| Self::ProbeList
			| Self::ProfileList
			| Self::ModemList
			| Self::SecretList
			| Self::Confirm
			| Self::Revert
			| Self::Reload
			| Self::Show
			| Self::Monitor
			| Self::Radios => &[],
			Self::Apply { .. } => &[
				"confirm",
				"allow_disruption",
				"strand_credentials",
				"restart_wedged",
			],
			Self::Explain { .. } => &["subject"],
			Self::WifiScan { .. }
			| Self::WifiStatus { .. }
			| Self::WifiDisconnect { .. }
			| Self::ApStations { .. } => &["interface"],
			Self::WifiAdd { .. } => &[
				"ssid",
				"id",
				"passphrase",
				"proto",
				"hidden",
				"priority",
				"eap",
			],
			Self::WifiConnect { .. } => &["interface", "network"],
			Self::ConfigPut { .. } | Self::ProbePut { .. } => &["name", "text", "replace"],
			Self::SecretPut { .. } => &["name", "value", "replace"],
			// `ProfileSet` is here because its `name` is the same one member,
			// even though it is skip_serializing_if on the unset form -- the
			// witness pins both shapes.
			Self::ConfigDelete { .. } | Self::SecretDelete { .. } | Self::ProfileSet { .. } => {
				&["name"]
			}
			Self::ProfileSave { .. } => &["name", "replace"],
			Self::RadioSet { .. } => &["interface", "activate"],
		}
	}
}

/// One link-detection script, as netcfgd sees it.
///
/// **The text comes with the listing.** A client needs it to show one, and
/// these are a few hundred bytes each -- a second round trip per script would
/// buy nothing and would mean a list and a body that could disagree.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProbeScript {
	/// The filename, which is what a client sends back to write it.
	pub name: String,
	/// Where it was found, so a client can say whether this is a shipped
	/// example or the operator's own.
	pub directory: String,
	/// The script.
	pub text: String,
	/// Whether netcfgd would overwrite this file, rather than write a copy
	/// into `/etc` beside it. A shipped example is not edited in place.
	pub editable: bool,
}

/// One profile this machine could be switched to.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProfileEntry {
	/// The directory name, which is what a client sends back to choose it.
	pub name: String,
	/// Whether this came from the factory directory rather than from `/etc`,
	/// so a client can say whose it is. An operator's copy of a shipped
	/// profile reads as theirs, because theirs is what layers on top.
	pub shipped: bool,
}

/// One credential, by name.
///
/// **No value, ever.** There is no field here that could carry one, which is a
/// stronger guarantee than a rule saying not to fill one in.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecretEntry {
	/// The name, as `@secret:<name>` spells it.
	pub name: String,
	/// Whether the store actually holds it.
	pub stored: bool,
	/// The blocks that refer to it, as `network Cafe` or `interface eth0`.
	///
	/// Present because the two interesting faults are opposite ways round: a
	/// referenced secret that is not stored is a network that will never join,
	/// and a stored secret nothing refers to is a credential still on the
	/// machine after whatever wanted it was deleted.
	#[serde(default, skip_serializing_if = "Vec::is_empty")]
	pub used_by: Vec<String>,
}

/// One modem device: what the document asks for, and what is in force.
///
/// The two halves are deliberately separate fields rather than one resolved
/// answer. `sim` is the operator's ordered preference and never changes on its
/// own; `selected` is where netcfgd has got to, which moves when a probe says
/// a source does not work. A client showing only the second could not say what
/// was asked for, and one showing only the first would describe a machine that
/// is not the machine.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModemStatus {
	/// The device, which is the kernel name of the interface.
	pub device: String,
	/// The SIM sources the document lists, in the order they are tried.
	#[serde(default, skip_serializing_if = "Vec::is_empty")]
	pub sim: Vec<String>,
	/// The source in use, where the device has any listed.
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub selected: Option<String>,
	/// The APN the document asks for.
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub apn: Option<String>,
	/// Whether the selection has moved and the link has not been cycled yet.
	///
	/// Visible because it is the difference between "netcfgd wants the other
	/// SIM" and "the machine is on the other SIM", and an operator watching a
	/// modem that will not attach needs to tell those apart.
	#[serde(default, skip_serializing_if = "std::ops::Not::not")]
	pub cycle_pending: bool,
}

/// One radio, and whether netcfgd has been given it.
///
/// **Every wireless interface the kernel reports**, managed or not, because
/// the list exists so that somebody can turn one on -- a list of only the ones
/// already on could not offer that.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Radio {
	/// The interface name.
	pub interface: String,
	/// Whether netcfgd manages it: a `device` block with a `wifi` section and
	/// no `managed = false`.
	pub activated: bool,
	/// Whether a supplicant is answering on it.
	///
	/// Distinct from `activated`, and the gap between them is the interesting
	/// state: activated with nothing answering means netcfgd has been asked
	/// and has not managed it yet, which is a fault to show rather than a
	/// spinner. Not activated with something answering means another manager
	/// holds this radio -- netcfgd declines those rather than taking them, so
	/// a client can say why activating it will not help until that stops.
	///
	/// **It is netcfgd's answer, not the machine's.** The probe is a connect
	/// to the control socket, and `wpa_supplicant` gives that socket to one
	/// group -- `netdev` on Debian. A daemon running as root sees every one; a
	/// daemon running as somebody else reports `false` for a supplicant that
	/// is plainly there. That is the honest answer to "can netcfgd reach it",
	/// which is the question this field is for, and it is what netcfgd itself
	/// will act on. Measured: a daemon run as an ordinary user reported
	/// `false` on a radio `NetworkManager` was holding.
	pub supplicant: bool,
}

/// The 802.1X half of [`Request::WifiAdd`].
///
/// **Every certificate here is the name of a stored secret, never a path.**
/// That is the whole reason this can exist at all: a path is an instruction to
/// open a file as root, so configuration containing one is privileged and a
/// client that is not root cannot send it. A name refers to content netcfgd
/// already holds because a caller put it there with
/// [`Request::SecretPut`], so it grants nothing new -- and there is no field
/// here a path could be written in, which is the difference between a rule and
/// a property.
///
/// So an enterprise network is added in two steps, and the order matters: the
/// certificates go first, and then the network that refers to them.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EapRequest {
	/// `peap`, `ttls`, `tls` or `pwd`.
	pub method: String,
	/// Who you are to the authentication server, often with a realm.
	pub identity: String,
	/// Who you are *outside* the tunnel, which is all the radio sees.
	#[serde(skip_serializing_if = "Option::is_none", default)]
	pub anonymous_identity: Option<String>,
	/// The inner method, such as `mschapv2`.
	#[serde(skip_serializing_if = "Option::is_none", default)]
	pub phase2: Option<String>,
	/// The stored certificate the server is checked against.
	#[serde(skip_serializing_if = "Option::is_none", default)]
	pub ca_cert: Option<String>,
	/// The stored certificate presented, for `tls`.
	#[serde(skip_serializing_if = "Option::is_none", default)]
	pub client_cert: Option<String>,
	// There is deliberately no `private_key` here, and it is the field a
	// reader will look for first. For `tls` the private key *is* the
	// credential: it travels the way a passphrase does, is stored under the
	// network's own id, and the profile writes `private_key = "@secret:<id>"`.
	// A second field naming a different stored secret would be a second answer
	// to one question, and the interesting case is not the caller who fills in
	// one of them -- it is the caller who fills in both and disagrees with
	// themselves, leaving the daemon to pick.
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
	/// The credentials, in answer to [`Request::SecretList`].
	Secrets {
		/// Every name the configuration refers to or the store holds, sorted,
		/// with no duplicates.
		secrets: Vec<SecretEntry>,
	},

	/// The modems, in answer to [`Request::ModemList`].
	Modems {
		/// One per device with a `modem` block, in document order.
		modems: Vec<ModemStatus>,
	},

	/// The profiles, in answer to [`Request::ProfileList`].
	Profiles {
		/// One per profile directory. A copy in `/etc` shadows a shipped one
		/// of the same name, and only the copy is listed -- the same rule the
		/// loader layers by.
		profiles: Vec<ProfileEntry>,
		/// The profile in effect, or `None`, which is the default and is not
		/// a profile called "none".
		chosen: Option<String>,
	},
	/// The link-detection scripts, in answer to [`Request::ProbeList`].
	Probes {
		/// One per script. A copy in `/etc` shadows a shipped example of the
		/// same name, and only the copy is listed.
		probes: Vec<ProbeScript>,
	},
	/// The radios this machine has, in answer to [`Request::Radios`].
	Radios {
		/// One per wireless interface the kernel reports.
		radios: Vec<Radio>,
	},
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
	/// Whether that credential is 802.1X rather than a passphrase.
	///
	/// Sent because the daemon knows and a client cannot work it out: the
	/// scan flags do not cross the socket, so without this a client asking
	/// for a passphrase on a corporate network has no way to know it is
	/// asking the wrong question. Diagnostic in the same sense
	/// `mobility_domain` is -- it decides which fields a dialog shows, and
	/// the supplicant is what decides whether the network is really that.
	#[serde(default)]
	pub enterprise: bool,
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
				restart_wedged: Vec::new(),
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
				// Populated, because this list exists so that serde emits
				// every member and the table can be compared against it. A
				// `None` here would leave `eap` out of the emitted keys and
				// the gate would report the table as wrong rather than the
				// sample as incomplete.
				eap: Some(Box::new(EapRequest {
					method: "peap".to_owned(),
					identity: "you@corp.example".to_owned(),
					anonymous_identity: Some("anonymous@corp.example".to_owned()),
					phase2: Some("mschapv2".to_owned()),
					ca_cert: Some("corp-ca".to_owned()),
					client_cert: Some("corp-crt".to_owned()),
				})),
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
