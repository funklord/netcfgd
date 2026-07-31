//! An NM settings dictionary, as a netcfgd `network` block.
//!
//! Design section 9.4: the GUI is just another editor of config files. What a
//! client sends as `a{sa{sv}}` becomes plain text under `/etc/netcfgd`, and
//! from there it is an ordinary block -- `ncfg plan` explains it, drift
//! detection watches it, hooks fire for it, with no second code path anywhere.
//! A wifi network created from a desktop applet is a file you can diff and
//! commit, which NM never gave anybody.
//!
//! This module is the translation and nothing else: no filesystem, no bus. It
//! takes a dictionary and produces text, a secret to store, and a list of
//! everything the client asked for that netcfgd cannot say. That last part is
//! the reason this is a separate module -- the honest handling of a lossy
//! translation is to write down what was lost, in the file, where the operator
//! will find it.

use crate::settings::Dict;
use netcfgd_model::Ssid;
use std::fmt::Write as _;

/// What a settings dictionary became.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Emitted {
	/// The `network` block's label, which is also the profile id.
	pub(crate) id: String,
	/// The block, ready to write.
	pub(crate) text: String,
	/// `(name, value)` for a credential that has to go to the secret provider.
	pub(crate) secret: Option<(String, String)>,
}

/// Something a client asked for that cannot become a netcfgd block.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Unsupported {
	/// A connection type other than wifi.
	Kind {
		/// What was asked for.
		given: String,
	},
	/// A required field the dictionary did not carry.
	Missing {
		/// Which one, in NM's own spelling.
		field: &'static str,
	},
	/// A key management this build cannot express.
	KeyManagement {
		/// What was asked for.
		given: String,
	},
	/// Enterprise wifi, which needs more than a passphrase.
	Enterprise,
	/// A passphrase outside WPA's range.
	PassphraseLength {
		/// How long it was.
		len: usize,
	},
	/// An id that cannot be a block label.
	MalformedId {
		/// What was asked for.
		given: String,
	},
	/// Something that should have been an address and is not.
	MalformedAddress {
		/// What was asked for.
		given: String,
	},
}

impl std::fmt::Display for Unsupported {
	fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		match self {
			Self::Kind { given } => write!(
				formatter,
				"netcfgd-nm can create wifi networks and nothing else; this asked for \
				 `{given}`. An interface is configured by an `interface` block in \
				 /etc/netcfgd, which is a file to edit rather than a profile to create"
			),
			Self::Missing { field } => write!(
				formatter,
				"the connection settings have no `{field}`, which a netcfgd `network` \
				 block cannot do without"
			),
			Self::KeyManagement { given } => write!(
				formatter,
				"`{given}` is not a key management netcfgd can write down. It knows \
				 open networks, `wpa-psk`, `sae` and `owe`"
			),
			Self::Enterprise => formatter.write_str(
				"an enterprise network needs an `eap` block naming a method, an identity \
				 and certificate paths, which is more than a settings dictionary from a \
				 connect dialog carries. Write it in /etc/netcfgd (decision 0008)",
			),
			Self::PassphraseLength { len } => write!(
				formatter,
				"a WPA passphrase is 8 to 63 characters; this one is {len}"
			),
			Self::MalformedId { given } => write!(
				formatter,
				"`{given}` cannot be a block label: netcfgd names a network with printable \
				 text and no quotes or newlines"
			),
			Self::MalformedAddress { given } => write!(
				formatter,
				"`{given}` is not an IP address, and writing it into the configuration \
				 would make netcfgd refuse to compile a network you were told was created"
			),
		}
	}
}

impl std::error::Error for Unsupported {}

/// Read a string out of a settings group.
fn string(settings: &Dict, group: &str, key: &str) -> Option<String> {
	let value = settings.get(group)?.get(key)?;
	String::try_from(value.try_clone().ok()?).ok()
}

/// Read a boolean.
fn flag(settings: &Dict, group: &str, key: &str) -> Option<bool> {
	let value = settings.get(group)?.get(key)?;
	bool::try_from(value.try_clone().ok()?).ok()
}

/// Read a byte array.
fn octets(settings: &Dict, group: &str, key: &str) -> Option<Vec<u8>> {
	let value = settings.get(group)?.get(key)?;
	Vec::<u8>::try_from(value.try_clone().ok()?).ok()
}

/// Whether a block label is one the DSL will take back.
///
/// The label is written between quotes, so a quote or a newline inside it
/// would end the string and turn the rest into config. That is the injection
/// this checks for; it is not a style rule.
fn is_writable_label(id: &str) -> bool {
	!id.is_empty()
		&& id.len() <= 64
		&& !id.contains(['"', '\\', '\n', '\r', '\0'])
		&& id.chars().all(|c| !c.is_control())
}

/// Keys that carry no information netcfgd is missing.
///
/// Either derived here anyway (`uuid`), meaningless to a file-backed store
/// (`timestamp`), or NM's own bookkeeping. Listing them means the "dropped"
/// note in a generated file names things an operator would actually want to
/// know about, rather than fifteen lines of noise every client sends.
const UNINTERESTING: &[(&str, &str)] = &[
	("connection", "id"),
	("connection", "uuid"),
	("connection", "type"),
	("connection", "timestamp"),
	("connection", "permissions"),
	("connection", "autoconnect"),
	("connection", "interface-name"),
	("802-11-wireless", "ssid"),
	("802-11-wireless", "mode"),
	("802-11-wireless", "security"),
	("802-11-wireless", "hidden"),
	("802-11-wireless", "seen-bssids"),
	("802-11-wireless-security", "key-mgmt"),
	("802-11-wireless-security", "psk"),
	("802-11-wireless-security", "auth-alg"),
	("802-11-wireless-security", "psk-flags"),
	("802-11-wireless-security", "wep-key-flags"),
	("802-11-wireless-security", "leap-password-flags"),
	("ipv4", "method"),
	("ipv4", "address-data"),
	("ipv4", "gateway"),
	("ipv4", "route-data"),
	("ipv4", "addresses"),
	("ipv4", "routes"),
	("ipv6", "method"),
	("ipv6", "address-data"),
	("ipv6", "gateway"),
	("ipv6", "route-data"),
	("ipv6", "addresses"),
	("ipv6", "routes"),
	("ipv6", "addr-gen-mode"),
	("proxy", ""),
];

/// Everything the client asked for that this translation did not carry over.
///
/// An empty value is not a request: NM sends `address-data` as an empty array
/// on every profile, and reporting that as dropped would bury the one line
/// that matters under fourteen that do not.
fn dropped_settings(settings: &Dict) -> Vec<String> {
	let mut dropped = Vec::new();
	for (group, fields) in settings {
		if UNINTERESTING.contains(&(group.as_str(), "")) {
			continue;
		}
		for (key, value) in fields {
			if UNINTERESTING.contains(&(group.as_str(), key.as_str())) {
				continue;
			}
			if is_empty(value) {
				continue;
			}
			dropped.push(format!("{group}.{key}"));
		}
	}
	dropped.sort();
	dropped
}

/// Whether a value says nothing.
fn is_empty(value: &zbus::zvariant::OwnedValue) -> bool {
	use zbus::zvariant::Value;
	match &**value {
		Value::Str(text) => text.is_empty(),
		Value::Array(array) => array.is_empty(),
		Value::U32(number) => *number == 0,
		Value::Bool(flag) => !flag,
		Value::Dict(dict) => dict.iter().next().is_none(),
		_ => false,
	}
}

/// How netcfgd spells the addressing NM asked for.
///
/// Both families, in one list, because netcfgd's `config` is one list --
/// decision 0006's composition rather than NM's two independent settings.
fn addressing(settings: &Dict) -> Result<Vec<String>, Unsupported> {
	let mut sources = Vec::new();
	match string(settings, "ipv4", "method").as_deref() {
		Some("auto") => sources.push("dhcp".to_owned()),
		Some("manual") => sources.extend(static_addresses(settings, "ipv4")?),
		// `disabled` and `link-local` have no netcfgd spelling that says
		// anything: an interface netcfgd is not given addressing for gets
		// none, which is what both of those mean.
		_ => {}
	}
	match string(settings, "ipv6", "method").as_deref() {
		Some("auto") => sources.push("slaac".to_owned()),
		Some("dhcp") => sources.push("dhcp6".to_owned()),
		Some("manual") => sources.extend(static_addresses(settings, "ipv6")?),
		Some("link-local") => sources.push("link_local".to_owned()),
		_ => {}
	}
	Ok(sources)
}

/// The static addresses in one family's `address-data`.
///
/// NM keeps the address and the prefix apart; netcfgd writes CIDR, which is
/// what an operator types and what `ip addr` prints. Rejoining them here means
/// the file reads like one somebody wrote.
fn static_addresses(settings: &Dict, group: &str) -> Result<Vec<String>, Unsupported> {
	let Some(entries) = dictionaries(settings, group, "address-data") else {
		return Err(Unsupported::Missing {
			field: "ipv4.address-data",
		});
	};
	let mut addresses = Vec::new();
	for entry in entries {
		let address = entry
			.get("address")
			.and_then(|value| String::try_from(value.try_clone().ok()?).ok())
			.ok_or(Unsupported::Missing {
				field: "address-data.address",
			})?;
		let prefix = entry
			.get("prefix")
			.and_then(|value| u32::try_from(value.try_clone().ok()?).ok())
			.ok_or(Unsupported::Missing {
				field: "address-data.prefix",
			})?;
		// Checked rather than trusted: this goes into a configuration file, and
		// a value that is not an address would make the file refuse to compile
		// -- which the caller would see as netcfgd rejecting a network the
		// client thought was fine.
		if address.parse::<std::net::IpAddr>().is_err() {
			return Err(Unsupported::MalformedAddress { given: address });
		}
		addresses.push(format!("{address}/{prefix}"));
	}
	Ok(addresses)
}

/// The routes a client asked for, as netcfgd writes them.
///
/// The gateway comes back together with them: NM keeps the default route's
/// next hop in `gateway` and everything else in `route-data`, and netcfgd has
/// one list of routes with `default` in it like any other destination.
fn routes(settings: &Dict) -> Result<Vec<String>, Unsupported> {
	let mut routes = Vec::new();
	for group in ["ipv4", "ipv6"] {
		if let Some(gateway) = string(settings, group, "gateway") {
			if gateway.parse::<std::net::IpAddr>().is_err() {
				return Err(Unsupported::MalformedAddress { given: gateway });
			}
			routes.push(format!("default via {gateway}"));
		}
		let Some(entries) = dictionaries(settings, group, "route-data") else {
			continue;
		};
		for entry in entries {
			let Some(destination) = entry
				.get("dest")
				.and_then(|value| String::try_from(value.try_clone().ok()?).ok())
			else {
				continue;
			};
			if destination.parse::<std::net::IpAddr>().is_err() {
				return Err(Unsupported::MalformedAddress { given: destination });
			}
			let prefix = entry
				.get("prefix")
				.and_then(|value| u32::try_from(value.try_clone().ok()?).ok())
				.unwrap_or(0);
			let mut route = format!("{destination}/{prefix}");
			if let Some(next) = entry
				.get("next-hop")
				.and_then(|value| String::try_from(value.try_clone().ok()?).ok())
			{
				if next.parse::<std::net::IpAddr>().is_err() {
					return Err(Unsupported::MalformedAddress { given: next });
				}
				route.push_str(&format!(" via {next}"));
			}
			if let Some(metric) = entry
				.get("metric")
				.and_then(|value| u32::try_from(value.try_clone().ok()?).ok())
			{
				route.push_str(&format!(" metric {metric}"));
			}
			routes.push(route);
		}
	}
	Ok(routes)
}

/// Read an `aa{sv}` out of a settings group.
fn dictionaries(
	settings: &Dict,
	group: &str,
	key: &str,
) -> Option<Vec<std::collections::HashMap<String, zbus::zvariant::OwnedValue>>> {
	let value = settings.get(group)?.get(key)?;
	Vec::<std::collections::HashMap<String, zbus::zvariant::OwnedValue>>::try_from(
		value.try_clone().ok()?,
	)
	.ok()
}

/// Turn a settings dictionary into a `network` block.
///
/// # Errors
///
/// Returns [`Unsupported`] for anything a client can send that netcfgd's
/// configuration language cannot say. Every one of them is refused by name, so
/// the client shows a sentence rather than a generic failure.
pub(crate) fn network_block(settings: &Dict) -> Result<Emitted, Unsupported> {
	network_block_keeping_secret(settings, false)
}

/// The same, for an update that may leave the credential alone.
///
/// `stored` says a secret already exists under this profile's name. A client
/// updating a profile sends back what `GetSettings` gave it, and that never
/// contains the passphrase -- so requiring one would refuse every edit of an
/// existing network that was not a password change.
///
/// # Errors
///
/// As [`network_block`].
pub(crate) fn network_block_keeping_secret(
	settings: &Dict,
	stored: bool,
) -> Result<Emitted, Unsupported> {
	let kind = string(settings, "connection", "type").ok_or(Unsupported::Missing {
		field: "connection.type",
	})?;
	if kind != "802-11-wireless" {
		return Err(Unsupported::Kind { given: kind });
	}

	let id = string(settings, "connection", "id").ok_or(Unsupported::Missing {
		field: "connection.id",
	})?;
	if !is_writable_label(&id) {
		return Err(Unsupported::MalformedId { given: id });
	}

	let ssid = octets(settings, "802-11-wireless", "ssid").ok_or(Unsupported::Missing {
		field: "802-11-wireless.ssid",
	})?;
	let ssid = Ssid::new(ssid).map_err(|_| Unsupported::Missing {
		field: "802-11-wireless.ssid",
	})?;

	let key_mgmt = string(settings, "802-11-wireless-security", "key-mgmt");
	let mut secret = None;
	let security = match key_mgmt.as_deref() {
		None => "open = true".to_owned(),
		Some("owe") => "owe = true".to_owned(),
		Some("wpa-eap" | "wpa-eap-suite-b-192") => return Err(Unsupported::Enterprise),
		Some(mechanism @ ("wpa-psk" | "sae")) => {
			match string(settings, "802-11-wireless-security", "psk") {
				Some(passphrase) => {
					let len = passphrase.chars().count();
					if !(8..=63).contains(&len) {
						return Err(Unsupported::PassphraseLength { len });
					}
					// The secret's name is the profile's, which makes the
					// reference in the file readable and the file in the
					// secrets directory findable. It never appears in the
					// block: constraint 5, and the whole reason the document
					// holds references rather than values.
					secret = Some((id.clone(), passphrase));
				}
				// No passphrase and one already stored: an edit of something
				// else. Leaving the secret untouched is the only reading that
				// does not silently break a working network.
				None if stored => {}
				None => {
					return Err(Unsupported::Missing {
						field: "802-11-wireless-security.psk",
					})
				}
			}
			let proto = if mechanism == "sae" { "wpa3" } else { "wpa2" };
			format!("psk = \"@secret:{id}\"; proto = \"{proto}\"")
		}
		Some(other) => {
			return Err(Unsupported::KeyManagement {
				given: other.to_owned(),
			})
		}
	};

	let mut text = String::new();
	text.push_str(
		"# Written by netcfgd-nm from a NetworkManager client. This file is\n\
		 # ordinary netcfgd configuration: edit it, diff it, commit it, or delete\n\
		 # it. Deleting netcfgd-nm leaves it behind, still valid.\n",
	);

	let lost = dropped_settings(settings);
	if !lost.is_empty() {
		text.push_str(
			"#\n# The client also asked for the settings below. netcfgd has no way to\n\
			 # say them, so they are recorded here rather than silently discarded:\n",
		);
		for setting in &lost {
			let _ = writeln!(text, "#   {setting}");
		}
	}

	let _ = writeln!(text, "\nnetwork \"{id}\" {{");
	// The SSID as hex whenever it is not exactly the label. An SSID is octets
	// and the label is text, so a network whose name has a space, or is not
	// UTF-8 at all, needs both -- and writing the hex form unconditionally
	// would make every generated file harder to read than it has to be.
	if ssid.as_bytes() != id.as_bytes() {
		let _ = writeln!(text, "\tssid = \"{}\"", ssid.to_hex());
	}
	let _ = writeln!(text, "\twifi {{ {security} }}");
	if flag(settings, "802-11-wireless", "hidden") == Some(true) {
		text.push_str("\thidden = true\n");
	}
	if flag(settings, "connection", "autoconnect") == Some(false) {
		text.push_str("\tautoconnect = false\n");
	}
	let sources = addressing(settings)?;
	if !sources.is_empty() {
		let rendered: Vec<String> = sources.iter().map(|s| format!("\"{s}\"")).collect();
		let _ = writeln!(text, "\tconfig = [{}]", rendered.join(", "));
	}
	let routes = routes(settings)?;
	if !routes.is_empty() {
		let rendered: Vec<String> = routes.iter().map(|r| format!("\"{r}\"")).collect();
		let _ = writeln!(text, "\troutes = [{}]", rendered.join(", "));
	}
	text.push_str("}\n");

	Ok(Emitted { id, text, secret })
}

#[cfg(test)]
mod tests {
	use super::*;
	use std::collections::HashMap;
	use zbus::zvariant::{OwnedValue, Value};

	fn value(v: Value<'_>) -> OwnedValue {
		OwnedValue::try_from(v).expect("an owned value")
	}

	fn wifi_settings(id: &str, key_mgmt: Option<&str>, psk: Option<&str>) -> Dict {
		let mut dict = Dict::new();
		let mut connection = HashMap::new();
		connection.insert("id".to_owned(), value(Value::from(id)));
		connection.insert("type".to_owned(), value(Value::from("802-11-wireless")));
		dict.insert("connection".to_owned(), connection);

		let mut wireless = HashMap::new();
		wireless.insert(
			"ssid".to_owned(),
			value(Value::from(id.as_bytes().to_vec())),
		);
		dict.insert("802-11-wireless".to_owned(), wireless);

		if let Some(mechanism) = key_mgmt {
			let mut security = HashMap::new();
			security.insert("key-mgmt".to_owned(), value(Value::from(mechanism)));
			if let Some(psk) = psk {
				security.insert("psk".to_owned(), value(Value::from(psk)));
			}
			dict.insert("802-11-wireless-security".to_owned(), security);
		}

		let mut ipv4 = HashMap::new();
		ipv4.insert("method".to_owned(), value(Value::from("auto")));
		dict.insert("ipv4".to_owned(), ipv4);
		dict
	}

	#[test]
	fn a_psk_network_becomes_a_block_and_a_secret() {
		let emitted = network_block(&wifi_settings(
			"HomeFiber",
			Some("wpa-psk"),
			Some("hunter2hunter2"),
		))
		.expect("it renders");
		assert_eq!(emitted.id, "HomeFiber");
		assert!(emitted.text.contains("network \"HomeFiber\" {"));
		assert!(emitted.text.contains("psk = \"@secret:HomeFiber\""));
		assert!(emitted.text.contains("proto = \"wpa2\""));
		assert!(emitted.text.contains("config = [\"dhcp\"]"));
		// The value goes to the provider and never into the block. This is the
		// assertion constraint 5 is made of.
		assert!(!emitted.text.contains("hunter2hunter2"));
		assert_eq!(
			emitted.secret,
			Some(("HomeFiber".to_owned(), "hunter2hunter2".to_owned()))
		);
	}

	#[test]
	fn sae_is_written_as_wpa3() {
		let emitted = network_block(&wifi_settings(
			"HomeFiber",
			Some("sae"),
			Some("hunter2hunter2"),
		))
		.expect("it renders");
		assert!(emitted.text.contains("proto = \"wpa3\""));
	}

	#[test]
	fn an_open_network_needs_no_secret() {
		let emitted = network_block(&wifi_settings("Cafe", None, None)).expect("it renders");
		assert!(emitted.text.contains("open = true"));
		assert_eq!(emitted.secret, None);
	}

	/// An SSID is octets and a label is text. Where they differ the hex form
	/// has to be written, or the network created from a GUI is a differently
	/// named one.
	#[test]
	fn an_ssid_that_is_not_the_label_is_written_out() {
		let mut settings = wifi_settings("Guest", None, None);
		settings
			.get_mut("802-11-wireless")
			.expect("the group")
			.insert(
				"ssid".to_owned(),
				value(Value::from(vec![0x00_u8, 0xff, 0x20])),
			);
		let emitted = network_block(&settings).expect("it renders");
		assert!(emitted.text.contains("ssid = \"00ff20\""));

		// And where they agree, it is left out: every generated file should be
		// as readable as one somebody wrote.
		let plain = network_block(&wifi_settings("Cafe", None, None)).expect("it renders");
		assert!(!plain.text.contains("ssid ="));
	}

	/// A label goes between quotes, so a quote in it would end the string and
	/// turn the rest of the name into configuration.
	#[test]
	fn a_label_that_would_escape_its_quotes_is_refused() {
		for hostile in ["ev\"il", "two\nlines", "back\\slash"] {
			let result = network_block(&wifi_settings(hostile, None, None));
			assert_eq!(
				result,
				Err(Unsupported::MalformedId {
					given: hostile.to_owned()
				}),
				"for {hostile:?}"
			);
		}
	}

	#[test]
	fn what_cannot_be_expressed_is_refused_by_name() {
		assert_eq!(
			network_block(&wifi_settings("X", Some("wpa-eap"), None)),
			Err(Unsupported::Enterprise)
		);
		assert_eq!(
			network_block(&wifi_settings(
				"X",
				Some("wpa-none"),
				Some("hunter2hunter2")
			)),
			Err(Unsupported::KeyManagement {
				given: "wpa-none".to_owned()
			})
		);
		assert_eq!(
			network_block(&wifi_settings("X", Some("wpa-psk"), Some("short"))),
			Err(Unsupported::PassphraseLength { len: 5 })
		);
		assert_eq!(
			network_block(&wifi_settings("X", Some("wpa-psk"), None)),
			Err(Unsupported::Missing {
				field: "802-11-wireless-security.psk"
			})
		);
	}

	fn entry(pairs: &[(&str, Value<'_>)]) -> HashMap<String, OwnedValue> {
		pairs
			.iter()
			.map(|(key, item)| {
				(
					(*key).to_owned(),
					OwnedValue::try_from(item.try_clone().expect("cloneable")).expect("a value"),
				)
			})
			.collect()
	}

	fn with_static(id: &str) -> Dict {
		let mut settings = wifi_settings(id, None, None);
		let mut ipv4 = HashMap::new();
		ipv4.insert("method".to_owned(), value(Value::from("manual")));
		ipv4.insert(
			"address-data".to_owned(),
			OwnedValue::try_from(Value::from(vec![entry(&[
				("address", Value::from("192.0.2.5")),
				("prefix", Value::from(24_u32)),
			])]))
			.expect("an array"),
		);
		ipv4.insert("gateway".to_owned(), value(Value::from("192.0.2.1")));
		ipv4.insert(
			"route-data".to_owned(),
			OwnedValue::try_from(Value::from(vec![entry(&[
				("dest", Value::from("10.0.0.0")),
				("prefix", Value::from(8_u32)),
				("next-hop", Value::from("192.0.2.9")),
				("metric", Value::from(600_u32)),
			])]))
			.expect("an array"),
		);
		settings.insert("ipv4".to_owned(), ipv4);
		settings
	}

	/// A settings panel's static address becomes the line an operator would
	/// have typed: address and prefix rejoined into CIDR, and the gateway back
	/// among the routes where netcfgd keeps it.
	#[test]
	fn a_static_address_becomes_a_config_line() {
		let emitted = network_block(&with_static("Office")).expect("it renders");
		assert!(
			emitted.text.contains(r#"config = ["192.0.2.5/24"]"#),
			"{}",
			emitted.text
		);
		assert!(
			emitted.text.contains(
				r#"routes = ["default via 192.0.2.1", "10.0.0.0/8 via 192.0.2.9 metric 600"]"#
			),
			"{}",
			emitted.text
		);
	}

	/// Anything that is not an address is refused rather than written. A file
	/// that does not compile would be reported to the client as netcfgd
	/// rejecting a network the client was told had been created.
	#[test]
	fn something_that_is_not_an_address_is_refused() {
		let mut settings = with_static("Office");
		settings
			.get_mut("ipv4")
			.expect("the group")
			.insert("gateway".to_owned(), value(Value::from("not-an-address")));
		assert_eq!(
			network_block(&settings),
			Err(Unsupported::MalformedAddress {
				given: "not-an-address".to_owned()
			})
		);
	}

	/// `manual` with nothing to be manual about is a mistake worth naming: a
	/// panel that sent it would otherwise produce a network with no addressing
	/// and no explanation.
	#[test]
	fn manual_with_no_addresses_is_refused() {
		let mut settings = wifi_settings("Office", None, None);
		let mut ipv4 = HashMap::new();
		ipv4.insert("method".to_owned(), value(Value::from("manual")));
		settings.insert("ipv4".to_owned(), ipv4);
		assert_eq!(
			network_block(&settings),
			Err(Unsupported::Missing {
				field: "ipv4.address-data"
			})
		);
	}

	#[test]
	fn a_wired_profile_is_refused_by_name() {
		let mut settings = wifi_settings("eth0", None, None);
		settings
			.get_mut("connection")
			.expect("the group")
			.insert("type".to_owned(), value(Value::from("802-3-ethernet")));
		assert_eq!(
			network_block(&settings),
			Err(Unsupported::Kind {
				given: "802-3-ethernet".to_owned()
			})
		);
	}

	/// What could not be carried across is written into the file. A lossy
	/// translation that says nothing is how an operator finds out months later
	/// that their metered flag never took effect.
	#[test]
	fn settings_that_were_dropped_are_named_in_the_file() {
		let mut settings = wifi_settings("HomeFiber", None, None);
		settings
			.get_mut("connection")
			.expect("the group")
			.insert("metered".to_owned(), value(Value::from(1_u32)));
		settings
			.get_mut("802-11-wireless")
			.expect("the group")
			.insert("powersave".to_owned(), value(Value::from(2_u32)));
		let emitted = network_block(&settings).expect("it renders");
		assert!(
			emitted.text.contains("#   connection.metered"),
			"{}",
			emitted.text
		);
		assert!(emitted.text.contains("#   802-11-wireless.powersave"));
	}

	/// And what NM sends on every profile is not reported as dropped. A note
	/// listing fifteen empty arrays is one nobody reads, which makes the one
	/// line that matters invisible.
	#[test]
	fn empty_settings_are_not_reported_as_lost() {
		let mut settings = wifi_settings("HomeFiber", None, None);
		settings.get_mut("ipv4").expect("the group").insert(
			"address-data".to_owned(),
			value(Value::from(Vec::<String>::new())),
		);
		settings
			.get_mut("connection")
			.expect("the group")
			.insert("zone".to_owned(), value(Value::from("")));
		let emitted = network_block(&settings).expect("it renders");
		assert!(!emitted.text.contains("address-data"), "{}", emitted.text);
		assert!(!emitted.text.contains("connection.zone"));
	}
}
