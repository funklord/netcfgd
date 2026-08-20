//! What a configuration asks for beyond configuring a network.
//!
//! [0127](../../../docs/decisions/0127-netcfgd-is-the-only-writer-and-the-socket-carries-the-rest.md)
//! makes netcfgd the only writer of `/etc/netcfgd`: a client cannot write
//! system files and system configuration cannot live under a user, so
//! everything a client wants netcfgd to have arrives over the socket. That
//! settles the architecture and inherits
//! [0117](../../../docs/decisions/0117-adding-a-network-is-a-typed-request-not-a-written-file.md)'s
//! obligation whole, because 0117's line was never *socket versus file*:
//!
//! > A request that carries config text is remote code execution. A request
//! > that carries an SSID and a passphrase is not.
//!
//! This is what tells the two apart. Given a parsed file it returns every
//! production in it that grants more than "configure this machine's network",
//! so a caller who is not root can be refused with the reason rather than with
//! a shrug.
//!
//! **It is not a hook check.** Enumerating against the compiler rather than
//! from memory found six, three of which execute code, and only one is hooks.
//! `@secret:exec:` is the one that makes the point: a command run as root,
//! living inside the *secrets* feature, where somebody auditing for code
//! execution would not think to look. A list written from memory lists hooks
//! and stops.
//!
//! **The table is keyed on the block as well as the key, and that is load
//! bearing.** `config` inside `openvpn` is the path to a `.ovpn` file, which
//! carries `up` and `down` scripts; `config` inside `interface` is the
//! addressing list. Same word, and one of them is code execution. A key-only
//! table classifies one of the two wrongly and does it silently.

use crate::ast::{Block, File, Item, Value};
use crate::diag::Span;

/// Why a production needs more than the network-configuration right.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reason {
	/// A hook body is shell, and `run_as` absent means the daemon's own user,
	/// which is root.
	Hook,
	/// 0119's probe block, whose own documentation calls it "a program, how
	/// often to run it, how long to wait".
	Probe,
	/// A secret fetched by running a command.
	SecretExec,
	/// A path to another program's configuration, which that program will read
	/// as root and which may itself name scripts.
	ForeignConfig,
	/// A filesystem path this machine's config points at, opened by something
	/// running as root.
	Path,
	/// `include` pulls another file into the configuration wholesale.
	Include,
	/// Hands something netcfgd creates to a named user or group.
	///
	/// Found by reviewing the generated inventory rather than by the audit
	/// that produced the other six, which is the argument for the inventory
	/// existing: `tun { owner, group }` is netcfgd, as root, giving a tunnel
	/// device to a principal of the caller's choosing. A client naming itself
	/// gets packet-level access to an interface it does not otherwise own.
	Principal,
}

impl Reason {
	/// A sentence for the caller, naming what it grants rather than what it is.
	#[must_use]
	pub fn why(self) -> &'static str {
		match self {
			Self::Hook => {
				"a hook body is shell, and a hook with no `run_as` runs as the daemon's \
				 own user, which is root"
			}
			Self::Probe => "a probe block is a program netcfgd runs, as root",
			Self::SecretExec => {
				"an `exec` secret provider is a command netcfgd runs, as root, to fetch \
				 the value"
			}
			Self::ForeignConfig => {
				"that names another program's configuration file, which netcfgd hands to \
				 it as root and which may itself name scripts to run"
			}
			Self::Path => {
				"that names a path on this machine, which is opened by a program running \
				 as root -- send the contents instead and netcfgd will store them"
			}
			Self::Include => {
				"`include` reads another file into this configuration, and a client \
				 cannot know what is in it"
			}
			Self::Principal => {
				"that hands a device netcfgd creates to a named user or group, which \
				 gives them the traffic on it"
			}
		}
	}
}

/// One production that needs more than an ordinary caller has.
#[derive(Debug, Clone)]
pub struct Finding {
	/// Which kind.
	pub reason: Reason,
	/// What it was, as written: `post_up`, `openvpn.config`, `@secret:exec:`.
	pub what: String,
	/// Where, so a diagnostic can point at it.
	pub span: Span,
}

/// Assignments that are privileged, by the block they appear in.
///
/// **Every key the compiler accepts is classified**, here or in
/// `tools/privilege-ordinary.txt`, and `tools/privilege_gate.py` fails when one is
/// neither. That is the `tier_of` construction in a language that has no enum
/// of config keys to be exhaustive over: a key added later is classified or a
/// gate refuses it, rather than defaulting to safe and being noticed by
/// nobody.
const PRIVILEGED: &[(&str, &str, Reason)] = &[
	// 0119's probe. `command` and `args` are the program and its arguments.
	("probe", "command", Reason::Probe),
	("probe", "args", Reason::Probe),
	// An .ovpn file, read by openvpn as root. 0046 puts everything else in
	// that file, which is exactly why naming one is not an ordinary thing to
	// be able to do.
	("openvpn", "config", Reason::ForeignConfig),
	("openvpn", "file", Reason::ForeignConfig),
	// 802.1X certificate paths, opened by a supplicant running as root. Under
	// 0127 these stop being paths -- a client sends the bytes and netcfgd
	// chooses where they live -- and until then they are privileged.
	("wifi", "ca_cert", Reason::Path),
	("wifi", "client_cert", Reason::Path),
	// A tun device handed to a principal the caller chose. Note `vxlan`'s
	// `group` is a multicast address and is nothing to do with this -- the
	// same word, two meanings, which is the second time the block qualifier
	// has earned its place in this table.
	("tun", "owner", Reason::Principal),
	("tun", "group", Reason::Principal),
];

/// Whether an assignment is privileged, given the block it sits in.
fn assignment_reason(block: &str, key: &str) -> Option<Reason> {
	PRIVILEGED
		.iter()
		.find(|(head, name, _)| *head == block && *name == key)
		.map(|(_, _, reason)| *reason)
}

/// The `@secret:exec:` provider, wherever a value can carry one.
///
/// A value and not a key, which is why the table above cannot express it: any
/// key taking a secret reference can carry this, and the provider is the third
/// field of a string.
fn secret_exec(value: &Value) -> bool {
	match value {
		Value::Str(text) => text.starts_with("@secret:exec:"),
		Value::List(items) => items.iter().any(|item| secret_exec(&item.node)),
		_ => false,
	}
}

/// Every privileged production in a parsed file.
///
/// Walks rather than compiles, deliberately: this has to answer for text that
/// may not compile at all, since a caller sending something malformed should
/// be told what is wrong with it rather than what it would have been allowed
/// to do.
#[must_use]
pub fn findings(file: &File) -> Vec<Finding> {
	let mut found = Vec::new();
	walk(&file.items, "", &mut found);
	found
}

fn walk(items: &[Item], block: &str, found: &mut Vec<Finding>) {
	for item in items {
		// Exhaustive, and that is the statement half of the guarantee: an
		// `Item` variant added later fails to compile here rather than
		// slipping through unclassified.
		match item {
			Item::Hook(hook) => found.push(Finding {
				reason: Reason::Hook,
				what: hook.phase.clone(),
				span: hook.span,
			}),
			Item::Include(path) => found.push(Finding {
				reason: Reason::Include,
				what: format!("include \"{}\"", path.node),
				span: path.span,
			}),
			Item::Assignment(assignment) => {
				if let Some(reason) = assignment_reason(block, &assignment.key) {
					found.push(Finding {
						reason,
						what: format!("{block}.{}", assignment.key),
						span: assignment.span,
					});
				}
				if secret_exec(&assignment.value.node) {
					found.push(Finding {
						reason: Reason::SecretExec,
						what: format!("{}= @secret:exec:", assignment.key),
						span: assignment.value.span,
					});
				}
			}
			Item::Block(inner) => walk_block(inner, found),
		}
	}
}

fn walk_block(block: &Block, found: &mut Vec<Finding>) {
	walk(&block.items, &block.head, found);
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::diag::SourceId;
	use crate::parse;

	fn find(text: &str) -> Vec<Finding> {
		let file = parse::parse(SourceId(0), text).expect("it parses");
		findings(&file)
	}

	fn reasons(text: &str) -> Vec<Reason> {
		find(text).into_iter().map(|f| f.reason).collect()
	}

	/// The ordinary desktop case is ordinary, which is the half that matters
	/// most: a classifier that refused everything would pass every test below
	/// and make the feature pointless.
	#[test]
	fn a_wifi_network_and_an_address_are_not_privileged() {
		assert!(reasons(
			"interface eth0 {\n\tconfig = [\"dhcp\", \"192.0.2.10/24\"]\n\troutes = \"default via 192.0.2.1\"\n}\n"
		)
		.is_empty());
		assert!(
			reasons("network \"Cafe\" {\n\twifi {\n\t\tpsk = \"@secret:cafe\"\n\t}\n}\n")
				.is_empty()
		);
	}

	#[test]
	fn a_hook_is_privileged() {
		assert_eq!(
			reasons("interface eth0 {\n\tpost_up {\n\t\tlogger hello\n\t}\n}\n"),
			vec![Reason::Hook]
		);
	}

	#[test]
	fn a_probe_block_is_privileged() {
		let found = reasons(
			"interface eth0 {\n\tprobe {\n\t\tcommand = \"/bin/true\"\n\t\tinterval = 30\n\t}\n}\n",
		);
		assert_eq!(found, vec![Reason::Probe]);
	}

	/// `interval` inside the same block is not, which is what makes this a
	/// classification rather than a block-level refusal.
	#[test]
	fn an_ordinary_key_in_a_privileged_block_is_ordinary() {
		assert!(reasons("interface eth0 {\n\tprobe {\n\t\tinterval = 30\n\t}\n}\n").is_empty());
	}

	/// The one an enumeration from memory misses.
	#[test]
	fn an_exec_secret_provider_is_privileged() {
		assert_eq!(
			reasons("network \"Corp\" {\n\twifi {\n\t\tpsk = \"@secret:exec:fetch\"\n\t}\n}\n"),
			vec![Reason::SecretExec]
		);
	}

	/// And an ordinary secret reference is not, in the same position.
	#[test]
	fn a_file_secret_provider_is_ordinary() {
		assert!(
			reasons("network \"Corp\" {\n\twifi {\n\t\tpsk = \"@secret:file:home\"\n\t}\n}\n")
				.is_empty()
		);
	}

	/// The pair that proves the table is keyed on the block and not the key.
	///
	/// `config` means an addressing list in one block and the path to a `.ovpn`
	/// file in another. A key-only table gets one of them wrong, and gets it
	/// wrong silently -- which is the whole reason the table carries a block.
	#[test]
	fn config_is_privileged_in_openvpn_and_ordinary_in_an_interface() {
		assert_eq!(
			reasons(
				"interface tun0 {\n\topenvpn {\n\t\tconfig = \"/etc/openvpn/c.conf\"\n\t}\n}\n"
			),
			vec![Reason::ForeignConfig]
		);
		assert!(reasons("interface eth0 {\n\tconfig = \"dhcp\"\n}\n").is_empty());
	}

	#[test]
	fn an_include_is_privileged() {
		assert_eq!(
			reasons("include \"/etc/netcfgd/site.conf\"\n"),
			vec![Reason::Include]
		);
	}

	/// Certificate paths, until 0127 turns them into content.
	#[test]
	fn a_certificate_path_is_privileged() {
		assert_eq!(
			reasons(
				"network \"eduroam\" {\n\twifi {\n\t\teap = \"peap\"\n\t\tca_cert = \"/etc/ssl/x.pem\"\n\t}\n}\n"
			),
			vec![Reason::Path]
		);
	}

	/// A tun device given to a named user, and the multicast address that
	/// shares the word.
	#[test]
	fn tun_ownership_is_privileged_and_a_vxlan_group_is_not() {
		assert_eq!(
			reasons("interface tun0 {\n\ttun {\n\t\towner = \"nobody\"\n\t}\n}\n"),
			vec![Reason::Principal]
		);
		assert!(reasons(
			"interface vx0 {\n\tvxlan {\n\t\tid = 100\n\t\tgroup = \"239.1.1.1\"\n\t}\n}\n"
		)
		.is_empty());
	}

	/// Every reason has a sentence, and none of them is empty.
	#[test]
	fn every_reason_explains_itself() {
		for reason in [
			Reason::Hook,
			Reason::Probe,
			Reason::SecretExec,
			Reason::ForeignConfig,
			Reason::Path,
			Reason::Include,
			Reason::Principal,
		] {
			assert!(reason.why().len() > 20, "{reason:?} explains nothing");
		}
	}
}
