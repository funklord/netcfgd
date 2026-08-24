//! `org.freedesktop.NetworkManager.AgentManager`, and asking an agent.
//!
//! Design section 9.3: clients register secret agents and expect to be asked
//! for a passphrase. This is the bridge, and it runs in one direction only --
//! an agent supplies a credential, netcfgd's provider stores it, and the
//! configuration keeps a `@secret:` reference. Nothing ever travels the other
//! way; `GetSecrets` on a profile still refuses (decision 0029).
//!
//! The trigger is deliberate rather than opportunistic. A client activates a
//! network whose `psk` is a `@secret:` reference to a file that does not
//! exist; that is a question netcfgd cannot answer and a desktop can, so the
//! agent is asked, the answer is stored, and the activation proceeds. It is
//! the same shape as a `network` block somebody wrote by hand and never
//! created the secret for -- which, before this, failed at apply time with a
//! message and no way to act on it.

use crate::state::State;
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

/// Where a secret agent serves its object. Fixed by NM's contract.
const AGENT_PATH: &str = "/org/freedesktop/NetworkManager/SecretAgent";
/// The interface it serves there.
const AGENT_INTERFACE: &str = "org.freedesktop.NetworkManager.SecretAgent";

/// `NMSecretAgentGetSecretsFlags`.
mod flags {
	/// The agent may put a dialog on the screen.
	pub(super) const ALLOW_INTERACTION: u32 = 0x1;
	/// A person asked for this, so a prompt is expected rather than intrusive.
	pub(super) const USER_REQUESTED: u32 = 0x4;
}

/// Every agent that has registered, by bus name.
#[derive(Debug, Default)]
pub(crate) struct Agents {
	registered: Mutex<BTreeMap<String, String>>,
}

impl Agents {
	/// Remember an agent.
	pub(crate) fn register(&self, bus_name: String, identifier: String) {
		let mut registered = self
			.registered
			.lock()
			.unwrap_or_else(std::sync::PoisonError::into_inner);
		registered.insert(bus_name, identifier);
	}

	/// Forget one.
	pub(crate) fn unregister(&self, bus_name: &str) {
		let mut registered = self
			.registered
			.lock()
			.unwrap_or_else(std::sync::PoisonError::into_inner);
		registered.remove(bus_name);
	}

	/// Who is registered, most recently first.
	#[must_use]
	pub(crate) fn names(&self) -> Vec<String> {
		let registered = self
			.registered
			.lock()
			.unwrap_or_else(std::sync::PoisonError::into_inner);
		registered.keys().cloned().collect()
	}
}

/// The `AgentManager` object.
pub(crate) struct AgentManager {
	state: Arc<State>,
}

impl AgentManager {
	/// An agent manager over one state.
	#[must_use]
	pub(crate) fn new(state: Arc<State>) -> Self {
		Self { state }
	}
}

#[zbus::interface(
	name = "org.freedesktop.NetworkManager.AgentManager",
	introspection_docs = false
)]
impl AgentManager {
	/// Register a secret agent.
	///
	/// The identifier is the agent's own name for itself -- NM requires a
	/// reverse-DNS string and uses it in logs. It is recorded and otherwise
	/// unused: what identifies an agent for the purpose of calling it is its
	/// bus name, which the bus assigns and a client cannot forge.
	///
	/// # Errors
	///
	/// Returns an error if the bus did not say who is calling.
	fn register(
		&self,
		identifier: &str,
		#[zbus(header)] header: zbus::message::Header<'_>,
	) -> zbus::fdo::Result<()> {
		let sender = sender_of(&header)?;
		self.state.agents().register(sender, identifier.to_owned());
		Ok(())
	}

	/// The same, with capabilities the shim does not use.
	///
	/// The only capability NM defines is VPN hints. Recording it and acting on
	/// nothing would be a claim; the argument is accepted because clients send
	/// it, and dropped because there is no VPN here to hint about.
	///
	/// # Errors
	///
	/// As [`Self::register`].
	fn register_with_capabilities(
		&self,
		identifier: &str,
		capabilities: u32,
		#[zbus(header)] header: zbus::message::Header<'_>,
	) -> zbus::fdo::Result<()> {
		let _ = capabilities;
		self.register(identifier, header)
	}

	/// Stop being asked.
	///
	/// # Errors
	///
	/// As [`Self::register`].
	fn unregister(
		&self,
		#[zbus(header)] header: zbus::message::Header<'_>,
	) -> zbus::fdo::Result<()> {
		let sender = sender_of(&header)?;
		self.state.agents().unregister(&sender);
		Ok(())
	}
}

/// Who sent a message, as the bus reported it.
fn sender_of(header: &zbus::message::Header<'_>) -> zbus::fdo::Result<String> {
	header
		.sender()
		.map(|sender| sender.as_str().to_owned())
		.ok_or_else(|| {
			zbus::fdo::Error::Failed(
				"the bus did not say who is calling, so this agent cannot be registered".to_owned(),
			)
		})
}

/// Ask a registered agent for a network's passphrase.
///
/// Returns `None` when no agent is registered, which is the ordinary state of a
/// machine with no desktop on it -- the caller then reports netcfgd's own
/// "secret was not found" rather than inventing a failure about agents.
///
/// # Errors
///
/// Returns a message when an agent was asked and refused, or answered with
/// something that is not a passphrase. A user pressing cancel arrives here, and
/// it is not a fault: the message says so.
pub(crate) async fn ask_for_passphrase(
	connection: &zbus::Connection,
	state: &Arc<State>,
	asker: Option<&str>,
	settings: &crate::settings::Dict,
	profile_path: &zbus::zvariant::OwnedObjectPath,
) -> Result<Option<String>, String> {
	crate::trace::mark("ask: creating the bus proxy");
	let bus = zbus::fdo::DBusProxy::new(connection)
		.await
		.map_err(|error| format!("cannot reach the bus: {error}"))?;

	crate::trace::mark("ask: bus proxy ready");
	for name in state.agents().names() {
		// **Never the caller.** A secret is asked for from inside
		// `ActivateConnection`, before it returns -- so a client that
		// registered an agent of its own and then activated a profile is
		// sitting on a blocking call waiting for this very reply, and cannot
		// answer a question. nmcli does exactly that: it registers a secret
		// agent for `connection up`, and the shim asking it produced a
		// circular wait that unwound at GDBus's twenty-five-second default,
		// intermittently, depending on which agent came first out of the list.
		//
		// Real NetworkManager does not have this problem because it returns the
		// active-connection path first and asks for secrets during the
		// asynchronous activation that follows; the caller is free by then.
		// Until the shim's activation is asynchronous too, the caller is the
		// one party that provably cannot answer, and skipping it costs nothing:
		// any other registered agent is still asked (0107).
		if asker.is_some_and(|asker| asker == name.as_str()) {
			crate::trace::mark("ask: skipping the caller's own agent");
			continue;
		}
		let Ok(bus_name) = zbus::names::BusName::try_from(name.clone()) else {
			continue;
		};
		// An agent whose process has gone leaves its registration behind: NM
		// watches NameOwnerChanged for this, and asking the bus at the moment
		// it matters gets the same answer with no signal plumbing and no
		// window where a stale entry is believed.
		crate::trace::mark("ask: calling NameHasOwner");
		let owned = bus.name_has_owner(bus_name.clone()).await;
		crate::trace::mark("ask: NameHasOwner returned");
		if !matches!(owned, Ok(true)) {
			state.agents().unregister(&name);
			continue;
		}

		crate::trace::mark("ask: building the agent proxy");
		let proxy = zbus::Proxy::new(connection, bus_name, AGENT_PATH, AGENT_INTERFACE)
			.await
			.map_err(|error| format!("cannot reach the secret agent `{name}`: {error}"))?;

		// The flags say a person is waiting, which is what lets the agent put
		// a dialog on the screen instead of failing quietly.
		crate::trace::asking(name.as_str());
		crate::trace::mark("ask: calling GetSecrets");
		let answer: Result<crate::settings::Dict, _> = proxy
			.call(
				"GetSecrets",
				&(
					settings,
					profile_path,
					"802-11-wireless-security",
					Vec::<String>::new(),
					flags::ALLOW_INTERACTION | flags::USER_REQUESTED,
				),
			)
			.await;
		crate::trace::mark("ask: GetSecrets returned");

		let returned = answer.map_err(|error| {
			// A user pressing cancel is a D-Bus error from the agent, and it
			// is not a fault to report as one. NM's own agents return
			// `UserCanceled` here.
			format!("the secret agent `{name}` did not supply a passphrase: {error}")
		})?;

		if let Some(passphrase) = passphrase_in(&returned) {
			return Ok(Some(passphrase));
		}
		return Err(format!(
			"the secret agent `{name}` answered without a passphrase in it"
		));
	}

	Ok(None)
}

/// Pull the passphrase out of what an agent returned.
#[must_use]
pub(crate) fn passphrase_in(returned: &crate::settings::Dict) -> Option<String> {
	let group = returned.get("802-11-wireless-security")?;
	let value = group.get("psk")?;
	String::try_from(value.try_clone().ok()?).ok()
}

#[cfg(test)]
mod tests {
	use super::*;
	use std::collections::HashMap;
	use zbus::zvariant::{OwnedValue, Value};

	#[test]
	fn agents_are_remembered_by_bus_name_and_forgotten_on_request() {
		let agents = Agents::default();
		agents.register(":1.42".to_owned(), "org.gnome.nm-applet".to_owned());
		agents.register(":1.43".to_owned(), "org.kde.plasma-nm".to_owned());
		assert_eq!(agents.names(), vec![":1.42".to_owned(), ":1.43".to_owned()]);

		agents.unregister(":1.42");
		assert_eq!(agents.names(), vec![":1.43".to_owned()]);
	}

	/// Registering twice from one connection is one agent, not two. A client
	/// that re-registers after a reconnect is ordinary, and asking it twice
	/// would put two dialogs on the screen.
	#[test]
	fn registering_twice_from_one_connection_is_one_agent() {
		let agents = Agents::default();
		agents.register(":1.42".to_owned(), "first".to_owned());
		agents.register(":1.42".to_owned(), "second".to_owned());
		assert_eq!(agents.names().len(), 1);
	}

	#[test]
	fn a_passphrase_is_found_where_nm_puts_it() {
		let mut returned = crate::settings::Dict::new();
		let mut group = HashMap::new();
		group.insert(
			"psk".to_owned(),
			OwnedValue::try_from(Value::from("hunter2hunter2")).expect("a value"),
		);
		returned.insert("802-11-wireless-security".to_owned(), group);
		assert_eq!(passphrase_in(&returned), Some("hunter2hunter2".to_owned()));

		// An answer with the group and no key is not a passphrase, and must
		// not be read as an empty one -- which would be written to the
		// provider and then fail to associate for a reason nobody could see.
		let mut empty = crate::settings::Dict::new();
		empty.insert("802-11-wireless-security".to_owned(), HashMap::new());
		assert_eq!(passphrase_in(&empty), None);
		assert_eq!(passphrase_in(&crate::settings::Dict::new()), None);
	}
}
