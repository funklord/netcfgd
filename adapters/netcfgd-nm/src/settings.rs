//! `org.freedesktop.NetworkManager.Settings`, and the profiles under it.
//!
//! A netcfgd `network` block or `interface` block becomes one NM connection
//! profile. The projection is one-way and lossy in netcfgd's favour: the
//! document says things NM's settings dictionary has no field for, and the
//! dictionary has fields netcfgd would never store. Neither is a problem while
//! the arrow points this way -- design section 9.2's whole discipline is that a
//! foreign model may be *produced* from the native one and never consulted for
//! what the native one should contain.
//!
//! Two things are deliberately not here. Secrets never leave: `GetSecrets`
//! refuses, because the document holds a `SecretRef` and handing the resolved
//! value to any D-Bus client would be a worse leak than the one constraint 5
//! exists to prevent. And writes are refused: section 9.4 gives GUI-created
//! profiles their own directory under `/etc/netcfgd/conf.d/nm/`, which is a
//! write path with its own commit and its own decisions to make.

use crate::state::State;
use netcfgd_model::{AddressSource, Interface, Security, WifiNetwork};
use std::collections::HashMap;
use std::sync::Arc;
use zbus::zvariant::{OwnedObjectPath, OwnedValue, Value};

/// The namespace netcfgd derives connection UUIDs in.
///
/// Design section 9.3: rather than storing UUIDs -- which would be state
/// outside the configuration files, and constraint 1 forbids that -- they are
/// derived as `UUIDv5` over a fixed namespace plus the profile's identity. The
/// same config produces the same UUIDs on another machine, and a GUI client's
/// stored reference survives a restart because nothing generated it in the
/// first place.
///
/// The constant itself is an ordinary random v4 UUID, generated once and
/// written down here. It has no meaning beyond being ours and never changing:
/// changing it renames every profile every client has ever seen.
const NAMESPACE: uuid::Uuid = uuid::uuid!("4ed6290d-3761-405c-8ad8-0d40f258ee63");

/// What a connection profile came from.
///
/// The two kinds differ in more than their settings dictionary: a wifi profile
/// can be activated on any radio, and an interface profile is the interface.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Profile {
	/// A `network` block: an SSID netcfgd knows how to join.
	Network(Box<WifiNetwork>),
	/// An `interface` block: a link netcfgd configures.
	Interface(Box<Interface>),
}

impl Profile {
	/// The identity UUIDs are derived from.
	///
	/// Prefixed by kind, so a `network` block and an `interface` block that
	/// happen to share a name are still two profiles. Without the prefix, an
	/// `interface wlan0` and a `network "wlan0"` would collide, which is
	/// unlikely and would be baffling.
	#[must_use]
	pub(crate) fn identity(&self) -> String {
		match self {
			Self::Network(network) => format!("network:{}", network.id),
			Self::Interface(interface) => format!("interface:{}", interface.name),
		}
	}

	/// The name a client displays.
	#[must_use]
	pub(crate) fn id(&self) -> String {
		match self {
			Self::Network(network) => network.id.clone(),
			Self::Interface(interface) => interface.name.clone(),
		}
	}

	/// NM's connection type string.
	#[must_use]
	pub(crate) fn kind(&self) -> &'static str {
		match self {
			Self::Network(_) => "802-11-wireless",
			Self::Interface(_) => "802-3-ethernet",
		}
	}

	/// The addressing the profile asks for.
	#[must_use]
	pub(crate) fn addressing(&self) -> &[AddressSource] {
		match self {
			Self::Network(network) => &network.addressing,
			Self::Interface(interface) => &interface.addressing,
		}
	}

	/// Its DNS policy, where it has one.
	#[must_use]
	pub(crate) fn dns(&self) -> Option<&netcfgd_model::DnsPolicy> {
		match self {
			Self::Network(network) => network.dns.as_ref(),
			Self::Interface(interface) => interface.dns.as_ref(),
		}
	}

	/// The routes it asks for.
	#[must_use]
	pub(crate) fn routes(&self) -> &[netcfgd_model::Route] {
		match self {
			Self::Network(network) => &network.routes,
			Self::Interface(interface) => &interface.routes,
		}
	}

	/// Which interface this profile is bound to, where it is bound to one.
	///
	/// A wifi profile is not: design section 9.3 keeps a `network` block
	/// unbound because an SSID may be in range of any radio, which is the same
	/// reason netcfgd's own model separates `network` from `device`.
	#[must_use]
	pub(crate) fn interface(&self) -> Option<String> {
		match self {
			Self::Network(_) => None,
			Self::Interface(interface) => Some(interface.name.clone()),
		}
	}
}

/// The UUID for a profile.
#[must_use]
pub(crate) fn uuid_of(profile: &Profile) -> String {
	uuid::Uuid::new_v5(&NAMESPACE, profile.identity().as_bytes()).to_string()
}

/// The object path for a connection number.
#[must_use]
pub(crate) fn path_for(number: u32) -> OwnedObjectPath {
	OwnedObjectPath::try_from(format!("/org/freedesktop/NetworkManager/Settings/{number}"))
		.expect("a settings path built from a number is always valid")
}

/// One group of NM settings.
type Group = HashMap<String, OwnedValue>;
/// A whole settings dictionary.
pub(crate) type Dict = HashMap<String, Group>;

/// A string, as a settings value.
///
/// `try_from` rather than `from`: converting a borrowed `Value` into an owned
/// one can fail for the variants that hold file descriptors, which none of
/// these do. The `expect` is on a case the type system cannot rule out and the
/// code cannot reach.
fn text(value: impl Into<String>) -> OwnedValue {
	OwnedValue::try_from(Value::from(value.into())).expect("a string owns itself")
}

fn number(value: u32) -> OwnedValue {
	OwnedValue::try_from(Value::from(value)).expect("a number owns itself")
}

/// NM's `NM_METERED_YES`.
pub(crate) const METERED_YES: i32 = 1;
/// NM's `NM_METERED_NO`.
pub(crate) const METERED_NO: i32 = 2;

fn signed(value: i32) -> OwnedValue {
	OwnedValue::try_from(Value::from(value)).expect("a number owns itself")
}

fn strings(values: Vec<String>) -> OwnedValue {
	OwnedValue::try_from(Value::from(values)).expect("an array of strings owns itself")
}

/// Nameservers in NM's deprecated packed form.
///
/// `au` for IPv4 and `aay` for IPv6, which is the same split the address
/// configuration objects have and for the same reason: an IPv6 address does not
/// fit in a `u32`.
fn packed_servers(servers: &[std::net::IpAddr], v6: bool) -> OwnedValue {
	if v6 {
		let octets: Vec<Vec<u8>> = servers
			.iter()
			.filter_map(|address| match address {
				std::net::IpAddr::V6(v6) => Some(v6.octets().to_vec()),
				std::net::IpAddr::V4(_) => None,
			})
			.collect();
		OwnedValue::try_from(Value::from(octets)).expect("an array owns itself")
	} else {
		let words: Vec<u32> = servers
			.iter()
			.filter_map(|address| match address {
				std::net::IpAddr::V4(v4) => Some(crate::ipconfig::packed(*v4)),
				std::net::IpAddr::V6(_) => None,
			})
			.collect();
		OwnedValue::try_from(Value::from(words)).expect("an array owns itself")
	}
}

fn flag(value: bool) -> OwnedValue {
	OwnedValue::try_from(Value::from(value)).expect("a boolean owns itself")
}

fn octets(value: Vec<u8>) -> OwnedValue {
	OwnedValue::try_from(Value::from(value)).expect("a byte array owns itself")
}

/// How NM spells the addressing netcfgd was given.
///
/// Only the method, which is the field every client reads and the only one
/// that changes what a panel shows. Static addresses would go in
/// `address-data`, and rendering them is work with no reader until the settings
/// panels of tier 2 -- so this reports `manual` and leaves the list empty,
/// which is honest about what is being said rather than silently claiming
/// `auto`.
#[must_use]
pub(crate) fn ipv4_method(addressing: &[AddressSource]) -> &'static str {
	if addressing
		.iter()
		.any(|source| matches!(source, AddressSource::Dhcp4(_)))
	{
		"auto"
	} else if addressing
		.iter()
		.any(|source| matches!(source, AddressSource::Static(_)))
	{
		"manual"
	} else {
		"disabled"
	}
}

/// The same question for IPv6, where "the kernel does it" is a separate answer.
#[must_use]
pub(crate) fn ipv6_method(addressing: &[AddressSource]) -> &'static str {
	if addressing
		.iter()
		.any(|source| matches!(source, AddressSource::Slaac(_)))
	{
		"auto"
	} else if addressing
		.iter()
		.any(|source| matches!(source, AddressSource::Dhcp6(_)))
	{
		"dhcp"
	} else if addressing
		.iter()
		.any(|source| matches!(source, AddressSource::Static(_)))
	{
		"manual"
	} else if addressing
		.iter()
		.any(|source| matches!(source, AddressSource::LinkLocal))
	{
		"link-local"
	} else {
		"ignore"
	}
}

/// How NM spells a network's security.
///
/// `key-mgmt` is the field a client switches on to decide what credential to
/// ask for, so it carries the same distinctions [`crate::accesspoint`] puts in
/// `RsnFlags` and for the same reason.
#[must_use]
pub(crate) fn key_management(security: &Security) -> Option<&'static str> {
	match security {
		Security::Open => None,
		Security::Psk(psk) => Some(match psk.proto {
			netcfgd_model::security::PskProto::Wpa2 => "wpa-psk",
			// SAE, and "wpa-psk wpa-psk-sha256 sae" for the transition case --
			// except `key-mgmt` takes exactly one value, so a transition
			// network is reported as SAE. A WPA2-only client reading this
			// would refuse a network it could in fact join; reporting
			// `wpa-psk` instead would have a WPA3 client silently downgrade,
			// which is the worse of the two.
			netcfgd_model::security::PskProto::Wpa3
			| netcfgd_model::security::PskProto::Wpa2Wpa3 => "sae",
		}),
		Security::Eap(_) => Some("wpa-eap"),
		Security::Owe => Some("owe"),
	}
}

/// Render a profile as NM's settings dictionary.
///
/// The shape was read off a running `NetworkManager` 1.52, which reports six
/// groups for a wifi profile. Four are reproduced; `proxy` is empty there too,
/// and `seen-bssids` is a cache NM keeps and netcfgd does not.
#[must_use]
pub(crate) fn settings_of(profile: &Profile) -> Dict {
	let mut dict = Dict::new();

	let mut connection = Group::new();
	connection.insert("id".to_owned(), text(profile.id()));
	connection.insert("uuid".to_owned(), text(uuid_of(profile)));
	connection.insert("type".to_owned(), text(profile.kind()));
	if let Some(interface) = profile.interface() {
		connection.insert("interface-name".to_owned(), text(interface));
	}
	if let Profile::Network(network) = profile {
		connection.insert("autoconnect".to_owned(), flag(network.autoconnect));
		connection.insert("autoconnect-priority".to_owned(), signed(network.priority));
		// NM's `connection.metered` is a tri-state and netcfgd's is a boolean,
		// so `false` becomes an explicit "no" rather than "unknown". An
		// operator who wrote `metered = false` said something, and reporting it
		// as unknown would have a desktop guess at it instead.
		connection.insert(
			"metered".to_owned(),
			signed(if network.metered {
				METERED_YES
			} else {
				METERED_NO
			}),
		);
	}
	dict.insert("connection".to_owned(), connection);

	match profile {
		Profile::Network(network) => {
			let mut wireless = Group::new();
			// NetworkManager's `802-11-wireless` requires an SSID, and a
			// network that names access points instead has not been given one
			// yet -- netcfgd reads it off a scan at apply time. Projecting an
			// empty one would describe a profile that matches anything, so the
			// name is left out and the rest of the profile still carries the
			// addresses it is restricted to. Constraint 6's direction: the shim
			// reports what netcfgd has, and does not invent what it does not.
			if let Some(ssid) = &network.ssid {
				wireless.insert("ssid".to_owned(), octets(ssid.as_bytes().to_vec()));
			}
			wireless.insert("mode".to_owned(), text("infrastructure"));
			if network.hidden {
				wireless.insert("hidden".to_owned(), flag(true));
			}
			// One address is NM's `bssid`, which pins. A list has no
			// equivalent -- NM has no "any of these" -- so it is not projected
			// rather than projected as a pin on whichever happened to be first.
			if let [only] = network.bssid.as_slice() {
				wireless.insert("bssid".to_owned(), text(only.clone()));
			}
			if key_management(&network.security).is_some() {
				wireless.insert("security".to_owned(), text("802-11-wireless-security"));
			}
			dict.insert("802-11-wireless".to_owned(), wireless);

			if let Some(key_mgmt) = key_management(&network.security) {
				let mut security = Group::new();
				security.insert("key-mgmt".to_owned(), text(key_mgmt));
				// System-owned, and it means what it says: netcfgd holds the
				// credential and will use it. A client reading this does not
				// prompt, which is correct -- there is nothing for a user to
				// type that netcfgd does not already have.
				security.insert("psk-flags".to_owned(), number(0));
				dict.insert("802-11-wireless-security".to_owned(), security);
			}

			insert_ip(&mut dict, profile);
		}
		Profile::Interface(interface) => {
			let mut ethernet = Group::new();
			// The one per-connection option that lives on an interface rather
			// than a network: netcfgd has no per-SSID MTU, and a client asking
			// for one is told so in the file it gets back.
			if let Some(mtu) = interface.mtu {
				ethernet.insert("mtu".to_owned(), number(mtu));
			}
			dict.insert("802-3-ethernet".to_owned(), ethernet);
			insert_ip(&mut dict, profile);
		}
	}

	dict
}

/// The two IP groups, with whatever the profile actually says.
///
/// The method alone was enough while nothing read the rest. A settings panel
/// reads all of it: a profile reporting `manual` and no addresses is one the
/// panel draws as an empty table, and an operator who then presses save has
/// just deleted their static address.
fn insert_ip(dict: &mut Dict, profile: &Profile) {
	for v6 in [false, true] {
		let mut group = Group::new();
		let method = if v6 {
			ipv6_method(profile.addressing())
		} else {
			ipv4_method(profile.addressing())
		};
		group.insert("method".to_owned(), text(method));

		let addresses: Vec<HashMap<String, OwnedValue>> = profile
			.addressing()
			.iter()
			.filter_map(|source| match source {
				AddressSource::Static(fixed) => crate::ipconfig::parse_cidr(&fixed.address),
				_ => None,
			})
			.filter(|address| address.address.is_ipv6() == v6)
			.map(|address| crate::ipconfig::address_entry(&address))
			.collect();
		if !addresses.is_empty() {
			group.insert("address-data".to_owned(), array_of(addresses));
		}

		// NM splits what netcfgd keeps together: the default route's next hop
		// is `gateway`, and everything else is `route-data`. Reporting the
		// default route in both would have a panel show a route table with a
		// duplicate of the gateway in it.
		if let Some(gateway) = gateway_of(profile.routes(), v6) {
			group.insert("gateway".to_owned(), text(gateway.to_string()));
		}
		let routes: Vec<HashMap<String, OwnedValue>> = profile
			.routes()
			.iter()
			.filter(|route| !is_default(&route.destination))
			.filter(|route| route.destination.contains(':') == v6)
			.map(|route| {
				let (destination, prefix) = crate::ipconfig::destination_of(&route.destination, v6);
				crate::ipconfig::route_entry(&destination, prefix, route.via, route.metric)
			})
			.collect();
		if !routes.is_empty() {
			group.insert("route-data".to_owned(), array_of(routes));
		}

		// The profile's own DNS, in both of NM's spellings. `dns-data` is what
		// a current client sends and reads; `dns` is the packed form that
		// older ones still use, and serving only one of them works until it
		// does not.
		//
		// Only where the method allows it. libnm validates the whole
		// dictionary before it will activate anything, and `ipv4.dns` beside
		// `method=disabled` is invalid -- so a network with nameservers and no
		// addressing in that family had a profile no client would connect
		// with. Losing the field is much cheaper than losing the profile, and
		// NM has no way to say "no addressing, but these nameservers" anyway.
		let carries_dns = !matches!(method, "disabled" | "ignore");
		if let Some(policy) = profile.dns().filter(|_| carries_dns) {
			let servers: Vec<std::net::IpAddr> = policy
				.servers
				.iter()
				.map(|server| server.addr)
				.filter(|address| address.is_ipv6() == v6)
				.collect();
			if !servers.is_empty() {
				group.insert(
					"dns-data".to_owned(),
					strings(servers.iter().map(ToString::to_string).collect()),
				);
				group.insert("dns".to_owned(), packed_servers(&servers, v6));
			}
			if !policy.search.is_empty() {
				group.insert("dns-search".to_owned(), strings(policy.search.clone()));
			}
		}

		dict.insert(if v6 { "ipv6" } else { "ipv4" }.to_owned(), group);
	}
}

/// Whether a destination is the default route, in either spelling.
#[must_use]
pub(crate) fn is_default(destination: &str) -> bool {
	destination == "default" || destination == "0.0.0.0/0" || destination == "::/0"
}

/// The next hop of a profile's default route, in one family.
#[must_use]
fn gateway_of(routes: &[netcfgd_model::Route], v6: bool) -> Option<std::net::IpAddr> {
	routes
		.iter()
		.find(|route| {
			is_default(&route.destination) && route.via.is_some_and(|via| via.is_ipv6() == v6)
		})
		.and_then(|route| route.via)
}

/// An array of settings entries, which is what `address-data` and `route-data`
/// are: `aa{sv}`, a list of little dictionaries.
fn array_of(entries: Vec<HashMap<String, OwnedValue>>) -> OwnedValue {
	OwnedValue::try_from(Value::from(entries)).expect("an array of dictionaries owns itself")
}

/// The `Settings` object.
pub(crate) struct Settings {
	state: Arc<State>,
}

impl Settings {
	/// A settings object over one state.
	#[must_use]
	pub(crate) fn new(state: Arc<State>) -> Self {
		Self { state }
	}
}

#[zbus::interface(
	name = "org.freedesktop.NetworkManager.Settings",
	introspection_docs = false
)]
impl Settings {
	/// Every profile netcfgd's configuration describes.
	fn list_connections(&self) -> Vec<OwnedObjectPath> {
		self.connections()
	}

	/// Find one by UUID.
	///
	/// # Errors
	///
	/// Returns a D-Bus error when nothing matches, which is what NM does.
	fn get_connection_by_uuid(&self, uuid: &str) -> zbus::fdo::Result<OwnedObjectPath> {
		self.state
			.profiles()
			.into_iter()
			.find(|(profile, _)| uuid_of(profile) == uuid)
			.map(|(_, number)| path_for(number))
			.ok_or_else(|| {
				zbus::fdo::Error::Failed(format!(
					"no connection in netcfgd's configuration has uuid {uuid}"
				))
			})
	}

	/// Create a profile.
	///
	/// Design section 9.4: this writes a netcfgd `network` block into the
	/// operator's configuration and reloads. There is no profile store to add
	/// to -- the file *is* the profile, and it stays valid with this program
	/// uninstalled.
	///
	/// # Errors
	///
	/// Returns a refusal naming what could not be written: a caller who may not
	/// change the configuration, a connection type netcfgd has no block for, or
	/// a configuration that no longer compiles with the new file in it.
	async fn add_connection(
		&self,
		settings: Dict,
		#[zbus(header)] header: zbus::message::Header<'_>,
		#[zbus(connection)] connection: &zbus::Connection,
	) -> zbus::fdo::Result<OwnedObjectPath> {
		let caller = caller_uid(&header, connection).await?;
		self.authorize(caller)?;

		let emitted = crate::emit::network_block(&settings)
			.map_err(|error| zbus::fdo::Error::InvalidArgs(error.to_string()))?;
		let identity = format!("network:{}", emitted.id);

		crate::store::write(&emitted).map_err(zbus::fdo::Error::Failed)?;

		// Reload before answering, so a client that reads the returned path
		// immediately finds an object there. It also means a block that does
		// not compile is reported *here*, as a failed AddConnection, rather
		// than as a machine that quietly stopped reconciling.
		if let Err(error) = self.state.reload() {
			// The file is what broke the configuration, so it goes. Leaving it
			// would leave the machine with a config that does not compile
			// because of something a GUI did and nobody can see.
			let _ = crate::store::remove(&emitted.id);
			let _ = self.state.reload();
			return Err(zbus::fdo::Error::Failed(format!(
				"netcfgd would not accept the new network: {error}. The file has been \
				 removed again"
			)));
		}

		let path = self
			.state
			.profiles()
			.into_iter()
			.find(|(profile, _)| profile.identity() == identity)
			.map(|(_, number)| path_for(number))
			.ok_or_else(|| {
				zbus::fdo::Error::Failed(format!(
					"wrote `{}` but netcfgd does not report it; the file may have been \
					 overridden by another block with the same name",
					emitted.id
				))
			})?;

		// Serve it before answering. The main loop publishes profiles too, when
		// netcfgd's reload event arrives -- but a client calls `GetSettings` on
		// the path this returns immediately, and "operation succeeded but the
		// object does not exist" is what it says when the two race. Registering
		// here is idempotent with the main loop's pass.
		self.republish(connection.object_server()).await?;
		Ok(path)
	}

	/// The newer spelling, which `nmcli connection add` prefers.
	///
	/// It has to exist rather than being left to the older one: a client that
	/// finds the method missing reports "Unknown method 'AddConnection2'",
	/// which tells the operator nothing about netcfgd whether the answer is
	/// yes or no.
	///
	/// # Errors
	///
	/// As [`Self::add_connection`]. The flags and extra arguments are NM's
	/// (block-autoconnect, and a request for the settings back); neither
	/// changes what is written, so both are dropped rather than half-honoured.
	async fn add_connection2(
		&self,
		settings: Dict,
		flags: u32,
		args: HashMap<String, OwnedValue>,
		#[zbus(header)] header: zbus::message::Header<'_>,
		#[zbus(connection)] connection: &zbus::Connection,
	) -> zbus::fdo::Result<(OwnedObjectPath, HashMap<String, OwnedValue>)> {
		drop((flags, args));
		self.add_connection(settings, header, connection)
			.await
			.map(|path| (path, HashMap::new()))
	}

	/// Create a profile that is not written to disk.
	///
	/// # Errors
	///
	/// Always. There is nowhere for an unsaved profile to live: netcfgd's
	/// authority is its files, and a profile held only in this process would be
	/// exactly the hidden state constraint 1 forbids.
	fn add_connection_unsaved(&self, settings: Dict) -> zbus::fdo::Result<OwnedObjectPath> {
		drop(settings);
		Err(zbus::fdo::Error::AuthFailed(
			"netcfgd has nowhere to put an unsaved profile. Its authority is its files, \
			 and a profile held only in this process would be exactly the hidden state \
			 constraint 1 exists to prevent"
				.to_owned(),
		))
	}

	/// Re-read the configuration.
	///
	/// # Errors
	///
	/// Returns netcfgd's own message if the reload fails.
	fn reload_connections(&self) -> zbus::fdo::Result<bool> {
		self.state
			.reload()
			.map(|_| true)
			.map_err(zbus::fdo::Error::Failed)
	}

	#[zbus(property)]
	fn connections(&self) -> Vec<OwnedObjectPath> {
		self.state
			.profiles()
			.into_iter()
			.map(|(_, number)| path_for(number))
			.collect()
	}

	#[zbus(property)]
	fn hostname(&self) -> String {
		// netcfgd has a hostname policy rather than a hostname, and reporting
		// the machine's current one would be answering a different question
		// from the one asked. Empty is NM's own answer for "not managed here".
		String::new()
	}

	#[zbus(property)]
	fn can_modify(&self) -> bool {
		// True now that profiles can be created. Clients render this: a GUI
		// that reads false greys out its "add" button, which would hide a
		// feature that works.
		true
	}
}

impl Settings {
	/// Make sure every profile netcfgd reports has an object.
	///
	/// Idempotent: `at` answers false for a path already served, so this can
	/// run from a method handler and from the main loop without the two
	/// treading on each other.
	async fn republish(&self, server: &zbus::ObjectServer) -> zbus::fdo::Result<()> {
		for (profile, number) in self.state.profiles() {
			server
				.at(
					path_for(number),
					Connection::new(Arc::clone(&self.state), profile.identity()),
				)
				.await?;
		}
		Ok(())
	}

	/// Whether a caller may change the configuration.
	fn authorize(&self, caller: u32) -> zbus::fdo::Result<()> {
		crate::store::may_write(caller, &self.state.admin_principal())
			.map_err(zbus::fdo::Error::AuthFailed)
	}
}

/// Who is calling.
///
/// From the bus rather than from the message: a sender name can be anything the
/// client puts there, and `GetConnectionUnixUser` is the bus telling us what it
/// knows about the connection. That distinction is the whole security of this.
pub(crate) async fn caller_uid(
	header: &zbus::message::Header<'_>,
	connection: &zbus::Connection,
) -> zbus::fdo::Result<u32> {
	let Some(sender) = header.sender() else {
		return Err(zbus::fdo::Error::AuthFailed(
			"the bus did not say who is calling, so this cannot decide whether they may \
			 change the configuration"
				.to_owned(),
		));
	};
	let bus = zbus::fdo::DBusProxy::new(connection).await?;
	bus.get_connection_unix_user(sender.clone().into()).await
}

/// One connection profile.
pub(crate) struct Connection {
	state: Arc<State>,
	identity: String,
}

impl Connection {
	/// A connection object for one profile identity.
	#[must_use]
	pub(crate) fn new(state: Arc<State>, identity: String) -> Self {
		Self { state, identity }
	}

	fn profile(&self) -> Option<Profile> {
		self.state.profile(&self.identity)
	}
}

#[zbus::interface(
	name = "org.freedesktop.NetworkManager.Settings.Connection",
	introspection_docs = false
)]
impl Connection {
	/// The profile, as NM's settings dictionary.
	///
	/// # Errors
	///
	/// Returns an error if the profile has left the configuration, which a
	/// client sees between a reload and the object being unregistered.
	fn get_settings(&self) -> zbus::fdo::Result<Dict> {
		self.profile()
			.map(|profile| settings_of(&profile))
			.ok_or_else(|| {
				zbus::fdo::Error::Failed(format!(
					"`{}` is no longer in netcfgd's configuration",
					self.identity
				))
			})
	}

	/// The credential.
	///
	/// # Errors
	///
	/// Always, and deliberately. The document holds a `SecretRef` and netcfgd
	/// resolves it inside the daemon; handing the resolved value to a D-Bus
	/// client would put a passphrase on a bus any local process can name. NM
	/// itself gates this behind polkit, and netcfgd's answer is that there is
	/// nothing to gate -- the secret does not travel.
	///
	/// This costs nothing a client needs. `psk-flags` is reported as
	/// system-owned, so a client knows the daemon holds the credential and
	/// does not prompt.
	fn get_secrets(&self, group: &str) -> zbus::fdo::Result<Dict> {
		let _ = group;
		Err(zbus::fdo::Error::AuthFailed(
			"netcfgd does not hand out secrets. The configuration holds a reference \
			 and the daemon resolves it when it connects; nothing needs the value on \
			 the bus, and putting it there would be a leak with no beneficiary"
				.to_owned(),
		))
	}

	/// Change the profile.
	///
	/// # Errors
	///
	/// Always. Section 9.4 exposes hand-written blocks read-only for exactly
	/// this reason: a stray click in a settings panel must not rewrite a tuned
	/// `interface eth0`, and the error a GUI already renders is the right way
	/// to say so.
	async fn update(
		&self,
		settings: Dict,
		#[zbus(header)] header: zbus::message::Header<'_>,
		#[zbus(connection)] connection: &zbus::Connection,
	) -> zbus::fdo::Result<()> {
		let caller = caller_uid(&header, connection).await?;
		let id = self
			.identity
			.strip_prefix("network:")
			.unwrap_or(&self.identity);
		self.writable(id)?;
		crate::store::may_write(caller, &self.state.admin_principal())
			.map_err(zbus::fdo::Error::AuthFailed)?;

		// A client updating a profile sends back what `GetSettings` gave it,
		// which never includes the passphrase -- so an update that changed the
		// hidden flag would arrive with no `psk` and be refused for missing
		// one. The credential is not being changed, so the stored one stands.
		let emitted =
			crate::emit::network_block_keeping_secret(&settings, crate::store::has_secret(id))
				.map_err(|error| zbus::fdo::Error::InvalidArgs(error.to_string()))?;
		// Renaming is a delete and an add, because the block label is the
		// identity and the filename is derived from it. Doing it silently would
		// leave the old file behind as a second network nobody asked for.
		if emitted.id != id {
			crate::store::remove(id).map_err(zbus::fdo::Error::Failed)?;
		}
		crate::store::write(&emitted).map_err(zbus::fdo::Error::Failed)?;
		// Posted rather than done here: see `Job::Reload`.
		self.state
			.request_reload()
			.map_err(zbus::fdo::Error::Failed)
	}

	/// Whether this profile is one the shim wrote and may therefore change.
	fn writable(&self, id: &str) -> zbus::fdo::Result<()> {
		if crate::store::is_machine_generated(id) {
			return Ok(());
		}
		Err(zbus::fdo::Error::AuthFailed(format!(
			"`{}` is a hand-written netcfgd block and is read-only here (design section \
			 9.4). Edit it in /etc/netcfgd and run `ncfg apply` -- a GUI that could \
			 rewrite a tuned interface with a stray click is the thing that rule exists \
			 to prevent. Networks this shim created are editable, because it knows it \
			 wrote them",
			self.identity
		)))
	}

	/// Delete the profile.
	///
	/// # Errors
	///
	/// Always, for the reason [`Self::update`] gives.
	async fn delete(
		&self,
		#[zbus(header)] header: zbus::message::Header<'_>,
		#[zbus(connection)] connection: &zbus::Connection,
	) -> zbus::fdo::Result<()> {
		let caller = caller_uid(&header, connection).await?;
		let id = self
			.identity
			.strip_prefix("network:")
			.unwrap_or(&self.identity);
		self.writable(id)?;
		crate::store::may_write(caller, &self.state.admin_principal())
			.map_err(zbus::fdo::Error::AuthFailed)?;
		crate::store::remove(id).map_err(zbus::fdo::Error::Failed)?;
		// Posted rather than done here. Removing the file is the deletion; the
		// object that stands for it is unregistered by the main loop, which
		// cannot happen until this method has returned. See `Job::Reload`.
		self.state
			.request_reload()
			.map_err(zbus::fdo::Error::Failed)
	}

	/// The newer spelling of [`Self::update`], which `nmcli connection modify`
	/// calls.
	///
	/// # Errors
	///
	/// Always, and with netcfgd's own explanation rather than the bus's
	/// "Unknown method" -- which is what a client showed before this existed.
	async fn update2(
		&self,
		settings: Dict,
		flags: u32,
		args: HashMap<String, OwnedValue>,
		#[zbus(header)] header: zbus::message::Header<'_>,
		#[zbus(connection)] connection: &zbus::Connection,
	) -> zbus::fdo::Result<HashMap<String, OwnedValue>> {
		drop((flags, args));
		self.update(settings, header, connection)
			.await
			.map(|()| HashMap::new())
	}

	/// Change the profile without writing it.
	///
	/// # Errors
	///
	/// Always, as [`Self::update`].
	fn update_unsaved(&self, settings: Dict) -> zbus::fdo::Result<()> {
		drop(settings);
		Err(zbus::fdo::Error::AuthFailed(
			"netcfgd has nowhere to put an unsaved change: the file is the profile".to_owned(),
		))
	}

	/// Write an unsaved profile.
	///
	/// # Errors
	///
	/// Always. Nothing here is ever unsaved, so there is nothing to save.
	fn save(&self) {
		// Nothing here is ever unsaved: a profile is a file, and it was written
		// before this method could have been called. So this succeeds by doing
		// nothing, which is the honest answer rather than a refusal -- the
		// state being asked for is the state that holds.
	}

	/// Forget the stored credential.
	///
	/// # Errors
	///
	/// Always. The credential is a `SecretRef` in the configuration and a file
	/// wherever the provider keeps it; clearing it means editing those, which
	/// is the same boundary every other write here runs into.
	fn clear_secrets(&self) -> zbus::fdo::Result<()> {
		Err(zbus::fdo::Error::AuthFailed(
			"the credential is a `@secret:` reference in the configuration and a file \
			 wherever the provider keeps it. Clearing it means editing those, or deleting \
			 the network, which takes its secret with it"
				.to_owned(),
		))
	}

	#[zbus(property)]
	fn unsaved(&self) -> bool {
		false
	}

	/// NM bumps this on every change so clients can tell one apart.
	///
	/// netcfgd's profiles change when the files do, and nothing here observes
	/// that per profile -- so it is constant, which is honest for a store
	/// nothing can write through.
	#[zbus(property)]
	fn version_id(&self) -> u64 {
		0
	}

	#[zbus(property)]
	fn flags(&self) -> u32 {
		0
	}

	#[zbus(property)]
	fn filename(&self) -> String {
		// Where a client would look, and where the operator should. netcfgd's
		// config is a directory rather than a file per profile, so this names
		// the directory: a wrong-looking path is worse than an honest one.
		std::env::var("NCFG_CONFIG_DIR").unwrap_or_else(|_| "/etc/netcfgd".to_owned())
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use netcfgd_model::secret::{SecretProvider, SecretRef};
	use netcfgd_model::security::{PskConfig, PskProto};
	use netcfgd_model::Ssid;

	fn network(id: &str, security: Security) -> Profile {
		Profile::Network(Box::new(WifiNetwork {
			id: id.to_owned(),
			ssid: Some(Ssid::new(id.as_bytes().to_vec()).expect("a valid ssid")),
			hidden: false,
			security,
			priority: 0,
			autoconnect: true,
			metered: false,
			bssid: Vec::new(),
			roam: None,
			addressing: vec![AddressSource::Dhcp4(
				netcfgd_model::address::Dhcp4::default(),
			)],
			routes: Vec::new(),
			dns: None,
			hooks: Vec::new(),
		}))
	}

	/// A minimal interface block. `Interface` has no `Default`, deliberately:
	/// every field is a decision the compiler makes explicitly, and a default
	/// would let one be forgotten.
	fn interface(name: &str) -> Interface {
		Interface {
			name: name.to_owned(),
			kind: netcfgd_model::InterfaceKind::Physical,
			enabled: true,
			mtu: None,
			mac: None,
			addressing: Vec::new(),
			routes: Vec::new(),
			dns: None,
			hooks: Vec::new(),
			nat: None,
			qdisc: None,
			ingress_redirect: None,
			on_drift: None,
			master: None,
			dot1x: None,
			advertise: None,
			forwarding: None,
			guard: None,
			ipv6_token: None,
			link_settings: None,
			preference: None,
			probe: None,
			bridge_vlans: Vec::new(),
		}
	}

	fn psk(proto: PskProto) -> Security {
		Security::Psk(PskConfig {
			passphrase: SecretRef {
				provider: SecretProvider::File,
				name: "home".to_owned(),
			},
			proto,
		})
	}

	fn string_of(dict: &Dict, group: &str, key: &str) -> Option<String> {
		let value = dict.get(group)?.get(key)?;
		String::try_from(value.try_clone().ok()?).ok()
	}

	/// The same configuration produces the same UUIDs, on this machine and any
	/// other. That is the whole point of deriving rather than storing them:
	/// nothing generates one, so nothing has to remember it.
	#[test]
	fn a_uuid_is_derived_and_therefore_stable() {
		let first = uuid_of(&network("HomeFiber", Security::Open));
		let again = uuid_of(&network("HomeFiber", Security::Open));
		assert_eq!(first, again);
		// The literal, because this value is a promise to every client that
		// has ever stored it: changing the namespace or the identity format
		// renames every profile, and this test is what makes that a decision
		// rather than an accident.
		//
		// Computed by a second implementation rather than by reading it back
		// out of this one -- Python's `uuid.uuid5` over the same namespace and
		// name agrees, which is what makes this a check on the derivation
		// rather than a photograph of it.
		assert_eq!(first, "7b9da559-bfbe-5bf1-82b1-bc18e6e2e81a");
		assert_eq!(
			uuid_of(&Profile::Interface(Box::new(interface("wlan0")))),
			"b76831ed-4c06-5109-8f0c-53321dab799e"
		);
	}

	/// A profile's identity carries its kind, so an `interface wlan0` and a
	/// `network "wlan0"` are two profiles rather than one collision.
	#[test]
	fn the_two_kinds_of_profile_cannot_collide() {
		let as_network = network("wlan0", Security::Open);
		let as_interface = Profile::Interface(Box::new(interface("wlan0")));
		assert_ne!(uuid_of(&as_network), uuid_of(&as_interface));
		assert_eq!(as_network.identity(), "network:wlan0");
		assert_eq!(as_interface.identity(), "interface:wlan0");
	}

	#[test]
	fn a_wifi_profile_carries_the_ssid_as_octets_and_names_its_security() {
		let dict = settings_of(&network("HomeFiber", psk(PskProto::Wpa2)));
		assert_eq!(
			string_of(&dict, "connection", "type").as_deref(),
			Some("802-11-wireless")
		);
		assert_eq!(
			string_of(&dict, "802-11-wireless-security", "key-mgmt").as_deref(),
			Some("wpa-psk")
		);
		assert_eq!(
			string_of(&dict, "802-11-wireless", "security").as_deref(),
			Some("802-11-wireless-security")
		);
		// An SSID is octets in both models, so it goes across unchanged.
		let ssid = dict
			.get("802-11-wireless")
			.and_then(|group| group.get("ssid"))
			.expect("an ssid");
		assert_eq!(
			Vec::<u8>::try_from(ssid.try_clone().expect("cloneable")).expect("bytes"),
			b"HomeFiber".to_vec()
		);
	}

	/// An open network has no security group at all, and specifically not an
	/// empty one: a client that finds the group assumes a credential exists.
	#[test]
	fn an_open_network_has_no_security_group() {
		let dict = settings_of(&network("Cafe", Security::Open));
		assert!(!dict.contains_key("802-11-wireless-security"));
		assert!(dict
			.get("802-11-wireless")
			.is_some_and(|group| !group.contains_key("security")));
	}

	#[test]
	fn each_generation_gets_the_key_management_a_client_switches_on() {
		for (proto, expected) in [
			(PskProto::Wpa2, "wpa-psk"),
			(PskProto::Wpa3, "sae"),
			// Transition mode reports SAE: `key-mgmt` takes one value, and a
			// WPA3 client silently downgrading is worse than a WPA2 client
			// declining a network it could have joined.
			(PskProto::Wpa2Wpa3, "sae"),
		] {
			let dict = settings_of(&network("HomeFiber", psk(proto)));
			assert_eq!(
				string_of(&dict, "802-11-wireless-security", "key-mgmt").as_deref(),
				Some(expected),
				"for {proto:?}"
			);
		}
		assert_eq!(key_management(&Security::Owe), Some("owe"));
	}

	#[test]
	fn addressing_becomes_the_method_a_panel_shows() {
		use netcfgd_model::address::{Dhcp4, Static};
		assert_eq!(
			ipv4_method(&[AddressSource::Dhcp4(Dhcp4::default())]),
			"auto"
		);
		assert_eq!(
			ipv4_method(&[AddressSource::Static(Static {
				address: "192.0.2.1/24".to_owned(),
				peer: None,
				preferred_lifetime: None,
				valid_lifetime: None,
			})]),
			"manual"
		);
		assert_eq!(ipv4_method(&[]), "disabled");
		assert_eq!(ipv6_method(&[]), "ignore");
		assert_eq!(ipv6_method(&[AddressSource::LinkLocal]), "link-local");
	}

	/// Nameservers on a family with no addressing make the whole profile
	/// invalid.
	///
	/// libnm validates the dictionary before it will activate anything, and
	/// `ipv4.dns` beside `method=disabled` fails that check -- so a network
	/// with nameservers and no IPv4 had a profile no client would connect
	/// with, and the error named the DNS rather than the addressing. Losing
	/// one field is much cheaper than losing the profile.
	#[test]
	fn dns_is_left_out_where_the_method_would_make_it_invalid() {
		use netcfgd_model::{DnsPolicy, DnsServer};

		let mut network = match network("Quiet", Security::Open) {
			Profile::Network(network) => *network,
			Profile::Interface(_) => unreachable!("built as a network"),
		};
		network.dns = Some(DnsPolicy {
			servers: vec![DnsServer {
				addr: "9.9.9.9".parse().expect("an address"),
				port: None,
				sni: None,
			}],
			..DnsPolicy::default()
		});

		// No addressing at all: `method` is `disabled`, so no nameservers.
		network.addressing = Vec::new();
		let quiet = settings_of(&Profile::Network(Box::new(network.clone())));
		assert_eq!(
			string_of(&quiet, "ipv4", "method").as_deref(),
			Some("disabled")
		);
		assert!(
			quiet
				.get("ipv4")
				.is_some_and(|group| !group.contains_key("dns-data")),
			"a disabled family must not carry nameservers"
		);

		// With addressing, the same policy is reported.
		network.addressing = vec![AddressSource::Dhcp4(
			netcfgd_model::address::Dhcp4::default(),
		)];
		let live = settings_of(&Profile::Network(Box::new(network)));
		assert_eq!(string_of(&live, "ipv4", "method").as_deref(), Some("auto"));
		assert!(live
			.get("ipv4")
			.is_some_and(|group| group.contains_key("dns-data")));
	}

	/// A wifi profile is not bound to an interface. An SSID may be in range of
	/// any radio, which is why netcfgd's model keeps `network` and `device`
	/// apart, and pinning one here would make a laptop with two radios able to
	/// join a network on only one of them.
	#[test]
	fn a_wifi_profile_names_no_interface() {
		let dict = settings_of(&network("HomeFiber", Security::Open));
		assert!(dict
			.get("connection")
			.is_some_and(|group| !group.contains_key("interface-name")));
	}
}
