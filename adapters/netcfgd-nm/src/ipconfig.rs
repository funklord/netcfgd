//! `org.freedesktop.NetworkManager.IP4Config` and its IPv6 twin.
//!
//! What a settings panel's "Details" tab is made of: the addresses, gateway,
//! routes and nameservers a device actually has. Every one of them is read
//! from netcfgd's observation, which is the same thing `ncfg status` prints --
//! so a desktop and the command line cannot disagree about what the machine is
//! doing.
//!
//! These are the objects `Device.Ip4Config` and `ActiveConnection.Ip4Config`
//! point at. Until now both were `/`, NM's spelling for "no object", and a
//! panel opened on a working connection showed nothing at all.
//!
//! # The deprecated properties are implemented anyway
//!
//! NM marks `Addresses`, `Routes` and `Nameservers` deprecated in favour of the
//! `*Data` forms, and still serves them, because clients written against the
//! old API are still installed. They are a packed integer format that is easy
//! to get subtly wrong, so the numbers here were checked against what a running
//! `NetworkManager` 1.52 reports for an address this machine actually holds.

use crate::state::State;
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use zbus::zvariant::{OwnedObjectPath, OwnedValue, Value};

/// The object path for an IPv4 configuration number.
#[must_use]
pub(crate) fn path_for(number: u32, v6: bool) -> OwnedObjectPath {
	let family = if v6 { "IP6Config" } else { "IP4Config" };
	OwnedObjectPath::try_from(format!("/org/freedesktop/NetworkManager/{family}/{number}"))
		.expect("an address config path built from a number is always valid")
}

/// One address, split the way NM wants it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Address {
	/// The address without its prefix.
	pub(crate) address: IpAddr,
	/// The prefix length.
	pub(crate) prefix: u32,
}

/// Split a CIDR string the way netcfgd stores it.
///
/// Returns `None` for anything that is not an address and a prefix, which is
/// what a kernel that reported something unexpected would produce -- and a
/// device with one unreadable address should still show the others.
#[must_use]
pub(crate) fn parse_cidr(text: &str) -> Option<Address> {
	let (address, prefix) = text.split_once('/')?;
	Some(Address {
		address: address.parse().ok()?,
		prefix: prefix.parse().ok()?,
	})
}

/// An IPv4 address as NM's deprecated `au` entries carry it.
///
/// The octets in wire order, read back as a native-endian `u32`. That is not a
/// byte-order conversion so much as the absence of one: NM stores the four
/// bytes as they appear on the wire and reinterprets them, so on a
/// little-endian machine 10.0.125.37 comes out as 628949002.
///
/// Checked against a running `NetworkManager` 1.52 rather than reasoned about:
/// it reported exactly that number for that address, and 16777226 for the
/// gateway 10.0.0.1.
#[must_use]
pub(crate) fn packed(address: std::net::Ipv4Addr) -> u32 {
	u32::from_ne_bytes(address.octets())
}

fn text(value: impl Into<String>) -> OwnedValue {
	OwnedValue::try_from(Value::from(value.into())).expect("a string owns itself")
}

fn number(value: u32) -> OwnedValue {
	OwnedValue::try_from(Value::from(value)).expect("a number owns itself")
}

/// One entry of `AddressData`.
#[must_use]
pub(crate) fn address_entry(address: &Address) -> HashMap<String, OwnedValue> {
	let mut entry = HashMap::new();
	entry.insert("address".to_owned(), text(address.address.to_string()));
	entry.insert("prefix".to_owned(), number(address.prefix));
	entry
}

/// One entry of `NameserverData`.
#[must_use]
pub(crate) fn nameserver_entry(address: IpAddr) -> HashMap<String, OwnedValue> {
	let mut entry = HashMap::new();
	entry.insert("address".to_owned(), text(address.to_string()));
	entry
}

/// One entry of `RouteData`.
#[must_use]
pub(crate) fn route_entry(
	destination: &str,
	prefix: u32,
	via: Option<IpAddr>,
	metric: Option<u32>,
) -> HashMap<String, OwnedValue> {
	let mut entry = HashMap::new();
	entry.insert("dest".to_owned(), text(destination.to_owned()));
	entry.insert("prefix".to_owned(), number(prefix));
	if let Some(via) = via {
		entry.insert("next-hop".to_owned(), text(via.to_string()));
	}
	if let Some(metric) = metric {
		entry.insert("metric".to_owned(), number(metric));
	}
	entry
}

/// How netcfgd spells a default route, split into NM's destination and prefix.
///
/// netcfgd writes `default`, which is what an operator types and what `ip
/// route` prints. NM wants `0.0.0.0/0` or `::/0` as two fields, so the
/// translation happens here rather than at three call sites.
#[must_use]
pub(crate) fn destination_of(route: &str, v6: bool) -> (String, u32) {
	if route == "default" {
		return if v6 {
			("::".to_owned(), 0)
		} else {
			("0.0.0.0".to_owned(), 0)
		};
	}
	match parse_cidr(route) {
		Some(address) => (address.address.to_string(), address.prefix),
		// Not a CIDR and not `default`: pass it through rather than dropping
		// the route, so a client shows something odd instead of nothing.
		None => (route.to_owned(), 0),
	}
}

/// One device's addressing, in one family.
pub(crate) struct IpConfig {
	state: Arc<State>,
	interface: String,
	v6: bool,
}

impl IpConfig {
	/// An address configuration object for one interface and family.
	#[must_use]
	pub(crate) fn new(state: Arc<State>, interface: String, v6: bool) -> Self {
		Self {
			state,
			interface,
			v6,
		}
	}

	fn parsed_addresses(&self) -> Vec<Address> {
		self.state
			.addresses_of(&self.interface)
			.iter()
			.filter_map(|text| parse_cidr(text))
			.filter(|address| address.address.is_ipv6() == self.v6)
			.collect()
	}

	fn parsed_routes(&self) -> Vec<(String, u32, Option<IpAddr>, Option<u32>)> {
		self.state
			.routes_of(&self.interface)
			.into_iter()
			.filter(|(destination, via, _)| {
				// A route's family is the family of its destination, except for
				// `default`, which netcfgd writes for both and which is then
				// told apart by its next hop.
				if destination == "default" {
					via.is_none_or(|via| via.is_ipv6() == self.v6)
				} else {
					destination.contains(':') == self.v6
				}
			})
			.map(|(destination, via, metric)| {
				let (dest, prefix) = destination_of(&destination, self.v6);
				(dest, prefix, via, metric)
			})
			.collect()
	}

	fn gateway(&self) -> Option<IpAddr> {
		self.state.gateway_of(&self.interface, self.v6)
	}

	fn domains(&self) -> Vec<String> {
		self.state.search_domains()
	}

	fn parsed_nameservers(&self) -> Vec<IpAddr> {
		self.state
			.nameservers()
			.into_iter()
			.filter(|address| address.is_ipv6() == self.v6)
			.collect()
	}
}

/// The IPv4 object.
///
/// Two types rather than one with a flag, because NM's two interfaces are not
/// the same shape: `Addresses` is `aau` here and `a(ayuay)` on the IPv6 object,
/// and `WinsServers` exists on one and not the other. A single type cannot
/// serve both, and pretending otherwise would mean serving one of them wrongly.
pub(crate) struct Ip4Config(IpConfig);

impl Ip4Config {
	/// An IPv4 configuration object for one interface.
	#[must_use]
	pub(crate) fn new(state: Arc<State>, interface: String) -> Self {
		Self(IpConfig::new(state, interface, false))
	}
}

#[zbus::interface(
	name = "org.freedesktop.NetworkManager.IP4Config",
	introspection_docs = false
)]
impl Ip4Config {
	#[zbus(property)]
	fn address_data(&self) -> Vec<HashMap<String, OwnedValue>> {
		self.0
			.parsed_addresses()
			.iter()
			.map(address_entry)
			.collect()
	}

	/// The deprecated packed form, for clients that still read it.
	#[zbus(property)]
	fn addresses(&self) -> Vec<Vec<u32>> {
		let gateway = match self.0.gateway() {
			Some(IpAddr::V4(v4)) => Some(v4),
			_ => None,
		};
		self.0
			.parsed_addresses()
			.iter()
			.filter_map(|address| match address.address {
				IpAddr::V4(v4) => Some(vec![packed(v4), address.prefix, gateway.map_or(0, packed)]),
				IpAddr::V6(_) => None,
			})
			.collect()
	}

	#[zbus(property)]
	fn gateway(&self) -> String {
		self.0
			.gateway()
			.map_or_else(String::new, |address| address.to_string())
	}

	#[zbus(property)]
	fn route_data(&self) -> Vec<HashMap<String, OwnedValue>> {
		self.0
			.parsed_routes()
			.into_iter()
			.map(|(destination, prefix, via, metric)| {
				route_entry(&destination, prefix, via, metric)
			})
			.collect()
	}

	#[zbus(property)]
	fn routes(&self) -> Vec<Vec<u32>> {
		self.0
			.parsed_routes()
			.into_iter()
			.filter_map(|(destination, prefix, via, metric)| {
				let destination = destination.parse::<std::net::Ipv4Addr>().ok()?;
				let next = match via {
					Some(IpAddr::V4(v4)) => packed(v4),
					_ => 0,
				};
				Some(vec![packed(destination), prefix, next, metric.unwrap_or(0)])
			})
			.collect()
	}

	#[zbus(property)]
	fn nameserver_data(&self) -> Vec<HashMap<String, OwnedValue>> {
		self.0
			.parsed_nameservers()
			.into_iter()
			.map(nameserver_entry)
			.collect()
	}

	#[zbus(property)]
	fn nameservers(&self) -> Vec<u32> {
		self.0
			.parsed_nameservers()
			.into_iter()
			.filter_map(|address| match address {
				IpAddr::V4(v4) => Some(packed(v4)),
				IpAddr::V6(_) => None,
			})
			.collect()
	}

	#[zbus(property)]
	fn domains(&self) -> Vec<String> {
		self.0.domains()
	}

	#[zbus(property)]
	fn searches(&self) -> Vec<String> {
		self.0.domains()
	}

	#[zbus(property)]
	fn dns_options(&self) -> Vec<String> {
		Vec::new()
	}

	#[zbus(property)]
	fn dns_priority(&self) -> i32 {
		0
	}

	#[zbus(property)]
	fn wins_server_data(&self) -> Vec<String> {
		Vec::new()
	}

	#[zbus(property)]
	fn wins_servers(&self) -> Vec<u32> {
		Vec::new()
	}
}

/// The IPv6 object.
pub(crate) struct Ip6Config(IpConfig);

impl Ip6Config {
	/// An IPv6 configuration object for one interface.
	#[must_use]
	pub(crate) fn new(state: Arc<State>, interface: String) -> Self {
		Self(IpConfig::new(state, interface, true))
	}
}

#[zbus::interface(
	name = "org.freedesktop.NetworkManager.IP6Config",
	introspection_docs = false
)]
impl Ip6Config {
	#[zbus(property)]
	fn address_data(&self) -> Vec<HashMap<String, OwnedValue>> {
		self.0
			.parsed_addresses()
			.iter()
			.map(address_entry)
			.collect()
	}

	/// The deprecated form, which for IPv6 is octets rather than a packed
	/// integer -- an IPv6 address does not fit in one.
	#[zbus(property)]
	fn addresses(&self) -> Vec<(Vec<u8>, u32, Vec<u8>)> {
		let gateway = match self.0.gateway() {
			Some(IpAddr::V6(v6)) => v6.octets().to_vec(),
			_ => Vec::new(),
		};
		self.0
			.parsed_addresses()
			.iter()
			.filter_map(|address| match address.address {
				IpAddr::V6(v6) => Some((v6.octets().to_vec(), address.prefix, gateway.clone())),
				IpAddr::V4(_) => None,
			})
			.collect()
	}

	#[zbus(property)]
	fn gateway(&self) -> String {
		self.0
			.gateway()
			.map_or_else(String::new, |address| address.to_string())
	}

	#[zbus(property)]
	fn route_data(&self) -> Vec<HashMap<String, OwnedValue>> {
		self.0
			.parsed_routes()
			.into_iter()
			.map(|(destination, prefix, via, metric)| {
				route_entry(&destination, prefix, via, metric)
			})
			.collect()
	}

	#[zbus(property)]
	fn routes(&self) -> Vec<(Vec<u8>, u32, Vec<u8>, u32)> {
		self.0
			.parsed_routes()
			.into_iter()
			.filter_map(|(destination, prefix, via, metric)| {
				let destination = destination.parse::<std::net::Ipv6Addr>().ok()?;
				let next = match via {
					Some(IpAddr::V6(v6)) => v6.octets().to_vec(),
					_ => Vec::new(),
				};
				Some((
					destination.octets().to_vec(),
					prefix,
					next,
					metric.unwrap_or(0),
				))
			})
			.collect()
	}

	#[zbus(property)]
	fn nameserver_data(&self) -> Vec<HashMap<String, OwnedValue>> {
		self.0
			.parsed_nameservers()
			.into_iter()
			.map(nameserver_entry)
			.collect()
	}

	#[zbus(property)]
	fn nameservers(&self) -> Vec<Vec<u8>> {
		self.0
			.parsed_nameservers()
			.into_iter()
			.filter_map(|address| match address {
				IpAddr::V6(v6) => Some(v6.octets().to_vec()),
				IpAddr::V4(_) => None,
			})
			.collect()
	}

	#[zbus(property)]
	fn domains(&self) -> Vec<String> {
		self.0.domains()
	}

	#[zbus(property)]
	fn searches(&self) -> Vec<String> {
		self.0.domains()
	}

	#[zbus(property)]
	fn dns_options(&self) -> Vec<String> {
		Vec::new()
	}

	#[zbus(property)]
	fn dns_priority(&self) -> i32 {
		0
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	/// The number a real daemon reported for an address this machine held.
	///
	/// Reasoning about byte order produces two plausible answers and one right
	/// one; this is the right one, taken from `NetworkManager` 1.52 rather than
	/// from an argument about endianness.
	#[test]
	fn the_packed_form_matches_what_a_real_daemon_reports() {
		assert_eq!(
			packed("10.0.125.37".parse().expect("an address")),
			628_949_002
		);
		assert_eq!(packed("10.0.0.1".parse().expect("an address")), 16_777_226);
	}

	#[test]
	fn a_cidr_splits_into_an_address_and_a_prefix() {
		assert_eq!(
			parse_cidr("192.0.2.5/24"),
			Some(Address {
				address: "192.0.2.5".parse().expect("an address"),
				prefix: 24,
			})
		);
		assert_eq!(parse_cidr("2001:db8::1/64").map(|a| a.prefix), Some(64));
		// Not a CIDR: a device with one unreadable address should still show
		// the others, so this is dropped rather than made into a panic.
		assert_eq!(parse_cidr("192.0.2.5"), None);
		assert_eq!(parse_cidr("not/an/address"), None);
	}

	/// netcfgd writes `default`, which is what an operator types. NM wants a
	/// destination and a prefix, and which zero it is depends on the family.
	#[test]
	fn a_default_route_becomes_the_right_zero() {
		assert_eq!(destination_of("default", false), ("0.0.0.0".to_owned(), 0));
		assert_eq!(destination_of("default", true), ("::".to_owned(), 0));
		assert_eq!(
			destination_of("10.0.0.0/16", false),
			("10.0.0.0".to_owned(), 16)
		);
	}

	#[test]
	fn an_address_entry_carries_what_a_panel_reads() {
		let entry = address_entry(&Address {
			address: "192.0.2.5".parse().expect("an address"),
			prefix: 24,
		});
		assert_eq!(
			String::try_from(entry["address"].try_clone().expect("cloneable")).ok(),
			Some("192.0.2.5".to_owned())
		);
		assert_eq!(
			u32::try_from(entry["prefix"].try_clone().expect("cloneable")).ok(),
			Some(24)
		);
	}

	#[test]
	fn a_route_entry_omits_a_next_hop_it_does_not_have() {
		let direct = route_entry("10.0.0.0", 16, None, Some(600));
		assert!(!direct.contains_key("next-hop"));
		assert_eq!(
			u32::try_from(direct["metric"].try_clone().expect("cloneable")).ok(),
			Some(600)
		);

		let via = route_entry(
			"0.0.0.0",
			0,
			Some("10.0.0.1".parse().expect("an address")),
			None,
		);
		assert_eq!(
			String::try_from(via["next-hop"].try_clone().expect("cloneable")).ok(),
			Some("10.0.0.1".to_owned())
		);
		// A metric netcfgd did not record is absent rather than zero: zero is a
		// metric, and claiming it would reorder a client's route list.
		assert!(!via.contains_key("metric"));
	}
}
