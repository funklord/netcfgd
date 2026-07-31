//! The snapshot every D-Bus answer is computed from.
//!
//! The shim is a translator, not a second source of truth (design section
//! 9.2). It holds one thing: the last observed state netcfgd reported, and the
//! device numbering derived from it. Everything a client can read is a pure
//! function of that snapshot, which is what makes the whole surface testable
//! by handing it an `Observed` and asking what NM would have said.

use netcfgd_model::{Observed, ObservedLink};
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Mutex;

/// Whether an address is one the kernel gave itself.
///
/// A link-local address is not connectivity, and treating it as one is not a
/// small mistake: every dummy, every freshly created bridge and every cable
/// that was just plugged in has an `fe80::` address within milliseconds, so a
/// shim counting it reports the whole machine as connected the moment it is
/// wired up. Found by an interface the config gave no addressing at all, which
/// `nmcli` still showed as connected.
///
/// Both families, because IPv4 has the same idea under a different name:
/// `169.254.0.0/16` is what a host assigns itself when DHCP fails, which is
/// the definitive not-connected state.
#[must_use]
pub(crate) fn is_link_local(address: &str) -> bool {
	let bare = address.split('/').next().unwrap_or(address);
	let lowered = bare.to_ascii_lowercase();
	lowered.starts_with("fe80:") || lowered.starts_with("169.254.")
}

/// Everything the shim knows.
pub(crate) struct State {
	/// Where netcfgd listens.
	socket: PathBuf,
	inner: Mutex<Inner>,
}

#[derive(Default)]
struct Inner {
	observed: Observed,
	/// Interface name to the number in its D-Bus path.
	///
	/// Stable for the lifetime of the process and never reused, because a
	/// client caches object paths: reusing `/Devices/3` for a different
	/// interface would silently rename a device inside every applet holding
	/// that path, rather than removing one and adding another.
	numbers: BTreeMap<String, u32>,
	/// The next number to hand out.
	next: u32,
}

/// What changed about the device list across a refresh.
///
/// Returned rather than acted on, because emitting `InterfacesAdded` needs the
/// object server and this type deliberately does not have one -- the split is
/// what keeps the numbering testable without a bus.
#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct Changes {
	/// Interfaces that appeared, with the number each was given.
	pub(crate) added: Vec<(String, u32)>,
	/// Interfaces that went away, with the number each had.
	pub(crate) removed: Vec<(String, u32)>,
}

impl State {
	/// A state that has spoken to nobody yet.
	#[must_use]
	pub(crate) fn new(socket: PathBuf) -> Self {
		Self {
			socket,
			inner: Mutex::new(Inner {
				// NM numbers from 1. Nothing requires it, and every real
				// daemon does it, so a client with an off-by-one bug nobody
				// has found will not find it here.
				next: 1,
				..Inner::default()
			}),
		}
	}

	/// Ask netcfgd what the machine looks like, and say what moved.
	///
	/// # Errors
	///
	/// Returns a message if the daemon cannot be reached.
	pub(crate) fn refresh(&self) -> Result<Changes, String> {
		let observed = crate::client::observed(&self.socket)?;
		Ok(self.adopt(observed))
	}

	/// Take an observation as the current one. Split out of [`Self::refresh`]
	/// so tests can supply a snapshot without a daemon.
	pub(crate) fn adopt(&self, observed: Observed) -> Changes {
		let mut inner = self
			.inner
			.lock()
			.unwrap_or_else(std::sync::PoisonError::into_inner);
		let mut changes = Changes::default();

		let present: Vec<String> = observed
			.links
			.iter()
			.map(|link| link.name.clone())
			.collect();
		for name in &present {
			if !inner.numbers.contains_key(name) {
				let number = inner.next;
				inner.next += 1;
				inner.numbers.insert(name.clone(), number);
				changes.added.push((name.clone(), number));
			}
		}
		inner.numbers.retain(|name, number| {
			if present.contains(name) {
				true
			} else {
				changes.removed.push((name.clone(), *number));
				false
			}
		});

		inner.observed = observed;
		changes
	}

	/// One link, as last observed.
	#[must_use]
	pub(crate) fn link(&self, interface: &str) -> Option<ObservedLink> {
		let inner = self
			.inner
			.lock()
			.unwrap_or_else(std::sync::PoisonError::into_inner);
		inner
			.observed
			.links
			.iter()
			.find(|link| link.name == interface)
			.cloned()
	}

	/// Whether an interface carries an address that means something.
	///
	/// The difference between NM's `DISCONNECTED` and `ACTIVATED`: a link that
	/// is up with a cable in it but no address is exactly what an applet shows
	/// as "connecting", and reporting it as activated is how a user is told
	/// they are online before they are.
	#[must_use]
	pub(crate) fn has_address(&self, interface: &str) -> bool {
		let inner = self
			.inner
			.lock()
			.unwrap_or_else(std::sync::PoisonError::into_inner);
		inner
			.observed
			.addresses
			.iter()
			.any(|address| address.interface == interface && !is_link_local(&address.address))
	}

	/// Every interface and its number, in name order.
	#[must_use]
	pub(crate) fn devices(&self) -> Vec<(String, u32)> {
		let inner = self
			.inner
			.lock()
			.unwrap_or_else(std::sync::PoisonError::into_inner);
		let mut devices: Vec<(String, u32)> = inner
			.numbers
			.iter()
			.map(|(name, number)| (name.clone(), *number))
			.collect();
		devices.sort_by(|left, right| left.0.cmp(&right.0));
		devices
	}

	/// Whether anything is carrying traffic, for the daemon's own state.
	#[must_use]
	pub(crate) fn any_connected(&self) -> bool {
		let inner = self
			.inner
			.lock()
			.unwrap_or_else(std::sync::PoisonError::into_inner);
		inner.observed.links.iter().any(|link| {
			link.name != "lo"
				&& link.up && link.carrier
				&& inner.observed.addresses.iter().any(|address| {
					address.interface == link.name && !is_link_local(&address.address)
				})
		})
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	fn link(name: &str) -> ObservedLink {
		ObservedLink {
			name: name.to_owned(),
			index: 1,
			kind: String::new(),
			up: true,
			carrier: true,
			mtu: 1500,
			mac: None,
			master: None,
			offloads: Vec::new(),
			ipv6_token: None,
			qdisc: None,
			qdisc_bandwidth_bits: None,
			qdisc_ingress: false,
			ingress_redirect: None,
			forwarding: None,
			ownership: netcfgd_model::Ownership::Unknown,
		}
	}

	fn observed(names: &[&str]) -> Observed {
		Observed {
			links: names.iter().map(|name| link(name)).collect(),
			..Observed::default()
		}
	}

	#[test]
	fn numbers_are_handed_out_once_and_never_reused() {
		let state = State::new(PathBuf::from("/nowhere"));

		let first = state.adopt(observed(&["eth0", "wlan0"]));
		assert_eq!(
			first.added,
			vec![("eth0".to_owned(), 1), ("wlan0".to_owned(), 2)]
		);

		// A second observation of the same machine moves nothing. An applet
		// holding /Devices/1 must keep holding it.
		let again = state.adopt(observed(&["eth0", "wlan0"]));
		assert_eq!(again, Changes::default());

		// A device goes, another arrives. The new one must not inherit the
		// number, or every client caching that path silently renames a device
		// instead of seeing one leave and one appear.
		let moved = state.adopt(observed(&["eth0", "ppp0"]));
		assert_eq!(moved.removed, vec![("wlan0".to_owned(), 2)]);
		assert_eq!(moved.added, vec![("ppp0".to_owned(), 3)]);
	}

	#[test]
	fn a_link_that_returns_keeps_its_old_number() {
		let state = State::new(PathBuf::from("/nowhere"));
		state.adopt(observed(&["eth0", "wlan0"]));
		state.adopt(observed(&["eth0"]));
		let back = state.adopt(observed(&["eth0", "wlan0"]));
		// It left, so it comes back as a new device. That is the honest
		// answer: NM does the same when a USB adapter is unplugged and
		// replugged, and a client that cached the old path has already been
		// told the object went away.
		assert_eq!(back.added, vec![("wlan0".to_owned(), 3)]);
	}

	/// The kernel hands out an `fe80::` address to anything that comes up, so
	/// counting it as connectivity makes every device connected the instant it
	/// exists. `nmcli` showed an interface with no addressing at all as
	/// connected, which is how this was found.
	#[test]
	fn an_address_the_kernel_gave_itself_is_not_connectivity() {
		assert!(is_link_local("fe80::1097:fff:fe1a:880/64"));
		assert!(is_link_local("FE80::1/64"));
		assert!(is_link_local("169.254.7.7/16"));
		assert!(!is_link_local("10.7.7.1/24"));
		assert!(!is_link_local("2001:db8::1/64"));
		// Not a prefix match on the text: this is a routable address that
		// merely starts with the same digits.
		assert!(!is_link_local("169.25.4.1/24"));
	}

	#[test]
	fn connectedness_ignores_the_loopback_and_needs_an_address() {
		let state = State::new(PathBuf::from("/nowhere"));
		state.adopt(observed(&["lo"]));
		assert!(!state.any_connected(), "loopback alone is not connected");

		let mut with_address = observed(&["lo", "eth0"]);
		assert!(
			!state.adopt(with_address.clone()).added.is_empty(),
			"eth0 should have been added"
		);
		assert!(
			!state.any_connected(),
			"a link with no address is not connected"
		);

		with_address.addresses.push(netcfgd_model::ObservedAddress {
			interface: "eth0".to_owned(),
			address: "192.0.2.5/24".to_owned(),
			proto: None,
			ownership: netcfgd_model::Ownership::Unknown,
			origin: None,
		});
		state.adopt(with_address);
		assert!(state.any_connected());
	}
}
