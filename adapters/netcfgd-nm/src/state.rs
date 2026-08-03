//! The snapshot every D-Bus answer is computed from.
//!
//! The shim is a translator, not a second source of truth (design section
//! 9.2). It holds one thing: the last observed state netcfgd reported, and the
//! device numbering derived from it. Everything a client can read is a pure
//! function of that snapshot, which is what makes the whole surface testable
//! by handing it an `Observed` and asking what NM would have said.

use netcfgd_model::{Document, Observed, ObservedLink, Security};
use netcfgd_proto::ScanEntry;
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

/// Something the main loop has to do, from somewhere that cannot do it.
///
/// Only one thing so far. A D-Bus method runs on zbus's own thread and has no
/// access to the object server from a blocking context, and a scan has to end
/// with objects being registered and signals emitted. So `RequestScan` posts
/// the job and returns, which is also what NM's own semantics ask for: the
/// call is a request, and the results arrive later as `AccessPointAdded` and a
/// changed `LastScan`. Blocking the caller until the radio finished would be a
/// different method than the one clients think they are calling.
#[derive(Debug)]
pub(crate) enum Job {
	/// Re-read the observed state.
	Refresh,
	/// Scan on one radio.
	Scan(String),
	/// Re-read the configuration and republish what it describes.
	///
	/// Posted by a method that changed a file rather than done inside it. A
	/// D-Bus method runs while zbus holds a lock on the interface it was
	/// called on, and unregistering that interface is exactly what removing a
	/// deleted profile does -- so doing the reload inline had the main loop
	/// waiting for a method that was waiting for the main loop. `Delete`
	/// returned after ten seconds of nothing, which is what a client shows as
	/// "Timeout expired".
	Reload,
}

/// Everything the shim knows.
pub(crate) struct State {
	/// Where netcfgd listens.
	socket: PathBuf,
	inner: Mutex<Inner>,
	/// How to reach the main loop.
	jobs: Mutex<Option<std::sync::mpsc::Sender<Job>>>,
	/// Secret agents that have registered.
	agents: crate::agent::Agents,
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
	/// The compiled document, for the things an observation cannot say.
	///
	/// Two of them so far: which devices netcfgd treats as radios, and what
	/// security a configured network actually uses. Both are the configuration
	/// answering rather than the shim guessing, which is the whole shape of
	/// this program.
	document: Option<Document>,
	/// The last scan on each radio, newest first as netcfgd sorted it.
	scans: BTreeMap<String, Vec<ScanEntry>>,
	/// `(interface, bssid)` to the number in its D-Bus path.
	///
	/// Never reused, for the reason device numbers are not: an applet holds
	/// `/AccessPoint/7` while its menu is open, and handing that path to a
	/// different network mid-scan would have the user click on one name and
	/// join another.
	ap_numbers: BTreeMap<(String, String), u32>,
	/// The next access point number to hand out.
	next_ap: u32,
	/// Seconds since boot at the last scan of each radio.
	last_scan: BTreeMap<String, i32>,
	/// The BSSID each radio is associated with, where it is.
	associated: BTreeMap<String, String>,
	/// Profile identity to the number in its `Settings` path.
	///
	/// Numbered like devices and access points, and never reused for the same
	/// reason: a client stores the path of the profile it last activated.
	profile_numbers: BTreeMap<String, u32>,
	/// The next profile number to hand out.
	next_profile: u32,
	/// `(profile identity, interface)` to the number of its active connection.
	///
	/// An activation is a pairing rather than a thing: the same `network` block
	/// active on two radios is two active connections, and NM's model says so
	/// too.
	active_numbers: BTreeMap<(String, String), u32>,
	/// The next active connection number to hand out.
	next_active: u32,
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

/// One profile active on one interface.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Activation {
	/// Which profile.
	pub(crate) identity: String,
	/// Where.
	pub(crate) interface: String,
}

/// What changed about the connection profiles across a reload.
#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct ProfileChanges {
	/// `(identity, number)` for each profile that appeared.
	pub(crate) added: Vec<(String, u32)>,
	/// The same for each that left the configuration.
	pub(crate) removed: Vec<(String, u32)>,
}

/// Every profile a document describes.
///
/// Free rather than a method, so it can be called while the state's lock is
/// held without the lock having to be reentrant.
#[must_use]
fn profiles_of(document: &Document) -> Vec<crate::settings::Profile> {
	document
		.networks
		.iter()
		.map(|network| crate::settings::Profile::Network(Box::new(network.clone())))
		.chain(
			document
				.interfaces
				.iter()
				// A radio's `interface` block is not a profile of its own. Its
				// profiles are the `network` blocks: what you activate on a
				// radio is a network, and offering an `802-3-ethernet` profile
				// named `wlan0` alongside them would put a thing in every
				// client's connection list that cannot be activated and is not
				// an ethernet.
				.filter(|interface| !is_radio_in(document, &interface.name))
				// And a tunnel is not one either, by the same sentence read
				// twice. NM's own profile for a WireGuard device carries the
				// peers and the private key, which is a shape this shim will
				// not project (0029 keeps secrets from travelling, 0036 keeps
				// VPN out of NM's interfaces) -- so the honest offer is none.
				// The *device* is projected in full and says what it is; what
				// is missing is a profile pretending to configure it.
				.filter(|interface| {
					!matches!(interface.kind, netcfgd_model::InterfaceKind::WireGuard(_))
				})
				.map(|interface| crate::settings::Profile::Interface(Box::new(interface.clone()))),
		)
		.collect()
}

/// Whether a document makes an interface a radio.
///
/// The same question [`State::is_radio`] answers, asked where the lock is
/// already held. Kept beside it rather than duplicated inside it: two
/// definitions of "radio" is exactly the disagreement this whole arrangement
/// exists to avoid.
#[must_use]
fn is_radio_in(document: &Document, interface: &str) -> bool {
	document
		.devices
		.iter()
		.any(|device| device.name == interface && device.managed && device.wifi.is_some())
		|| crate::device::has_sysfs_wireless(interface)
}

/// What changed about one radio's access points across a scan.
#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct ApChanges {
	/// `(interface, bssid, number)` for each access point that appeared.
	pub(crate) added: Vec<(String, String, u32)>,
	/// The same for each that is no longer in range.
	pub(crate) removed: Vec<(String, String, u32)>,
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
				next_ap: 1,
				next_profile: 1,
				next_active: 1,
				..Inner::default()
			}),
			jobs: Mutex::new(None),
			agents: crate::agent::Agents::default(),
		}
	}

	/// The registered secret agents.
	#[must_use]
	pub(crate) fn agents(&self) -> &crate::agent::Agents {
		&self.agents
	}

	/// The credential a profile needs and does not have, if that is the case.
	///
	/// Only for the `file` provider, and only when the file is missing. The
	/// other providers are somebody else's store -- `pass` may be locked, an
	/// `exec` may be about to succeed -- and a shim that decided they were
	/// empty would put a dialog in front of a user who had already answered
	/// the question elsewhere.
	#[must_use]
	pub(crate) fn missing_secret(&self, identity: &str) -> Option<String> {
		let crate::settings::Profile::Network(network) = self.profile(identity)? else {
			return None;
		};
		let netcfgd_model::Security::Psk(psk) = &network.security else {
			return None;
		};
		if psk.passphrase.provider != netcfgd_model::SecretProvider::File {
			return None;
		}
		if crate::store::has_secret(&psk.passphrase.name) {
			return None;
		}
		Some(psk.passphrase.name.clone())
	}

	/// Tell the state how to reach the main loop.
	pub(crate) fn set_jobs(&self, sender: std::sync::mpsc::Sender<Job>) {
		let mut jobs = self
			.jobs
			.lock()
			.unwrap_or_else(std::sync::PoisonError::into_inner);
		*jobs = Some(sender);
	}

	/// Ask for a scan on a radio.
	///
	/// Returns as soon as the job is posted, which is what NM's `RequestScan`
	/// means. The refusals here are the ones that can be decided without
	/// touching the radio; anything the scan itself fails at arrives as no new
	/// access points, and netcfgd's message is logged rather than returned,
	/// because by then the caller has gone.
	///
	/// # Errors
	///
	/// Returns a message if the interface is not a radio netcfgd knows about,
	/// or if the main loop is gone.
	pub(crate) fn request_scan(&self, interface: &str) -> Result<(), String> {
		if !self.is_radio(interface) {
			return Err(format!(
				"{interface} is not a radio netcfgd manages. A wireless device needs a \
				 `device {interface} {{ wifi {{ }} }}` block before netcfgd will drive it"
			));
		}
		let jobs = self
			.jobs
			.lock()
			.unwrap_or_else(std::sync::PoisonError::into_inner);
		let Some(sender) = jobs.as_ref() else {
			return Err("the shim is still starting up".to_owned());
		};
		sender
			.send(Job::Scan(interface.to_owned()))
			.map_err(|_| "the shim is shutting down".to_owned())
	}

	/// Ask the main loop to re-read the configuration.
	///
	/// # Errors
	///
	/// Returns a message if the main loop is gone.
	pub(crate) fn request_reload(&self) -> Result<(), String> {
		let jobs = self
			.jobs
			.lock()
			.unwrap_or_else(std::sync::PoisonError::into_inner);
		let Some(sender) = jobs.as_ref() else {
			return Err("the shim is still starting up".to_owned());
		};
		sender
			.send(Job::Reload)
			.map_err(|_| "the shim is shutting down".to_owned())
	}

	/// Scan, and take the result. Called from the main loop.
	///
	/// # Errors
	///
	/// Returns netcfgd's own message.
	pub(crate) fn rescan(&self, interface: &str) -> Result<ApChanges, String> {
		let entries = crate::client::scan(&self.socket, interface)?;
		Ok(self.adopt_scan(interface, entries))
	}

	/// Ask which access point each radio is on, and record it.
	pub(crate) fn refresh_associations(&self) {
		for (interface, _) in self.devices() {
			if !self.is_radio(&interface) {
				continue;
			}
			// A radio with no supplicant answers with an error, which is not
			// worth reporting on every reconcile -- it is the ordinary state of
			// a radio the configuration has not been applied to yet.
			if let Ok(bssid) = crate::client::associated(&self.socket, &interface) {
				self.adopt_association(&interface, bssid);
			}
		}
	}

	/// Every connection profile the configuration describes, with its number.
	///
	/// `network` blocks first and then `interface` blocks, each in document
	/// order, so the numbering is a function of the configuration rather than
	/// of the order things were first noticed.
	#[must_use]
	pub(crate) fn profiles(&self) -> Vec<(crate::settings::Profile, u32)> {
		let inner = self
			.inner
			.lock()
			.unwrap_or_else(std::sync::PoisonError::into_inner);
		let Some(document) = inner.document.as_ref() else {
			return Vec::new();
		};
		profiles_of(document)
			.into_iter()
			.filter_map(|profile| {
				inner
					.profile_numbers
					.get(&profile.identity())
					.map(|number| (profile, *number))
			})
			.collect()
	}

	/// Who the configuration lets change it.
	///
	/// Root when nothing is loaded, which is the safe direction: a shim that
	/// could not read the document must not decide that anybody may write it.
	#[must_use]
	pub(crate) fn admin_principal(&self) -> netcfgd_model::Principal {
		let inner = self
			.inner
			.lock()
			.unwrap_or_else(std::sync::PoisonError::into_inner);
		inner
			.document
			.as_ref()
			.map_or(netcfgd_model::Principal::Root, |document| {
				document.globals.control.admin.clone()
			})
	}

	/// One profile, by identity.
	#[must_use]
	pub(crate) fn profile(&self, identity: &str) -> Option<crate::settings::Profile> {
		let inner = self
			.inner
			.lock()
			.unwrap_or_else(std::sync::PoisonError::into_inner);
		profiles_of(inner.document.as_ref()?)
			.into_iter()
			.find(|profile| profile.identity() == identity)
	}

	/// Ask netcfgd to re-read its configuration, then take the result.
	///
	/// # Errors
	///
	/// Returns netcfgd's own message.
	pub(crate) fn reload(&self) -> Result<ProfileChanges, String> {
		crate::client::reload(&self.socket)?;
		let document = crate::client::document(&self.socket)?;
		Ok(self.adopt_document(Some(document)))
	}

	/// Which profiles are active, and on which interface.
	///
	/// Derived rather than recorded, which is the same discipline as
	/// everywhere else here: a radio's association names a network, and an
	/// interface that is up with an address is its own profile activated. If
	/// netcfgd says neither, nothing is active, and there is no third place
	/// holding a different opinion.
	#[must_use]
	pub(crate) fn active(&self) -> Vec<Activation> {
		let mut active = Vec::new();
		for (profile, _) in self.profiles() {
			match &profile {
				crate::settings::Profile::Network(network) => {
					for radio in self.radios() {
						if self.associated_id(&radio).as_deref() == Some(network.id.as_str()) {
							active.push(Activation {
								identity: profile.identity(),
								interface: radio,
							});
						}
					}
				}
				crate::settings::Profile::Interface(interface) => {
					// A radio's interface block is not separately active: the
					// network it joined is the activation, and reporting both
					// would put two connections on one device.
					if self.is_radio(&interface.name) {
						continue;
					}
					if self
						.link(&interface.name)
						.is_some_and(|link| link.up && link.carrier)
						&& self.has_address(&interface.name)
					{
						active.push(Activation {
							identity: profile.identity(),
							interface: interface.name.clone(),
						});
					}
				}
			}
		}
		active
	}

	/// The number for one activation, assigning it if this is the first time.
	#[must_use]
	pub(crate) fn active_number(&self, activation: &Activation) -> u32 {
		let mut inner = self
			.inner
			.lock()
			.unwrap_or_else(std::sync::PoisonError::into_inner);
		let key = (activation.identity.clone(), activation.interface.clone());
		if let Some(number) = inner.active_numbers.get(&key) {
			return *number;
		}
		let number = inner.next_active;
		inner.next_active += 1;
		inner.active_numbers.insert(key, number);
		number
	}

	/// Drop the numbers of activations that are no longer live, and say which
	/// they were.
	///
	/// The state is what remembers which activations have objects, because zbus
	/// has no way to enumerate what is served under a path prefix and
	/// reconstructing that by matching path strings would be a second opinion
	/// about the object tree.
	pub(crate) fn forget_inactive(&self, live: &[(Activation, u32)]) -> Vec<u32> {
		let mut inner = self
			.inner
			.lock()
			.unwrap_or_else(std::sync::PoisonError::into_inner);
		let keep: Vec<(String, String)> = live
			.iter()
			.map(|(activation, _)| (activation.identity.clone(), activation.interface.clone()))
			.collect();
		let mut dropped = Vec::new();
		inner.active_numbers.retain(|key, number| {
			if keep.contains(key) {
				true
			} else {
				dropped.push(*number);
				false
			}
		});
		dropped
	}

	/// The id of the `network` block a radio is currently on.
	#[must_use]
	pub(crate) fn associated_id(&self, interface: &str) -> Option<String> {
		let bssid = {
			let inner = self
				.inner
				.lock()
				.unwrap_or_else(std::sync::PoisonError::into_inner);
			inner.associated.get(interface).cloned()?
		};
		self.scan_entry(interface, &bssid)?.configured
	}

	/// Whether an interface carries a default route netcfgd can see.
	///
	/// What NM's `Default` and `Default6` mean, and what an applet uses to
	/// decide which of two connections is "the" one. Read from the observation
	/// rather than from the configuration, because on a laptop that switches
	/// uplinks the answer changes without the config doing so.
	#[must_use]
	pub(crate) fn has_default_route(&self, interface: &str, v6: bool) -> bool {
		let inner = self
			.inner
			.lock()
			.unwrap_or_else(std::sync::PoisonError::into_inner);
		inner.observed.routes.iter().any(|route| {
			route.interface == interface
				&& (route.destination == "default" || route.destination == "::/0")
				&& route.destination.contains(':') == v6
		})
	}

	/// Ask netcfgd to join a network, by profile identity.
	///
	/// # Errors
	///
	/// Returns netcfgd's own message, including its refusal when the profile is
	/// not something that can be activated this way.
	pub(crate) fn activate(&self, identity: &str, interface: &str) -> Result<(), String> {
		match self.profile(identity) {
			Some(crate::settings::Profile::Network(network)) => {
				crate::client::connect(&self.socket, interface, &network.id)
			}
			// An interface profile is not activated: netcfgd brings an
			// interface up because the configuration says to, and an already-up
			// interface is the state being asked for. Saying so beats either
			// failing at something that is already true or pretending to have
			// done something.
			Some(crate::settings::Profile::Interface(interface_block)) => {
				if self.link(&interface_block.name).is_some_and(|link| link.up) {
					Ok(())
				} else {
					Err(format!(
						"netcfgd brings `{}` up from the configuration, not on request. It \
						 is currently down, which means the configuration says so or the \
						 last apply failed -- `ncfg plan` will say which",
						interface_block.name
					))
				}
			}
			None => Err(format!(
				"netcfgd's configuration has no profile `{identity}`"
			)),
		}
	}

	/// Ask netcfgd to leave a network.
	///
	/// # Errors
	///
	/// Returns netcfgd's own message, or a refusal for a profile that cannot be
	/// deactivated without editing the configuration.
	pub(crate) fn deactivate(&self, activation: &Activation) -> Result<(), String> {
		match self.profile(&activation.identity) {
			Some(crate::settings::Profile::Network(_)) => {
				crate::client::disconnect(&self.socket, &activation.interface)
			}
			Some(crate::settings::Profile::Interface(_)) => Err(format!(
				"`{}` is up because /etc/netcfgd says it should be. Taking it down means \
				 changing that -- `enabled = false` on the interface, then `ncfg apply` -- \
				 rather than a request that the next reconcile would undo",
				activation.interface
			)),
			None => Err(format!(
				"netcfgd's configuration has no profile `{}`",
				activation.identity
			)),
		}
	}

	/// Every radio netcfgd knows about.
	#[must_use]
	pub(crate) fn radios(&self) -> Vec<String> {
		self.devices()
			.into_iter()
			.map(|(name, _)| name)
			.filter(|name| self.is_radio(name))
			.collect()
	}

	/// Take the compiled document as the current one, numbering any profile
	/// that is new and saying which profiles moved.
	pub(crate) fn adopt_document(&self, document: Option<Document>) -> ProfileChanges {
		let mut inner = self
			.inner
			.lock()
			.unwrap_or_else(std::sync::PoisonError::into_inner);
		let mut changes = ProfileChanges::default();

		let present: Vec<String> = document
			.as_ref()
			.map(|document| {
				profiles_of(document)
					.into_iter()
					.map(|profile| profile.identity())
					.collect()
			})
			.unwrap_or_default();

		let mut next = inner.next_profile;
		for identity in &present {
			if let std::collections::btree_map::Entry::Vacant(slot) =
				inner.profile_numbers.entry(identity.clone())
			{
				slot.insert(next);
				changes.added.push((identity.clone(), next));
				next += 1;
			}
		}
		inner.next_profile = next;
		inner.profile_numbers.retain(|identity, number| {
			if present.contains(identity) {
				true
			} else {
				changes.removed.push((identity.clone(), *number));
				false
			}
		});

		inner.document = document;
		changes
	}

	/// Whether netcfgd treats this interface as a radio.
	///
	/// The document first, and sysfs only as a fallback. `device wlan0 { wifi
	/// {} }` is what makes netcfgd start a supplicant on an interface -- it is
	/// the planner's own definition of a radio -- so it is the right answer
	/// here too, and it is the one that can be arranged in a test on a machine
	/// with no wireless hardware.
	#[must_use]
	pub(crate) fn is_radio(&self, interface: &str) -> bool {
		let inner = self
			.inner
			.lock()
			.unwrap_or_else(std::sync::PoisonError::into_inner);
		let declared = inner
			.document
			.as_ref()
			.is_some_and(|document| is_radio_in(document, interface));
		drop(inner);
		declared || crate::device::has_sysfs_wireless(interface)
	}

	/// Whether netcfgd will touch this interface at all.
	///
	/// `device X { managed = false }` means it will not (the planner enforces
	/// that at its own choke point), so NM's `Managed` has to say so. This
	/// property is what a client reads before offering to do anything with a
	/// device, and reporting an unmanaged one as managed is how a desktop comes
	/// to offer a connect button that quietly does nothing.
	#[must_use]
	pub(crate) fn is_managed(&self, interface: &str) -> bool {
		let inner = self
			.inner
			.lock()
			.unwrap_or_else(std::sync::PoisonError::into_inner);
		inner.document.as_ref().is_none_or(|document| {
			document
				.devices
				.iter()
				.find(|device| device.name == interface)
				.is_none_or(|device| device.managed)
		})
	}

	/// What the configuration says a network's security is.
	#[must_use]
	pub(crate) fn security_of(&self, network_id: &str) -> Option<Security> {
		let inner = self
			.inner
			.lock()
			.unwrap_or_else(std::sync::PoisonError::into_inner);
		inner.document.as_ref().and_then(|document| {
			document
				.networks
				.iter()
				.find(|network| network.id == network_id)
				.map(|network| network.security.clone())
		})
	}

	/// Take a scan result as the current one for a radio, and say what moved.
	pub(crate) fn adopt_scan(&self, interface: &str, entries: Vec<ScanEntry>) -> ApChanges {
		let mut inner = self
			.inner
			.lock()
			.unwrap_or_else(std::sync::PoisonError::into_inner);
		let mut changes = ApChanges::default();
		// Held outside the loop because the map is borrowed by the entry API
		// while a number is being handed out, and `inner.next_ap` cannot be
		// read through that borrow.
		let mut next_ap = inner.next_ap;

		for entry in &entries {
			let key = (interface.to_owned(), entry.bssid.clone());
			if let std::collections::btree_map::Entry::Vacant(slot) = inner.ap_numbers.entry(key) {
				let number = next_ap;
				next_ap += 1;
				slot.insert(number);
				changes
					.added
					.push((interface.to_owned(), entry.bssid.clone(), number));
			}
		}
		inner.next_ap = next_ap;

		let seen: Vec<String> = entries.iter().map(|entry| entry.bssid.clone()).collect();
		inner.ap_numbers.retain(|(iface, bssid), number| {
			if iface != interface || seen.contains(bssid) {
				true
			} else {
				changes
					.removed
					.push((iface.clone(), bssid.clone(), *number));
				false
			}
		});

		inner.scans.insert(interface.to_owned(), entries);
		inner
			.last_scan
			.insert(interface.to_owned(), crate::accesspoint::boot_seconds());
		changes
	}

	/// One entry from the last scan on a radio.
	#[must_use]
	pub(crate) fn scan_entry(&self, interface: &str, bssid: &str) -> Option<ScanEntry> {
		let inner = self
			.inner
			.lock()
			.unwrap_or_else(std::sync::PoisonError::into_inner);
		inner
			.scans
			.get(interface)?
			.iter()
			.find(|entry| entry.bssid == bssid)
			.cloned()
	}

	/// Every access point on a radio, with its number, strongest first.
	///
	/// Scan order, not sorted here: netcfgd already returns them strongest
	/// first, and that is the order an applet's menu should be in.
	#[must_use]
	pub(crate) fn access_points(&self, interface: &str) -> Vec<(String, u32)> {
		let inner = self
			.inner
			.lock()
			.unwrap_or_else(std::sync::PoisonError::into_inner);
		let Some(entries) = inner.scans.get(interface) else {
			return Vec::new();
		};
		entries
			.iter()
			.filter_map(|entry| {
				inner
					.ap_numbers
					.get(&(interface.to_owned(), entry.bssid.clone()))
					.map(|number| (entry.bssid.clone(), *number))
			})
			.collect()
	}

	/// When the last scan on a radio finished, in seconds since boot.
	#[must_use]
	pub(crate) fn last_scan_seconds(&self, interface: &str) -> Option<i32> {
		let inner = self
			.inner
			.lock()
			.unwrap_or_else(std::sync::PoisonError::into_inner);
		inner.last_scan.get(interface).copied()
	}

	/// Record which access point a radio is associated with.
	pub(crate) fn adopt_association(&self, interface: &str, bssid: Option<String>) {
		let mut inner = self
			.inner
			.lock()
			.unwrap_or_else(std::sync::PoisonError::into_inner);
		match bssid {
			Some(bssid) => inner.associated.insert(interface.to_owned(), bssid),
			None => inner.associated.remove(interface),
		};
	}

	/// The number of the access point a radio is on, if it is on one this scan
	/// found.
	#[must_use]
	pub(crate) fn associated_number(&self, interface: &str) -> Option<u32> {
		let inner = self
			.inner
			.lock()
			.unwrap_or_else(std::sync::PoisonError::into_inner);
		let bssid = inner.associated.get(interface)?;
		inner
			.ap_numbers
			.get(&(interface.to_owned(), bssid.clone()))
			.copied()
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
	/// Every link the observation carries.
	///
	/// For the one question that is about the *relationship* between links
	/// rather than about one of them: which devices are enslaved to a master.
	/// The observation records `master` on each link, so the list a bridge
	/// wants is that field read from the other end.
	pub(crate) fn links(&self) -> Vec<ObservedLink> {
		let inner = self
			.inner
			.lock()
			.unwrap_or_else(std::sync::PoisonError::into_inner);
		inner.observed.links.clone()
	}

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

	/// Every address on an interface, as netcfgd reports them.
	#[must_use]
	pub(crate) fn addresses_of(&self, interface: &str) -> Vec<String> {
		let inner = self
			.inner
			.lock()
			.unwrap_or_else(std::sync::PoisonError::into_inner);
		inner
			.observed
			.addresses
			.iter()
			.filter(|address| address.interface == interface)
			.map(|address| address.address.clone())
			.collect()
	}

	/// Every route on an interface: `(destination, via, metric)`.
	#[must_use]
	pub(crate) fn routes_of(
		&self,
		interface: &str,
	) -> Vec<(String, Option<std::net::IpAddr>, Option<u32>)> {
		let inner = self
			.inner
			.lock()
			.unwrap_or_else(std::sync::PoisonError::into_inner);
		inner
			.observed
			.routes
			.iter()
			.filter(|route| route.interface == interface)
			.map(|route| (route.destination.clone(), route.via, route.metric))
			.collect()
	}

	/// The next hop of an interface's default route, in one family.
	///
	/// What NM calls the gateway. netcfgd has no such field -- it has routes,
	/// and the gateway is the next hop of the default one, which is the same
	/// thing said without a special case.
	#[must_use]
	pub(crate) fn gateway_of(&self, interface: &str, v6: bool) -> Option<std::net::IpAddr> {
		self.routes_of(interface)
			.into_iter()
			.find(|(destination, via, _)| {
				(destination == "default" || destination == "::/0" || destination == "0.0.0.0/0")
					&& via.is_some_and(|via| via.is_ipv6() == v6)
			})
			.and_then(|(_, via, _)| via)
	}

	/// Every nameserver netcfgd has applied.
	///
	/// From the applied DNS rather than from the configuration: what a panel
	/// shows should be what resolution actually uses, and decision 0007's whole
	/// point is that those can differ per scope.
	#[must_use]
	pub(crate) fn nameservers(&self) -> Vec<std::net::IpAddr> {
		let inner = self
			.inner
			.lock()
			.unwrap_or_else(std::sync::PoisonError::into_inner);
		inner
			.observed
			.dns
			.iter()
			.flat_map(|applied| applied.policy.servers.iter().map(|server| server.addr))
			.collect()
	}

	/// Every search domain netcfgd has applied.
	#[must_use]
	pub(crate) fn search_domains(&self) -> Vec<String> {
		let inner = self
			.inner
			.lock()
			.unwrap_or_else(std::sync::PoisonError::into_inner);
		inner
			.observed
			.dns
			.iter()
			.flat_map(|applied| applied.policy.search.iter().cloned())
			.collect()
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
			parent: None,
			offloads: Vec::new(),
			ipv6_token: None,
			qdisc: None,
			qdisc_bandwidth_bits: None,
			qdisc_ingress: false,
			ingress_redirect: None,
			forwarding: None,
			privacy: None,
			ownership: netcfgd_model::Ownership::Unknown,
			private_key_loaded: false,
			wireguard: None,
			bond: None,
			bridge: None,
			macvlan: None,
			vlan: None,
			tunnel: None,
			vxlan: None,
		}
	}

	fn entry(bssid: &str, signal: i32) -> ScanEntry {
		ScanEntry {
			bssid: bssid.to_owned(),
			frequency: 2412,
			signal,
			secured: true,
			ssid: "686f6d65".to_owned(),
			name: Some("home".to_owned()),
			configured: None,
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

	/// Scanning something that is not a radio is refused by name.
	///
	/// Not reachable through `nmcli`, which refuses before it calls: a device
	/// with no `.Device.Wireless` interface has no `RequestScan` to reach. It
	/// is reachable by anything speaking D-Bus directly, and the message is
	/// the difference between "netcfgd does not manage this as a radio" and a
	/// scan that silently never produces results.
	#[test]
	fn scanning_something_that_is_not_a_radio_says_so() {
		let state = State::new(PathBuf::from("/nowhere"));
		state.adopt(observed(&["eth0"]));
		let refusal = state.request_scan("eth0").expect_err("eth0 is not a radio");
		assert!(refusal.contains("not a radio"), "{refusal}");
		assert!(
			refusal.contains("device eth0 { wifi { } }"),
			"the refusal has to say what would make it one: {refusal}"
		);
	}

	/// Access point numbers behave like device numbers: handed out once, never
	/// reused. An applet holds `/AccessPoint/7` while its menu is open, and
	/// giving that path to a different network between scans would have the
	/// user click one name and join another.
	#[test]
	fn access_point_numbers_are_stable_across_scans() {
		let state = State::new(PathBuf::from("/nowhere"));
		let first = state.adopt_scan("wlan0", vec![entry("aa:aa:aa:aa:aa:aa", -50)]);
		assert_eq!(
			first.added,
			vec![("wlan0".to_owned(), "aa:aa:aa:aa:aa:aa".to_owned(), 1)]
		);

		// Seen again: same number, nothing announced.
		let again = state.adopt_scan("wlan0", vec![entry("aa:aa:aa:aa:aa:aa", -60)]);
		assert_eq!(again, ApChanges::default());
		// And the entry was replaced, so the signal level is the new one.
		assert_eq!(
			state
				.scan_entry("wlan0", "aa:aa:aa:aa:aa:aa")
				.map(|e| e.signal),
			Some(-60)
		);

		// Out of range, then back: a new number, because the client was told
		// the old object went away.
		let gone = state.adopt_scan("wlan0", Vec::new());
		assert_eq!(
			gone.removed,
			vec![("wlan0".to_owned(), "aa:aa:aa:aa:aa:aa".to_owned(), 1)]
		);
		let back = state.adopt_scan("wlan0", vec![entry("aa:aa:aa:aa:aa:aa", -50)]);
		assert_eq!(
			back.added,
			vec![("wlan0".to_owned(), "aa:aa:aa:aa:aa:aa".to_owned(), 2)]
		);
	}

	/// A scan on one radio must not remove another radio's access points. Two
	/// radios in one laptop is ordinary, and the first version of this
	/// retained on bssid alone.
	#[test]
	fn a_scan_on_one_radio_leaves_the_other_alone() {
		let state = State::new(PathBuf::from("/nowhere"));
		state.adopt_scan("wlan0", vec![entry("aa:aa:aa:aa:aa:aa", -50)]);
		let other = state.adopt_scan("wlan1", vec![entry("bb:bb:bb:bb:bb:bb", -50)]);
		assert!(other.removed.is_empty(), "{other:?}");
		assert_eq!(state.access_points("wlan0").len(), 1);
		assert_eq!(state.access_points("wlan1").len(), 1);
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
