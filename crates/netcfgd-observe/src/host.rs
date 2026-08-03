//! The parts of the observation that are not rtnetlink.
//!
//! Three things netcfgd now configures cannot be read from the link dump: the
//! `forwarding` sysctls, which live in `/proc/sys`; the nftables table, which is
//! a different netlink protocol; and a running access point's station lists,
//! which are another process's memory. All are read here so that
//! [`crate::build`] stays a pure function of a snapshot -- the diffing rules
//! for NAT, forwarding and access control are then testable without a kernel,
//! in the same way address ownership already is.
//!
//! Nothing in here fails the observation. A machine with no `nf_tables`, a
//! container with no writable `/proc/sys` and an access point that died between
//! the record being written and the socket being opened are all ordinary, and
//! the honest reading in each case is "netcfgd has installed nothing" or "there
//! is nothing to ask", which is what an empty list and a `None` say. What must
//! not happen is a daemon that refuses to start on a kernel that simply does
//! not have a feature nobody asked for.

use netcfgd_model::Observed;
use std::fs;
use std::path::{Path, PathBuf};

/// Where the sysctls live, overridable so this is testable without root.
fn proc_root() -> PathBuf {
	std::env::var_os("NCFG_PROC_ROOT").map_or_else(|| PathBuf::from("/proc"), PathBuf::from)
}

/// Where the device tree lives, overridable for the same reason.
///
/// rfkill is the first thing here that reads `/sys`, and it cannot be faked any
/// other way: a switch belongs to a radio, and a radio is the one thing this
/// project does not pretend to have (`fake_supplicant.py` speaks a protocol, not a
/// phy). A tree under a temporary directory is what makes the mapping testable at
/// a desk; `tests/live/rfkill.sh` reads the real one.
fn sys_root() -> PathBuf {
	std::env::var_os("NCFG_SYS_ROOT").map_or_else(|| PathBuf::from("/sys"), PathBuf::from)
}

/// Fill in everything the netlink snapshot could not supply.
pub fn augment(observed: &mut Observed, run_dir: &Path, desired: Option<&netcfgd_model::Document>) {
	let root = proc_root();
	for link in &mut observed.links {
		link.forwarding = forwarding(&root, &link.name);
		link.privacy = privacy(&root, &link.name);
		link.accept_ra = accept_ra(&root, &link.name);
	}
	observed.hostname = hostname(&root);
	let sys = sys_root();
	for link in &mut observed.links {
		link.rfkill = rfkill(&sys, &link.name);
	}
	read_netfilter(observed);
	read_offloads(observed);
	read_access_control(observed, run_dir);
	read_advertised(observed, run_dir);
	read_secret_currency(observed, run_dir, desired);
	read_tunnel_currency(observed, run_dir, desired);
	read_wireguard_keys(observed);
	read_wireguard_currency(observed, run_dir, desired);
}

/// Whether each `WireGuard` device still holds the key the store has.
///
/// The third comparison of this shape, after an access point's passphrase
/// (0052) and a tunnel's configuration file (0053), and it is here rather than
/// in the planner for the reason both of those are: one half is a secret, and a
/// pure planner may not hold one. What leaves this function is a boolean.
///
/// The record is a digest of the key netcfgd loaded, written when the kernel
/// accepted it. Comparing digests rather than deriving a public key is what
/// makes this possible at all without curve25519 -- which project.md carried as
/// the reason a rotated key could not be noticed.
fn read_wireguard_currency(
	observed: &mut Observed,
	run_dir: &Path,
	desired: Option<&netcfgd_model::Document>,
) {
	let Some(document) = desired else {
		return;
	};
	let resolver = netcfgd_secret::Resolver::with_secrets_dir(secrets_dir());
	for link in &mut observed.links {
		let Some(state) = link.wireguard.as_mut() else {
			continue;
		};
		let Some(config) = document.interfaces.iter().find_map(|interface| {
			match (&interface.kind, interface.name == link.name) {
				(netcfgd_model::InterfaceKind::WireGuard(wireguard), true) => Some(wireguard),
				_ => None,
			}
		}) else {
			continue;
		};
		let Ok(recorded) =
			fs::read_to_string(netcfgd_apply::kernel::key_record_path(run_dir, &link.name))
		else {
			// A device netcfgd did not configure, or a `/run` cleared under a
			// running one. Neither is a statement about the key.
			continue;
		};
		let Ok(secret) = resolver.resolve(&config.private_key) else {
			continue;
		};
		state.key_matches =
			Some(netcfgd_model::hash::sha256_hex(&decoded_key(secret.expose())) == recorded.trim());
		read_preset_currency(state, run_dir, &link.name, config, &resolver);
	}
}

/// Whether each peer's preshared key is still the one the store has.
///
/// Keyed by public key, which is the only name the kernel and the document
/// share. A peer with no record and a peer whose secret will not resolve are
/// both left `None`: "netcfgd cannot tell" is not "it changed", and the second
/// one would replace a whole peer list over an unreadable file.
fn read_preset_currency(
	state: &mut netcfgd_model::ObservedWireGuard,
	run_dir: &Path,
	iface: &str,
	config: &netcfgd_model::interface::WireGuardConfig,
	resolver: &netcfgd_secret::Resolver,
) {
	let Ok(recorded) =
		fs::read_to_string(netcfgd_apply::kernel::preset_record_path(run_dir, iface))
	else {
		return;
	};
	for peer in &mut state.peers {
		if !peer.preshared_key {
			continue;
		}
		let rendered = peer.public_key.render();
		let Some(digest) = recorded.lines().find_map(|line| {
			line.split_once(' ')
				.filter(|(key, _)| *key == rendered)
				.map(|(_, digest)| digest.trim())
		}) else {
			continue;
		};
		let Some(reference) = config
			.peers
			.iter()
			.find(|wanted| wanted.public_key == peer.public_key)
			.and_then(|wanted| wanted.preshared_key.as_ref())
		else {
			continue;
		};
		let Ok(secret) = resolver.resolve(reference) else {
			continue;
		};
		peer.preshared_matches =
			Some(netcfgd_model::hash::sha256_hex(&decoded_key(secret.expose())) == digest);
	}
}

/// The 32 octets a base64 key spells, or the raw bytes if it is not base64.
///
/// The executor hashes what it loaded, which is the decoded key -- so this has
/// to decode the same way or every device would report a rotated key forever.
/// Falling back to the raw bytes keeps that true for a store holding something
/// this cannot parse: both sides then hash the same unparseable thing.
fn decoded_key(secret: &str) -> Vec<u8> {
	netcfgd_model::Key::parse(secret.trim()).map_or_else(
		|_| secret.trim().as_bytes().to_vec(),
		|key| key.as_bytes().to_vec(),
	)
}

/// Which `WireGuard` devices have a private key loaded.
///
/// Asked as "does the kernel report a public key", which it derives from the
/// private one and reports for no other reason. Nothing here asks for the
/// private key, and `netcfgd_sys::wg::DeviceState` has no field that could
/// return one -- that is deliberate there and this must not be the reason it
/// changes.
///
/// Only for links the kernel calls `wireguard`, so a host with none of them
/// makes no generic-netlink request at all. A kernel with no `wireguard`
/// module has no such links either, so the same check covers it.
fn read_wireguard_keys(observed: &mut Observed) {
	if !observed.links.iter().any(|link| link.kind == "wireguard") {
		return;
	}
	let Ok(mut genl) = netcfgd_sys::genl::Genl::open() else {
		return;
	};
	for link in &mut observed.links {
		if link.kind != "wireguard" {
			continue;
		}
		// A device that cannot be read is reported as carrying nothing rather
		// than as carrying something. This feeds a refusal, and a refusal that
		// fires because a read failed is one people learn to override by
		// reflex -- which would leave them overriding the real ones too.
		let Ok(state) = netcfgd_sys::wg::get_device(&mut genl, &link.name) else {
			continue;
		};
		link.private_key_loaded = state.public_key.is_some();
		link.wireguard = Some(carried(&state));
	}
}

/// What of a device's state travels, which is everything the kernel offered.
///
/// The same request already answered `private_key_loaded` and the rest was
/// dropped on the floor, so an edited listen port or a deleted peer reached a
/// planner with nothing to compare (decision 0054). None of it is secret: the
/// device's public key is derived by the kernel and is what a peer is given,
/// and a preshared key arrives zeroed and becomes a boolean.
fn carried(state: &netcfgd_sys::wg::DeviceState) -> netcfgd_model::ObservedWireGuard {
	let mut peers: Vec<netcfgd_model::ObservedWgPeer> = state
		.peers
		.iter()
		.map(|peer| netcfgd_model::ObservedWgPeer {
			public_key: netcfgd_model::Key::from_bytes(peer.public_key),
			preshared_key: peer.has_preshared_key,
			// Filled in by `read_preset_currency`, which needs the document
			// and the store; the netlink reply alone cannot answer it.
			preshared_matches: None,
			endpoint: peer.endpoint.map(|endpoint| endpoint.to_string()),
			allowed_ips: {
				let mut prefixes: Vec<String> = peer
					.allowed_ips
					.iter()
					.map(|(address, length)| format!("{address}/{length}"))
					.collect();
				prefixes.sort();
				prefixes
			},
			// The kernel spells "no keepalive" as zero and the model spells it
			// as absent, which is the same distinction `Option` exists for. A
			// zero surviving into the model would differ from a document that
			// says nothing, every time, forever.
			keepalive: (peer.keepalive != 0).then_some(peer.keepalive),
		})
		.collect();
	// Sorted by the one field both sides have. The kernel's order is its own
	// and the document's is by the operator's label.
	peers.sort();
	netcfgd_model::ObservedWireGuard {
		public_key: state.public_key.map(netcfgd_model::Key::from_bytes),
		listen_port: state.listen_port,
		// Filled in by `read_wireguard_currency`, which needs the document and
		// the secret store and so cannot run from a netlink reply alone.
		key_matches: None,
		// Zero is how the kernel spells "no mark", the same way it spells "no
		// keepalive" -- and a `Some(0)` here would be a value in `/run` and on
		// the socket that says a mark is set when none is.
		fwmark: state.fwmark.filter(|mark| *mark != 0),
		peers,
	}
}

/// What a running access point holds in its access control lists.
///
/// Asked only of a backend netcfgd believes is running, and only of an access
/// point. That is the whole guard against reading a leftover: the recorded
/// policy comes from a file under `/run` that outlives the process that read
/// it, so the file alone would happily describe an access point that exited an
/// hour ago.
///
/// Failure leaves the field `None` rather than emptying it, and the difference
/// matters more here than anywhere else in this module. An empty
/// [`netcfgd_model::ObservedAccessControl`] means "hostapd denies nobody",
/// which the planner would converge by adding every station in the document --
/// harmless. `None` means "netcfgd could not ask", which it must not act on at
/// all: converging an unreadable list is converging against a guess.
fn read_access_control(observed: &mut Observed, run_dir: &Path) {
	for backend in &mut observed.backends {
		if backend.kind != netcfgd_model::BackendKind::AccessPoint || !backend.running {
			continue;
		}
		let Ok(live) = netcfgd_hostapd::acl::read(run_dir, &backend.interface) else {
			// hostapd is gone, or was never reachable. Recorded state said it
			// was running and the socket says otherwise; the socket is closer
			// to the truth, and saying nothing is the honest answer.
			continue;
		};
		backend.access_control = Some(netcfgd_model::ObservedAccessControl {
			policy: netcfgd_hostapd::recorded_policy(run_dir, &backend.interface),
			denied: live.denied,
			accepted: live.accepted,
		});
		backend.started_with = started_with(run_dir, &backend.interface);
	}
}

/// Whether a running access point still holds the passphrase the store has.
///
/// The one thing decision 0052 left open, and the reason it was left: the
/// secret is not in the observation, because constraint 5 keeps it out of
/// `/run` and the socket, and not in the document either -- what the document
/// holds is a `SecretRef`. A pure planner therefore has nothing to compare.
///
/// So the comparison happens here, where both halves are already in hand: the
/// value hostapd was started with is in the file netcfgd generated, and the
/// value the store holds now is a resolve away. What leaves this function is a
/// boolean. Neither value is copied anywhere, put in a message, or returned.
///
/// `None` is the answer whenever anything is missing -- no document, no
/// secret, an unreadable file, an access point with no passphrase at all --
/// because a restart deauthenticates every station and "I could not check" is
/// not a reason to.
fn read_secret_currency(
	observed: &mut Observed,
	run_dir: &Path,
	desired: Option<&netcfgd_model::Document>,
) {
	let Some(document) = desired else {
		return;
	};
	let resolver = netcfgd_secret::Resolver::with_secrets_dir(secrets_dir());
	for backend in &mut observed.backends {
		if backend.kind != netcfgd_model::BackendKind::AccessPoint || !backend.running {
			continue;
		}
		let Some(access_point) = document
			.access_points
			.iter()
			.find(|point| point.device == backend.interface)
		else {
			continue;
		};
		let netcfgd_model::Security::Psk(psk) = &access_point.security else {
			// An open network, or one this build does not render. Nothing to
			// compare rather than something that differs.
			continue;
		};
		let Ok(wanted) = resolver.resolve(&psk.passphrase) else {
			continue;
		};
		let Ok(text) =
			fs::read_to_string(netcfgd_hostapd::config_path(run_dir, &backend.interface))
		else {
			continue;
		};
		let started = text
			.lines()
			.map(str::trim)
			.find_map(|line| line.strip_prefix("wpa_passphrase="));
		backend.secret_matches = started.map(|started| started == wanted.expose());
	}
}

/// Whether a running tunnel's `.ovpn` is still the one it was started from.
///
/// netcfgd does not read that file for meaning -- decision 0046 is emphatic and
/// this does not weaken it -- but it hashes it, which is exactly what a hook's
/// `sha256` does for a script netcfgd equally does not interpret (section 2.2).
/// The comparison is here rather than in the planner for the reason the
/// passphrase's is: a pure planner may not read files, and only the answer
/// needs to travel.
fn read_tunnel_currency(
	observed: &mut Observed,
	run_dir: &Path,
	desired: Option<&netcfgd_model::Document>,
) {
	let Some(document) = desired else {
		return;
	};
	for backend in &mut observed.backends {
		if backend.kind != netcfgd_model::BackendKind::OpenVpn || !backend.running {
			continue;
		}
		let Some(config) = document.interfaces.iter().find_map(|interface| {
			match (&interface.kind, interface.name == backend.interface) {
				(netcfgd_model::InterfaceKind::OpenVpn(tunnel), true) => Some(&tunnel.config),
				_ => None,
			}
		}) else {
			continue;
		};
		let Ok(recorded) = fs::read_to_string(netcfgd_openvpn::config_hash_path(
			run_dir,
			&backend.interface,
		)) else {
			// Started by a netcfgd too old to write the record, or a `/run`
			// cleared underneath a running tunnel. Nothing may be concluded.
			continue;
		};
		backend.config_matches =
			netcfgd_openvpn::hash_of(config).map(|current| current == recorded.trim());
	}
}

/// Where the secrets live, which is `netcfgd-apply`'s definition.
///
/// One spelling, for the reason `report_dir` has one: two crates deciding
/// separately where `/etc/netcfgd/secrets` is would work until one of them
/// moved.
fn secrets_dir() -> PathBuf {
	netcfgd_apply::kernel::secrets_dir()
}

/// What a running access point was started with, from the file netcfgd wrote.
///
/// hostapd reads its configuration once, at startup (decision 0026), and
/// reports none of it back -- `GET_CONFIG` gives the SSID and the ciphers and
/// says nothing about the channel or the band. So the only account of what it
/// is running is netcfgd's own, and this reads it back into the model's
/// vocabulary rather than hostapd's: the planner then compares an `Ssid` to an
/// `Ssid` and can name the field that moved.
///
/// The passphrase is not read. It is in that file in the clear -- hostapd has
/// no indirection for one -- and an observation goes over the socket and into
/// `/run`, where constraint 5 says a secret may not.
fn started_with(run_dir: &Path, device: &str) -> Option<netcfgd_model::ObservedAccessPoint> {
	let text = fs::read_to_string(netcfgd_hostapd::config_path(run_dir, device)).ok()?;
	let value = |key: &str| -> Option<String> {
		text.lines()
			.map(str::trim)
			.find_map(|line| line.strip_prefix(&format!("{key}=")))
			.map(ToOwned::to_owned)
	};
	Some(netcfgd_model::ObservedAccessPoint {
		// `ssid2=` is hex, which is what the model holds: an SSID is 0..32
		// arbitrary octets and never guaranteed text.
		ssid: netcfgd_model::Ssid::from_hex(&value("ssid2")?).ok()?,
		band: value("hw_mode").and_then(|mode| netcfgd_hostapd::band_of_hw_mode(&mode)),
		channel: value("channel").and_then(|channel| channel.parse().ok()),
	})
}

/// What a running router advertisement daemon was last given.
///
/// Read from the configuration netcfgd generated, which is netcfgd's own record
/// of what it started the daemon with -- the same shape as the ACL policy above
/// and for the same reason: radvd has no way to be asked, and the file netcfgd
/// wrote is the only account of what is being announced.
///
/// The one value in it that matters is the prefix, because that is the one that
/// arrives after the document does. An ISP renumbers, the LAN's address moves,
/// and a daemon still announcing the old block tells every host on the wire to
/// use an address the upstream will not route. The planner compares this
/// against what the document and the current delegation imply, and reloads when
/// they differ.
fn read_advertised(observed: &mut Observed, run_dir: &Path) {
	for backend in &mut observed.backends {
		if backend.kind != netcfgd_model::BackendKind::RouterAdvert || !backend.running {
			continue;
		}
		let path = netcfgd_ra::config_path(run_dir, &backend.interface);
		let Ok(text) = fs::read_to_string(&path) else {
			// The file is gone from under a daemon netcfgd's record says is
			// running. Saying nothing is the honest answer, and it is also the
			// safe one: an empty list would read as "advertising nothing" and
			// make the planner reload on every reconcile.
			continue;
		};
		backend.advertised = text
			.lines()
			.map(str::trim)
			.filter_map(|line| line.strip_prefix("prefix "))
			.map(|prefix| prefix.trim().to_owned())
			.collect();
	}
}

/// Whether an interface forwards, from both families' sysctls.
///
/// `Some(true)` needs both. A machine with IPv4 forwarding on and IPv6 off
/// routes half its traffic and drops the other half at the router, which is a
/// state worth planning a change out of rather than reporting as configured.
fn forwarding(root: &std::path::Path, name: &str) -> Option<bool> {
	let read = |family: &str| -> Option<bool> {
		let path = root.join(format!("sys/net/{family}/conf/{name}/forwarding"));
		Some(fs::read_to_string(path).ok()?.trim() != "0")
	};
	// Both must be readable. One family present and the other missing means an
	// IPv6-disabled kernel, where reporting the IPv4 answer alone would have
	// the planner satisfied by half a change it can never complete.
	Some(read("ipv4")? && read("ipv6")?)
}

/// Whether one interface's radio is switched off.
///
/// Two reads and a search. `/sys/class/net/<iface>/phy80211/name` is the phy this
/// interface belongs to, and exists only for a radio -- so anything wired returns
/// `None` here without a special case. Then the `rfkill` entry whose `name` is
/// that phy carries `soft` and `hard`.
///
/// **The phy's own switch, deliberately.** A laptop has a second `wlan` entry for
/// the platform button -- `dell-wifi` on the machine this was written on -- and
/// reading that one instead would report a block for a different radio on a
/// machine with two cards. What the driver obeys is the phy's, which is why that
/// is the answer, and decision 0062 records the part that was not measured.
///
/// `None` for a kernel with no `CONFIG_RFKILL`, and for a phy with no switch
/// registered. Both mean "netcfgd cannot tell", which nothing is planned on.
fn rfkill(sys: &Path, iface: &str) -> Option<netcfgd_model::ObservedRfkill> {
	let phy = fs::read_to_string(sys.join(format!("class/net/{iface}/phy80211/name")))
		.ok()?
		.trim()
		.to_owned();
	// Sorted, because `read_dir` order is the filesystem's and a laptop has two
	// `wlan` switches: whichever comes first is luck, and a test that depends on
	// that luck proves nothing about the search below. Deleting the name match
	// left the unit test passing until this sort was here.
	let mut entries: Vec<PathBuf> = fs::read_dir(sys.join("class/rfkill"))
		.ok()?
		.flatten()
		.map(|entry| entry.path())
		.collect();
	entries.sort();
	for path in entries {
		let name = fs::read_to_string(path.join("name")).ok()?;
		let name = name.trim().to_owned();
		if name != phy {
			continue;
		}
		// A flag that cannot be read is not a flag that is clear. Both are
		// required, so a truncated read reports nothing rather than a radio that
		// looks fine.
		let flag = |file: &str| -> Option<bool> {
			Some(fs::read_to_string(path.join(file)).ok()?.trim() == "1")
		};
		return Some(netcfgd_model::ObservedRfkill {
			// The name read from *this* entry, not the phy name the search started
			// from. They are equal by the check above -- which is the point: a
			// field describing where the flags came from must be able to disagree,
			// or it cannot be wrong when the search is.
			switch: name,
			soft: flag("soft")?,
			hard: flag("hard")?,
		});
	}
	None
}

/// The running hostname.
///
/// `/proc/sys/kernel/hostname` rather than the `gethostname` syscall, which would
/// be an `unsafe` FFI call in a crate that forbids it -- and the file is the same
/// value. Trimmed, because the kernel's file ends in a newline and the config's
/// string does not.
fn hostname(root: &std::path::Path) -> Option<String> {
	let name = fs::read_to_string(root.join("sys/kernel/hostname")).ok()?;
	Some(name.trim().to_owned())
}

/// Whether one interface prefers a temporary address.
///
/// `2` is the only value the document can ask for, so it is the only one that
/// reads as true -- `1` generates a temporary address and prefers the stable one,
/// which is a state nothing here can request and netcfgd therefore does not claim
/// as its own.
///
/// `None` where the file is not there at all, which is an IPv6-disabled kernel or
/// a container with no `/proc/sys`. Nothing is planned on a `None`.
fn privacy(root: &std::path::Path, name: &str) -> Option<bool> {
	let path = root.join(format!("sys/net/ipv6/conf/{name}/use_tempaddr"));
	Some(fs::read_to_string(path).ok()?.trim() == "2")
}

/// What this interface will do with a router advertisement.
///
/// Two files, read together, because neither answers on its own: `accept_ra=1`
/// is the kernel's default and means "accept unless this interface forwards", so
/// the same value is the working state on a laptop and the broken one on a
/// router. Decision 0073.
///
/// The forwarding file read here is the **IPv6** one alone. `ObservedLink::
/// forwarding` is `Some(true)` only when both families forward, which is the
/// right answer to a different question -- a machine with IPv6 forwarding on and
/// IPv4 off ignores advertisements while that field says `false`.
///
/// A forwarding sysctl that cannot be read is treated as off, which is the
/// kernel's own default for an interface: the value that is *there* is
/// `accept_ra`, and refusing to answer at all because its neighbour is missing
/// would report "netcfgd cannot tell" on a machine where it plainly can.
fn accept_ra(root: &std::path::Path, name: &str) -> Option<netcfgd_model::ObservedAcceptRa> {
	let path = root.join(format!("sys/net/ipv6/conf/{name}/accept_ra"));
	let value: u8 = fs::read_to_string(path).ok()?.trim().parse().ok()?;
	let forwards = fs::read_to_string(root.join(format!("sys/net/ipv6/conf/{name}/forwarding")))
		.map(|text| text.trim() == "1")
		.unwrap_or(false);
	Some(netcfgd_model::ObservedAcceptRa {
		value,
		effective: value == 2 || (value == 1 && !forwards),
	})
}

/// Every managed offload that is on, per interface.
///
/// One request per link, which is one more round trip than a dump would be --
/// but ethtool has no dump: its messages are per-device by construction. On a
/// laptop that is a handful of requests and on a router a few dozen, each
/// costing microseconds.
///
/// A device with no ethtool operations answers `EOPNOTSUPP`, which is most
/// virtual interfaces and is not an error. So is a kernel older than 5.6, which
/// has no `ethtool` family at all -- there the list is empty everywhere and
/// nothing is planned, which is the honest outcome.
fn read_offloads(observed: &mut Observed) {
	let Ok(mut ethtool) = netcfgd_sys::ethtool::Ethtool::open() else {
		return;
	};
	let managed: Vec<&str> = netcfgd_model::interface::offload_names::GRO
		.iter()
		.chain(netcfgd_model::interface::offload_names::GSO)
		.chain(netcfgd_model::interface::offload_names::TSO)
		.chain(netcfgd_model::interface::offload_names::RX_CHECKSUM)
		.chain(netcfgd_model::interface::offload_names::TX_CHECKSUM)
		.copied()
		.collect();

	for link in &mut observed.links {
		let Ok(active) = ethtool.active_features(&link.name) else {
			continue;
		};
		link.offloads = active
			.into_iter()
			.filter(|name| managed.contains(&name.as_str()))
			.collect();
	}
}

/// netcfgd's own NAT, and anyone else's.
fn read_netfilter(observed: &mut Observed) {
	let Ok(mut nft) = netcfgd_sys::nft::Nft::open() else {
		return;
	};
	observed.nat = nft.nat_uplinks().unwrap_or_default();

	let mut conflicts: Vec<String> = nft
		.chains()
		.unwrap_or_default()
		.into_iter()
		.filter(|chain| chain.is_source_nat() && chain.table != netcfgd_sys::nft::TABLE)
		.map(|chain| chain.table)
		.collect();
	conflicts.sort();
	conflicts.dedup();
	observed.nat_conflicts = conflicts;
}

#[cfg(test)]
mod tests {
	use super::*;

	/// A sysfs tree with one radio, one wired interface and two `wlan` switches.
	///
	/// The second switch is the point. A laptop registers one for the platform
	/// button beside the phy's own -- `dell-wifi` and `phy0` on the machine this
	/// was written on -- and a reader that took the first `wlan` entry it found
	/// would report the button's state for the card, which on a machine with two
	/// cards is somebody else's radio.
	fn sysfs(soft: &str, hard: &str) -> tempdir::TempDir {
		let dir = tempdir::TempDir::new("ncfg-rfkill");
		let write = |path: PathBuf, value: &str| {
			fs::create_dir_all(path.parent().expect("a parent")).expect("a directory");
			fs::write(path, value).expect("a file");
		};
		let root = dir.path().to_owned();
		write(root.join("class/net/wlan0/phy80211/name"), "phy0\n");
		// The wired interface has no `phy80211` at all, which is how the reader
		// tells them apart with no special case.
		write(root.join("class/net/eth0/mtu"), "1500\n");

		write(root.join("class/rfkill/rfkill0/name"), "dell-wifi\n");
		write(root.join("class/rfkill/rfkill0/type"), "wlan\n");
		write(root.join("class/rfkill/rfkill0/soft"), "1\n");
		write(root.join("class/rfkill/rfkill0/hard"), "0\n");

		write(root.join("class/rfkill/rfkill1/name"), "phy0\n");
		write(root.join("class/rfkill/rfkill1/type"), "wlan\n");
		write(root.join("class/rfkill/rfkill1/soft"), soft);
		write(root.join("class/rfkill/rfkill1/hard"), hard);
		dir
	}

	#[test]
	fn a_radio_reports_its_own_switch_and_not_the_platform_button() {
		let dir = sysfs("0\n", "0\n");
		let state = rfkill(dir.path(), "wlan0").expect("a switch");
		assert_eq!(state.switch, "phy0");
		// `dell-wifi` is soft-blocked in the fixture and this must not read it.
		assert!(!state.blocked(), "the platform button's state was reported");
	}

	#[test]
	fn a_soft_block_and_a_hard_block_are_told_apart() {
		let dir = sysfs("1\n", "0\n");
		let state = rfkill(dir.path(), "wlan0").expect("a switch");
		assert!(state.soft && !state.hard && state.blocked());

		let dir = sysfs("0\n", "1\n");
		let state = rfkill(dir.path(), "wlan0").expect("a switch");
		assert!(state.hard && !state.soft && state.blocked());
	}

	#[test]
	fn anything_that_is_not_a_radio_reports_nothing() {
		let dir = sysfs("0\n", "0\n");
		assert!(rfkill(dir.path(), "eth0").is_none());
		assert!(rfkill(dir.path(), "nonesuch").is_none());
	}

	/// A switch whose flags cannot be read is not a switch that is clear.
	///
	/// `None` is not `false` (0052's rule): a truncated entry -- a name with no
	/// `soft` beside it, which is what a partially-populated sysfs looks like --
	/// must report nothing rather than a radio that appears to be working.
	#[test]
	fn a_switch_with_no_flags_reports_nothing() {
		let dir = tempdir::TempDir::new("ncfg-rfkill-partial");
		let root = dir.path().to_owned();
		let write = |path: PathBuf, value: &str| {
			fs::create_dir_all(path.parent().expect("a parent")).expect("a directory");
			fs::write(path, value).expect("a file");
		};
		write(root.join("class/net/wlan0/phy80211/name"), "phy0\n");
		write(root.join("class/rfkill/rfkill0/name"), "phy0\n");
		// No `soft`, no `hard`.
		assert!(rfkill(dir.path(), "wlan0").is_none());
	}

	/// A kernel with no rfkill at all, which is not the same as a clear switch.
	#[test]
	fn a_kernel_without_rfkill_reports_nothing() {
		let dir = tempdir::TempDir::new("ncfg-rfkill-none");
		let path = dir.path().join("class/net/wlan0/phy80211/name");
		fs::create_dir_all(path.parent().expect("a parent")).expect("a directory");
		fs::write(path, "phy0\n").expect("a file");
		assert!(rfkill(dir.path(), "wlan0").is_none());
	}

	/// A directory that removes itself, with no dependency to do it.
	mod tempdir {
		use std::path::{Path, PathBuf};

		pub(super) struct TempDir(PathBuf);

		impl TempDir {
			pub(super) fn new(tag: &str) -> Self {
				// A counter as well as the process id, because the tag is *not*
				// enough: cargo runs these tests in parallel threads of one
				// process, and three of them ask for the same tree. The first
				// version wiped one test's fixture from under another and failed
				// whichever lost the race.
				static NEXT: std::sync::atomic::AtomicUsize =
					std::sync::atomic::AtomicUsize::new(0);
				let unique = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
				let path =
					std::env::temp_dir().join(format!("{tag}-{}-{unique}", std::process::id()));
				let _ = std::fs::remove_dir_all(&path);
				std::fs::create_dir_all(&path).expect("a temporary directory");
				Self(path)
			}

			pub(super) fn path(&self) -> &Path {
				&self.0
			}
		}

		impl Drop for TempDir {
			fn drop(&mut self) {
				let _ = std::fs::remove_dir_all(&self.0);
			}
		}
	}
}
