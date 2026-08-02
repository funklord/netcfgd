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

/// Fill in everything the netlink snapshot could not supply.
pub fn augment(observed: &mut Observed, run_dir: &Path, desired: Option<&netcfgd_model::Document>) {
	let root = proc_root();
	for link in &mut observed.links {
		link.forwarding = forwarding(&root, &link.name);
	}
	read_netfilter(observed);
	read_offloads(observed);
	read_access_control(observed, run_dir);
	read_advertised(observed, run_dir);
	read_secret_currency(observed, run_dir, desired);
	read_wireguard_keys(observed);
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
		link.private_key_loaded = netcfgd_sys::wg::get_device(&mut genl, &link.name)
			.is_ok_and(|state| state.public_key.is_some());
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
