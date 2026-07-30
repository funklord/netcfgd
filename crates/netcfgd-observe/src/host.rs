//! The parts of the observation that are not rtnetlink.
//!
//! Two things netcfgd now configures cannot be read from the link dump: the
//! `forwarding` sysctls, which live in `/proc/sys`, and the nftables table,
//! which is a different netlink protocol. Both are read here so that
//! [`crate::build`] stays a pure function of a snapshot -- the diffing rules
//! for NAT and forwarding are then testable without a kernel, in the same way
//! address ownership already is.
//!
//! Nothing in here fails the observation. A machine with no `nf_tables` and a
//! container with no writable `/proc/sys` are both ordinary, and the honest
//! reading in each case is "netcfgd has installed nothing", which is what an
//! empty list and a `None` say. What must not happen is a daemon that refuses
//! to start on a kernel that simply does not have a feature nobody asked for.

use netcfgd_model::Observed;
use std::fs;
use std::path::PathBuf;

/// Where the sysctls live, overridable so this is testable without root.
fn proc_root() -> PathBuf {
	std::env::var_os("NCFG_PROC_ROOT").map_or_else(|| PathBuf::from("/proc"), PathBuf::from)
}

/// Fill in everything the netlink snapshot could not supply.
pub fn augment(observed: &mut Observed) {
	let root = proc_root();
	for link in &mut observed.links {
		link.forwarding = forwarding(&root, &link.name);
	}
	read_netfilter(observed);
	read_offloads(observed);
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
