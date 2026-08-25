// This crate is section 1 constraint 4's single audited exception: the only
// place in netcfgd where `unsafe` is permitted. It is not forbidden here, and
// the absence of the usual attribute is deliberate rather than an oversight.
//
// Everything that touches bytes off the wire lives in `wire` and `dump`, both
// of which are entirely safe. The `unsafe` is six syscalls in `socket`, each
// with a SAFETY comment naming the invariant that makes it sound.

//! Direct kernel interfaces: rtnetlink, and inotify.
//!
//! Named for the larger half. What actually defines this crate is section 1
//! constraint 4 -- it is the single place `unsafe` is permitted, so every raw
//! syscall netcfgd makes lives here whether or not it is netlink. A second
//! crate making syscalls would mean a second thing to audit to the same bar,
//! which is what the constraint exists to prevent (`doc/decision/0012`).
//!
//! Depends on libc and the kernel and nothing else, which is why its record
//! types are its own rather than `netcfgd-model`'s -- turning them into an
//! `Observed` belongs to `netcfgd-observe`.

#[cfg(feature = "tui")]
pub mod curses;
pub mod dump;
pub mod ethtool;
pub mod genl;
pub mod inotify;
pub mod lock;
pub mod nft;
pub mod ops;
pub mod peer;
pub mod process;
pub mod qdisc;
pub mod radio;
pub mod rfkill;
pub mod rule;
pub mod signals;
pub mod socket;
pub mod term;
pub mod watch;
pub mod wg;
pub mod wire;

pub use dump::{AddressRecord, LinkRecord, RouteRecord};
pub use genl::{Family, Genl, GenlHeader};
pub use ops::{parse_mac, NewLink, RouteSpec};
pub use peer::{credentials, Peer};
pub use socket::Netlink;
pub use watch::{Mechanism, Watcher};

use std::io;

/// Everything the kernel currently reports, in one round of dumps.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Snapshot {
	/// Every link.
	pub links: Vec<LinkRecord>,
	/// Every address.
	pub addresses: Vec<AddressRecord>,
	/// Every route.
	pub routes: Vec<RouteRecord>,
	/// Every bridge VLAN, from the separate `AF_BRIDGE` dump.
	pub bridge_vlans: Vec<dump::BridgeVlanRecord>,
	/// Every interface's root qdisc, plus which carry an ingress hook.
	pub qdiscs: qdisc::QdiscDump,
	/// `(interface, target, ours)` for each ingress redirect installed.
	///
	/// `ours` is read from the filter's handle, which netcfgd stamps (0137),
	/// so a redirect stays recognisable as netcfgd's after `/run` is gone.
	pub redirects: Vec<(u32, u32, bool)>,
	/// Every policy routing rule, from the `RTM_GETRULE` dump.
	pub rules: Vec<rule::RuleRecord>,
	/// Whether any address in this dump carried `IFA_PROTO`.
	///
	/// **A lower bound, not a kernel capability check.** `false` means "no
	/// evidence seen", not "the kernel cannot do this".
	///
	/// The tempting reading is that a 5.18-or-later kernel tags its own
	/// addresses -- `IFAPROT_KERNEL_LO` on loopback, `IFAPROT_KERNEL_LL` on a
	/// link-local -- so a plain dump would answer the question for free. It
	/// does not. Checked against a 6.12 kernel: neither `127.0.0.1` nor a
	/// kernel-generated `fe80::/64` carried the attribute, and `ip -d addr`
	/// agreed, so a passive probe reports `false` on a kernel that supports
	/// the feature completely.
	///
	/// What actually works is decision 0002's read-back, folded into ordinary
	/// operation rather than run as a separate probe: netcfgd sets
	/// `IFA_PROTO` on every address it installs, an older kernel ignores the
	/// unknown attribute, and the next dump says which happened. So this flag
	/// starts `false` on a fresh system and becomes `true` once netcfgd owns
	/// its first address. Until then the weaker recorded-state fallback
	/// applies, which is the conservative direction and costs only
	/// convenience.
	pub address_proto_supported: bool,
}

/// Take one round of dumps.
///
/// # Errors
///
/// Returns the underlying `io::Error` from the socket, or from a netlink error
/// reply.
pub fn snapshot() -> io::Result<Snapshot> {
	let mut socket = Netlink::open()?;
	socket.set_timeout(5)?;
	snapshot_with(&mut socket)
}

/// Take one round of dumps over an existing socket.
///
/// # Errors
///
/// Returns the underlying `io::Error`.
pub fn snapshot_with(socket: &mut Netlink) -> io::Result<Snapshot> {
	let (body, attrs) = dump::link_request();
	let links: Vec<LinkRecord> = socket
		.request(dump::requests::LINK, dump::dump_flags(), &body, &attrs)?
		.iter()
		.filter_map(|payload| dump::decode_link(payload))
		.collect();

	let (body, attrs) = dump::address_request();
	let addresses: Vec<AddressRecord> = socket
		.request(dump::requests::ADDRESS, dump::dump_flags(), &body, &attrs)?
		.iter()
		.filter_map(|payload| dump::decode_address(payload))
		.collect();

	let (body, attrs) = dump::route_request();
	let routes: Vec<RouteRecord> = socket
		.request(dump::requests::ROUTE, dump::dump_flags(), &body, &attrs)?
		.iter()
		.filter_map(|payload| dump::decode_route(payload))
		.collect();

	// A second link dump, under AF_BRIDGE. It cannot be folded into the first:
	// the ordinary dump reports bridges with their VLAN configuration omitted
	// rather than empty, and asking for both families at once is not a thing
	// the request can express.
	let (body, attrs) = dump::bridge_vlan_request();
	let mut bridge_vlans: Vec<dump::BridgeVlanRecord> = socket
		.request(
			dump::requests::BRIDGE_VLAN,
			dump::dump_flags(),
			&body,
			&attrs,
		)?
		.iter()
		.flat_map(|payload| dump::decode_bridge_vlans(payload))
		.collect();
	bridge_vlans.sort_unstable();

	// Qdiscs, which need their own dump because `RTM_GETQDISC` is a different
	// message and not an attribute of a link.
	let qdiscs = qdisc::Qdisc::new(socket).dump()?;

	// And one filter dump per interface that has an ingress hook, because
	// `RTM_GETTFILTER` will not dump across interfaces. Usually none, and at
	// most one per shaped uplink -- so this is not the N requests it looks
	// like on a machine that does no ingress shaping.
	let mut redirects = Vec::new();
	for index in &qdiscs.ingress_hooks {
		for (target, ours) in qdisc::Qdisc::new(socket).redirects_on(*index)? {
			redirects.push((*index, target, ours));
		}
	}
	redirects.sort_unstable();

	let rules = socket.rules()?;

	let address_proto_supported = addresses.iter().any(|address| address.proto.is_some());

	Ok(Snapshot {
		links,
		addresses,
		routes,
		bridge_vlans,
		qdiscs,
		redirects,
		rules,
		address_proto_supported,
	})
}
