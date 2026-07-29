//! `WireGuard`, over generic netlink.
//!
//! The device itself is an ordinary rtnetlink link of kind `wireguard`. Its
//! configuration -- keys, peers, allowed IPs -- is not: it goes through the
//! `wireguard` generic netlink family, which is why this could not be written
//! before [`crate::genl`] existed.
//!
//! Nothing here is `unsafe`. The endpoint encoding builds a `sockaddr_in` or
//! `sockaddr_in6` by hand rather than transmuting a libc struct, because the
//! layout is four fixed fields and writing them out is both shorter than the
//! `SAFETY` comment a transmute would need and impossible to get wrong in a
//! way that compiles.
//!
//! Keys arrive as raw octets. Base64 is the config's spelling and belongs with
//! the config; this crate has no netcfgd dependencies and keeps none.

use crate::genl::{Family, Genl, GenlHeader};
use crate::wire::{flags, AttrBuf, Attrs};
use std::io;
use std::net::{IpAddr, SocketAddr};

/// The family name to resolve.
pub const WG_FAMILY: &str = "wireguard";

/// `WG_CMD_GET_DEVICE`.
const WG_CMD_GET_DEVICE: u8 = 0;
/// `WG_CMD_SET_DEVICE`.
const WG_CMD_SET_DEVICE: u8 = 1;
/// The family's interface version.
const WG_GENL_VERSION: u8 = 1;

/// `WGDEVICE_A_PUBLIC_KEY`, which only a `GET` produces.
const WGDEVICE_A_PUBLIC_KEY: u16 = 4;

/// `WGDEVICE_A_*`.
///
/// The numbering has a gap that is easy to miscount: `WGDEVICE_A_PUBLIC_KEY`
/// sits at 4 between the private key and the flags, because the kernel reports
/// the derived public key on a `GET` even though nothing sets it. Numbering
/// `FLAGS` as 4 sends a four-byte value where a 32-octet key is expected, and
/// the kernel answers `ERANGE` -- which names neither the attribute nor the
/// length. Found exactly that way.
const WGDEVICE_A_IFNAME: u16 = 2;
const WGDEVICE_A_PRIVATE_KEY: u16 = 3;
const WGDEVICE_A_FLAGS: u16 = 5;
const WGDEVICE_A_LISTEN_PORT: u16 = 6;
const WGDEVICE_A_FWMARK: u16 = 7;
const WGDEVICE_A_PEERS: u16 = 8;

/// `WGDEVICE_F_REPLACE_PEERS`.
///
/// Without it a `SET_DEVICE` merges: peers already on the device that the
/// document no longer mentions stay, and the tunnel keeps accepting traffic
/// from somebody the config has removed. netcfgd always sets it, which is
/// constraint 1 applied to a peer list.
const WGDEVICE_F_REPLACE_PEERS: u32 = 1;

/// `WGPEER_A_*`.
const WGPEER_A_PUBLIC_KEY: u16 = 1;
const WGPEER_A_PRESHARED_KEY: u16 = 2;
const WGPEER_A_FLAGS: u16 = 3;
const WGPEER_A_ENDPOINT: u16 = 4;
const WGPEER_A_PERSISTENT_KEEPALIVE_INTERVAL: u16 = 5;
const WGPEER_A_ALLOWEDIPS: u16 = 9;

/// `WGPEER_F_REPLACE_ALLOWEDIPS`, for the same reason as the device flag.
const WGPEER_F_REPLACE_ALLOWEDIPS: u32 = 2;

/// `WGALLOWEDIP_A_*`.
const WGALLOWEDIP_A_FAMILY: u16 = 1;
const WGALLOWEDIP_A_IPADDR: u16 = 2;
const WGALLOWEDIP_A_CIDR_MASK: u16 = 3;

/// `NLA_F_NESTED`.
///
/// Generic netlink validates strictly: an attribute the family declares as
/// nested must carry this bit, or the whole message is rejected with `EINVAL`
/// naming nothing. rtnetlink does not enforce it, which is why nothing in this
/// crate needed it until now -- and why its absence is easy to miss.
const NLA_F_NESTED: u16 = 0x8000;

const AF_INET: u16 = 2;
const AF_INET6: u16 = 10;

/// A key, as the kernel wants it.
pub type RawKey = [u8; 32];

/// One peer's desired configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Peer {
	/// The peer's public key, which is also its identity.
	pub public_key: RawKey,
	/// An optional additional symmetric key.
	pub preshared_key: Option<RawKey>,
	/// Where to send, when the peer is not roaming.
	pub endpoint: Option<SocketAddr>,
	/// Which destinations route to this peer, as `(address, prefix length)`.
	pub allowed_ips: Vec<(IpAddr, u8)>,
	/// Seconds between keepalives, or none.
	pub keepalive: Option<u16>,
}

/// A device's desired configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Device {
	/// Interface name.
	pub name: String,
	/// The device's private key.
	pub private_key: RawKey,
	/// UDP port to listen on, or none for an ephemeral one.
	pub listen_port: Option<u16>,
	/// Firewall mark to set on outgoing packets.
	pub fwmark: Option<u32>,
	/// Every peer the document describes.
	pub peers: Vec<Peer>,
}

/// Encode a peer's allowed IPs nest.
fn allowed_ips_attrs(allowed: &[(IpAddr, u8)]) -> AttrBuf {
	let mut nest = AttrBuf::new();
	for (index, (address, prefix)) in allowed.iter().enumerate() {
		let mut entry = AttrBuf::new();
		entry.push(
			WGALLOWEDIP_A_FAMILY,
			&if address.is_ipv4() { AF_INET } else { AF_INET6 }.to_ne_bytes(),
		);
		entry.push_ip(WGALLOWEDIP_A_IPADDR, *address);
		entry.push_u8(WGALLOWEDIP_A_CIDR_MASK, *prefix);
		// The nest is an array: the attribute *type* is the index, not a
		// meaning. Numbering them all the same produces a list the kernel
		// reads as one entry repeated.
		#[allow(clippy::cast_possible_truncation)]
		nest.push(index as u16 | NLA_F_NESTED, entry.as_bytes());
	}
	nest
}

/// Encode an endpoint as the `sockaddr` the kernel copies straight into place.
///
/// Built field by field rather than by transmuting a libc struct: the layout
/// is fixed by the ABI, the port is big-endian while the family is native, and
/// writing it out makes both facts visible instead of hiding them behind a
/// cast that would need its own `SAFETY` comment.
fn endpoint_bytes(endpoint: SocketAddr) -> Vec<u8> {
	let mut out = Vec::new();
	match endpoint {
		SocketAddr::V4(v4) => {
			out.extend_from_slice(&AF_INET.to_ne_bytes());
			out.extend_from_slice(&v4.port().to_be_bytes());
			out.extend_from_slice(&v4.ip().octets());
			// `sin_zero`, which pads the struct to the common 16 bytes.
			out.extend_from_slice(&[0_u8; 8]);
		}
		SocketAddr::V6(v6) => {
			out.extend_from_slice(&AF_INET6.to_ne_bytes());
			out.extend_from_slice(&v6.port().to_be_bytes());
			out.extend_from_slice(&v6.flowinfo().to_be_bytes());
			out.extend_from_slice(&v6.ip().octets());
			out.extend_from_slice(&v6.scope_id().to_ne_bytes());
		}
	}
	out
}

/// Encode one peer.
fn peer_attrs(peer: &Peer) -> AttrBuf {
	let mut attrs = AttrBuf::new();
	attrs.push(WGPEER_A_PUBLIC_KEY, &peer.public_key);
	if let Some(preshared) = &peer.preshared_key {
		attrs.push(WGPEER_A_PRESHARED_KEY, preshared);
	}
	// Replace rather than merge, for the same reason the device flag does: an
	// allowed IP the document has removed must stop routing to this peer.
	attrs.push_u32(WGPEER_A_FLAGS, WGPEER_F_REPLACE_ALLOWEDIPS);
	if let Some(endpoint) = peer.endpoint {
		attrs.push(WGPEER_A_ENDPOINT, &endpoint_bytes(endpoint));
	}
	if let Some(keepalive) = peer.keepalive {
		attrs.push(
			WGPEER_A_PERSISTENT_KEEPALIVE_INTERVAL,
			&keepalive.to_ne_bytes(),
		);
	}
	attrs.push(
		WGPEER_A_ALLOWEDIPS | NLA_F_NESTED,
		allowed_ips_attrs(&peer.allowed_ips).as_bytes(),
	);
	attrs
}

/// Build the attribute set for a `SET_DEVICE`, without sending it.
///
/// Separate from [`set_device`] so the encoding can be checked byte for byte
/// without a kernel -- which is most of what can go wrong here.
#[must_use]
pub fn set_device_attrs(device: &Device) -> AttrBuf {
	let mut attrs = AttrBuf::new();
	attrs.push_str(WGDEVICE_A_IFNAME, &device.name);
	attrs.push_u32(WGDEVICE_A_FLAGS, WGDEVICE_F_REPLACE_PEERS);
	attrs.push(WGDEVICE_A_PRIVATE_KEY, &device.private_key);
	if let Some(port) = device.listen_port {
		attrs.push(WGDEVICE_A_LISTEN_PORT, &port.to_ne_bytes());
	}
	if let Some(fwmark) = device.fwmark {
		attrs.push_u32(WGDEVICE_A_FWMARK, fwmark);
	}

	let mut peers = AttrBuf::new();
	for (index, peer) in device.peers.iter().enumerate() {
		#[allow(clippy::cast_possible_truncation)]
		peers.push(index as u16 | NLA_F_NESTED, peer_attrs(peer).as_bytes());
	}
	attrs.push(WGDEVICE_A_PEERS | NLA_F_NESTED, peers.as_bytes());
	attrs
}

/// Apply a device's whole configuration.
///
/// One message, replacing everything. `WireGuard` has no partial update that
/// netcfgd wants: the document is the peer list, so anything the kernel holds
/// that the document does not is drift to be removed rather than state to be
/// preserved.
///
/// # Errors
///
/// Returns `NotFound` if the `wireguard` family is absent -- the module is not
/// loaded -- and the errno the kernel replied with otherwise.
pub fn set_device(genl: &mut Genl, device: &Device) -> io::Result<()> {
	let family = genl.family(WG_FAMILY)?;
	set_device_with(genl, &family, device)
}

/// Apply a configuration to an already-resolved family.
///
/// # Errors
///
/// Returns the errno the kernel replied with.
pub fn set_device_with(genl: &mut Genl, family: &Family, device: &Device) -> io::Result<()> {
	genl.request(
		family,
		GenlHeader {
			cmd: WG_CMD_SET_DEVICE,
			version: WG_GENL_VERSION,
		},
		flags::NLM_F_ACK,
		&set_device_attrs(device),
	)?;
	Ok(())
}

/// What the kernel currently holds for a device.
///
/// Not the same shape as [`Device`]: a `GET` reports the *public* key, which
/// is derived, and never the private one. That asymmetry is the point --
/// reconciliation compares what can be read, and a private key that cannot be
/// read back is a private key that cannot leak through an observation.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct DeviceState {
	/// The public key derived from the private one.
	pub public_key: Option<RawKey>,
	/// The port it is listening on.
	pub listen_port: Option<u16>,
	/// The firewall mark, where one is set.
	pub fwmark: Option<u32>,
	/// Every peer, in the order the kernel reported them.
	pub peers: Vec<PeerState>,
}

/// One peer, as the kernel holds it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerState {
	/// The peer's identity.
	pub public_key: RawKey,
	/// Whether a preshared key is set. The value is not reported, and asking
	/// for it would be asking the kernel to hand back a secret.
	pub has_preshared_key: bool,
	/// Where it is, if it has an endpoint.
	pub endpoint: Option<SocketAddr>,
	/// What routes to it.
	pub allowed_ips: Vec<(IpAddr, u8)>,
	/// Keepalive interval in seconds, zero meaning off.
	pub keepalive: u16,
}

/// Read a device's current configuration.
///
/// # Errors
///
/// Returns `NotFound` if the family or the device is absent, and the errno the
/// kernel replied with otherwise.
pub fn get_device(genl: &mut Genl, name: &str) -> io::Result<DeviceState> {
	let family = genl.family(WG_FAMILY)?;
	let mut attrs = AttrBuf::new();
	attrs.push_str(WGDEVICE_A_IFNAME, name);

	let replies = genl.request(
		&family,
		GenlHeader {
			cmd: WG_CMD_GET_DEVICE,
			version: WG_GENL_VERSION,
		},
		flags::NLM_F_DUMP,
		&attrs,
	)?;

	let mut state = DeviceState::default();
	// A device with many peers arrives as several messages, each carrying a
	// slice of the peer list. Taking only the first would report a truncated
	// configuration as the whole of it.
	for reply in &replies {
		merge_device_reply(&mut state, reply);
	}
	Ok(state)
}

fn merge_device_reply(state: &mut DeviceState, payload: &[u8]) {
	let attrs = crate::genl::payload_attrs(payload);
	if let Some(key) = attrs.get(WGDEVICE_A_PUBLIC_KEY).and_then(raw_key) {
		state.public_key = Some(key);
	}
	if let Some(port) = attrs.get(WGDEVICE_A_LISTEN_PORT).and_then(|a| a.u16()) {
		state.listen_port = Some(port);
	}
	if let Some(mark) = attrs.get(WGDEVICE_A_FWMARK).and_then(|a| a.u32()) {
		state.fwmark = Some(mark);
	}
	let Some(peers) = attrs.get(WGDEVICE_A_PEERS) else {
		return;
	};
	for entry in Attrs::new(peers.value) {
		if let Some(peer) = parse_peer(entry.value) {
			state.peers.push(peer);
		}
	}
}

fn parse_peer(bytes: &[u8]) -> Option<PeerState> {
	let attrs = Attrs::new(bytes);
	let public_key = attrs.get(WGPEER_A_PUBLIC_KEY).and_then(raw_key)?;

	let mut allowed_ips = Vec::new();
	if let Some(nest) = attrs.get(WGPEER_A_ALLOWEDIPS) {
		for entry in Attrs::new(nest.value) {
			let inner = Attrs::new(entry.value);
			if let (Some(address), Some(prefix)) = (
				inner.get(WGALLOWEDIP_A_IPADDR).and_then(|a| a.ip()),
				inner.get(WGALLOWEDIP_A_CIDR_MASK).and_then(|a| a.u8()),
			) {
				allowed_ips.push((address, prefix));
			}
		}
	}

	Some(PeerState {
		public_key,
		// A preshared key is reported as 32 zero octets when unset, which is
		// the kernel saying "none" rather than "the key is zero" -- an
		// all-zero preshared key is not usable.
		has_preshared_key: attrs
			.get(WGPEER_A_PRESHARED_KEY)
			.and_then(raw_key)
			.is_some_and(|key| key != [0_u8; 32]),
		endpoint: attrs
			.get(WGPEER_A_ENDPOINT)
			.and_then(|a| parse_sockaddr(a.value)),
		allowed_ips,
		keepalive: attrs
			.get(WGPEER_A_PERSISTENT_KEEPALIVE_INTERVAL)
			.and_then(|a| a.u16())
			.unwrap_or(0),
	})
}

fn raw_key(attr: crate::wire::Attr<'_>) -> Option<RawKey> {
	attr.value.get(0..32)?.try_into().ok()
}

/// The inverse of [`endpoint_bytes`].
fn parse_sockaddr(bytes: &[u8]) -> Option<SocketAddr> {
	let family = u16::from_ne_bytes(bytes.get(0..2)?.try_into().ok()?);
	let port = u16::from_be_bytes(bytes.get(2..4)?.try_into().ok()?);
	match family {
		AF_INET => {
			let octets: [u8; 4] = bytes.get(4..8)?.try_into().ok()?;
			Some(SocketAddr::from((std::net::Ipv4Addr::from(octets), port)))
		}
		AF_INET6 => {
			let octets: [u8; 16] = bytes.get(8..24)?.try_into().ok()?;
			Some(SocketAddr::from((std::net::Ipv6Addr::from(octets), port)))
		}
		_ => None,
	}
}
