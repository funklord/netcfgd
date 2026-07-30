//! `WireGuard`: the encoding without a kernel, and a real tunnel with one.
//!
//! The live half needs `CAP_NET_ADMIN` and the `wireguard` module, and skips
//! without either -- unless `NCFG_LIVE` is set, which turns a skip into a
//! failure so `make live` cannot pass by doing nothing.

use netcfgd_sys::wg::{self, Device, Peer};
use netcfgd_sys::wire::Attrs;
use netcfgd_sys::{Genl, NewLink};
use std::net::{IpAddr, SocketAddr};

const NLA_F_NESTED: u16 = 0x8000;

/// Walk attribute headers keeping the type bits intact.
///
/// [`Attrs`] masks the nested and byte-order bits off, which is right for a
/// reader -- they say how to interpret the value, not what it is. It does mean
/// the one property under test here, that the bit is *set on the way out*, is
/// invisible through the ordinary parser.
fn raw_attrs(bytes: &[u8]) -> Vec<(u16, &[u8])> {
	let mut out = Vec::new();
	let mut rest = bytes;
	while rest.len() >= 4 {
		let len = u16::from_ne_bytes(rest[0..2].try_into().expect("len")) as usize;
		let kind = u16::from_ne_bytes(rest[2..4].try_into().expect("kind"));
		if len < 4 || len > rest.len() {
			break;
		}
		out.push((kind, &rest[4..len]));
		let advance = (len + 3) & !3;
		if advance == 0 || advance > rest.len() {
			break;
		}
		rest = &rest[advance..];
	}
	out
}

fn key(seed: u8) -> [u8; 32] {
	let mut out = [0_u8; 32];
	for (index, byte) in out.iter_mut().enumerate() {
		#[allow(clippy::cast_possible_truncation)]
		{
			*byte = seed.wrapping_add(index as u8);
		}
	}
	out
}

fn sample() -> Device {
	Device {
		name: "wg-test".to_owned(),
		private_key: key(1),
		listen_port: Some(51820),
		fwmark: Some(42),
		peers: vec![Peer {
			public_key: key(100),
			preshared_key: Some(key(200)),
			endpoint: Some("127.0.0.1:51821".parse().expect("endpoint")),
			allowed_ips: vec![
				("10.9.0.0".parse::<IpAddr>().expect("v4"), 24),
				("fd00::".parse::<IpAddr>().expect("v6"), 64),
			],
			keepalive: Some(25),
		}],
	}
}

/// Generic netlink validates strictly: an attribute a family declares as
/// nested must carry `NLA_F_NESTED` or the whole message is rejected with
/// `EINVAL` naming nothing. rtnetlink does not enforce it, so nothing in this
/// crate needed the bit until `WireGuard` did.
#[test]
fn nested_attributes_carry_the_nested_flag() {
	let encoded = wg::set_device_attrs(&sample());

	let (peers_kind, peers) = raw_attrs(encoded.as_bytes())
		.into_iter()
		.find(|(kind, _)| kind & !NLA_F_NESTED == 8)
		.expect("a peers attribute");
	assert!(
		peers_kind & NLA_F_NESTED != 0,
		"WGDEVICE_A_PEERS must be marked nested"
	);

	// Each element of the array too, and the allowed-ips nest inside it.
	let (entry_kind, entry) = raw_attrs(peers).into_iter().next().expect("one peer");
	assert!(entry_kind & NLA_F_NESTED != 0, "an array element is nested");
	let (allowed_kind, allowed) = raw_attrs(entry)
		.into_iter()
		.find(|(kind, _)| kind & !NLA_F_NESTED == 9)
		.expect("an allowedips attribute");
	assert!(allowed_kind & NLA_F_NESTED != 0);
	for (kind, _) in raw_attrs(allowed) {
		assert!(kind & NLA_F_NESTED != 0, "an allowed ip is nested");
	}
}

/// The device attribute numbering has a gap: `WGDEVICE_A_PUBLIC_KEY` sits at 4
/// between the private key and the flags, because a `GET` reports the derived
/// key. Numbering `FLAGS` as 4 sends four bytes where 32 octets are expected
/// and the kernel answers `ERANGE`, naming neither the attribute nor the
/// length. That is how this was found.
#[test]
fn the_flags_attribute_is_five_and_replaces_peers() {
	let encoded = wg::set_device_attrs(&sample());
	let flags = Attrs::new(encoded.as_bytes())
		.find(|attr| attr.kind == 5)
		.expect("a flags attribute at 5");
	assert_eq!(flags.u32(), Some(1), "WGDEVICE_F_REPLACE_PEERS");

	// And nothing is sent at 4, which would be a malformed public key.
	assert!(
		Attrs::new(encoded.as_bytes()).all(|attr| attr.kind != 4),
		"nothing may occupy WGDEVICE_A_PUBLIC_KEY on a set"
	);
}

/// A `sockaddr_in` is 16 bytes with a big-endian port and a native-endian
/// family. Getting either wrong produces an endpoint the kernel accepts and
/// sends nothing to.
#[test]
fn an_endpoint_encodes_as_a_sockaddr() {
	let encoded = wg::set_device_attrs(&sample());
	let peers = Attrs::new(encoded.as_bytes())
		.find(|attr| attr.kind == 8)
		.expect("peers");
	let peer = Attrs::new(peers.value).next().expect("one peer");
	let endpoint = Attrs::new(peer.value)
		.find(|attr| attr.kind == 4)
		.expect("an endpoint");

	assert_eq!(endpoint.value.len(), 16, "sizeof(struct sockaddr_in)");
	assert_eq!(
		u16::from_ne_bytes(endpoint.value[0..2].try_into().expect("family")),
		2,
		"AF_INET, native-endian"
	);
	assert_eq!(
		u16::from_be_bytes(endpoint.value[2..4].try_into().expect("port")),
		51821,
		"the port is big-endian"
	);
	assert_eq!(&endpoint.value[4..8], &[127, 0, 0, 1]);
}

fn live_or_skip() -> Option<Genl> {
	match Genl::open() {
		Ok(mut genl) => match genl.family(wg::WG_FAMILY) {
			Ok(_) => Some(genl),
			Err(error) => {
				assert!(
					std::env::var_os("NCFG_LIVE").is_none(),
					"NCFG_LIVE is set but the wireguard family is absent: {error}"
				);
				println!("skipping: {error}");
				None
			}
		},
		Err(error) => {
			assert!(
				std::env::var_os("NCFG_LIVE").is_none(),
				"NCFG_LIVE is set but generic netlink is unavailable: {error}"
			);
			println!("skipping: {error}");
			None
		}
	}
}

/// The whole round trip against a real kernel: create the link, configure it,
/// and read back what the kernel actually holds.
///
/// Reading it back is the point. `SET_DEVICE` returning `OK` says the message
/// parsed, not that the peer is configured -- and every bug found writing this
/// was one where the message parsed.
#[test]
fn a_tunnel_round_trips_through_the_kernel() {
	let Some(mut genl) = live_or_skip() else {
		return;
	};
	let Ok(mut route) = netcfgd_sys::Netlink::open() else {
		println!("skipping: no rtnetlink socket");
		return;
	};
	if route.create_link("wg-test", &NewLink::WireGuard).is_err() {
		assert!(
			std::env::var_os("NCFG_LIVE").is_none(),
			"NCFG_LIVE is set but a wireguard link cannot be created (CAP_NET_ADMIN?)"
		);
		println!("skipping: cannot create a link");
		return;
	}

	let wanted = sample();
	wg::set_device(&mut genl, &wanted).expect("configure");
	let state = wg::get_device(&mut genl, "wg-test").expect("read back");

	assert_eq!(state.listen_port, Some(51820));
	assert_eq!(state.fwmark, Some(42));
	// The public key is derived by the kernel from the private one, which is
	// the only evidence available here that the private key arrived intact:
	// a `GET` never reports it back.
	assert!(
		state.public_key.is_some(),
		"the kernel derived a public key"
	);

	assert_eq!(state.peers.len(), 1, "one peer in, one peer out");
	let peer = &state.peers[0];
	assert_eq!(peer.public_key, key(100));
	assert!(peer.has_preshared_key);
	assert_eq!(
		peer.endpoint,
		Some("127.0.0.1:51821".parse::<SocketAddr>().expect("endpoint"))
	);
	assert_eq!(peer.keepalive, 25);
	assert_eq!(
		peer.allowed_ips,
		vec![
			("10.9.0.0".parse::<IpAddr>().expect("v4"), 24),
			("fd00::".parse::<IpAddr>().expect("v6"), 64),
		],
		"both families, in order"
	);
}

/// Decision 1: the document is the peer list. A peer the config has removed
/// must stop being able to send, which needs `WGDEVICE_F_REPLACE_PEERS` --
/// without it a `SET_DEVICE` merges and the removed peer stays.
#[test]
fn removing_a_peer_from_the_document_removes_it_from_the_kernel() {
	let Some(mut genl) = live_or_skip() else {
		return;
	};
	let Ok(mut route) = netcfgd_sys::Netlink::open() else {
		return;
	};
	if route.create_link("wg-drop", &NewLink::WireGuard).is_err() {
		println!("skipping: cannot create a link");
		return;
	}

	let mut two = sample();
	two.name = "wg-drop".to_owned();
	two.peers.push(Peer {
		public_key: key(7),
		preshared_key: None,
		endpoint: None,
		allowed_ips: vec![("192.0.2.0".parse::<IpAddr>().expect("v4"), 24)],
		keepalive: None,
	});
	wg::set_device(&mut genl, &two).expect("configure two");
	assert_eq!(
		wg::get_device(&mut genl, "wg-drop")
			.expect("read")
			.peers
			.len(),
		2
	);

	let mut one = two.clone();
	one.peers.truncate(1);
	wg::set_device(&mut genl, &one).expect("configure one");
	let state = wg::get_device(&mut genl, "wg-drop").expect("read");
	assert_eq!(
		state.peers.len(),
		1,
		"a peer the document dropped is still in the kernel"
	);
	assert_eq!(state.peers[0].public_key, key(100));
}
