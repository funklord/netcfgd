//! The codec, against bytes rather than against a kernel.
//!
//! Everything here runs with no socket, no privileges and no hardware, which
//! is the property that makes the netlink layer reviewable at all. The
//! adversarial cases at the bottom are the deterministic stand-in for the fuzz
//! target section 6 requires.

use netcfgd_netlink::dump::{decode_address, decode_link, decode_route};
use netcfgd_netlink::wire::{
	align4, build_request, error_code, flags, ifa, ifla, msg_type, rta, AttrBuf, Attrs, Header,
	IfAddr, IfInfo, Messages, RtMsg, IFADDR_LEN, IFINFO_LEN, NLMSG_HDR_LEN, RTMSG_LEN,
};

/// Build one netlink message: header, body, attributes.
fn message(kind: u16, seq: u32, body: &[u8], attrs: &AttrBuf) -> Vec<u8> {
	build_request(kind, 0, seq, body, attrs)
}

#[test]
fn a_header_round_trips() {
	let header = Header {
		len: 64,
		kind: msg_type::RTM_NEWLINK,
		flags: flags::NLM_F_MULTI,
		seq: 0xdead_beef,
		pid: 4242,
	};
	let mut bytes = Vec::new();
	header.encode(&mut bytes);
	assert_eq!(bytes.len(), NLMSG_HDR_LEN);

	// This is the test that caught `seq` being decoded from a two-byte slice,
	// which made every decode return None and would have made the whole
	// crate silently see an empty kernel.
	assert_eq!(Header::decode(&bytes), Some(header));
}

#[test]
fn the_payload_structs_round_trip() {
	let info = IfInfo {
		family: 0,
		kind: 1,
		index: 7,
		flags: 0x1_0043,
		change: 0,
	};
	let mut bytes = Vec::new();
	info.encode(&mut bytes);
	assert_eq!(bytes.len(), IFINFO_LEN);
	assert_eq!(IfInfo::decode(&bytes), Some(info));

	let addr = IfAddr {
		family: 2,
		prefix_len: 24,
		flags: 0,
		scope: 0,
		index: 7,
	};
	let mut bytes = Vec::new();
	addr.encode(&mut bytes);
	assert_eq!(bytes.len(), IFADDR_LEN);
	assert_eq!(IfAddr::decode(&bytes), Some(addr));

	let route = RtMsg {
		family: 2,
		dst_len: 0,
		src_len: 0,
		tos: 0,
		table: 254,
		protocol: 110,
		scope: 0,
		kind: 1,
		flags: 0,
	};
	let mut bytes = Vec::new();
	route.encode(&mut bytes);
	assert_eq!(bytes.len(), RTMSG_LEN);
	assert_eq!(RtMsg::decode(&bytes), Some(route));
}

#[test]
fn attributes_round_trip_including_padding() {
	let mut attrs = AttrBuf::new();
	attrs.push_str(ifla::IFNAME, "eth0");
	attrs.push_u32(ifla::MTU, 9000);
	attrs.push(ifla::ADDRESS, &[0x02, 0x00, 0x00, 0x00, 0x00, 0x01]);
	attrs.push_u8(ifa::PROTO, 110);

	// Every attribute starts on a 4-byte boundary, so a 5-byte name and a
	// 6-byte MAC both pad. If padding were wrong the later attributes would
	// decode as garbage rather than failing outright.
	assert_eq!(attrs.len(), align4(attrs.len()));

	let parsed = Attrs::new(attrs.as_bytes());
	assert_eq!(
		parsed.get(ifla::IFNAME).and_then(|a| a.string()).as_deref(),
		Some("eth0")
	);
	assert_eq!(parsed.get(ifla::MTU).and_then(|a| a.u32()), Some(9000));
	assert_eq!(
		parsed.get(ifla::ADDRESS).and_then(|a| a.mac()).as_deref(),
		Some("02:00:00:00:00:01")
	);
	assert_eq!(parsed.get(ifa::PROTO).and_then(|a| a.u8()), Some(110));
	assert_eq!(parsed.count(), 4);
}

#[test]
fn a_link_message_decodes() {
	let mut attrs = AttrBuf::new();
	attrs.push_str(ifla::IFNAME, "eth0");
	attrs.push_u32(ifla::MTU, 1500);
	attrs.push(ifla::ADDRESS, &[0xde, 0xad, 0xbe, 0xef, 0x00, 0x01]);
	attrs.push_u8(ifla::CARRIER, 1);

	let mut body = Vec::new();
	IfInfo {
		family: 0,
		kind: 1,
		index: 3,
		// IFF_UP | IFF_RUNNING
		flags: 0x41,
		change: 0,
	}
	.encode(&mut body);

	let raw = message(msg_type::RTM_NEWLINK, 1, &body, &attrs);
	let parsed = Messages::new(&raw).next().expect("one message");
	let link = decode_link(parsed.payload).expect("decodes");

	assert_eq!(link.name, "eth0");
	assert_eq!(link.index, 3);
	assert_eq!(link.mtu, 1500);
	assert!(link.up);
	assert!(link.carrier);
	assert_eq!(link.mac.as_deref(), Some("de:ad:be:ef:00:01"));
	assert_eq!(link.kind, "");
}

/// A link kind lives one level down, inside the `LINKINFO` nest.
#[test]
fn a_nested_link_kind_decodes() {
	let mut nest = AttrBuf::new();
	nest.push_str(ifla::INFO_KIND, "bridge");

	let mut attrs = AttrBuf::new();
	attrs.push_str(ifla::IFNAME, "br0");
	attrs.push(ifla::LINKINFO, nest.as_bytes());

	let mut body = Vec::new();
	IfInfo::default().encode(&mut body);

	let raw = message(msg_type::RTM_NEWLINK, 1, &body, &attrs);
	let parsed = Messages::new(&raw).next().expect("one message");
	let link = decode_link(parsed.payload).expect("decodes");
	assert_eq!(link.kind, "bridge");
}

/// Administrative up and carrier are different things. Conflating them is how
/// a plan decides to reconfigure a perfectly good interface whose cable is
/// out, or ignores one that is administratively down.
#[test]
fn carrier_and_admin_state_are_independent() {
	let mut attrs = AttrBuf::new();
	attrs.push_str(ifla::IFNAME, "eth0");
	attrs.push_u8(ifla::CARRIER, 0);

	let mut body = Vec::new();
	IfInfo {
		flags: 0x1, // IFF_UP, but no carrier
		..IfInfo::default()
	}
	.encode(&mut body);

	let raw = message(msg_type::RTM_NEWLINK, 1, &body, &attrs);
	let link = decode_link(Messages::new(&raw).next().unwrap().payload).expect("decodes");
	assert!(link.up);
	assert!(!link.carrier);
}

#[test]
fn an_address_message_decodes_with_its_proto() {
	let mut attrs = AttrBuf::new();
	attrs.push_ip(ifa::LOCAL, "192.168.1.10".parse().unwrap());
	attrs.push_u8(ifa::PROTO, 110);

	let mut body = Vec::new();
	IfAddr {
		family: 2,
		prefix_len: 24,
		flags: 0,
		scope: 0,
		index: 3,
	}
	.encode(&mut body);

	let raw = message(msg_type::RTM_NEWADDR, 1, &body, &attrs);
	let address = decode_address(Messages::new(&raw).next().unwrap().payload).expect("decodes");

	assert_eq!(address.cidr(), "192.168.1.10/24");
	assert_eq!(address.proto, Some(110));
	assert_eq!(address.index, 3);
}

/// On a kernel before 5.18 there is no `IFA_PROTO`, and the record has to say
/// so rather than inventing a value -- decision 0002 turns on the difference.
#[test]
fn an_address_without_proto_reports_none() {
	let mut attrs = AttrBuf::new();
	attrs.push_ip(ifa::LOCAL, "10.0.0.1".parse().unwrap());

	let mut body = Vec::new();
	IfAddr {
		family: 2,
		prefix_len: 8,
		flags: 0,
		scope: 0,
		index: 2,
	}
	.encode(&mut body);

	let raw = message(msg_type::RTM_NEWADDR, 1, &body, &attrs);
	let address = decode_address(Messages::new(&raw).next().unwrap().payload).expect("decodes");
	assert_eq!(address.proto, None);
}

/// `IFA_LOCAL` is this host's address; `IFA_ADDRESS` is the peer on a
/// point-to-point link. Preferring LOCAL is what stops a PPP interface
/// reporting the far end as its own.
#[test]
fn local_wins_over_address_on_a_point_to_point_link() {
	let mut attrs = AttrBuf::new();
	attrs.push_ip(ifa::ADDRESS, "10.9.0.1".parse().unwrap()); // the peer
	attrs.push_ip(ifa::LOCAL, "10.9.0.2".parse().unwrap()); // us

	let mut body = Vec::new();
	IfAddr {
		family: 2,
		prefix_len: 32,
		flags: 0,
		scope: 0,
		index: 5,
	}
	.encode(&mut body);

	let raw = message(msg_type::RTM_NEWADDR, 1, &body, &attrs);
	let address = decode_address(Messages::new(&raw).next().unwrap().payload).expect("decodes");
	assert_eq!(address.address.to_string(), "10.9.0.2");
}

#[test]
fn a_default_route_decodes() {
	let mut attrs = AttrBuf::new();
	attrs.push_ip(rta::GATEWAY, "192.168.1.1".parse().unwrap());
	attrs.push_u32(rta::OIF, 3);
	attrs.push_u32(rta::PRIORITY, 100);

	let mut body = Vec::new();
	RtMsg {
		family: 2,
		dst_len: 0,
		table: 254,
		protocol: 110,
		kind: 1,
		..RtMsg::default()
	}
	.encode(&mut body);

	let raw = message(msg_type::RTM_NEWROUTE, 1, &body, &attrs);
	let route = decode_route(Messages::new(&raw).next().unwrap().payload).expect("decodes");

	assert_eq!(route.destination_text(), "default");
	assert_eq!(
		route.gateway.map(|g| g.to_string()).as_deref(),
		Some("192.168.1.1")
	);
	assert_eq!(route.metric, Some(100));
	assert_eq!(route.protocol, 110);
	assert_eq!(route.table, 254);
}

/// A table id above 255 does not fit `rtm_table` and arrives in `RTA_TABLE`
/// instead. Reading only the byte would report table 252 as table 252 and
/// table 300 as whatever the compat value happens to be.
#[test]
fn a_large_table_id_comes_from_the_attribute() {
	let mut attrs = AttrBuf::new();
	attrs.push_u32(rta::TABLE, 5000);

	let mut body = Vec::new();
	RtMsg {
		family: 2,
		table: 252, // RT_TABLE_COMPAT
		..RtMsg::default()
	}
	.encode(&mut body);

	let raw = message(msg_type::RTM_NEWROUTE, 1, &body, &attrs);
	let route = decode_route(Messages::new(&raw).next().unwrap().payload).expect("decodes");
	assert_eq!(route.table, 5000);
}

#[test]
fn several_messages_in_one_read_are_all_seen() {
	let mut attrs = AttrBuf::new();
	attrs.push_str(ifla::IFNAME, "eth0");
	let mut body = Vec::new();
	IfInfo::default().encode(&mut body);

	let mut buffer = message(msg_type::RTM_NEWLINK, 1, &body, &attrs);
	let mut second = AttrBuf::new();
	second.push_str(ifla::IFNAME, "eth1");
	buffer.extend_from_slice(&message(msg_type::RTM_NEWLINK, 1, &body, &second));

	let names: Vec<String> = Messages::new(&buffer)
		.filter_map(|m| decode_link(m.payload))
		.map(|link| link.name)
		.collect();
	assert_eq!(names, ["eth0", "eth1"]);
}

#[test]
fn an_error_payload_reports_its_errno() {
	// Netlink sends errno negated, and zero means acknowledgement rather than
	// failure -- its least obvious convention.
	let payload = (-libc::EPERM).to_ne_bytes();
	assert_eq!(error_code(&payload), Some(libc::EPERM));

	let ack = 0_i32.to_ne_bytes();
	assert_eq!(error_code(&ack), Some(0));
}

/// The classic netlink parser bug: a length field below the header size makes
/// no progress, and the loop runs forever. This test exists because that
/// failure mode does not look like a crash, it looks like a hang in a
/// privileged daemon.
#[test]
fn a_zero_length_message_terminates_rather_than_looping() {
	let mut buffer = vec![0_u8; 64];
	// nlmsg_len = 0, which is shorter than the header it sits in.
	buffer[0..4].copy_from_slice(&0_u32.to_ne_bytes());

	let count = Messages::new(&buffer).count();
	assert_eq!(count, 0);
}

/// Same hazard one level down.
#[test]
fn a_zero_length_attribute_terminates_rather_than_looping() {
	let mut buffer = vec![0_u8; 32];
	buffer[0..2].copy_from_slice(&0_u16.to_ne_bytes());

	let count = Attrs::new(&buffer).count();
	assert_eq!(count, 0);
}

/// A length that runs past the buffer must not index out of bounds.
#[test]
fn an_overlong_length_is_refused_rather_than_panicking() {
	let mut buffer = vec![0_u8; 32];
	buffer[0..4].copy_from_slice(&9999_u32.to_ne_bytes());
	assert_eq!(Messages::new(&buffer).count(), 0);

	let mut attrs = vec![0_u8; 16];
	attrs[0..2].copy_from_slice(&9999_u16.to_ne_bytes());
	assert_eq!(Attrs::new(&attrs).count(), 0);
}

/// The decoders take bytes from a socket, which is input this process does not
/// control. Nothing here may panic, whatever arrives. This is the cheap
/// deterministic stand-in for the fuzz target section 6 wants, not a
/// replacement for it.
#[test]
fn adversarial_bytes_never_panic() {
	let seeds: Vec<Vec<u8>> = vec![
		vec![],
		vec![0],
		vec![0xff; 3],
		vec![0xff; 16],
		vec![0xff; 64],
		vec![0x00; 15],
		vec![0x01, 0x00, 0x00, 0x00],
		(0..=255_u8).collect(),
		(0..=255_u8).rev().collect(),
		vec![0x10, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00],
	];

	for seed in &seeds {
		// Every entry point, on every seed. Any result is fine except a panic.
		let _ = Header::decode(seed);
		let _ = IfInfo::decode(seed);
		let _ = IfAddr::decode(seed);
		let _ = RtMsg::decode(seed);
		let _ = decode_link(seed);
		let _ = decode_address(seed);
		let _ = decode_route(seed);
		let _ = error_code(seed);
		assert!(Messages::new(seed).count() < 10_000);
		assert!(Attrs::new(seed).count() < 10_000);
		for message in Messages::new(seed) {
			let _ = decode_link(message.payload);
			let _ = decode_address(message.payload);
			let _ = decode_route(message.payload);
		}
	}

	// Every truncation of a well-formed message, which is the shape a short
	// read actually produces.
	let mut attrs = AttrBuf::new();
	attrs.push_str(ifla::IFNAME, "eth0");
	attrs.push_u32(ifla::MTU, 1500);
	let mut body = Vec::new();
	IfInfo::default().encode(&mut body);
	let whole = message(msg_type::RTM_NEWLINK, 1, &body, &attrs);

	for cut in 0..whole.len() {
		let partial = &whole[..cut];
		assert!(Messages::new(partial).count() < 10_000);
		let _ = decode_link(partial);
	}
}
