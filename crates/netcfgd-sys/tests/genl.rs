//! Generic netlink: the encoding, and the lookup against a real kernel.
//!
//! The family lookup needs no privilege at all -- the controller answers
//! anybody -- so unlike the rest of the live testing in this project, these
//! run in `cargo test` on any Linux machine.

use netcfgd_sys::genl::{getfamily_message, payload_attrs, GenlHeader, GENL_HDR_LEN};
use netcfgd_sys::wire::{Header, Messages};
use netcfgd_sys::Genl;

/// Four bytes between the netlink header and the attributes. Omitting it
/// produces a message the kernel parses as attributes starting four bytes
/// early, which fails naming neither the command nor the field.
#[test]
fn the_header_is_four_bytes_and_round_trips() {
	let header = GenlHeader { cmd: 3, version: 1 };
	let mut out = Vec::new();
	header.encode(&mut out);

	assert_eq!(out.len(), GENL_HDR_LEN);
	assert_eq!(out[0], 3, "command first");
	assert_eq!(out[1], 1, "then version");
	assert_eq!(&out[2..], &[0, 0], "then two the kernel ignores");
	assert_eq!(GenlHeader::decode(&out), Some(header));

	// A truncated payload is not a header, and must not be read as one.
	assert_eq!(GenlHeader::decode(&out[..3]), None);
	assert_eq!(GenlHeader::decode(&[]), None);
}

/// A `GETFAMILY` request has to be well formed before any of this can work,
/// and it is checkable without a socket.
#[test]
fn a_getfamily_request_is_well_formed() {
	let message = getfamily_message("nl80211", 42);

	let header = Header::decode(&message).expect("a netlink header");
	assert_eq!(header.kind, 16, "the controller's fixed family id");
	assert_eq!(header.seq, 42);
	assert_eq!(
		header.len as usize,
		message.len(),
		"the length field counts the whole message"
	);

	let payload = &message[16..];
	assert_eq!(
		GenlHeader::decode(payload),
		Some(GenlHeader { cmd: 3, version: 1 })
	);

	// The name is NUL-terminated: the controller compares it as a C string,
	// and one without the terminator matches nothing.
	let name = payload_attrs(payload)
		.get(2)
		.expect("a family name attribute");
	assert_eq!(name.value, b"nl80211\0");
}

/// `nlctrl` is the controller itself. It is always present, so this is the one
/// family lookup that can be asserted rather than skipped.
#[test]
fn the_controller_resolves_itself() {
	let Ok(mut genl) = Genl::open() else {
		println!("skipping: no generic netlink socket");
		return;
	};
	let family = genl.family("nlctrl").expect("nlctrl always exists");
	assert_eq!(family.id, 16, "the controller's id is the fixed one");
	assert_eq!(family.name, "nlctrl");

	// And it publishes a `notify` group, which is the case that exercises the
	// nested array parsing -- each entry's attribute *type* is an index rather
	// than a meaning, and a reader that treats it as a kind finds nothing.
	assert!(
		family.group("notify").is_some(),
		"nlctrl publishes a notify group: {:?}",
		family.groups
	);
}

/// A family that does not exist is `NotFound` rather than a protocol error,
/// because "that module is not loaded" is the ordinary answer and a caller
/// wants to tell it from a real failure.
#[test]
fn an_absent_family_is_not_found() {
	let Ok(mut genl) = Genl::open() else {
		println!("skipping: no generic netlink socket");
		return;
	};
	// Fifteen characters, because sixteen is the kernel's limit including the
	// terminator -- and a longer name is refused for its length before the
	// lookup happens, which is a different error.
	let error = genl.family("ncfg-no-such-f").expect_err("must not resolve");
	assert_eq!(error.kind(), std::io::ErrorKind::NotFound, "got: {error}");
	assert!(
		error.to_string().contains("not loaded"),
		"the message should point at the likely cause: {error}"
	);
}

/// A name too long to be a family is `NotFound` too, and says why. The kernel
/// answers `EINVAL` for the length before it looks anything up, which reads as
/// "netcfgd sent a broken request" rather than "you typed the name wrong".
#[test]
fn an_over_long_family_name_says_so() {
	let Ok(mut genl) = Genl::open() else {
		println!("skipping: no generic netlink socket");
		return;
	};
	let error = genl
		.family("a-name-far-too-long-to-be-a-family")
		.expect_err("must not resolve");
	assert_eq!(error.kind(), std::io::ErrorKind::NotFound, "got: {error}");
	assert!(error.to_string().contains("at most 15"), "got: {error}");
}

/// The lookup is cached, and the cache has to return the same answer rather
/// than a second one.
#[test]
fn a_second_lookup_agrees_with_the_first() {
	let Ok(mut genl) = Genl::open() else {
		println!("skipping: no generic netlink socket");
		return;
	};
	let first = genl.family("nlctrl").expect("resolves");
	let second = genl.family("nlctrl").expect("resolves again");
	assert_eq!(first, second);
}

/// Whatever the controller sends, parsing it must not panic. This is the entry
/// point a fuzzer would reach, and the reply is attacker-influenced only in
/// the sense that a broken kernel module can register anything -- but the
/// parser is the same one every future family will use.
#[test]
fn a_malformed_reply_does_not_panic() {
	for payload in [
		vec![],
		vec![0],
		vec![3, 1, 0, 0],
		vec![3, 1, 0, 0, 0xff, 0xff, 0xff, 0xff],
		vec![3, 1, 0, 0, 8, 0, 1, 0, 1, 0, 0, 0],
		// A groups nest that claims more length than it has.
		vec![3, 1, 0, 0, 0xff, 0x7f, 7, 0, 1, 2, 3],
	] {
		let attrs = payload_attrs(&payload);
		for attr in attrs {
			let _ = attr.u32();
			let _ = attr.string();
		}
	}

	// And a whole message stream of noise.
	for chunk in [vec![0_u8; 3], vec![0xff; 64], vec![16, 0, 0, 0, 3, 0, 0, 0]] {
		for message in Messages::new(&chunk) {
			let _ = GenlHeader::decode(message.payload);
		}
	}
}
