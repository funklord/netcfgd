//! Carving a LAN prefix out of what the ISP delegated.

use netcfgd_model::{derive_from_delegation, PrefixRef};

fn reference(subnet: u16) -> PrefixRef {
	PrefixRef {
		source: "wan0".to_owned(),
		index: 0,
		subnet,
	}
}

/// The ordinary router: a /56 from the ISP, one /64 per LAN, `::1` on each.
#[test]
fn the_common_case() {
	assert_eq!(
		derive_from_delegation("2001:db8:1234::/56", &reference(0), "::1/64").expect("derives"),
		"2001:db8:1234::1/64"
	);
	assert_eq!(
		derive_from_delegation("2001:db8:1234::/56", &reference(1), "::1/64").expect("derives"),
		"2001:db8:1234:1::1/64"
	);
	// Subnet 255 is the last one a /56 split into /64s has.
	assert_eq!(
		derive_from_delegation("2001:db8:1234::/56", &reference(255), "::1/64").expect("derives"),
		"2001:db8:1234:ff::1/64"
	);
}

/// A /48, which is what a business connection often gets, has 65536 /64s.
#[test]
fn a_larger_delegation_has_more_subnets() {
	assert_eq!(
		derive_from_delegation("2001:db8::/48", &reference(0x1234), "::1/64").expect("derives"),
		"2001:db8:0:1234::1/64"
	);
	assert_eq!(
		derive_from_delegation("2001:db8::/48", &reference(0xffff), "::1/64").expect("derives"),
		"2001:db8:0:ffff::1/64"
	);
}

/// A host part beyond `::1`, since a router is not always the first address.
#[test]
fn the_suffix_supplies_the_host_part() {
	assert_eq!(
		derive_from_delegation("2001:db8:1234::/56", &reference(2), "::dead:beef/64")
			.expect("derives"),
		"2001:db8:1234:2::dead:beef/64"
	);
}

/// An ISP that delegates a prefix with bits set below its own length -- and
/// they do -- must not contribute them.
///
/// The instructive part is where the boundary falls. A /56 ends in the middle
/// of the fourth hextet: `5678` contributes its top eight bits (`56`) to the
/// delegation and its bottom eight (`78`) are below it, so they are cleared
/// and the subnet number takes their place. Reading `/56` as "three hextets"
/// gets this wrong, which is what the first version of this test did.
#[test]
fn bits_below_the_delegation_length_are_cleared() {
	assert_eq!(
		derive_from_delegation("2001:db8:1234:5678::/56", &reference(1), "::1/64")
			.expect("derives"),
		"2001:db8:1234:5601::1/64",
		"56 is inside the delegation, 78 is not, and the subnet replaces it"
	);

	// A /48 boundary does fall on a hextet, so there the whole fourth group is
	// the subnet's.
	assert_eq!(
		derive_from_delegation("2001:db8:1234:5678::/48", &reference(1), "::1/64")
			.expect("derives"),
		"2001:db8:1234:1::1/64"
	);
}

/// Taking the whole delegation is legal: a /64 delegation used as a /64.
#[test]
fn a_subnet_may_be_the_whole_delegation() {
	assert_eq!(
		derive_from_delegation("2001:db8:1234:5600::/64", &reference(0), "::1/64")
			.expect("derives"),
		"2001:db8:1234:5600::1/64"
	);
}

/// A sub-prefix shorter than the delegation would route addresses the ISP did
/// not give this machine. Refused rather than silently widened.
#[test]
fn a_subnet_wider_than_the_delegation_is_refused() {
	let error =
		derive_from_delegation("2001:db8:1234::/56", &reference(0), "::1/48").expect_err("refused");
	assert!(error.contains("cannot be carved out"), "got: {error}");
	assert!(
		error.contains("/48"),
		"the message names both lengths: {error}"
	);
}

/// A subnet number with nowhere to go is a config that can never work, and the
/// error says how many there actually are.
#[test]
fn a_subnet_that_does_not_fit_says_how_many_there_are() {
	let error = derive_from_delegation("2001:db8:1234::/56", &reference(256), "::1/64")
		.expect_err("refused");
	assert!(error.contains("does not fit"), "got: {error}");
	assert!(error.contains("256 of them"), "got: {error}");

	// And a /64 delegation split into /64s has exactly one.
	let error =
		derive_from_delegation("2001:db8::/64", &reference(1), "::1/64").expect_err("refused");
	assert!(error.contains("1 of them"), "got: {error}");
}

/// Malformed input is named rather than guessed at.
#[test]
fn malformed_input_is_refused() {
	assert!(derive_from_delegation("not-a-prefix", &reference(0), "::1/64").is_err());
	// IPv4 is not a delegation.
	assert!(derive_from_delegation("10.0.0.0/8", &reference(0), "::1/64").is_err());
	// A suffix without a length has no sub-prefix size to use.
	assert!(derive_from_delegation("2001:db8::/56", &reference(0), "::1").is_err());
	assert!(derive_from_delegation("2001:db8::/129", &reference(0), "::1/64").is_err());
}

/// Renumbering: the ISP changes the delegation and every derived address
/// follows, which decision 0009 wants to be an ordinary diff rather than a
/// special case. The evidence is that the same reference against a different
/// delegation produces a different address and nothing else changes.
#[test]
fn renumbering_changes_only_the_prefix() {
	let before = derive_from_delegation("2001:db8:1111::/56", &reference(3), "::1/64").unwrap();
	let after = derive_from_delegation("2001:db8:2222::/56", &reference(3), "::1/64").unwrap();
	assert_eq!(before, "2001:db8:1111:3::1/64");
	assert_eq!(after, "2001:db8:2222:3::1/64");
}

/// Nothing panics, whatever the config says.
#[test]
fn arbitrary_input_never_panics() {
	let mut state = 0x9e37_79b9_7f4a_7c15_u64;
	let pieces = [
		"2001:db8::/56",
		"::/0",
		"::/128",
		"10.0.0.0/8",
		"",
		"/",
		"x/y",
		"::1/64",
		"::/-1",
		"ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/128",
	];
	for _ in 0..20_000 {
		state ^= state << 13;
		state ^= state >> 7;
		state ^= state << 17;
		let delegation = pieces[usize::try_from(state % pieces.len() as u64).unwrap_or(0)];
		let suffix = pieces[usize::try_from((state >> 8) % pieces.len() as u64).unwrap_or(0)];
		#[allow(clippy::cast_possible_truncation)]
		let subnet = (state >> 16) as u16;
		let _ = derive_from_delegation(delegation, &reference(subnet), suffix);
	}
}
