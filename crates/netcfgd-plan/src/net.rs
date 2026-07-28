//! The address arithmetic ordering rule 4 needs, and nothing more.

use std::net::IpAddr;

/// Split `10.0.0.1/24` into its address and prefix length.
#[must_use]
pub fn parse_cidr(text: &str) -> Option<(IpAddr, u8)> {
	let (addr, prefix) = text.split_once('/')?;
	let addr: IpAddr = addr.parse().ok()?;
	let prefix: u8 = prefix.parse().ok()?;
	let max = if addr.is_ipv4() { 32 } else { 128 };
	if prefix > max {
		return None;
	}
	Some((addr, prefix))
}

/// Whether `candidate` falls inside the subnet `network/prefix`.
///
/// Ordering rule 4 puts `addr.add` before a `route.add` whose next hop lies in
/// that address's subnet, so this decides whether the edge exists. A route
/// whose gateway is not covered by any address on the interface needs no edge,
/// and adding one anyway would serialise work that could run at once.
#[must_use]
pub fn subnet_contains(network: IpAddr, prefix: u8, candidate: IpAddr) -> bool {
	match (network, candidate) {
		(IpAddr::V4(net), IpAddr::V4(other)) => same_prefix(&net.octets(), &other.octets(), prefix),
		(IpAddr::V6(net), IpAddr::V6(other)) => same_prefix(&net.octets(), &other.octets(), prefix),
		// Different families never cover each other.
		_ => false,
	}
}

/// Whether two addresses agree on their first `prefix` bits.
fn same_prefix(left: &[u8], right: &[u8], prefix: u8) -> bool {
	let prefix = usize::from(prefix);
	debug_assert!(prefix <= left.len() * 8);
	let whole = prefix / 8;
	if left[..whole] != right[..whole] {
		return false;
	}
	let remainder = prefix % 8;
	if remainder == 0 {
		return true;
	}
	// A prefix of 0 bits would shift by 8 and overflow, which is why the
	// remainder == 0 case returns above rather than falling through.
	let mask = 0xff_u8 << (8 - remainder);
	left[whole] & mask == right[whole] & mask
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn a_gateway_inside_the_subnet_is_covered() {
		let (net, prefix) = parse_cidr("192.168.1.10/24").expect("parses");
		assert!(subnet_contains(net, prefix, "192.168.1.1".parse().unwrap()));
		assert!(!subnet_contains(
			net,
			prefix,
			"192.168.2.1".parse().unwrap()
		));
	}

	#[test]
	fn a_prefix_that_is_not_a_whole_number_of_bytes_still_works() {
		let (net, prefix) = parse_cidr("10.0.0.1/12").expect("parses");
		assert!(subnet_contains(
			net,
			prefix,
			"10.15.255.254".parse().unwrap()
		));
		assert!(!subnet_contains(net, prefix, "10.16.0.1".parse().unwrap()));
	}

	#[test]
	fn a_zero_length_prefix_covers_everything_without_overflowing() {
		let (net, prefix) = parse_cidr("0.0.0.0/0").expect("parses");
		assert!(subnet_contains(net, prefix, "8.8.8.8".parse().unwrap()));
	}

	#[test]
	fn families_do_not_cover_each_other() {
		let (net, prefix) = parse_cidr("192.168.1.10/24").expect("parses");
		assert!(!subnet_contains(net, prefix, "fe80::1".parse().unwrap()));
	}

	#[test]
	fn ipv6_prefixes_work_too() {
		let (net, prefix) = parse_cidr("2001:db8::1/64").expect("parses");
		assert!(subnet_contains(
			net,
			prefix,
			"2001:db8::ffff".parse().unwrap()
		));
		assert!(!subnet_contains(
			net,
			prefix,
			"2001:db9::1".parse().unwrap()
		));
	}

	#[test]
	fn nonsense_is_rejected_rather_than_guessed_at() {
		assert!(parse_cidr("192.168.1.1").is_none());
		assert!(parse_cidr("192.168.1.1/33").is_none());
		assert!(parse_cidr("not/an/address").is_none());
	}
}
