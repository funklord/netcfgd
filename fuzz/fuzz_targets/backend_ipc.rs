//! What netcfgd's backends read back from the daemons they drive.
//!
//! Section 6 asks for a target per parser and names three kinds: the DSL,
//! netlink messages, and **backend IPC**. The first two had targets and this
//! did not, so every reply netcfgd parses from `wpa_supplicant` and `hostapd`
//! went unfuzzed -- including the two paths that decide whether a station is
//! on an access point and whether a network exists at all.
//!
//! This is a lower-trust boundary than it looks. The replies arrive over a
//! unix socket from a separate process that netcfgd starts but does not
//! contain: a supplicant that is upgraded underneath it, crashes mid-reply, or
//! is simply a different implementation will send bytes these parsers have
//! never seen. `netlink_wire`'s header makes the same argument about the
//! kernel, and the kernel is the more trustworthy of the two.
//!
//! Split by line as well as whole: a control socket delivers one reply at a
//! time, so feeding only the whole blob would leave the per-line parsers
//! reachable solely through whatever the blob happened to contain.

#![no_main]

use libfuzzer_sys::fuzz_target;
use netcfgd_hostapd::acl;
use netcfgd_hostapd::station;
use netcfgd_supplicant::protocol::{
	parse_network_list, parse_scan_results, parse_status, Event, Reply,
};

fuzz_target!(|data: &[u8]| {
	let Ok(text) = std::str::from_utf8(data) else {
		return;
	};

	// Whole replies, as a `recv` would hand them over.
	let _ = Reply::parse(text);
	let _ = parse_scan_results(text);
	let _ = parse_network_list(text);
	let _ = parse_status(text);
	let _ = acl::parse_show(text);
	let _ = station::parse(text);

	// And line by line, which is how the event stream arrives. Bounded, so a
	// parser that consumed nothing would show up as a failure rather than as a
	// slow input.
	for line in text.lines().take(10_000) {
		let _ = Event::parse(line);
		let _ = Reply::parse(line);
		let _ = station::parse(line);
	}
});
