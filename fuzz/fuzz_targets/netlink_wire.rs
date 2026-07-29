//! Netlink messages arrive from the kernel on a socket a privileged process
//! reads. Section 6 requires a target per parser; this is the one that matters
//! most, because the failure mode of a bad netlink parser is a hang rather
//! than a crash and a hang in a daemon holding CAP_NET_ADMIN is invisible.

#![no_main]

use libfuzzer_sys::fuzz_target;
use netcfgd_netlink::dump::{decode_address, decode_link, decode_route};
use netcfgd_netlink::inotify::Events;
use netcfgd_netlink::wire::{error_code, Attrs, Header, IfAddr, IfInfo, Messages, RtMsg};

fuzz_target!(|data: &[u8]| {
	let _ = Header::decode(data);
	let _ = IfInfo::decode(data);
	let _ = IfAddr::decode(data);
	let _ = RtMsg::decode(data);
	let _ = error_code(data);
	let _ = decode_link(data);
	let _ = decode_address(data);
	let _ = decode_route(data);

	// inotify events come from the kernel on the same terms and have the same
	// termination hazard, so they are driven by the same target.
	assert!(Events::new(data).take(10_000).count() < 10_000);

	// Bounded rather than unbounded: a length field that makes no progress
	// would otherwise spin here forever and look like a slow input rather than
	// the infinite loop it is.
	assert!(Attrs::new(data).take(10_000).count() < 10_000);
	for message in Messages::new(data).take(10_000) {
		let _ = decode_link(message.payload);
		let _ = decode_address(message.payload);
		let _ = decode_route(message.payload);
		assert!(Attrs::new(message.payload).take(10_000).count() < 10_000);
	}
});
