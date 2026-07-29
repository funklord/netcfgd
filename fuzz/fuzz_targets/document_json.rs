//! The desired-state document is read back from /run, and will eventually
//! arrive over a socket. Section 2 requires that an unknown field is refused
//! rather than dropped; this checks that refusing never becomes panicking.

#![no_main]

use libfuzzer_sys::fuzz_target;
use netcfgd_model::Document;

fuzz_target!(|data: &[u8]| {
	let Ok(text) = std::str::from_utf8(data) else {
		return;
	};
	if let Ok(document) = Document::from_json(text) {
		// A document that parsed must survive a round trip, or the encoding is
		// not the function section 2 says it is.
		let encoded = document.to_json_canonical().expect("a valid document encodes");
		let back = Document::from_json(&encoded).expect("its own output parses");
		assert_eq!(document, back);
	}
});
