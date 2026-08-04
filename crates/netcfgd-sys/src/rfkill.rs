//! `/dev/rfkill`: the switch being flipped, as it happens.
//!
//! 0062 made netcfgd *report* a blocked radio, read out of `/sys` during an
//! observation. What it could not do is notice one being flipped: an
//! observation runs on a netlink event or on the loop's five-second backstop,
//! and a kill switch produces neither reliably -- blocking a radio usually
//! takes the interface down and so shows up on netlink, but unblocking one
//! produces nothing until something else happens.
//!
//! This is the kernel's own notification for it. Opening the device queues one
//! `ADD` per switch that already exists, so a reader learns the current state
//! without asking `/sys` for it, and then gets a record per change.
//!
//! **Read-only, always.** The same device accepts writes that block or unblock
//! every radio on the machine, and netcfgd does not do that -- 0062 decided
//! that a switch an operator flipped is a decision netcfgd reports rather than
//! overrules. Nothing here opens the device for writing, which makes that a
//! property of the code and not of the intent.
//!
//! No `unsafe`: this is a file with a fixed record format, and reading it is
//! `read` plus arithmetic. It lives in this crate because it is a kernel
//! interface, not because it needs the exception.

use std::fs::File;
use std::io::{self, Read};
use std::path::Path;

/// The kernel's `struct rfkill_event`, which is packed and eight bytes.
///
/// Newer kernels have `rfkill_event_ext`, which appends `hard_block_reasons`.
/// The kernel's own rule for userspace is to read at least the eight it knows
/// and ignore anything past them, so that a reader built today keeps working on
/// a kernel that grows the record -- which is what this does.
const RECORD: usize = 8;

/// What happened to a switch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Event {
	/// The kernel's index for this switch.
	pub index: u32,
	/// `RFKILL_TYPE_*`: which kind of radio it governs.
	pub kind: u8,
	/// `RFKILL_OP_*`: added, removed, or changed.
	pub op: u8,
	/// Blocked in software, which is what `rfkill block` sets.
	pub soft: bool,
	/// Blocked by a physical switch, which software cannot clear.
	pub hard: bool,
}

/// A reader for the event stream.
pub struct Rfkill {
	device: File,
}

impl Rfkill {
	/// Open the device.
	///
	/// Opening queues one `ADD` per switch that already exists, so the first
	/// few reads describe the machine as it stands before anything is flipped.
	/// Measured on a laptop with four switches: four `ADD` records, then
	/// nothing until something changes.
	///
	/// # Errors
	///
	/// Returns the underlying error. A machine with no radio has no
	/// `/dev/rfkill`, which is `NotFound` and is not a failure worth
	/// propagating past the caller that knows whether it wanted one.
	pub fn open(path: &Path) -> io::Result<Self> {
		Ok(Self {
			// Read-only. See the module comment: the write path on this device
			// blocks or unblocks radios, and not opening for writing is how
			// that stays impossible rather than merely unintended.
			device: File::open(path)?,
		})
	}

	/// The next event, blocking until one arrives.
	///
	/// **One read is one record.** The kernel dequeues a single event per read
	/// and copies `min(what you asked for, the struct it has)`, so a generous
	/// buffer gets one whole record and never two -- measured, because the
	/// first version of this assumed a byte stream and carried a reassembly
	/// buffer. On a kernel writing the longer `rfkill_event_ext` that buffer
	/// would have kept the extra byte and shifted every following record by
	/// one, which is a fault that appears only on kernels newer than the one it
	/// was written against.
	///
	/// # Errors
	///
	/// Returns the underlying error. End of file is `Ok(None)`, which for this
	/// device means it went away. A read shorter than a record is discarded
	/// rather than kept: there is nothing to join it to.
	pub fn next_event(&mut self) -> io::Result<Option<Event>> {
		loop {
			// Bigger than any record the kernel has, so the whole of one
			// arrives whatever version it is and the surplus is ignored.
			let mut buffer = [0_u8; 64];
			let read = self.device.read(&mut buffer)?;
			if read == 0 {
				return Ok(None);
			}
			if read >= RECORD {
				return Ok(Some(parse_slice(&buffer[..read])));
			}
			// Shorter than the eight bytes every version of this record has.
			// Nothing sensible to do with it and nothing to join it to, so it
			// is dropped rather than buffered into the next one.
		}
	}
}

/// One record's bytes as an event.
///
/// Little-endian for `idx` because the kernel writes it in host order and every
/// machine this runs on is little-endian; a big-endian port would find this
/// comment before it found the bug.
#[must_use]
pub fn parse(record: &[u8; RECORD]) -> Event {
	Event {
		index: u32::from_le_bytes([record[0], record[1], record[2], record[3]]),
		kind: record[4],
		op: record[5],
		soft: record[6] != 0,
		hard: record[7] != 0,
	}
}

/// One record's bytes as an event, from a slice of at least [`RECORD`].
fn parse_slice(record: &[u8]) -> Event {
	let mut fixed = [0_u8; RECORD];
	fixed.copy_from_slice(&record[..RECORD]);
	parse(&fixed)
}

#[cfg(test)]
mod tests {
	use super::*;

	/// The kernel's layout, byte for byte.
	#[test]
	fn a_record_is_read_the_way_the_kernel_writes_it() {
		// idx = 1, type = 1 (WLAN), op = 2 (CHANGE), soft = 1, hard = 0.
		let event = parse(&[0x01, 0x00, 0x00, 0x00, 0x01, 0x02, 0x01, 0x00]);
		assert_eq!(event.index, 1);
		assert_eq!(event.kind, 1);
		assert_eq!(event.op, 2);
		assert!(event.soft);
		assert!(!event.hard);

		// And a multi-byte index, which is where a byte order mistake shows.
		let event = parse(&[0x02, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01]);
		assert_eq!(event.index, 0x0102);
		assert!(!event.soft);
		assert!(event.hard);
	}

	/// What a real kernel handed over, replayed.
	///
	/// Captured by opening the device on the machine this was written on: four
	/// switches, one `ADD` each, two WLAN and two Bluetooth, none blocked. A
	/// fixture written by hand would agree with whatever this file believes;
	/// these are bytes the kernel produced.
	#[test]
	fn the_records_a_real_kernel_sent_read_back() {
		let seen = [
			[0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00],
			[0x01, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00],
			[0x02, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00],
			[0x03, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00],
		];
		for (index, record) in seen.iter().enumerate() {
			let event = parse(record);
			assert_eq!(event.index, u32::try_from(index).expect("small"));
			assert_eq!(event.op, 0, "every one of these was an ADD");
			assert!(!event.soft && !event.hard, "none of them was blocked");
		}
		assert_eq!(parse(&seen[0]).kind, 1, "wlan");
		assert_eq!(parse(&seen[1]).kind, 2, "bluetooth");
	}

	/// A longer record is one event, and the surplus is ignored.
	///
	/// A kernel with `rfkill_event_ext` writes nine bytes. This is the case the
	/// first version of this module got wrong: it buffered whatever a read
	/// returned and cut records at eight, so the ninth byte became the first
	/// byte of the next one and every event after it was wrong.
	#[test]
	fn a_longer_record_is_still_one_event() {
		let extended = [0x01, 0x00, 0x00, 0x00, 0x01, 0x02, 0x01, 0x00, 0xff];
		let event = parse_slice(&extended);
		assert_eq!(event.index, 1);
		assert_eq!(event.op, 2);
		assert!(event.soft);
	}
}
