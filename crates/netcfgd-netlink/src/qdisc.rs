//! Queueing disciplines, over the rtnetlink socket everything else here uses.
//!
//! Only the **root** qdisc on an interface, which is the whole of decision
//! 0023's scope: a named algorithm and at most a rate, never a class tree and
//! never a filter.
//!
//! The unit is the trap. `tc` takes `bandwidth 100mbit` and the kernel wants
//! **bytes per second**, so the conversion is a division by eight that nothing
//! checks -- a rate sent in bits is accepted and shapes at one eighth of what
//! was asked for, which looks like a slow link rather than a bug. It is read
//! back and compared for that reason.

use crate::socket::Netlink;
use crate::wire::{self, flags, AttrBuf};
use std::io;

/// `RTM_NEWQDISC`, `RTM_DELQDISC`, `RTM_GETQDISC`.
const RTM_NEWQDISC: u16 = 36;
const RTM_DELQDISC: u16 = 37;
const RTM_GETQDISC: u16 = 38;

/// `TC_H_ROOT`, the parent of the root qdisc.
const TC_H_ROOT: u32 = 0xffff_ffff;

/// `TCA_KIND` and `TCA_OPTIONS`.
const TCA_KIND: u16 = 1;
const TCA_OPTIONS: u16 = 2;

/// `TCA_CAKE_BASE_RATE64`, the only qdisc parameter in scope.
///
/// Two, not one: `TCA_CAKE_PAD` is 1, and it exists because the kernel dumps
/// this value with `nla_put_u64_64bit`.
const TCA_CAKE_BASE_RATE64: u16 = 2;

/// `struct tcmsg`, which is 20 bytes and has no encoder anywhere else in this
/// crate because nothing else speaks traffic control.
#[derive(Debug, Clone, Copy, Default)]
struct TcMsg {
	family: u8,
	index: i32,
	handle: u32,
	parent: u32,
	info: u32,
}

/// Length of `struct tcmsg`.
const TCMSG_LEN: usize = 20;

impl TcMsg {
	fn encode(&self, out: &mut Vec<u8>) {
		out.push(self.family);
		out.push(0);
		out.extend_from_slice(&0_u16.to_ne_bytes());
		out.extend_from_slice(&self.index.to_ne_bytes());
		out.extend_from_slice(&self.handle.to_ne_bytes());
		out.extend_from_slice(&self.parent.to_ne_bytes());
		out.extend_from_slice(&self.info.to_ne_bytes());
	}

	fn decode(bytes: &[u8]) -> Option<Self> {
		if bytes.len() < TCMSG_LEN {
			return None;
		}
		Some(Self {
			family: bytes[0],
			index: i32::from_ne_bytes(bytes[4..8].try_into().ok()?),
			handle: u32::from_ne_bytes(bytes[8..12].try_into().ok()?),
			parent: u32::from_ne_bytes(bytes[12..16].try_into().ok()?),
			info: u32::from_ne_bytes(bytes[16..20].try_into().ok()?),
		})
	}
}

/// The root qdisc on one interface, as the kernel reports it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QdiscRecord {
	/// Which interface.
	pub index: u32,
	/// The algorithm, as the kernel spells it: `fq_codel`, `cake`, `noqueue`.
	pub kind: String,
	/// The shaped rate in **bits** per second, where the qdisc shapes.
	///
	/// Bits rather than the kernel's bytes, because bits is what an operator
	/// writes and what every other tool prints. The conversion happens once,
	/// here and in [`Qdisc::set_root`], rather than at each place that reads
	/// it.
	pub bandwidth_bits: Option<u64>,
}

/// What to install as the root qdisc.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RootQdisc<'a> {
	/// The algorithm.
	pub kind: &'a str,
	/// Shaped rate in bits per second, for the qdiscs that shape.
	pub bandwidth_bits: Option<u64>,
}

/// Traffic control over an existing rtnetlink socket.
///
/// Borrowed rather than owned: qdiscs are the same protocol and the same
/// socket as links and addresses, so opening a second one would be a socket
/// per feature for no reason.
#[derive(Debug)]
pub struct Qdisc<'a> {
	socket: &'a mut Netlink,
}

impl<'a> Qdisc<'a> {
	/// Borrow a socket for traffic control.
	pub fn new(socket: &'a mut Netlink) -> Self {
		Self { socket }
	}

	/// Every interface's root qdisc.
	///
	/// # Errors
	///
	/// Returns the errno the kernel replied with.
	pub fn roots(&mut self) -> io::Result<Vec<QdiscRecord>> {
		let mut body = Vec::new();
		TcMsg::default().encode(&mut body);
		let replies = self.socket.request(
			RTM_GETQDISC,
			flags::NLM_F_REQUEST | flags::NLM_F_DUMP,
			&body,
			&AttrBuf::new(),
		)?;

		Ok(replies
			.iter()
			.filter_map(|payload| decode(payload))
			.collect())
	}

	/// Replace the root qdisc on one interface.
	///
	/// `NLM_F_REPLACE` rather than a delete followed by an add: the two-step
	/// version leaves the interface on the kernel default in between, which on
	/// a shaped uplink is a window where traffic is unshaped.
	///
	/// # Errors
	///
	/// Returns the errno the kernel replied with. `ENOENT` means the module
	/// for this qdisc is not loaded and could not be autoloaded, which is the
	/// ordinary failure for `cake` on a kernel that does not ship it.
	pub fn set_root(&mut self, index: u32, root: &RootQdisc<'_>) -> io::Result<()> {
		let mut body = Vec::new();
		TcMsg {
			index: i32::try_from(index).unwrap_or(0),
			parent: TC_H_ROOT,
			..TcMsg::default()
		}
		.encode(&mut body);

		let mut attrs = AttrBuf::new();
		attrs.push_str(TCA_KIND, root.kind);
		if let Some(bits) = root.bandwidth_bits {
			let mut options = AttrBuf::new();
			// Bits in, bytes out. The kernel's field is `rate_bps` and the
			// `bps` is bytes; `tc` does this same division and it is the one
			// place a factor of eight can hide.
			options.push(TCA_CAKE_BASE_RATE64, &(bits / 8).to_ne_bytes());
			attrs.push(TCA_OPTIONS, options.as_bytes());
		}

		self.socket.request(
			RTM_NEWQDISC,
			flags::NLM_F_REQUEST | flags::NLM_F_ACK | flags::NLM_F_CREATE | flags::NLM_F_REPLACE,
			&body,
			&attrs,
		)?;
		Ok(())
	}

	/// Remove the root qdisc, which restores whatever the kernel defaults to.
	///
	/// There is no such thing as an interface without a qdisc, so this is not
	/// deletion in the sense `del_address` is: the kernel immediately puts
	/// `net.core.default_qdisc` back. That is the correct meaning of "netcfgd
	/// no longer manages this", and it is why nothing here has to know what
	/// the default was.
	///
	/// # Errors
	///
	/// Returns the errno the kernel replied with, except `ENOENT` and
	/// `EINVAL`, which both mean there was nothing to remove.
	pub fn delete_root(&mut self, index: u32) -> io::Result<()> {
		let mut body = Vec::new();
		TcMsg {
			index: i32::try_from(index).unwrap_or(0),
			parent: TC_H_ROOT,
			..TcMsg::default()
		}
		.encode(&mut body);

		match self.socket.request(
			RTM_DELQDISC,
			flags::NLM_F_REQUEST | flags::NLM_F_ACK,
			&body,
			&AttrBuf::new(),
		) {
			Ok(_) => Ok(()),
			Err(error) if matches!(error.raw_os_error(), Some(libc::ENOENT | libc::EINVAL)) => {
				Ok(())
			}
			Err(error) => Err(error),
		}
	}
}

/// One dump entry, if it is a root qdisc.
///
/// The dump returns every qdisc on the machine, including the ingress one and
/// the children of any class tree somebody else set up. Only the root is in
/// scope, and `tcm_parent` is what says so.
fn decode(payload: &[u8]) -> Option<QdiscRecord> {
	let header = TcMsg::decode(payload)?;
	if header.parent != TC_H_ROOT {
		return None;
	}
	let attrs = wire::Attrs::new(payload.get(TCMSG_LEN..)?);
	let kind = attrs.get(TCA_KIND)?.string()?;
	let bandwidth_bits = attrs
		.get(TCA_OPTIONS)
		.and_then(|options| cake_rate(options.value))
		// Bytes back to bits, the inverse of the division in `set_root`.
		.map(|bytes| bytes * 8);

	Some(QdiscRecord {
		index: u32::try_from(header.index).unwrap_or(0),
		kind,
		bandwidth_bits,
	})
}

/// The shaped rate out of a `cake` options blob, in bytes per second.
///
/// Returns `None` for every other qdisc, whose options this deliberately does
/// not try to parse: `TCA_OPTIONS` is not self-describing, so the same
/// attribute number means something different under each kind, and reading
/// `fq_codel`'s options with `cake`'s numbering yields a plausible-looking
/// integer that is not a rate.
fn cake_rate(options: &[u8]) -> Option<u64> {
	let attr = wire::Attrs::new(options).get(TCA_CAKE_BASE_RATE64)?;
	let bytes: [u8; 8] = attr.value.get(0..8)?.try_into().ok()?;
	let rate = u64::from_ne_bytes(bytes);
	(rate > 0).then_some(rate)
}

/// Whether this qdisc kind takes a bandwidth.
///
/// Named here rather than in the model because it is a fact about the kernel's
/// schedulers, not about netcfgd's configuration language.
#[must_use]
pub fn shapes(kind: &str) -> bool {
	kind == "cake"
}
