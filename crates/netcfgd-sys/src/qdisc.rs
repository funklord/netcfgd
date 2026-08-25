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
/// `TCA_CAKE_INGRESS`, which tells `cake` it is shaping traffic that has
/// already arrived.
///
/// It changes what the shaper counts: on the way out it meters what it sends,
/// and on the way in the only lever it has is dropping, so it has to account
/// for what the sender will retransmit. Without this an ingress shaper
/// undershoots.
const TCA_CAKE_INGRESS: u16 = 15;

/// `TC_H_INGRESS`, the parent of the ingress qdisc, and the handle that qdisc
/// takes.
///
/// `ffff:fff1` and `ffff:0000` respectively, which is what `tc qdisc show`
/// prints for them.
const TC_H_INGRESS: u32 = 0xffff_fff1;
const INGRESS_HANDLE: u32 = 0xffff_0000;

/// `RTM_NEWTFILTER` and `RTM_GETTFILTER`.
///
/// There is no `RTM_DELTFILTER` here on purpose: removing the ingress qdisc
/// takes every filter hanging off it, so netcfgd never has to delete one
/// individually and never has to know which of them it wrote.
const RTM_NEWTFILTER: u16 = 44;
const RTM_GETTFILTER: u16 = 46;

/// `NLA_F_NESTED`. Required by the non-deprecated nested parsers, and
/// harmless to the rest, which mask it off when reading an attribute type.
const NLA_F_NESTED: u16 = 0x8000;

/// `TCA_MATCHALL_ACT`, the action list on a match-everything classifier.
const TCA_MATCHALL_ACT: u16 = 2;

/// `TCA_ACT_KIND` and `TCA_ACT_OPTIONS`, inside one element of an action list.
const TCA_ACT_KIND: u16 = 1;
const TCA_ACT_OPTIONS: u16 = 2;

/// `TCA_MIRRED_PARMS`, which carries `struct tc_mirred`.
const TCA_MIRRED_PARMS: u16 = 2;

/// `TCA_EGRESS_REDIR`: send the packet out of another device instead of here.
const TCA_EGRESS_REDIR: i32 = 1;
/// `TC_ACT_STOLEN`, which is what a redirect does to the original packet.
const TC_ACT_STOLEN: i32 = 4;

/// `ETH_P_ALL`, big-endian, as it sits in `tcm_info`.
const ETH_P_ALL_BE: u32 = 0x0300;
/// The priority netcfgd's redirect filter takes.
///
/// 1, because a redirect that runs after another filter has already stolen
/// the packet does nothing. That is a correctness constraint, which is why
/// the ownership mark went in the filter's *handle* instead.
const FILTER_PRIORITY: u32 = 1;

/// The handle netcfgd stamps on the root qdisc it installs (0137).
///
/// Duplicated from `netcfgd-model` rather than depended on, because this
/// crate must stay free of anything but libc and the kernel -- the same
/// arrangement `wire::netcfgd_proto` has, and asserted against the model by
/// a test for the same reason.
const NETCFGD_QDISC_HANDLE: u32 = 110 << 16;

/// [`NETCFGD_QDISC_HANDLE`], for the test in `netcfgd-observe` that holds
/// this copy and the model's together.
#[must_use]
pub const fn netcfgd_qdisc_handle() -> u32 {
	NETCFGD_QDISC_HANDLE
}

/// The handle netcfgd stamps on its ingress redirect filter. Duplicated for
/// the reason above.
const NETCFGD_FILTER_HANDLE: u32 = 110;

/// [`NETCFGD_FILTER_HANDLE`], for the same test.
#[must_use]
pub const fn netcfgd_filter_handle() -> u32 {
	NETCFGD_FILTER_HANDLE
}

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

/// Everything one `RTM_GETQDISC` dump says.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct QdiscDump {
	/// The root qdisc on each interface that has one.
	pub roots: Vec<QdiscRecord>,
	/// Interfaces carrying an ingress qdisc, sorted.
	pub ingress_hooks: Vec<u32>,
}

/// The root qdisc on one interface, as the kernel reports it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QdiscRecord {
	/// Which interface.
	pub index: u32,
	/// The `tc` handle, `major << 16 | minor`.
	///
	/// netcfgd stamps [`NETCFGD_QDISC_HANDLE`] on the qdiscs it installs, so
	/// that reading one back says who asked for it (0137). Anything else is
	/// a handle the kernel assigned or somebody else chose.
	pub handle: u32,
	/// The algorithm, as the kernel spells it: `fq_codel`, `cake`, `noqueue`.
	pub kind: String,
	/// The shaped rate in **bits** per second, where the qdisc shapes.
	///
	/// Bits rather than the kernel's bytes, because bits is what an operator
	/// writes and what every other tool prints. The conversion happens once,
	/// here and in [`Qdisc::set_root`], rather than at each place that reads
	/// it.
	pub bandwidth_bits: Option<u64>,
	/// Whether `cake` was told it is shaping on the way in.
	pub ingress: bool,
}

/// What to install as the root qdisc.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RootQdisc<'a> {
	/// The algorithm.
	pub kind: &'a str,
	/// Shaped rate in bits per second, for the qdiscs that shape.
	pub bandwidth_bits: Option<u64>,
	/// Whether this shaper is metering traffic that has already arrived.
	pub ingress: bool,
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

	/// Everything one qdisc dump says.
	///
	/// The ingress hooks come out of the same dump as the roots because they
	/// are in it -- and knowing which interfaces have one is what makes the
	/// filter dump affordable, since that has to be asked per interface.
	///
	/// # Errors
	///
	/// Returns the errno the kernel replied with.
	pub fn dump(&mut self) -> io::Result<QdiscDump> {
		let mut body = Vec::new();
		TcMsg::default().encode(&mut body);
		let replies = self.socket.request(
			RTM_GETQDISC,
			flags::NLM_F_REQUEST | flags::NLM_F_DUMP,
			&body,
			&AttrBuf::new(),
		)?;

		let mut roots = Vec::new();
		let mut ingress_hooks = Vec::new();
		for payload in &replies {
			let Some(header) = TcMsg::decode(payload) else {
				continue;
			};
			let index = u32::try_from(header.index).unwrap_or(0);
			if header.parent == TC_H_INGRESS {
				ingress_hooks.push(index);
			} else if let Some(record) = decode(payload) {
				roots.push(record);
			}
		}
		ingress_hooks.sort_unstable();
		ingress_hooks.dedup();

		Ok(QdiscDump {
			roots,
			ingress_hooks,
		})
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
			// netcfgd's mark. The kernel assigns a handle when none is given,
			// which is what this used to let it do -- and an assigned handle
			// says nothing about who asked for the qdisc.
			handle: NETCFGD_QDISC_HANDLE,
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
			if root.ingress {
				options.push_u32(TCA_CAKE_INGRESS, 1);
			}
			attrs.push(TCA_OPTIONS, options.as_bytes());
		}

		let flags =
			flags::NLM_F_REQUEST | flags::NLM_F_ACK | flags::NLM_F_CREATE | flags::NLM_F_REPLACE;
		match self.socket.request(RTM_NEWQDISC, flags, &body, &attrs) {
			Ok(_) => Ok(()),
			// **Changing the scheduler at a fixed handle is not allowed.**
			// Naming a handle turns a replace into a change of the qdisc
			// already wearing it, and a qdisc cannot change kind -- the kernel
			// answers `EINVAL`, and `tc qdisc replace ... handle 6e: cake`
			// over an `fq_codel 6e:` fails in exactly the same way, with
			// "Invalid qdisc name".
			//
			// Netcfgd names a handle so that the qdisc carries its own
			// ownership (0137), so this case has to be met rather than
			// avoided. Removing the root first and retrying is what `tc` does
			// when it is not given a handle, and it is confined to here: a
			// rate change on the same scheduler keeps the handle and takes
			// this path never.
			//
			// **It reopens the window `NLM_F_REPLACE` was chosen to close**,
			// for as long as one netlink round trip takes, and only when the
			// scheduler itself changes -- which is a config edit somebody
			// made, not something netcfgd does on its own. That is the trade,
			// and it is smaller than the one-way door it buys out of.
			Err(error) if error.raw_os_error() == Some(libc::EINVAL) => {
				self.delete_root(index)?;
				self.socket.request(RTM_NEWQDISC, flags, &body, &attrs)?;
				Ok(())
			}
			Err(error) => Err(error),
		}
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

impl Qdisc<'_> {
	/// Attach the ingress qdisc to an interface, if it has none.
	///
	/// This is the hook the redirect filter hangs off. It queues nothing
	/// itself -- there is no queue on the way in -- it exists so that a
	/// classifier has somewhere to live.
	///
	/// # Errors
	///
	/// Returns the errno the kernel replied with. `EEXIST` is not an error:
	/// the qdisc is a fixed singleton, so one that is already there is already
	/// correct.
	pub fn add_ingress(&mut self, index: u32) -> io::Result<()> {
		let mut body = Vec::new();
		TcMsg {
			index: i32::try_from(index).unwrap_or(0),
			handle: INGRESS_HANDLE,
			parent: TC_H_INGRESS,
			..TcMsg::default()
		}
		.encode(&mut body);

		let mut attrs = AttrBuf::new();
		attrs.push_str(TCA_KIND, "ingress");

		match self.socket.request(
			RTM_NEWQDISC,
			flags::NLM_F_REQUEST | flags::NLM_F_ACK | flags::NLM_F_CREATE | flags::NLM_F_EXCL,
			&body,
			&attrs,
		) {
			Ok(_) => Ok(()),
			Err(error) if error.raw_os_error() == Some(libc::EEXIST) => Ok(()),
			Err(error) => Err(error),
		}
	}

	/// Remove the ingress qdisc, and with it every filter hanging off it.
	///
	/// # Errors
	///
	/// Returns the errno the kernel replied with, except the two that mean it
	/// was not there.
	pub fn delete_ingress(&mut self, index: u32) -> io::Result<()> {
		let mut body = Vec::new();
		TcMsg {
			index: i32::try_from(index).unwrap_or(0),
			handle: INGRESS_HANDLE,
			parent: TC_H_INGRESS,
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

	/// Redirect everything arriving on `index` to the device at `target`.
	///
	/// One `matchall` classifier with one `mirred` action, which is the whole
	/// of the filter machinery netcfgd generates. It carries no policy: it
	/// matches every packet unconditionally, and the only thing configurable
	/// about it is which device the traffic lands on.
	///
	/// # Errors
	///
	/// Returns the errno the kernel replied with. `ENOENT` means `cls_matchall`
	/// or `act_mirred` is missing from this kernel.
	pub fn redirect_ingress(&mut self, index: u32, target: u32) -> io::Result<()> {
		let mut body = Vec::new();
		TcMsg {
			index: i32::try_from(index).unwrap_or(0),
			parent: INGRESS_HANDLE,
			// Priority in the top half, protocol in the bottom, and the
			// protocol is already big-endian. `ETH_P_ALL` is the point: this
			// has to see ARP and IPv6 as well as IPv4, and a filter installed
			// for one protocol silently passes the rest unshaped.
			info: (FILTER_PRIORITY << 16) | ETH_P_ALL_BE,
			// netcfgd's mark, and the reason it is here rather than in the
			// priority above: a handle carries no ordering, and the priority
			// has to stay 1 for the redirect to see the packet at all.
			handle: NETCFGD_FILTER_HANDLE,
			..TcMsg::default()
		}
		.encode(&mut body);

		// `struct tc_mirred`: five ints of `tc_gen`, then the action and the
		// device. `eaction` says redirect rather than mirror -- a mirror would
		// copy the traffic and leave the original to arrive unshaped as well.
		let mut mirred = Vec::with_capacity(28);
		for field in [0_u32, 0] {
			mirred.extend_from_slice(&field.to_ne_bytes()); // index, capab
		}
		for field in [TC_ACT_STOLEN, 0, 0, TCA_EGRESS_REDIR] {
			mirred.extend_from_slice(&field.to_ne_bytes()); // action, refcnt, bindcnt, eaction
		}
		mirred.extend_from_slice(&target.to_ne_bytes());

		let mut mirred_options = AttrBuf::new();
		mirred_options.push(TCA_MIRRED_PARMS, &mirred);

		let mut action = AttrBuf::new();
		action.push_str(TCA_ACT_KIND, "mirred");
		action.push(TCA_ACT_OPTIONS | NLA_F_NESTED, mirred_options.as_bytes());

		// The action list is indexed from one, and the index is the attribute
		// type rather than a field.
		let mut actions = AttrBuf::new();
		actions.push(1 | NLA_F_NESTED, action.as_bytes());

		let mut options = AttrBuf::new();
		options.push(TCA_MATCHALL_ACT | NLA_F_NESTED, actions.as_bytes());

		let mut attrs = AttrBuf::new();
		attrs.push_str(TCA_KIND, "matchall");
		attrs.push(TCA_OPTIONS | NLA_F_NESTED, options.as_bytes());

		self.socket.request(
			RTM_NEWTFILTER,
			flags::NLM_F_REQUEST | flags::NLM_F_ACK | flags::NLM_F_CREATE | flags::NLM_F_REPLACE,
			&body,
			&attrs,
		)?;
		Ok(())
	}

	/// The devices traffic arriving on `index` is redirected to.
	///
	/// Per interface, not machine-wide: `RTM_GETTFILTER` resolves the ifindex
	/// in the request and returns an empty dump for one it cannot find, so a
	/// request with a zero index quietly succeeds and reports nothing. That is
	/// the whole failure mode -- it looks exactly like "no redirects are
	/// installed", which is a plan that reinstalls one on every apply.
	///
	/// # Errors
	///
	/// Returns the errno the kernel replied with.
	/// Returns `(target index, whether netcfgd installed it)` per redirect.
	pub fn redirects_on(&mut self, index: u32) -> io::Result<Vec<(u32, bool)>> {
		let mut body = Vec::new();
		TcMsg {
			index: i32::try_from(index).unwrap_or(0),
			parent: INGRESS_HANDLE,
			..TcMsg::default()
		}
		.encode(&mut body);

		let replies = match self.socket.request(
			RTM_GETTFILTER,
			flags::NLM_F_REQUEST | flags::NLM_F_DUMP,
			&body,
			&AttrBuf::new(),
		) {
			Ok(replies) => replies,
			// A dump of filters on an interface with no ingress qdisc is not
			// an error worth propagating: it means there are none.
			Err(error) if matches!(error.raw_os_error(), Some(libc::ENOENT | libc::EINVAL)) => {
				return Ok(Vec::new())
			}
			Err(error) => return Err(error),
		};

		let mut out: Vec<(u32, bool)> = replies
			.iter()
			.filter_map(|payload| decode_redirect(payload))
			.collect();
		out.sort_unstable();
		out.dedup();
		Ok(out)
	}
}

/// One filter dump entry, if it is a match-all redirect.
///
/// Anything else is ignored rather than guessed at, for the same reason the
/// NAT reader ignores a rule that is not the exact shape netcfgd writes: a
/// `u32` classifier somebody added by hand is not netcfgd's, and reporting it
/// as one would produce a plan that removed it.
fn decode_redirect(payload: &[u8]) -> Option<(u32, bool)> {
	let header = TcMsg::decode(payload)?;
	if header.parent != INGRESS_HANDLE {
		return None;
	}
	// Whose filter this is. netcfgd stamps its own handle (0137); anything
	// else is a redirect somebody else installed, which is reported and never
	// cleared.
	let ours = header.handle == NETCFGD_FILTER_HANDLE;
	let attrs = wire::Attrs::new(payload.get(TCMSG_LEN..)?);
	if attrs.get(TCA_KIND)?.string()? != "matchall" {
		return None;
	}

	let options = attrs.get(TCA_OPTIONS)?;
	let actions = wire::Attrs::new(options.value).get(TCA_MATCHALL_ACT)?;
	for element in wire::Attrs::new(actions.value) {
		let action = wire::Attrs::new(element.value);
		if action.get(TCA_ACT_KIND).and_then(|attr| attr.string()) != Some("mirred".to_owned()) {
			continue;
		}
		let parms = action
			.get(TCA_ACT_OPTIONS)
			.and_then(|attr| wire::Attrs::new(attr.value).get(TCA_MIRRED_PARMS))?;
		// `ifindex` is the last of the seven words in `struct tc_mirred`.
		let target = parms.value.get(24..28)?;
		return Some((u32::from_ne_bytes(target.try_into().ok()?), ours));
	}
	None
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
	let options = attrs.get(TCA_OPTIONS).map(|attr| attr.value);
	let bandwidth_bits = options
		.and_then(cake_rate)
		// Bytes back to bits, the inverse of the division in `set_root`.
		.map(|bytes| bytes * 8);
	let ingress = options.is_some_and(|options| {
		wire::Attrs::new(options)
			.get(TCA_CAKE_INGRESS)
			.and_then(|attr| attr.u32())
			.is_some_and(|flag| flag != 0)
	});

	Some(QdiscRecord {
		handle: header.handle,
		index: u32::try_from(header.index).unwrap_or(0),
		kind,
		bandwidth_bits,
		ingress,
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
