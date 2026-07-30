//! Policy routing rules: the `ip rule` table.
//!
//! A rule says *which routing table to consult*, before any table is consulted.
//! That is what makes source-based routing, VRFs and multi-uplink policy work,
//! and it is why the model carries the field set `ip rule` exposes and no more
//! (`netcfgd_model::RoutingRule`).
//!
//! **Ownership comes from `FRA_PROTOCOL`**, exactly as it does for routes.
//! Decision 0002 stamps 110 on everything netcfgd installs and refuses to
//! delete anything not carrying it; rules get the same treatment from the same
//! constant. Without it a rule would be indistinguishable from one an operator
//! added by hand, and reconciliation would either remove theirs or never remove
//! its own.
//!
//! `FRA_PROTOCOL` arrived in Linux 4.17. On anything older the attribute is
//! ignored on the way in and absent on the way out, so every rule reads as
//! unowned and netcfgd installs but never removes. That is the safe direction,
//! and it is stated rather than discovered.

use crate::socket::Netlink;
use crate::wire::{self, flags, AttrBuf};
use std::io;
use std::net::IpAddr;

/// `RTM_NEWRULE`, `RTM_DELRULE`, `RTM_GETRULE`.
const RTM_NEWRULE: u16 = 32;
const RTM_DELRULE: u16 = 33;
const RTM_GETRULE: u16 = 34;

/// `FRA_*`, the rule attributes.
const FRA_DST: u16 = 1;
const FRA_SRC: u16 = 2;
const FRA_IIFNAME: u16 = 3;
const FRA_PRIORITY: u16 = 6;
const FRA_FWMARK: u16 = 10;
const FRA_SUPPRESS_PREFIXLEN: u16 = 14;
const FRA_TABLE: u16 = 15;
const FRA_FWMASK: u16 = 16;
const FRA_OIFNAME: u16 = 17;
const FRA_L3MDEV: u16 = 19;
const FRA_PROTOCOL: u16 = 21;

/// `FR_ACT_*`.
pub const FR_ACT_TO_TBL: u8 = 1;
/// Drop silently.
pub const FR_ACT_BLACKHOLE: u8 = 6;
/// Drop, and say so.
pub const FR_ACT_UNREACHABLE: u8 = 7;
/// Drop, administratively.
pub const FR_ACT_PROHIBIT: u8 = 8;

/// `FIB_RULE_INVERT`.
const FIB_RULE_INVERT: u32 = 0x0000_0002;

/// `RT_TABLE_UNSPEC`, which is what the header carries when the real table id
/// is in `FRA_TABLE` because it does not fit in a byte.
const RT_TABLE_UNSPEC: u8 = 0;

/// Length of `struct fib_rule_hdr`.
const FIB_RULE_HDR_LEN: usize = 12;

/// One rule, as it goes out and comes back.
///
/// The same type both ways, because a rule netcfgd installs and a rule it reads
/// have to be comparable field by field -- a separate "spec" and "record" pair
/// is two places for the comparison to drift.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RuleRecord {
	/// `AF_INET` or `AF_INET6`.
	pub family: u8,
	/// Consulted in ascending order.
	pub priority: u32,
	/// Which table to look up, for [`FR_ACT_TO_TBL`].
	pub table: u32,
	/// What to do on a match.
	pub action: u8,
	/// Source selector, as address and prefix length.
	pub from: Option<(IpAddr, u8)>,
	/// Destination selector.
	pub to: Option<(IpAddr, u8)>,
	/// Incoming interface selector.
	pub iif: Option<String>,
	/// Outgoing interface selector.
	pub oif: Option<String>,
	/// Firewall mark selector.
	pub fwmark: Option<u32>,
	/// Mask applied before comparing the mark.
	pub fwmask: Option<u32>,
	/// Ignore routes shorter than this.
	pub suppress_prefixlength: Option<u32>,
	/// Match packets belonging to an l3mdev master.
	pub l3mdev: bool,
	/// Invert the selectors.
	pub invert: bool,
	/// `FRA_PROTOCOL`. 110 is netcfgd's, per decision 0002.
	pub protocol: u8,
}

/// `struct fib_rule_hdr`.
///
/// Byte-for-byte the same shape as `rtmsg`, and deliberately not that type:
/// bytes five, six and seven are `res1`, `res2` and `action` here against
/// `protocol`, `scope` and `type` there. Reusing `RtMsg` would compile and put
/// the action where the kernel reads a route type.
fn header(rule: &RuleRecord) -> Vec<u8> {
	let mut out = Vec::with_capacity(FIB_RULE_HDR_LEN);
	out.push(rule.family);
	out.push(rule.to.map_or(0, |(_, prefix)| prefix));
	out.push(rule.from.map_or(0, |(_, prefix)| prefix));
	out.push(0); // tos
			  // Only tables that fit in a byte go here; anything larger travels in
			  // `FRA_TABLE` and this stays unspecified. Truncating instead would send
			  // table 1000 as table 232.
	out.push(u8::try_from(rule.table).unwrap_or(RT_TABLE_UNSPEC));
	out.push(0); // res1
	out.push(0); // res2
	out.push(rule.action);
	out.extend_from_slice(&if rule.invert { FIB_RULE_INVERT } else { 0 }.to_ne_bytes());
	out
}

/// The attributes for one rule.
fn attributes(rule: &RuleRecord) -> AttrBuf {
	let mut attrs = AttrBuf::new();
	attrs.push_u32(FRA_PRIORITY, rule.priority);
	if rule.table != 0 {
		attrs.push_u32(FRA_TABLE, rule.table);
	}
	if let Some((address, _)) = rule.from {
		attrs.push_ip(FRA_SRC, address);
	}
	if let Some((address, _)) = rule.to {
		attrs.push_ip(FRA_DST, address);
	}
	if let Some(name) = &rule.iif {
		attrs.push_str(FRA_IIFNAME, name);
	}
	if let Some(name) = &rule.oif {
		attrs.push_str(FRA_OIFNAME, name);
	}
	if let Some(mark) = rule.fwmark {
		attrs.push_u32(FRA_FWMARK, mark);
	}
	if let Some(mask) = rule.fwmask {
		attrs.push_u32(FRA_FWMASK, mask);
	}
	if let Some(length) = rule.suppress_prefixlength {
		attrs.push_u32(FRA_SUPPRESS_PREFIXLEN, length);
	}
	if rule.l3mdev {
		attrs.push_u8(FRA_L3MDEV, 1);
	}
	attrs.push_u8(FRA_PROTOCOL, rule.protocol);
	attrs
}

impl Netlink {
	/// Every policy routing rule, both families.
	///
	/// # Errors
	///
	/// Returns the errno the kernel replied with.
	pub fn rules(&mut self) -> io::Result<Vec<RuleRecord>> {
		// An all-zero header: family `AF_UNSPEC` asks for both families in one
		// dump, which is what `ip rule show` does.
		let body = vec![0_u8; FIB_RULE_HDR_LEN];
		let replies = self.request(
			RTM_GETRULE,
			flags::NLM_F_REQUEST | flags::NLM_F_DUMP,
			&body,
			&AttrBuf::new(),
		)?;
		Ok(replies
			.iter()
			.filter_map(|payload| decode(payload))
			.collect())
	}

	/// Install a rule.
	///
	/// # Errors
	///
	/// Returns the errno the kernel replied with. `EEXIST` means a rule with
	/// this priority and family is already there.
	pub fn add_rule(&mut self, rule: &RuleRecord) -> io::Result<()> {
		self.request(
			RTM_NEWRULE,
			flags::NLM_F_REQUEST | flags::NLM_F_ACK | flags::NLM_F_CREATE | flags::NLM_F_EXCL,
			&header(rule),
			&attributes(rule),
		)?;
		Ok(())
	}

	/// Remove a rule.
	///
	/// The request carries `FRA_PROTOCOL`, and the kernel matches a delete
	/// against every attribute it is given -- so a delete asking for protocol
	/// 110 cannot match a rule that does not carry it. That is a second layer
	/// under the planner's ownership check, at the kernel rather than in
	/// netcfgd, and it means even a planner bug cannot remove somebody else's
	/// rule.
	///
	/// Verified rather than assumed: a rule installed with protocol 0 survives
	/// a delete sent with 110, and goes away when sent with 0.
	///
	/// # Errors
	///
	/// Returns the errno the kernel replied with, except `ENOENT`, which means
	/// it was already gone -- which is also what a non-matching delete looks
	/// like.
	pub fn del_rule(&mut self, rule: &RuleRecord) -> io::Result<()> {
		match self.request(
			RTM_DELRULE,
			flags::NLM_F_REQUEST | flags::NLM_F_ACK,
			&header(rule),
			&attributes(rule),
		) {
			Ok(_) => Ok(()),
			Err(error) if error.raw_os_error() == Some(libc::ENOENT) => Ok(()),
			Err(error) => Err(error),
		}
	}
}

/// One rule out of a dump.
fn decode(payload: &[u8]) -> Option<RuleRecord> {
	if payload.len() < FIB_RULE_HDR_LEN {
		return None;
	}
	let attrs = wire::Attrs::new(payload.get(FIB_RULE_HDR_LEN..)?);
	let family = *payload.first()?;
	let dst_len = *payload.get(1)?;
	let src_len = *payload.get(2)?;
	let table_byte = *payload.get(4)?;
	let action = *payload.get(7)?;
	let rule_flags = u32::from_ne_bytes(payload.get(8..12)?.try_into().ok()?);

	// The suppressor is dumped as all-ones when unset, which is not a prefix
	// length. Reading it literally would make every ordinary rule look as
	// though it suppressed prefixes shorter than four billion.
	let suppress = attrs
		.get(FRA_SUPPRESS_PREFIXLEN)
		.and_then(|attr| attr.u32())
		.filter(|value| *value != u32::MAX);

	Some(RuleRecord {
		family,
		priority: attrs
			.get(FRA_PRIORITY)
			.and_then(|attr| attr.u32())
			.unwrap_or(0),
		table: attrs
			.get(FRA_TABLE)
			.and_then(|attr| attr.u32())
			.unwrap_or_else(|| u32::from(table_byte)),
		action,
		from: attrs
			.get(FRA_SRC)
			.and_then(|attr| attr.ip())
			.map(|ip| (ip, src_len)),
		to: attrs
			.get(FRA_DST)
			.and_then(|attr| attr.ip())
			.map(|ip| (ip, dst_len)),
		iif: attrs.get(FRA_IIFNAME).and_then(|attr| attr.string()),
		oif: attrs.get(FRA_OIFNAME).and_then(|attr| attr.string()),
		fwmark: attrs.get(FRA_FWMARK).and_then(|attr| attr.u32()),
		fwmask: attrs.get(FRA_FWMASK).and_then(|attr| attr.u32()),
		suppress_prefixlength: suppress,
		l3mdev: attrs.get(FRA_L3MDEV).and_then(|attr| attr.u8()) == Some(1),
		invert: rule_flags & FIB_RULE_INVERT != 0,
		protocol: attrs
			.get(FRA_PROTOCOL)
			.and_then(|attr| attr.u8())
			.unwrap_or(0),
	})
}
