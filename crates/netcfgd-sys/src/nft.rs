//! nftables, over `NETLINK_NETFILTER`.
//!
//! Decision 0022: netcfgd may own exactly one table, named `netcfgd`,
//! containing NAT and nothing else. It replaces that table wholesale on every
//! apply and never reads, writes or deletes any other.
//!
//! Two things about this protocol differ from the rtnetlink everything else in
//! this crate speaks, and both are silent when got wrong:
//!
//! **Integers are big-endian.** rtnetlink attributes are native-endian and
//! nftables attributes are not. A priority sent native-endian is accepted and
//! the chain sits at 1677721600 instead of 100.
//!
//! **Changes are transactional.** A modification is a run of messages between
//! a batch-begin and a batch-end, applied all or nothing. Sending a `NEWRULE`
//! on its own does not fail -- the kernel ignores it, because it was not inside
//! a transaction.

use crate::socket::Netlink;
use crate::wire::{self, flags, AttrBuf};
use std::io;

/// `NETLINK_NETFILTER`.
pub const NETLINK_NETFILTER: libc::c_int = 12;

/// `NFNL_SUBSYS_NFTABLES`.
const SUBSYS_NFTABLES: u16 = 10;
/// `NFNL_MSG_BATCH_BEGIN` and `..._END`, which carry no subsystem of their own.
const NFNL_MSG_BATCH_BEGIN: u16 = 16;
const NFNL_MSG_BATCH_END: u16 = 17;

/// `NFT_MSG_*`, which become the low byte of the message type.
const NFT_MSG_NEWTABLE: u16 = 0;
const NFT_MSG_GETTABLE: u16 = 1;
const NFT_MSG_DELTABLE: u16 = 2;
const NFT_MSG_NEWCHAIN: u16 = 3;
const NFT_MSG_GETCHAIN: u16 = 4;
const NFT_MSG_NEWRULE: u16 = 6;
const NFT_MSG_GETRULE: u16 = 7;

/// `NFPROTO_INET`, the family that sees both IPv4 and IPv6.
const NFPROTO_INET: u8 = 1;
/// `NFPROTO_UNSPEC`, for a dump that wants every family.
const NFPROTO_UNSPEC: u8 = 0;

/// `NFTA_TABLE_*`.
const NFTA_TABLE_NAME: u16 = 1;

/// `NFTA_CHAIN_*`.
const NFTA_CHAIN_TABLE: u16 = 1;
const NFTA_CHAIN_NAME: u16 = 3;
const NFTA_CHAIN_HOOK: u16 = 4;
const NFTA_CHAIN_TYPE: u16 = 7;

/// `NFTA_HOOK_*`.
const NFTA_HOOK_HOOKNUM: u16 = 1;
const NFTA_HOOK_PRIORITY: u16 = 2;

/// `NFTA_RULE_*`.
const NFTA_RULE_TABLE: u16 = 1;
const NFTA_RULE_CHAIN: u16 = 2;
const NFTA_RULE_EXPRESSIONS: u16 = 4;

/// `NFTA_LIST_ELEM`, the type every element of a nested list carries.
const NFTA_LIST_ELEM: u16 = 1;
/// `NFTA_EXPR_*`.
const NFTA_EXPR_NAME: u16 = 1;
const NFTA_EXPR_DATA: u16 = 2;

/// `NFTA_META_*` and the key for an outgoing interface name.
///
/// `NFT_META_OIFNAME` is 7. Counting the `enum nft_meta_keys` wrong lands on
/// `NFT_META_NFTRACE` at 12, which is a key that can be set and not read, so
/// the kernel rejects it with `EOPNOTSUPP` -- an error that reads like "this
/// kernel has no NAT" rather than "that is the wrong number".
const NFTA_META_DREG: u16 = 1;
const NFTA_META_KEY: u16 = 2;
const NFT_META_OIFNAME: u32 = 7;

/// `NFTA_CMP_*`, `NFT_CMP_EQ` and the register they use.
const NFTA_CMP_SREG: u16 = 1;
const NFTA_CMP_OP: u16 = 2;
const NFTA_CMP_DATA: u16 = 3;
const NFT_CMP_EQ: u32 = 0;
const NFTA_DATA_VALUE: u16 = 1;
const NFT_REG_1: u32 = 1;

/// `NF_INET_POST_ROUTING`, and the priority source NAT runs at.
const NF_INET_POST_ROUTING: u32 = 4;
const NF_IP_PRI_NAT_SRC: i32 = 100;

/// The one table netcfgd owns.
pub const TABLE: &str = "netcfgd";
/// The one chain in it.
pub const CHAIN: &str = "postrouting";

/// A table the kernel currently holds.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct TableRecord {
	/// Address family, as `NFPROTO_*`.
	pub family: u8,
	/// Its name.
	pub name: String,
}

/// A chain, and enough about it to tell whether it does NAT.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct ChainRecord {
	/// Which table it belongs to.
	pub table: String,
	/// Its name.
	pub name: String,
	/// Its type, where it is a base chain: `filter`, `nat`, `route`.
	pub kind: Option<String>,
	/// Which hook it registers at, where it is a base chain.
	pub hook: Option<u32>,
}

impl ChainRecord {
	/// Whether this chain translates source addresses on the way out.
	///
	/// Two of these on one machine double-NAT, which is the conflict decision
	/// 0022 says to detect and report.
	#[must_use]
	pub fn is_source_nat(&self) -> bool {
		self.kind.as_deref() == Some("nat") && self.hook == Some(NF_INET_POST_ROUTING)
	}
}

/// An nftables connection.
#[derive(Debug)]
pub struct Nft {
	socket: Netlink,
}

/// The header every nftables message carries after the netlink one.
///
/// `struct nfgenmsg { __u8 nfgen_family; __u8 version; __be16 res_id; }`. The
/// `res_id` is big-endian, which is the first place this protocol differs from
/// rtnetlink and the first place it is easy to get wrong.
fn nfgenmsg(family: u8, res_id: u16) -> Vec<u8> {
	let mut out = Vec::with_capacity(4);
	out.push(family);
	out.push(0); // NFNETLINK_V0
	out.extend_from_slice(&res_id.to_be_bytes());
	out
}

/// A big-endian `u32` attribute, which is what nftables wants everywhere
/// rtnetlink would want a native-endian one.
fn push_be32(attrs: &mut AttrBuf, kind: u16, value: u32) {
	attrs.push(kind, &value.to_be_bytes());
}

/// A NUL-terminated string attribute.
fn push_cstr(attrs: &mut AttrBuf, kind: u16, value: &str) {
	let mut bytes = value.as_bytes().to_vec();
	bytes.push(0);
	attrs.push(kind, &bytes);
}

impl Nft {
	/// Open a netfilter socket.
	///
	/// # Errors
	///
	/// Returns the underlying `io::Error`. `EPROTONOSUPPORT` means the kernel
	/// has no `nf_tables`, which is worth distinguishing from a permission
	/// problem.
	pub fn open() -> io::Result<Self> {
		let socket = Netlink::open_protocol(NETLINK_NETFILTER, 0)?;
		socket.set_timeout(5)?;
		Ok(Self { socket })
	}

	/// Every table the kernel holds, in every family.
	///
	/// # Errors
	///
	/// Returns the errno the kernel replied with.
	pub fn tables(&mut self) -> io::Result<Vec<TableRecord>> {
		let body = nfgenmsg(NFPROTO_UNSPEC, 0);
		let replies = self.socket.request(
			(SUBSYS_NFTABLES << 8) | NFT_MSG_GETTABLE,
			flags::NLM_F_REQUEST | flags::NLM_F_DUMP,
			&body,
			&AttrBuf::new(),
		)?;

		let mut out: Vec<TableRecord> = replies
			.iter()
			.filter_map(|payload| {
				let attrs = wire::Attrs::new(payload.get(4..)?);
				Some(TableRecord {
					family: *payload.first()?,
					name: attrs.get(NFTA_TABLE_NAME)?.string()?,
				})
			})
			.collect();
		out.sort_unstable();
		Ok(out)
	}

	/// Every chain, with enough detail to tell what it hooks.
	///
	/// # Errors
	///
	/// Returns the errno the kernel replied with.
	pub fn chains(&mut self) -> io::Result<Vec<ChainRecord>> {
		let body = nfgenmsg(NFPROTO_UNSPEC, 0);
		let replies = self.socket.request(
			(SUBSYS_NFTABLES << 8) | NFT_MSG_GETCHAIN,
			flags::NLM_F_REQUEST | flags::NLM_F_DUMP,
			&body,
			&AttrBuf::new(),
		)?;

		let mut out: Vec<ChainRecord> = replies
			.iter()
			.filter_map(|payload| {
				let attrs = wire::Attrs::new(payload.get(4..)?);
				let hook = attrs.get(NFTA_CHAIN_HOOK).and_then(|nest| {
					wire::Attrs::new(nest.value)
						.get(NFTA_HOOK_HOOKNUM)
						.and_then(|attr| attr.value.get(0..4).map(be32))
				});
				Some(ChainRecord {
					table: attrs.get(NFTA_CHAIN_TABLE)?.string()?,
					name: attrs.get(NFTA_CHAIN_NAME)?.string()?,
					kind: attrs.get(NFTA_CHAIN_TYPE).and_then(|attr| attr.string()),
					hook,
				})
			})
			.collect();
		out.sort_unstable();
		Ok(out)
	}

	/// The interfaces netcfgd's own table currently masquerades, sorted.
	///
	/// This is the observation half of the reconciliation: what the kernel
	/// holds, in the same shape as what the document asks for, so the two can
	/// be compared without either side knowing how a rule is encoded.
	///
	/// A rule that is not the exact `oifname "X" masquerade` shape written by
	/// [`Nft::replace_nat`] is ignored rather than guessed at. Anything else in
	/// this table is not netcfgd's doing, and the next apply replaces the table
	/// wholesale anyway -- so reporting it as an uplink would produce a plan
	/// that claimed to remove something it never installed.
	///
	/// # Errors
	///
	/// Returns the errno the kernel replied with. `ENOENT` where the table does
	/// not exist is not an error: no table is no uplinks.
	pub fn nat_uplinks(&mut self) -> io::Result<Vec<String>> {
		let mut filter = AttrBuf::new();
		push_cstr(&mut filter, NFTA_RULE_TABLE, TABLE);
		push_cstr(&mut filter, NFTA_RULE_CHAIN, CHAIN);

		let replies = match self.socket.request(
			(SUBSYS_NFTABLES << 8) | NFT_MSG_GETRULE,
			flags::NLM_F_REQUEST | flags::NLM_F_DUMP,
			&nfgenmsg(NFPROTO_INET, 0),
			&filter,
		) {
			Ok(replies) => replies,
			Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
			Err(error) => return Err(error),
		};

		let mut out: Vec<String> = replies
			.iter()
			.filter_map(|payload| {
				let attrs = wire::Attrs::new(payload.get(4..)?);
				masqueraded_interface(attrs.get(NFTA_RULE_EXPRESSIONS)?.value)
			})
			.collect();
		out.sort_unstable();
		out.dedup();
		Ok(out)
	}

	/// Replace netcfgd's table with one masquerading each named interface.
	///
	/// The whole table goes and comes back inside one transaction, so there is
	/// no moment where a packet could be translated by half a configuration.
	/// An empty `uplinks` removes the table and puts nothing back, which is how
	/// a config that stops asking for NAT is honoured.
	///
	/// # Errors
	///
	/// Returns the errno the kernel replied with. One failure rolls the whole
	/// transaction back, so the previous table survives a bad apply.
	pub fn replace_nat(&mut self, uplinks: &[String]) -> io::Result<()> {
		let ours_exists = self
			.tables()?
			.iter()
			.any(|table| table.name == TABLE && table.family == NFPROTO_INET);

		let mut buffer = Vec::new();
		let begin = self.socket.take_seq();
		buffer.extend_from_slice(&batch_marker(NFNL_MSG_BATCH_BEGIN, begin));
		// The last message that asked for an acknowledgement, which is what
		// the reply loop waits for. Not the batch-end marker: the kernel
		// acknowledges the contents of a transaction and says nothing about
		// its end, so waiting for the end waits for the timeout.
		let mut last_acked = begin;

		// Deleting first is what makes this a replacement rather than an
		// accumulation. It is conditional because deleting a table that is not
		// there is ENOENT, and one failure aborts the transaction -- so the
		// error would not be "no table", it would be "no NAT".
		if ours_exists {
			let mut attrs = AttrBuf::new();
			push_cstr(&mut attrs, NFTA_TABLE_NAME, TABLE);
			let (message, seq) = self.message(NFT_MSG_DELTABLE, flags::NLM_F_ACK, &attrs);
			buffer.extend_from_slice(&message);
			last_acked = seq;
		}

		if !uplinks.is_empty() {
			let mut table = AttrBuf::new();
			push_cstr(&mut table, NFTA_TABLE_NAME, TABLE);
			let create = flags::NLM_F_ACK | flags::NLM_F_CREATE;

			for (kind, attrs) in [(NFT_MSG_NEWTABLE, table), (NFT_MSG_NEWCHAIN, nat_chain())] {
				let (message, seq) = self.message(kind, create, &attrs);
				buffer.extend_from_slice(&message);
				last_acked = seq;
			}

			for uplink in uplinks {
				let (message, seq) =
					self.message(NFT_MSG_NEWRULE, create, &masquerade_rule(uplink));
				buffer.extend_from_slice(&message);
				last_acked = seq;
			}
		}

		let end = self.socket.take_seq();
		buffer.extend_from_slice(&batch_marker(NFNL_MSG_BATCH_END, end));

		self.socket.send_batch(&buffer, last_acked)?;
		Ok(())
	}

	/// One message of a transaction, with its own sequence number.
	fn message(&mut self, kind: u16, message_flags: u16, attrs: &AttrBuf) -> (Vec<u8>, u32) {
		let seq = self.socket.take_seq();
		let message = wire::build_request(
			(SUBSYS_NFTABLES << 8) | kind,
			flags::NLM_F_REQUEST | message_flags,
			seq,
			&nfgenmsg(NFPROTO_INET, 0),
			attrs,
		);
		(message, seq)
	}
}

/// The interface one rule masquerades, if it has the shape netcfgd writes.
///
/// Reads the three expressions back the way they went out: a `meta` loading
/// `oifname`, a `cmp` holding the name, and a `masq`. All three must be there.
/// A rule with the comparison and no `masq` matches traffic and does nothing to
/// it, and calling that an uplink would report NAT that is not happening.
fn masqueraded_interface(expressions: &[u8]) -> Option<String> {
	let mut name = None;
	let mut reads_oifname = false;
	let mut masquerades = false;

	for element in wire::Attrs::new(expressions) {
		if element.kind != NFTA_LIST_ELEM {
			continue;
		}
		let expression = wire::Attrs::new(element.value);
		let Some(kind) = expression
			.get(NFTA_EXPR_NAME)
			.and_then(|attr| attr.string())
		else {
			continue;
		};
		let data = expression.get(NFTA_EXPR_DATA).map(|attr| attr.value);
		match (kind.as_str(), data) {
			("meta", Some(data)) => {
				let key = wire::Attrs::new(data)
					.get(NFTA_META_KEY)
					.and_then(|attr| attr.value.get(0..4).map(be32));
				reads_oifname = key == Some(NFT_META_OIFNAME);
			}
			("cmp", Some(data)) => {
				name = wire::Attrs::new(data)
					.get(NFTA_CMP_DATA)
					.and_then(|attr| wire::Attrs::new(attr.value).get(NFTA_DATA_VALUE))
					.map(|attr| {
						// Written with a trailing NUL, which is part of the
						// comparison and not part of the name.
						String::from_utf8_lossy(attr.value)
							.trim_end_matches('\0')
							.to_owned()
					});
			}
			("masq", _) => masquerades = true,
			_ => {}
		}
	}

	if reads_oifname && masquerades {
		name.filter(|name| !name.is_empty())
	} else {
		None
	}
}

/// A `u32` from four big-endian bytes.
fn be32(bytes: &[u8]) -> u32 {
	u32::from_be_bytes(bytes.try_into().unwrap_or([0; 4]))
}

/// A batch begin or end marker.
///
/// These carry `NFNL_SUBSYS_NFTABLES` in `res_id` rather than in the message
/// type, which is how the kernel knows which subsystem the transaction is for.
fn batch_marker(kind: u16, seq: u32) -> Vec<u8> {
	wire::build_request(
		kind,
		flags::NLM_F_REQUEST,
		seq,
		&nfgenmsg(NFPROTO_UNSPEC, SUBSYS_NFTABLES),
		&AttrBuf::new(),
	)
}

/// The `postrouting` chain: `type nat hook postrouting priority srcnat`.
fn nat_chain() -> AttrBuf {
	let mut hook = AttrBuf::new();
	push_be32(&mut hook, NFTA_HOOK_HOOKNUM, NF_INET_POST_ROUTING);
	// Signed on the wire, and negative priorities are ordinary in nftables --
	// so this is a cast rather than a conversion.
	#[allow(clippy::cast_sign_loss)]
	push_be32(&mut hook, NFTA_HOOK_PRIORITY, NF_IP_PRI_NAT_SRC as u32);

	let mut chain = AttrBuf::new();
	push_cstr(&mut chain, NFTA_CHAIN_TABLE, TABLE);
	push_cstr(&mut chain, NFTA_CHAIN_NAME, CHAIN);
	chain.push(NFTA_CHAIN_HOOK, hook.as_bytes());
	push_cstr(&mut chain, NFTA_CHAIN_TYPE, "nat");
	chain
}

/// `oifname "NAME" masquerade`, as three expressions.
///
/// nftables has no single "masquerade this interface" primitive. It is: load
/// the outgoing interface name into a register, compare it, and if the
/// comparison passes, masquerade.
fn masquerade_rule(uplink: &str) -> AttrBuf {
	// meta oifname => reg 1
	let mut meta = AttrBuf::new();
	push_be32(&mut meta, NFTA_META_KEY, NFT_META_OIFNAME);
	push_be32(&mut meta, NFTA_META_DREG, NFT_REG_1);

	// cmp reg 1 == "NAME\0"
	//
	// The NUL is part of the comparison and is what makes it exact. Comparing
	// `strlen` bytes would match any interface with this name as a prefix, so
	// masquerading `eth0` would also masquerade `eth0.42`.
	let mut name = uplink.as_bytes().to_vec();
	name.push(0);
	let mut value = AttrBuf::new();
	value.push(NFTA_DATA_VALUE, &name);

	let mut cmp = AttrBuf::new();
	push_be32(&mut cmp, NFTA_CMP_SREG, NFT_REG_1);
	push_be32(&mut cmp, NFTA_CMP_OP, NFT_CMP_EQ);
	cmp.push(NFTA_CMP_DATA, value.as_bytes());

	let mut expressions = AttrBuf::new();
	expressions.push(NFTA_LIST_ELEM, expression("meta", &meta).as_bytes());
	expressions.push(NFTA_LIST_ELEM, expression("cmp", &cmp).as_bytes());
	expressions.push(
		NFTA_LIST_ELEM,
		expression("masq", &AttrBuf::new()).as_bytes(),
	);

	let mut rule = AttrBuf::new();
	push_cstr(&mut rule, NFTA_RULE_TABLE, TABLE);
	push_cstr(&mut rule, NFTA_RULE_CHAIN, CHAIN);
	rule.push(NFTA_RULE_EXPRESSIONS, expressions.as_bytes());
	rule
}

/// One expression: a name and its parameters.
fn expression(name: &str, data: &AttrBuf) -> AttrBuf {
	let mut expr = AttrBuf::new();
	push_cstr(&mut expr, NFTA_EXPR_NAME, name);
	expr.push(NFTA_EXPR_DATA, data.as_bytes());
	expr
}
