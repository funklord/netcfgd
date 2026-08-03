//! Netlink framing: headers, attributes, and the payloads rtnetlink uses.
//!
//! Entirely safe code, on purpose. Everything here takes a `&[u8]` that came
//! off a socket -- which is to say, input this process does not control -- and
//! the whole point of the split is that the part which handles hostile bytes
//! contains no `unsafe` at all. The `unsafe` lives in `socket`, where it is
//! six syscalls and no parsing.
//!
//! Two properties every iterator here must have, because a malformed message
//! is the expected case rather than the exceptional one:
//!
//! - **It terminates.** A length field of zero must not produce an infinite
//!   loop. This is the classic netlink parser bug and there is a test for it.
//! - **It does not panic.** Truncation yields `None`, never an index panic.

/// Length of `struct nlmsghdr`.
pub const NLMSG_HDR_LEN: usize = 16;
/// Length of `struct rtattr`.
pub const RTATTR_HDR_LEN: usize = 4;
/// Length of `struct ifinfomsg`.
pub const IFINFO_LEN: usize = 16;
/// Length of `struct ifaddrmsg`.
pub const IFADDR_LEN: usize = 8;
/// Length of `struct rtmsg`.
pub const RTMSG_LEN: usize = 12;

/// Round up to the 4-byte boundary netlink aligns everything to.
#[must_use]
pub const fn align4(len: usize) -> usize {
	(len + 3) & !3
}

/// Message types this crate uses. Values from `linux/rtnetlink.h`.
pub mod msg_type {
	/// End of a multipart dump.
	pub const NLMSG_DONE: u16 = 3;
	/// An error, or an acknowledgement when the error code is zero.
	pub const NLMSG_ERROR: u16 = 2;
	/// A link record.
	pub const RTM_NEWLINK: u16 = 16;
	/// Delete a link.
	pub const RTM_DELLINK: u16 = 17;
	/// Request links.
	pub const RTM_GETLINK: u16 = 18;
	/// Set link attributes.
	pub const RTM_SETLINK: u16 = 19;
	/// An address record, or a request to add one.
	pub const RTM_NEWADDR: u16 = 20;
	/// Delete an address.
	pub const RTM_DELADDR: u16 = 21;
	/// Request addresses.
	pub const RTM_GETADDR: u16 = 22;
	/// A route record, or a request to add one.
	pub const RTM_NEWROUTE: u16 = 24;
	/// Delete a route.
	pub const RTM_DELROUTE: u16 = 25;
	/// Request routes.
	pub const RTM_GETROUTE: u16 = 26;
}

/// Message flags. Values from `linux/netlink.h`.
pub mod flags {
	/// This is a request.
	pub const NLM_F_REQUEST: u16 = 0x0001;
	/// Reply with more than one message.
	pub const NLM_F_MULTI: u16 = 0x0002;
	/// Acknowledge this request.
	pub const NLM_F_ACK: u16 = 0x0004;
	/// Return the whole table.
	pub const NLM_F_DUMP: u16 = 0x0100 | 0x0200;
	/// Replace an existing object.
	pub const NLM_F_REPLACE: u16 = 0x0100;
	/// Do not touch an existing object.
	pub const NLM_F_EXCL: u16 = 0x0200;
	/// Create if absent.
	pub const NLM_F_CREATE: u16 = 0x0400;
	/// Append rather than replace.
	pub const NLM_F_APPEND: u16 = 0x0800;
}

/// `IFLA_*` attribute types, verified against `linux/if_link.h`.
pub mod ifla {
	/// Hardware address.
	pub const ADDRESS: u16 = 1;
	/// Interface name.
	pub const IFNAME: u16 = 3;
	/// MTU.
	pub const MTU: u16 = 4;
	/// The device a virtual link rides on.
	///
	/// What a VLAN or a macvlan is *configured* with, and what the kernel
	/// *reports* for a tunnel whose underlay was set in its own nest -- so this
	/// is the one place to read a parent from for every kind but a `VXLAN`,
	/// which reports its underlay only inside `INFO_DATA`.
	pub const LINK: u16 = 5;
	/// Bridge or bond this link is enslaved to.
	pub const MASTER: u16 = 10;
	/// RFC 2863 operational state.
	pub const OPERSTATE: u16 = 16;
	/// Nested link-type information.
	pub const LINKINFO: u16 = 18;
	/// Carrier.
	pub const CARRIER: u16 = 33;
	/// Link kind, inside a `LINKINFO` nest.
	pub const INFO_KIND: u16 = 1;
}

/// `IFA_*` attribute types, verified against `linux/if_addr.h`.
pub mod ifa {
	/// The address; for a point-to-point link, the peer.
	pub const ADDRESS: u16 = 1;
	/// The local address.
	pub const LOCAL: u16 = 2;
	/// Interface label.
	pub const LABEL: u16 = 3;
	/// Extended flags.
	pub const FLAGS: u16 = 8;
	/// Address protocol. Kernel 5.18 and later only; see decision 0002.
	pub const PROTO: u16 = 11;
}

/// `RTA_*` attribute types, verified against `linux/rtnetlink.h`.
pub mod rta {
	/// Destination prefix.
	pub const DST: u16 = 1;
	/// Output interface index.
	pub const OIF: u16 = 4;
	/// Next hop.
	pub const GATEWAY: u16 = 5;
	/// Metric.
	pub const PRIORITY: u16 = 6;
	/// Preferred source.
	pub const PREFSRC: u16 = 7;
	/// Table id, for tables that do not fit `rtm_table`.
	pub const TABLE: u16 = 15;
}

/// A netlink message header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Header {
	/// Total message length including this header.
	pub len: u32,
	/// Message type.
	pub kind: u16,
	/// Flags.
	pub flags: u16,
	/// Sequence number.
	pub seq: u32,
	/// Sending port id.
	pub pid: u32,
}

impl Header {
	/// Decode a header, or `None` if there are not enough bytes.
	#[must_use]
	pub fn decode(bytes: &[u8]) -> Option<Self> {
		if bytes.len() < NLMSG_HDR_LEN {
			return None;
		}
		Some(Self {
			len: u32::from_ne_bytes(bytes[0..4].try_into().ok()?),
			kind: u16::from_ne_bytes(bytes[4..6].try_into().ok()?),
			flags: u16::from_ne_bytes(bytes[6..8].try_into().ok()?),
			seq: u32::from_ne_bytes(bytes[8..12].try_into().ok()?),
			pid: u32::from_ne_bytes(bytes[12..16].try_into().ok()?),
		})
	}

	/// Append the encoded header to `out`.
	pub fn encode(&self, out: &mut Vec<u8>) {
		out.extend_from_slice(&self.len.to_ne_bytes());
		out.extend_from_slice(&self.kind.to_ne_bytes());
		out.extend_from_slice(&self.flags.to_ne_bytes());
		out.extend_from_slice(&self.seq.to_ne_bytes());
		out.extend_from_slice(&self.pid.to_ne_bytes());
	}
}

/// One message from a netlink buffer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Message<'a> {
	/// Its header.
	pub header: Header,
	/// Everything after the header, up to `header.len`.
	pub payload: &'a [u8],
}

/// Walk the messages in a netlink read.
///
/// A read may carry several messages, and a dump carries many. Iteration stops
/// at the first thing that does not make sense rather than trying to resync,
/// because a netlink stream that has gone wrong is not one to guess about.
#[derive(Debug, Clone)]
pub struct Messages<'a> {
	rest: &'a [u8],
}

impl<'a> Messages<'a> {
	/// Start walking `bytes`.
	#[must_use]
	pub fn new(bytes: &'a [u8]) -> Self {
		Self { rest: bytes }
	}
}

impl<'a> Iterator for Messages<'a> {
	type Item = Message<'a>;

	fn next(&mut self) -> Option<Self::Item> {
		let header = Header::decode(self.rest)?;
		let len = header.len as usize;
		// A message shorter than its own header would make `advance` below
		// zero or negative, and the loop would never end. This is the netlink
		// parser bug, and refusing here is the whole fix.
		if len < NLMSG_HDR_LEN || len > self.rest.len() {
			self.rest = &[];
			return None;
		}
		let payload = &self.rest[NLMSG_HDR_LEN..len];
		let advance = align4(len).min(self.rest.len());
		self.rest = &self.rest[advance..];
		Some(Message { header, payload })
	}
}

/// One attribute.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Attr<'a> {
	/// Attribute type, with the nested and byte-order bits masked off.
	pub kind: u16,
	/// The value.
	pub value: &'a [u8],
}

impl Attr<'_> {
	/// The value as a `u8`.
	#[must_use]
	pub fn u8(&self) -> Option<u8> {
		self.value.first().copied()
	}

	/// The value as a native-endian `u16`.
	///
	/// Netlink is not consistent about integer widths and the header gives no
	/// hint: `CTRL_ATTR_FAMILY_ID` is two bytes where almost everything around
	/// it is four. Reading one with the wrong accessor returns `None` rather
	/// than a wrong number, which is the right failure -- but only if the
	/// right accessor exists.
	#[must_use]
	pub fn u16(&self) -> Option<u16> {
		Some(u16::from_ne_bytes(self.value.get(0..2)?.try_into().ok()?))
	}

	/// The value as a native-endian `u32`.
	#[must_use]
	pub fn u32(&self) -> Option<u32> {
		Some(u32::from_ne_bytes(self.value.get(0..4)?.try_into().ok()?))
	}

	/// The value as a NUL-terminated string.
	#[must_use]
	pub fn string(&self) -> Option<String> {
		let end = self
			.value
			.iter()
			.position(|byte| *byte == 0)
			.unwrap_or(self.value.len());
		std::str::from_utf8(&self.value[..end])
			.ok()
			.map(ToOwned::to_owned)
	}

	/// The value as a MAC address in the usual colon notation.
	#[must_use]
	pub fn mac(&self) -> Option<String> {
		if self.value.len() != 6 {
			return None;
		}
		let mut out = String::with_capacity(17);
		for (index, byte) in self.value.iter().enumerate() {
			if index > 0 {
				out.push(':');
			}
			out.push_str(&format!("{byte:02x}"));
		}
		Some(out)
	}

	/// The value as an IPv4 or IPv6 address, decided by its length.
	#[must_use]
	pub fn ip(&self) -> Option<std::net::IpAddr> {
		match self.value.len() {
			4 => {
				let octets: [u8; 4] = self.value.try_into().ok()?;
				Some(std::net::IpAddr::from(octets))
			}
			16 => {
				let octets: [u8; 16] = self.value.try_into().ok()?;
				Some(std::net::IpAddr::from(octets))
			}
			_ => None,
		}
	}
}

/// Walk the attributes in an attribute area.
#[derive(Debug, Clone)]
pub struct Attrs<'a> {
	rest: &'a [u8],
}

impl<'a> Attrs<'a> {
	/// Start walking `bytes`, which must begin at an attribute header.
	#[must_use]
	pub fn new(bytes: &'a [u8]) -> Self {
		Self { rest: bytes }
	}

	/// The first attribute of this type, if present.
	///
	/// Named `get` rather than `find` so it does not shadow `Iterator::find`,
	/// which this very method needs.
	#[must_use]
	pub fn get(&self, kind: u16) -> Option<Attr<'a>> {
		self.clone().find(|attr| attr.kind == kind)
	}
}

impl<'a> Iterator for Attrs<'a> {
	type Item = Attr<'a>;

	fn next(&mut self) -> Option<Self::Item> {
		if self.rest.len() < RTATTR_HDR_LEN {
			return None;
		}
		let len = u16::from_ne_bytes(self.rest[0..2].try_into().ok()?) as usize;
		let kind = u16::from_ne_bytes(self.rest[2..4].try_into().ok()?);
		// Same termination hazard as messages: a length below the header size
		// makes no progress.
		if len < RTATTR_HDR_LEN || len > self.rest.len() {
			self.rest = &[];
			return None;
		}
		let value = &self.rest[RTATTR_HDR_LEN..len];
		let advance = align4(len).min(self.rest.len());
		self.rest = &self.rest[advance..];
		// The top two bits mark nested and network-byte-order attributes and
		// are not part of the type.
		Some(Attr {
			kind: kind & 0x3fff,
			value,
		})
	}
}

/// Build an attribute area.
#[derive(Debug, Default)]
pub struct AttrBuf {
	bytes: Vec<u8>,
}

impl AttrBuf {
	/// An empty buffer.
	#[must_use]
	pub fn new() -> Self {
		Self::default()
	}

	/// Append an attribute with a raw value, padded to alignment.
	pub fn push(&mut self, kind: u16, value: &[u8]) {
		let len = RTATTR_HDR_LEN + value.len();
		#[allow(clippy::cast_possible_truncation)]
		self.bytes.extend_from_slice(&(len as u16).to_ne_bytes());
		self.bytes.extend_from_slice(&kind.to_ne_bytes());
		self.bytes.extend_from_slice(value);
		self.bytes.resize(align4(self.bytes.len()), 0);
	}

	/// Append a `u8` attribute.
	pub fn push_u8(&mut self, kind: u16, value: u8) {
		self.push(kind, &[value]);
	}

	/// Append a `u32` attribute.
	pub fn push_u32(&mut self, kind: u16, value: u32) {
		self.push(kind, &value.to_ne_bytes());
	}

	/// Append a NUL-terminated string attribute.
	pub fn push_str(&mut self, kind: u16, value: &str) {
		let mut bytes = value.as_bytes().to_vec();
		bytes.push(0);
		self.push(kind, &bytes);
	}

	/// Append an address attribute in its wire form.
	pub fn push_ip(&mut self, kind: u16, value: std::net::IpAddr) {
		match value {
			std::net::IpAddr::V4(addr) => self.push(kind, &addr.octets()),
			std::net::IpAddr::V6(addr) => self.push(kind, &addr.octets()),
		}
	}

	/// The encoded bytes.
	#[must_use]
	pub fn as_bytes(&self) -> &[u8] {
		&self.bytes
	}

	/// How many bytes.
	#[must_use]
	pub fn len(&self) -> usize {
		self.bytes.len()
	}

	/// Whether nothing has been appended.
	#[must_use]
	pub fn is_empty(&self) -> bool {
		self.bytes.is_empty()
	}
}

/// `struct ifinfomsg`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct IfInfo {
	/// Address family.
	pub family: u8,
	/// ARPHRD type.
	pub kind: u16,
	/// Interface index.
	pub index: i32,
	/// Interface flags.
	pub flags: u32,
	/// Which flag bits this message changes.
	pub change: u32,
}

impl IfInfo {
	/// Decode, or `None` if truncated.
	#[must_use]
	pub fn decode(bytes: &[u8]) -> Option<Self> {
		if bytes.len() < IFINFO_LEN {
			return None;
		}
		Some(Self {
			family: bytes[0],
			kind: u16::from_ne_bytes(bytes[2..4].try_into().ok()?),
			index: i32::from_ne_bytes(bytes[4..8].try_into().ok()?),
			flags: u32::from_ne_bytes(bytes[8..12].try_into().ok()?),
			change: u32::from_ne_bytes(bytes[12..16].try_into().ok()?),
		})
	}

	/// Append the encoded struct to `out`.
	pub fn encode(&self, out: &mut Vec<u8>) {
		out.push(self.family);
		out.push(0);
		out.extend_from_slice(&self.kind.to_ne_bytes());
		out.extend_from_slice(&self.index.to_ne_bytes());
		out.extend_from_slice(&self.flags.to_ne_bytes());
		out.extend_from_slice(&self.change.to_ne_bytes());
	}
}

/// `struct ifaddrmsg`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct IfAddr {
	/// Address family.
	pub family: u8,
	/// Prefix length.
	pub prefix_len: u8,
	/// Address flags.
	pub flags: u8,
	/// Address scope.
	pub scope: u8,
	/// Interface index.
	pub index: u32,
}

impl IfAddr {
	/// Decode, or `None` if truncated.
	#[must_use]
	pub fn decode(bytes: &[u8]) -> Option<Self> {
		if bytes.len() < IFADDR_LEN {
			return None;
		}
		Some(Self {
			family: bytes[0],
			prefix_len: bytes[1],
			flags: bytes[2],
			scope: bytes[3],
			index: u32::from_ne_bytes(bytes[4..8].try_into().ok()?),
		})
	}

	/// Append the encoded struct to `out`.
	pub fn encode(&self, out: &mut Vec<u8>) {
		out.push(self.family);
		out.push(self.prefix_len);
		out.push(self.flags);
		out.push(self.scope);
		out.extend_from_slice(&self.index.to_ne_bytes());
	}
}

/// `struct rtmsg`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RtMsg {
	/// Address family.
	pub family: u8,
	/// Destination prefix length.
	pub dst_len: u8,
	/// Source prefix length.
	pub src_len: u8,
	/// Type of service.
	pub tos: u8,
	/// Table id, for tables below 256.
	pub table: u8,
	/// Routing protocol. netcfgd stamps [`netcfgd_proto`] here.
	pub protocol: u8,
	/// Scope.
	pub scope: u8,
	/// Route type.
	pub kind: u8,
	/// Flags.
	pub flags: u32,
}

/// The `rtm_protocol` value netcfgd stamps on routes it installs.
///
/// Duplicated from `netcfgd-model` rather than depended on, because this crate
/// must stay free of anything but libc and the kernel. Decision 0002 fixes the
/// value at 110; a test in `netcfgd-observe` asserts the two agree.
#[must_use]
pub const fn netcfgd_proto() -> u8 {
	110
}

impl RtMsg {
	/// Decode, or `None` if truncated.
	#[must_use]
	pub fn decode(bytes: &[u8]) -> Option<Self> {
		if bytes.len() < RTMSG_LEN {
			return None;
		}
		Some(Self {
			family: bytes[0],
			dst_len: bytes[1],
			src_len: bytes[2],
			tos: bytes[3],
			table: bytes[4],
			protocol: bytes[5],
			scope: bytes[6],
			kind: bytes[7],
			flags: u32::from_ne_bytes(bytes[8..12].try_into().ok()?),
		})
	}

	/// Append the encoded struct to `out`.
	pub fn encode(&self, out: &mut Vec<u8>) {
		out.extend_from_slice(&[
			self.family,
			self.dst_len,
			self.src_len,
			self.tos,
			self.table,
			self.protocol,
			self.scope,
			self.kind,
		]);
		out.extend_from_slice(&self.flags.to_ne_bytes());
	}
}

/// Assemble a complete request: header, payload struct, attributes.
#[must_use]
pub fn build_request(kind: u16, flags: u16, seq: u32, body: &[u8], attrs: &AttrBuf) -> Vec<u8> {
	let len = NLMSG_HDR_LEN + align4(body.len()) + attrs.len();
	let mut out = Vec::with_capacity(len);
	#[allow(clippy::cast_possible_truncation)]
	let header = Header {
		len: len as u32,
		kind,
		flags,
		seq,
		pid: 0,
	};
	header.encode(&mut out);
	out.extend_from_slice(body);
	out.resize(NLMSG_HDR_LEN + align4(body.len()), 0);
	out.extend_from_slice(attrs.as_bytes());
	out
}

/// The error code in an `NLMSG_ERROR` payload, negated into a positive errno.
///
/// Zero means this was an acknowledgement rather than a failure.
#[must_use]
pub fn error_code(payload: &[u8]) -> Option<i32> {
	let raw = i32::from_ne_bytes(payload.get(0..4)?.try_into().ok()?);
	Some(-raw)
}
