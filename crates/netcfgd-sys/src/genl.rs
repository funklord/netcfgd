//! Generic netlink: resolving a family by name, and talking to it.
//!
//! rtnetlink has fixed message types compiled into the kernel headers. Generic
//! netlink does not: a family is registered at runtime, gets whatever numeric
//! id was free at the time, and a client has to ask the controller what that
//! id is before it can send anything. The id is not stable across reboots, not
//! stable across module loads, and caching it in a config file would be a bug.
//!
//! That indirection is the whole cost decision 0016 identified for `nl80211`,
//! and it is the same cost for `wireguard` and for ethtool's newer interface.
//! Paying it once here is the point of this module.
//!
//! No `unsafe` in this file. The socket underneath has it; the encoding and
//! the family lookup are ordinary byte handling, which is the same split the
//! rest of the crate uses.

use crate::socket::{Netlink, NETLINK_GENERIC};
use crate::wire::{self, flags, AttrBuf, Attrs};
use std::io;

/// The controller family's id, which is the one fixed number in the protocol.
///
/// Everything else is looked up; this cannot be, or there would be nothing to
/// ask.
const GENL_ID_CTRL: u16 = 16;

/// `CTRL_CMD_GETFAMILY`.
const CTRL_CMD_GETFAMILY: u8 = 3;

/// `CTRL_ATTR_*`.
const CTRL_ATTR_FAMILY_ID: u16 = 1;
const CTRL_ATTR_FAMILY_NAME: u16 = 2;
const CTRL_ATTR_MCAST_GROUPS: u16 = 7;

/// `GENL_NAMSIZ`, including the terminator.
///
/// A name longer than this cannot name a family that exists, and the kernel
/// answers `EINVAL` for the length rather than `ENOENT` for the lookup -- so
/// without checking it here, a typo in a long name reports as a malformed
/// request.
const GENL_NAMSIZ: usize = 16;

/// `CTRL_ATTR_MCAST_GRP_*`, inside the groups nest.
const CTRL_ATTR_MCAST_GRP_NAME: u16 = 1;
const CTRL_ATTR_MCAST_GRP_ID: u16 = 2;

/// The `genlmsghdr` that sits between the netlink header and the attributes.
///
/// Four bytes: a command, a version, and two the kernel ignores. Small enough
/// that it could be inlined at every call site, and a struct because forgetting
/// it produces a message the kernel parses as attributes starting four bytes
/// early -- which fails in a way that names neither the command nor the field.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GenlHeader {
	/// The family-specific command.
	pub cmd: u8,
	/// The family-specific interface version.
	pub version: u8,
}

/// How long a `genlmsghdr` is on the wire.
pub const GENL_HDR_LEN: usize = 4;

impl GenlHeader {
	/// Append this header to a message body.
	pub fn encode(self, out: &mut Vec<u8>) {
		out.push(self.cmd);
		out.push(self.version);
		// `reserved`, which the kernel neither reads nor sets.
		out.extend_from_slice(&0_u16.to_ne_bytes());
	}

	/// Read one from the front of a payload.
	#[must_use]
	pub fn decode(bytes: &[u8]) -> Option<Self> {
		if bytes.len() < GENL_HDR_LEN {
			return None;
		}
		Some(Self {
			cmd: bytes[0],
			version: bytes[1],
		})
	}
}

/// The attributes of a generic netlink reply, past its header.
#[must_use]
pub fn payload_attrs(payload: &[u8]) -> Attrs<'_> {
	Attrs::new(payload.get(GENL_HDR_LEN..).unwrap_or(&[]))
}

/// One multicast group a family publishes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct McastGroup {
	/// The group's name, which is what a caller knows it by.
	pub name: String,
	/// Its runtime id, which is what a socket subscribes to.
	pub id: u32,
}

/// What the controller knows about a family.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Family {
	/// The name that was looked up.
	pub name: String,
	/// The runtime message type to send to.
	pub id: u16,
	/// Multicast groups, by name.
	pub groups: Vec<McastGroup>,
}

impl Family {
	/// The id of a named multicast group.
	#[must_use]
	pub fn group(&self, name: &str) -> Option<u32> {
		self.groups
			.iter()
			.find(|group| group.name == name)
			.map(|group| group.id)
	}
}

/// A generic netlink socket, with the families it has already resolved.
///
/// The cache is per-socket and per-process, deliberately. Family ids change
/// when a module is unloaded and reloaded, and a long-lived daemon that cached
/// one across that would send to whatever family took the number next -- so
/// the cache lives no longer than the socket, and a reconnect re-resolves.
#[derive(Debug)]
pub struct Genl {
	socket: Netlink,
	families: Vec<Family>,
}

impl Genl {
	/// Open a generic netlink socket.
	///
	/// # Errors
	///
	/// Returns the underlying `io::Error`.
	pub fn open() -> io::Result<Self> {
		let socket = Netlink::open_protocol(NETLINK_GENERIC, 0)?;
		socket.set_timeout(5)?;
		Ok(Self {
			socket,
			families: Vec::new(),
		})
	}

	/// Look a family up by name, caching the result.
	///
	/// # Errors
	///
	/// Returns `NotFound` when the kernel has no such family, which is the
	/// ordinary answer for a module that is not loaded and is worth
	/// distinguishing from a protocol failure.
	pub fn family(&mut self, name: &str) -> io::Result<Family> {
		if let Some(found) = self.families.iter().find(|family| family.name == name) {
			return Ok(found.clone());
		}
		if name.len() >= GENL_NAMSIZ {
			return Err(io::Error::new(
				io::ErrorKind::NotFound,
				format!(
					"`{name}` is {} characters; a generic netlink family name is at most {}",
					name.len(),
					GENL_NAMSIZ - 1
				),
			));
		}

		let mut body = Vec::new();
		GenlHeader {
			cmd: CTRL_CMD_GETFAMILY,
			version: 1,
		}
		.encode(&mut body);

		let mut attrs = AttrBuf::new();
		// NUL-terminated: the controller compares it as a C string, and one
		// without the terminator matches nothing.
		attrs.push(CTRL_ATTR_FAMILY_NAME, &c_string(name));

		let replies = self
			.socket
			.request(GENL_ID_CTRL, flags::NLM_F_REQUEST, &body, &attrs)
			.map_err(|error| {
				if error.raw_os_error() == Some(libc_enoent()) {
					io::Error::new(
						io::ErrorKind::NotFound,
						format!(
							"the kernel has no generic netlink family called `{name}`; \
							 the module providing it is probably not loaded"
						),
					)
				} else {
					error
				}
			})?;

		let family = replies
			.iter()
			.find_map(|reply| parse_family(name, reply))
			.ok_or_else(|| {
				io::Error::new(
					io::ErrorKind::InvalidData,
					format!("the controller answered about `{name}` without a family id"),
				)
			})?;

		self.families.push(family.clone());
		Ok(family)
	}

	/// Send a command to a resolved family and collect the replies.
	///
	/// # Errors
	///
	/// Returns the underlying `io::Error`, or the errno the family replied
	/// with.
	pub fn request(
		&mut self,
		family: &Family,
		header: GenlHeader,
		request_flags: u16,
		attrs: &AttrBuf,
	) -> io::Result<Vec<Vec<u8>>> {
		let mut body = Vec::new();
		header.encode(&mut body);
		self.socket.request(
			family.id,
			flags::NLM_F_REQUEST | request_flags,
			&body,
			attrs,
		)
	}

	/// The socket underneath, for a caller that needs to subscribe or wait.
	#[must_use]
	pub fn socket(&self) -> &Netlink {
		&self.socket
	}
}

/// `ENOENT`, without pulling libc into every caller.
fn libc_enoent() -> i32 {
	2
}

/// A name with the NUL the kernel's string comparison expects.
fn c_string(name: &str) -> Vec<u8> {
	let mut out = name.as_bytes().to_vec();
	out.push(0);
	out
}

/// Pull a [`Family`] out of one controller reply.
fn parse_family(name: &str, payload: &[u8]) -> Option<Family> {
	let attrs = payload_attrs(payload);
	// Two bytes, not four. Netlink is not consistent about integer widths and
	// nothing in the attribute header says which this is: `CTRL_ATTR_FAMILY_ID`
	// is a `u16` while the multicast group id beside it is a `u32`. Reading it
	// as four bytes returns `None`, which surfaced as "the controller answered
	// without a family id" -- an honest error for a wrong reason.
	let id = attrs.get(CTRL_ATTR_FAMILY_ID)?.u16()?;

	let mut groups = Vec::new();
	if let Some(nest) = attrs.get(CTRL_ATTR_MCAST_GROUPS) {
		// The groups nest is an array: each attribute's *type* is an index
		// rather than a meaning, and its value is another nest holding the
		// name and id. A reader that treated the index as a kind would find
		// nothing and report a family with no groups.
		for entry in Attrs::new(nest.value) {
			let inner = Attrs::new(entry.value);
			if let (Some(group_name), Some(group_id)) = (
				inner.get(CTRL_ATTR_MCAST_GRP_NAME).and_then(|a| a.string()),
				inner.get(CTRL_ATTR_MCAST_GRP_ID).and_then(|a| a.u32()),
			) {
				groups.push(McastGroup {
					name: group_name,
					id: group_id,
				});
			}
		}
	}

	Some(Family {
		name: name.to_owned(),
		id,
		groups,
	})
}

/// Build a controller `GETFAMILY` request, for tests and fuzzing.
///
/// Exposed so the encoding can be exercised without a socket: the wire format
/// is the part that can be silently wrong, and it does not need a kernel to
/// check.
#[must_use]
pub fn getfamily_message(name: &str, seq: u32) -> Vec<u8> {
	let mut body = Vec::new();
	GenlHeader {
		cmd: CTRL_CMD_GETFAMILY,
		version: 1,
	}
	.encode(&mut body);
	let mut attrs = AttrBuf::new();
	attrs.push(CTRL_ATTR_FAMILY_NAME, &c_string(name));
	wire::build_request(GENL_ID_CTRL, flags::NLM_F_REQUEST, seq, &body, &attrs)
}
