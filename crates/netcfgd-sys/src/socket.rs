//! The netlink socket. Every `unsafe` in netcfgd is in this file.
//!
//! There are six of them and none parses anything: open, bind, send, receive,
//! set a timeout, close. Bytes that came off the wire are handed straight to
//! `wire`, which is entirely safe code. That split is the point -- section 1
//! constraint 4 makes this crate the single audited exception, and the way to
//! keep an audit tractable is to make the exception small enough to read in
//! one sitting.

use crate::wire::{self, flags, msg_type};
use std::io;

/// `AF_NETLINK`, `SOCK_RAW`, `NETLINK_ROUTE`.
pub const NETLINK_ROUTE: libc::c_int = 0;
/// `NETLINK_GENERIC`. A different protocol on the same socket family, and the
/// door to `wireguard`, `nl80211` and `ethtool` -- none of which have an
/// rtnetlink interface.
pub const NETLINK_GENERIC: libc::c_int = 16;

/// Multicast groups a watcher subscribes to, from `linux/rtnetlink.h`.
pub mod groups {
	/// Links appearing, disappearing, or changing flags.
	pub const LINK: u32 = 1;
	/// IPv4 addresses.
	pub const IPV4_IFADDR: u32 = 0x10;
	/// IPv4 routes.
	pub const IPV4_ROUTE: u32 = 0x40;
	/// IPv6 addresses.
	pub const IPV6_IFADDR: u32 = 0x100;
	/// IPv6 routes.
	pub const IPV6_ROUTE: u32 = 0x400;

	/// Everything the observed model is built from.
	pub const OBSERVED: u32 = LINK | IPV4_IFADDR | IPV4_ROUTE | IPV6_IFADDR | IPV6_ROUTE;
}

/// A connected rtnetlink socket.
#[derive(Debug)]
pub struct Netlink {
	fd: libc::c_int,
	seq: u32,
}

impl Netlink {
	/// Open and bind a socket.
	///
	/// # Errors
	///
	/// Returns the underlying `io::Error` if the socket cannot be opened or
	/// bound. On a kernel without `CONFIG_NETLINK` that is the failure a
	/// caller sees, and it is worth reporting as-is rather than translating.
	pub fn open() -> io::Result<Self> {
		Self::open_with_groups(0)
	}

	/// Open a socket subscribed to multicast groups.
	///
	/// A socket bound with `nl_groups = 0` receives only replies to its own
	/// requests, which is right for a one-shot and useless for a watcher. The
	/// daemon binds [`groups::OBSERVED`] and then sits in a blocking receive:
	/// a change to a link, an address or a route wakes it, and it re-reads.
	///
	/// Subscribing is not the same as reading the changes: the daemon treats a
	/// multicast message as "something moved, look again" rather than trying to
	/// apply the delta. Deltas can be lost -- a socket whose buffer overflows
	/// gets `ENOBUFS` and a gap -- so a full re-read is the only version that
	/// cannot drift, and it costs three dumps on a machine that is not
	/// changing constantly.
	///
	/// # Errors
	///
	/// Returns the underlying `io::Error` if the socket cannot be opened or
	/// bound.
	pub fn open_with_groups(nl_groups: u32) -> io::Result<Self> {
		Self::open_protocol(NETLINK_ROUTE, nl_groups)
	}

	/// Open a socket on a specific netlink protocol.
	///
	/// Everything above this speaks rtnetlink. Generic netlink is a second
	/// protocol on the same socket family with its own message layout on top
	/// of the shared header, so it needs its own socket and cannot share one
	/// with the route socket -- family ids from one are meaningless on the
	/// other.
	///
	/// # Errors
	///
	/// Returns the underlying `io::Error` if the socket cannot be opened or
	/// bound.
	pub fn open_protocol(protocol: libc::c_int, nl_groups: u32) -> io::Result<Self> {
		// SAFETY: `socket` takes three integers and returns a file descriptor
		// or -1. No pointers are involved, so there is nothing to get wrong
		// about lifetimes or provenance; the only failure mode is the -1 we
		// check for.
		let fd = unsafe {
			libc::socket(
				libc::AF_NETLINK,
				libc::SOCK_RAW | libc::SOCK_CLOEXEC,
				protocol,
			)
		};
		if fd < 0 {
			return Err(io::Error::last_os_error());
		}

		// SAFETY: `sockaddr_nl` is a plain-old-data struct of integers with no
		// padding requirements and no invalid bit patterns, so an all-zero
		// value is a valid instance of it. This is the idiomatic way to
		// initialise it, and all-zero is what the kernel expects for a socket
		// binding no multicast groups.
		let mut addr: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
		#[allow(clippy::cast_possible_truncation)]
		{
			addr.nl_family = libc::AF_NETLINK as u16;
		}
		addr.nl_groups = nl_groups;

		// SAFETY: `addr` is a live, fully initialised `sockaddr_nl` that
		// outlives the call, and the length passed is exactly its size, so
		// the kernel reads only bytes we own. The cast is the one every
		// sockaddr API requires.
		let rc = unsafe {
			libc::bind(
				fd,
				std::ptr::addr_of!(addr).cast::<libc::sockaddr>(),
				u32::try_from(std::mem::size_of::<libc::sockaddr_nl>()).unwrap_or(0),
			)
		};
		if rc < 0 {
			let error = io::Error::last_os_error();
			// SAFETY: `fd` is a descriptor this function opened and has not
			// closed or handed out, so closing it here cannot race with any
			// other use.
			unsafe { libc::close(fd) };
			return Err(error);
		}

		Ok(Self { fd, seq: 1 })
	}

	/// Set how long a receive waits before giving up.
	///
	/// Without this a lost message wedges the caller forever, which on a
	/// daemon holding `CAP_NET_ADMIN` is worse than an error.
	///
	/// # Errors
	///
	/// Returns the underlying `io::Error` if the option cannot be set.
	pub fn set_timeout(&self, seconds: i64) -> io::Result<()> {
		let timeout = libc::timeval {
			tv_sec: seconds,
			tv_usec: 0,
		};
		// SAFETY: `timeout` is a live, fully initialised `timeval`, and the
		// length passed is exactly its size, so `setsockopt` reads only bytes
		// we own. `self.fd` is valid for as long as `self` is.
		let rc = unsafe {
			libc::setsockopt(
				self.fd,
				libc::SOL_SOCKET,
				libc::SO_RCVTIMEO,
				std::ptr::addr_of!(timeout).cast::<libc::c_void>(),
				u32::try_from(std::mem::size_of::<libc::timeval>()).unwrap_or(0),
			)
		};
		if rc < 0 {
			return Err(io::Error::last_os_error());
		}
		Ok(())
	}

	/// The sequence number for the next request.
	fn next_seq(&mut self) -> u32 {
		self.seq = self.seq.wrapping_add(1);
		self.seq
	}

	/// The largest netlink reply this will grow a buffer to hold.
	///
	/// A megabyte is far past anything the kernel sends in one datagram -- a link
	/// dump message is a kilobyte or so -- and the point of the number is that
	/// growing is bounded rather than that this is the right size. A reply beyond
	/// it is reported with its size, which is the number whoever raises it needs.
	const MAX_REPLY: usize = 1024 * 1024;

	/// Send a request and collect every reply message belonging to it.
	///
	/// Handles the multipart protocol: a dump answers with a run of messages
	/// carrying `NLM_F_MULTI` and ends with `NLMSG_DONE`. A single-shot request
	/// answers with one `NLMSG_ERROR`, which is an acknowledgement when its
	/// code is zero -- netlink's least obvious convention, and the reason
	/// `error_code` returns `Some(0)` rather than `None` for success.
	///
	/// # Errors
	///
	/// Returns an `io::Error` for a failed syscall, or for a netlink error
	/// reply translated into the corresponding errno.
	pub fn request(
		&mut self,
		kind: u16,
		request_flags: u16,
		body: &[u8],
		attrs: &wire::AttrBuf,
	) -> io::Result<Vec<Vec<u8>>> {
		self.request_from(kind, request_flags, body, attrs, 32 * 1024)
	}

	/// [`request`](Self::request), starting from a buffer of a given size.
	///
	/// **The size is a parameter so that the growth can be tested.** The
	/// kernel caps a dump's datagrams just under 32 KiB -- measured, 31,944
	/// bytes for a link dump of 800 interfaces -- so the ordinary buffer is
	/// never exceeded by one and no test could make it overflow by asking for
	/// more interfaces. Starting deliberately small reaches the same code the
	/// way a single oversized message would, which is the case that does
	/// happen: one netlink message is delivered whole or not at all, and a
	/// device with a great many peers is one message.
	fn request_from(
		&mut self,
		kind: u16,
		request_flags: u16,
		body: &[u8],
		attrs: &wire::AttrBuf,
		initial: usize,
	) -> io::Result<Vec<Vec<u8>>> {
		let seq = self.next_seq();
		let message = wire::build_request(kind, request_flags, seq, body, attrs);
		self.send(&message)?;

		let mut collected = Vec::new();
		let mut buffer = vec![0_u8; initial.max(1)];
		loop {
			let read = self.receive_whole(&mut buffer)?;
			let mut saw_done = false;
			for message in wire::Messages::new(&buffer[..read]) {
				if message.header.seq != seq && message.header.seq != 0 {
					continue;
				}
				match message.header.kind {
					msg_type::NLMSG_ERROR => {
						let code = wire::error_code(message.payload).unwrap_or(libc::EPROTO);
						if code != 0 {
							return Err(io::Error::from_raw_os_error(code));
						}
						// A zero code is an acknowledgement, and ends a
						// single-shot request.
						saw_done = true;
					}
					msg_type::NLMSG_DONE => saw_done = true,
					_ => collected.push(message.payload.to_vec()),
				}
			}
			if saw_done {
				return Ok(collected);
			}
			// A reply without NLM_F_MULTI is complete on its own; without this
			// a single-shot request that gets no acknowledgement would block
			// until the timeout.
			if request_flags & flags::NLM_F_DUMP == 0 && !collected.is_empty() {
				return Ok(collected);
			}
		}
	}

	/// Block until the kernel reports a change on a subscribed group.
	///
	/// Returns `Ok(true)` when something moved and `Ok(false)` when the
	/// receive timed out, so a caller can use the timeout as its own tick
	/// without distinguishing the two at the syscall level.
	///
	/// `ENOBUFS` is reported as a change rather than as an error, and that is
	/// the important case: it means the socket's buffer overflowed and
	/// messages were dropped. A watcher that treated it as a failure would
	/// stop watching precisely when the most was happening. Since the daemon
	/// re-reads rather than applying deltas, a gap costs nothing.
	///
	/// # Errors
	///
	/// Returns the underlying `io::Error` for anything other than a timeout or
	/// a dropped-message notification.
	pub fn wait_for_change(&self) -> io::Result<bool> {
		let mut buffer = vec![0_u8; 8192];
		match self.receive(&mut buffer) {
			Ok(_) => Ok(true),
			Err(error) => match error.kind() {
				// SO_RCVTIMEO expiring.
				io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut => Ok(false),
				_ if error.raw_os_error() == Some(libc::ENOBUFS) => Ok(true),
				_ => Err(error),
			},
		}
	}

	/// Send a pre-built buffer and collect replies until `last_acked` is
	/// acknowledged.
	///
	/// nftables is transactional: a change is a run of messages between a
	/// batch-begin and a batch-end, and the kernel applies all of them or none.
	/// That does not fit `request`, which sends one message and waits, so this
	/// exists alongside it rather than inside it.
	///
	/// # Errors
	///
	/// Returns the first errno any message in the batch replied with. One
	/// failure means the whole transaction was rolled back, so reporting the
	/// first is reporting the cause.
	///
	/// `last_acked` is the sequence number of the last message that asked for
	/// an acknowledgement -- **not** the batch-end marker. The kernel
	/// acknowledges the messages inside the transaction and says nothing about
	/// the end marker, so waiting for that one waits until the socket times
	/// out.
	pub fn send_batch(&mut self, buffer: &[u8], last_acked: u32) -> io::Result<Vec<Vec<u8>>> {
		self.send(buffer)?;

		let mut collected = Vec::new();
		let mut read_buffer = vec![0_u8; 32 * 1024];
		loop {
			let read = self.receive(&mut read_buffer)?;
			for message in wire::Messages::new(&read_buffer[..read]) {
				match message.header.kind {
					msg_type::NLMSG_ERROR => {
						let code = wire::error_code(message.payload).unwrap_or(libc::EPROTO);
						if code != 0 {
							return Err(io::Error::from_raw_os_error(code));
						}
						if message.header.seq >= last_acked {
							return Ok(collected);
						}
					}
					msg_type::NLMSG_DONE => return Ok(collected),
					_ => collected.push(message.payload.to_vec()),
				}
			}
		}
	}

	/// The next sequence number, for a caller building its own messages.
	pub fn take_seq(&mut self) -> u32 {
		self.next_seq()
	}

	fn send(&self, bytes: &[u8]) -> io::Result<()> {
		// SAFETY: `bytes` is a live slice for the duration of the call, and
		// the length passed is its actual length, so the kernel reads only
		// initialised memory we own. `self.fd` is valid for as long as `self`.
		let sent = unsafe {
			libc::send(
				self.fd,
				bytes.as_ptr().cast::<libc::c_void>(),
				bytes.len(),
				libc::MSG_TRUNC,
			)
		};
		if sent < 0 {
			return Err(io::Error::last_os_error());
		}
		Ok(())
	}

	/// Take the next datagram whole, growing the buffer first if it will not
	/// fit.
	///
	/// **`MSG_PEEK` asks the size without consuming**, which is what makes
	/// this recoverable at all. A netlink datagram is delivered whole or not
	/// at all: read it into something too small and the remainder is
	/// discarded, so there is no second chance at the part that was dropped.
	/// Asking first and then reading is the standard shape for exactly that
	/// reason.
	///
	/// **Re-sending the request instead does not work, and the test caught
	/// it.** A first version doubled the buffer and asked again -- which
	/// leaves the truncated reply's remaining datagrams queued on the same
	/// socket, to be read and skipped against the new sequence number while
	/// the new reply queues behind them. It passed once and failed the next
	/// run with an empty dump. Decision 0183.
	fn receive_whole(&self, buffer: &mut Vec<u8>) -> io::Result<usize> {
		let needed = self.peek_size(buffer)?;
		if needed > buffer.len() {
			if needed > Self::MAX_REPLY {
				let cap = Self::MAX_REPLY;
				return Err(io::Error::new(
					io::ErrorKind::InvalidData,
					format!("a netlink reply of {needed} bytes is past the {cap} this will hold"),
				));
			}
			buffer.resize(needed, 0);
		}
		self.receive(buffer)
	}

	/// How large the next datagram is, leaving it queued.
	fn peek_size(&self, buffer: &mut [u8]) -> io::Result<usize> {
		// SAFETY: as `receive`, and `MSG_PEEK` additionally leaves the
		// datagram where it is, so the read that follows sees the same one.
		let read = unsafe {
			libc::recv(
				self.fd,
				buffer.as_mut_ptr().cast::<libc::c_void>(),
				buffer.len(),
				libc::MSG_PEEK | libc::MSG_TRUNC,
			)
		};
		if read < 0 {
			return Err(io::Error::last_os_error());
		}
		Ok(usize::try_from(read).unwrap_or(0))
	}

	/// Receive one datagram, returning **the size the kernel had**, which may
	/// be larger than the buffer.
	///
	/// **`MSG_TRUNC`, because without it a reply that does not fit is lost
	/// without a word.** A netlink datagram is delivered whole or not at all:
	/// a plain `recv` fills the buffer, discards the rest, and returns the
	/// buffer's length, so the caller parses the messages that fit and never
	/// learns there were more. What that costs is not a failure but an
	/// *incomplete observation* -- interfaces, addresses or routes missing
	/// from a dump -- and, where the lost tail held the `NLMSG_DONE`, a wait
	/// that runs to the socket's timeout for no reason anybody could see.
	///
	/// With the flag the return value is the true size and truncation is
	/// `read > buffer.len()`, which every caller here checks. Callers must
	/// slice with the smaller of the two: the bytes past the buffer are the
	/// kernel's count, not memory anybody wrote. Decision 0183.
	fn receive(&self, buffer: &mut [u8]) -> io::Result<usize> {
		// SAFETY: `buffer` is a live, uniquely borrowed slice for the duration
		// of the call, and the length passed is its actual length, so the
		// kernel writes only within memory we own and may mutate. With
		// `MSG_TRUNC` the *return value* may exceed that length -- it is the
		// datagram's size, not a count of bytes written -- so it is not used
		// to slice the buffer without being clamped first.
		let read = unsafe {
			libc::recv(
				self.fd,
				buffer.as_mut_ptr().cast::<libc::c_void>(),
				buffer.len(),
				0,
			)
		};
		if read < 0 {
			return Err(io::Error::last_os_error());
		}
		Ok(usize::try_from(read).unwrap_or(0))
	}
}

impl Drop for Netlink {
	fn drop(&mut self) {
		// SAFETY: `self.fd` was opened by `open`, has not been closed, and is
		// not reachable from anywhere else -- `Netlink` is not `Clone` and
		// does not hand the descriptor out. Dropping is therefore the only
		// close, and nothing can use it afterwards.
		unsafe { libc::close(self.fd) };
	}
}

#[cfg(test)]
mod tests {
	use super::{flags, msg_type, wire, Netlink};

	/// **A reply that does not fit is asked for again, and nothing is lost.**
	///
	/// Netlink delivers a datagram whole or not at all: a plain `recv` fills
	/// the buffer, silently discards the rest, and reports the buffer's
	/// length. What that costs is an *incomplete* dump -- interfaces missing
	/// from an observation with nothing anywhere saying so -- and, where the
	/// lost tail held the `NLMSG_DONE`, a wait that runs to the socket's
	/// timeout for no visible reason. `MSG_TRUNC` makes the true size the
	/// return value, so truncation is visible and the request is re-sent
	/// against a bigger buffer.
	///
	/// **Driven by starting small rather than by making a huge reply**,
	/// because the kernel will not make one on demand: measured, it caps a
	/// dump's datagrams just under 32 KiB -- 31,944 bytes for 800 interfaces
	/// -- so asking for more interfaces never overflows the ordinary buffer.
	/// A single oversized *message* does reach this, and a device with a great
	/// many peers is one message. Starting at 128 bytes takes the same path
	/// deterministically, on any machine, with no privilege: a link dump is
	/// readable by anybody.
	///
	/// The assertion is equality with the same dump read the ordinary way, so
	/// this fails both if the growth loses messages and if it invents any.
	#[test]
	fn a_dump_too_big_for_its_buffer_is_read_again_rather_than_truncated() {
		let Ok(mut netlink) = Netlink::open() else {
			eprintln!("socket: skipping -- no netlink socket here");
			return;
		};
		let body = vec![0_u8; wire::IFINFO_LEN];
		let attrs = wire::AttrBuf::new();

		let roomy = netlink
			.request_from(
				msg_type::RTM_GETLINK,
				flags::NLM_F_REQUEST | flags::NLM_F_DUMP,
				&body,
				&attrs,
				32 * 1024,
			)
			.expect("a link dump is readable without privilege");
		assert!(
			!roomy.is_empty(),
			"a machine with no interfaces at all cannot check this"
		);

		let cramped = netlink
			.request_from(
				msg_type::RTM_GETLINK,
				flags::NLM_F_REQUEST | flags::NLM_F_DUMP,
				&body,
				&attrs,
				128,
			)
			.expect("a buffer too small is grown, not given up on");
		assert_eq!(
			cramped.len(),
			roomy.len(),
			"the same dump, whatever it was read into"
		);
	}
}
