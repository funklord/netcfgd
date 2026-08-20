//! Who is on the other end of a unix socket.
//!
//! Here rather than in the daemon for the reason decision 0012 gives: this
//! crate is where raw syscalls live, and `getsockopt(SO_PEERCRED)` is one.
//!
//! The interesting part is what `SO_PEERCRED` does not tell you. It reports
//! the peer's pid, uid and *primary* gid, and a user's primary group is
//! usually their own -- so checking `group:netdev` against it alone would deny
//! nearly everybody the rule is meant to allow, while looking configured.
//! Supplementary groups come from `/proc`, with the cross-check decision 0013
//! describes.

use std::io;
use std::os::fd::AsRawFd;

/// Who connected.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Peer {
	/// The connecting process.
	pub pid: i32,
	/// Its effective user.
	pub uid: u32,
	/// Its primary group.
	pub gid: u32,
	/// Its supplementary groups, where they could be read.
	///
	/// Empty means "could not tell", not "none" -- the caller must treat that
	/// as no group membership rather than as membership in nothing, which are
	/// the same thing here only because both deny.
	pub groups: Vec<u32>,
}

impl Peer {
	/// Whether this peer is in a group, by id.
	#[must_use]
	pub fn in_group(&self, gid: u32) -> bool {
		self.gid == gid || self.groups.contains(&gid)
	}

	/// Whether this peer is root.
	#[must_use]
	pub fn is_root(&self) -> bool {
		self.uid == 0
	}
}

/// Read the credentials of whoever is on the other end.
///
/// # Errors
///
/// Returns the underlying `io::Error` if the option cannot be read, which on
/// a unix socket means the connection has already gone.
pub fn credentials(socket: &impl AsRawFd) -> io::Result<Peer> {
	let mut credentials = libc::ucred {
		pid: 0,
		uid: 0,
		gid: 0,
	};
	#[allow(clippy::cast_possible_truncation)]
	let mut length = std::mem::size_of::<libc::ucred>() as libc::socklen_t;

	// SAFETY: `credentials` is a live, fully initialised `ucred` that outlives
	// the call, and `length` is its exact size, so the kernel writes only
	// within memory we own. The descriptor comes from a borrowed socket that
	// is alive for the duration of the call.
	let rc = unsafe {
		libc::getsockopt(
			socket.as_raw_fd(),
			libc::SOL_SOCKET,
			libc::SO_PEERCRED,
			std::ptr::addr_of_mut!(credentials).cast::<libc::c_void>(),
			std::ptr::addr_of_mut!(length),
		)
	};
	if rc < 0 {
		return Err(io::Error::last_os_error());
	}

	let groups = supplementary_groups(credentials.pid, credentials.uid);
	Ok(Peer {
		pid: credentials.pid,
		uid: credentials.uid,
		gid: credentials.gid,
		groups,
	})
}

/// Supplementary groups from `/proc/<pid>/status`.
///
/// The pid can be recycled between `SO_PEERCRED` returning and this file being
/// read. Comparing the uid the file reports against the one the kernel gave us
/// closes every recycling that lands on a different user; a recycled pid
/// belonging to the same user is not a privilege boundary. On any doubt this
/// returns no groups, which denies rather than allows.
fn supplementary_groups(pid: i32, expected_uid: u32) -> Vec<u32> {
	let Ok(status) = std::fs::read_to_string(format!("/proc/{pid}/status")) else {
		return Vec::new();
	};

	// The real uid is the first field of the Uid: line. A mismatch means the
	// pid is not the process that connected.
	let uid_matches = status
		.lines()
		.find_map(|line| line.strip_prefix("Uid:"))
		.and_then(|rest| rest.split_whitespace().next())
		.and_then(|field| field.parse::<u32>().ok())
		.is_some_and(|uid| uid == expected_uid);
	if !uid_matches {
		return Vec::new();
	}

	status
		.lines()
		.find_map(|line| line.strip_prefix("Groups:"))
		.map(|rest| {
			rest.split_whitespace()
				.filter_map(|field| field.parse::<u32>().ok())
				.collect()
		})
		.unwrap_or_default()
}

/// The numeric id of a group, by name.
///
/// Reads `/etc/group` rather than calling `getgrnam`, which would pull in NSS
/// and with it whatever modules the host has configured -- LDAP, SSSD, a
/// network round trip inside a socket accept. A network configuration daemon
/// resolving a group over the network to decide who may configure the network
/// is a dependency loop with a bad failure mode.
#[must_use]
pub fn group_id(name: &str) -> Option<u32> {
	let text = std::fs::read_to_string("/etc/group").ok()?;
	for line in text.lines() {
		let mut fields = line.split(':');
		if fields.next() == Some(name) {
			// name:passwd:gid:members
			return fields.nth(1).and_then(|gid| gid.parse().ok());
		}
	}
	None
}

/// Everything needed to become a user: uid, primary gid, supplementary groups.
///
/// Separate from [`user_id`] because dropping privilege needs all three and
/// getting one of them wrong is the classic way to drop it incompletely. A
/// `setuid` without `setgroups` leaves the process in **root's** supplementary
/// groups, which on a normal machine includes every group root is in -- so the
/// hook is no longer root and can still open everything root's groups can.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserIds {
	/// The user.
	pub uid: u32,
	/// Their primary group, from the passwd entry rather than guessed.
	pub gid: u32,
	/// Every group naming them as a member, which is what `initgroups` would
	/// compute. Empty is a legitimate answer and means exactly that: a user in
	/// no supplementary groups.
	pub groups: Vec<u32>,
}

/// Resolve a user name to what is needed to become them.
///
/// `/etc/passwd` and `/etc/group` are read directly, for the reason
/// [`group_id`] gives: no NSS, no getpwnam, nothing that dlopens a module into
/// a process holding `CAP_NET_ADMIN`.
///
/// Returns `None` for a user that does not exist, which the caller must treat
/// as "do not run this" rather than as "run it as whoever we already are".
#[must_use]
pub fn user_ids(name: &str) -> Option<UserIds> {
	let passwd = std::fs::read_to_string("/etc/passwd").ok()?;
	let mut found = None;
	for line in passwd.lines() {
		let mut fields = line.split(':');
		if fields.next() != Some(name) {
			continue;
		}
		// name:passwd:uid:gid:...
		let uid = fields.nth(1).and_then(|value| value.parse().ok())?;
		let gid = fields.next().and_then(|value| value.parse().ok())?;
		found = Some((uid, gid));
		break;
	}
	let (uid, gid) = found?;

	let mut groups = Vec::new();
	if let Ok(text) = std::fs::read_to_string("/etc/group") {
		for line in text.lines() {
			let fields: Vec<&str> = line.split(':').collect();
			let [_, _, id, members] = fields[..] else {
				continue;
			};
			if members.split(',').any(|member| member == name) {
				if let Ok(id) = id.parse() {
					groups.push(id);
				}
			}
		}
	}
	groups.sort_unstable();
	groups.dedup();

	Some(UserIds { uid, gid, groups })
}

/// The numeric id of a user, by name. Same reasoning as [`group_id`].
#[must_use]
pub fn user_id(name: &str) -> Option<u32> {
	let text = std::fs::read_to_string("/etc/passwd").ok()?;
	for line in text.lines() {
		let mut fields = line.split(':');
		if fields.next() == Some(name) {
			// name:passwd:uid:gid:...
			return fields.nth(1).and_then(|uid| uid.parse().ok());
		}
	}
	None
}
