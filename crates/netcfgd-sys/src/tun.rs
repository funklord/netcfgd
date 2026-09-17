//! Persistent tun and tap devices, which netlink cannot create.
//!
//! **The one link kind that is not an `RTM_NEWLINK`.** Every other virtual link
//! netcfgd makes -- a bridge, a bond, a VLAN, a VXLAN, a tunnel, a veth pair --
//! is a netlink message with a kind name in it. A tun or tap device is not: it
//! comes from a `TUNSETIFF` ioctl on `/dev/net/tun`, and it exists only as long
//! as something holds that descriptor unless `TUNSETPERSIST` is set on it.
//!
//! That is why the model carried [`crate::ops::NewLink`]'s cousin for years
//! with "in the schema and not implemented" written on it: an ioctl is
//! `unsafe`, and `unsafe` lives in this crate alone (constraint 4). So it
//! belongs here, beside the terminal size and `SO_PEERCRED`, rather than being
//! a permanent hole in what the configuration language can ask for.
//!
//! **What `ip tuntap add` does, in the same order.** Open the clone device, ask
//! for a name and a mode, hand it an owner and a group where the configuration
//! names them, then make it persist and close. The device outlives this process
//! because persistence is what the last ioctl asks for; closing without it
//! would delete the device again, which is the failure mode worth knowing about
//! before reading the code.

use std::io;
use std::os::fd::{AsRawFd as _, OwnedFd};

/// `TUNSETIFF`, `TUNSETPERSIST`, `TUNSETOWNER`, `TUNSETGROUP`.
///
/// Written out rather than taken from `libc`, which does not export them: each
/// is `_IOW('T', n, int)` and the encoding is stable kernel ABI. The numbers
/// are checked against `linux/if_tun.h` and, more usefully, against `ip tuntap`
/// producing the same device -- which is what the live test compares.
const TUNSETIFF: libc::c_ulong = 0x4004_54ca;
const TUNSETPERSIST: libc::c_ulong = 0x4004_54cb;
const TUNSETOWNER: libc::c_ulong = 0x4004_54cc;
const TUNSETGROUP: libc::c_ulong = 0x4004_54ce;

/// The clone device every tun and tap comes from.
const CLONE_DEVICE: &str = "/dev/net/tun";

/// `struct ifreq`, as `TUNSETIFF` reads it.
///
/// Declared here rather than borrowed from `libc::ifreq`, whose union arm
/// depends on the libc version and which would make the one field this needs --
/// the flags -- reachable only through a second `unsafe` block. The kernel
/// reads `ifr_name` and `ifr_flags` and nothing else from this call, and the
/// tail is padding it ignores.
#[repr(C)]
struct IfReq {
	name: [libc::c_char; libc::IFNAMSIZ],
	flags: libc::c_short,
	padding: [u8; 22],
}

/// Whether the device carries IP packets or ethernet frames.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
	/// Layer 3: IP packets, no ethernet header.
	Tun,
	/// Layer 2: full ethernet frames.
	Tap,
}

impl Mode {
	/// The flag `TUNSETIFF` wants, with `IFF_NO_PI` beside it.
	///
	/// **`IFF_NO_PI` always**, which is what `ip tuntap add` does without
	/// saying so. Without it every packet carries a four-byte protocol header
	/// that nothing else on the machine expects, and the device looks subtly
	/// broken to whatever attaches to it rather than failing to appear.
	fn flags(self) -> libc::c_short {
		let kind = match self {
			Self::Tun => libc::IFF_TUN,
			Self::Tap => libc::IFF_TAP,
		};
		#[allow(clippy::cast_possible_truncation)]
		{
			(kind | libc::IFF_NO_PI) as libc::c_short
		}
	}
}

/// Make a persistent tun or tap device.
///
/// `owner` and `group` are the ids permitted to attach to it, where the
/// configuration names them. A device with neither may be attached to by root
/// alone, which is the kernel's default and not something this invents.
///
/// # Errors
///
/// The errno from whichever step failed, with the step named: `EBUSY` from the
/// first ioctl means a device by that name already exists and is not a tun,
/// `EPERM` means no `CAP_NET_ADMIN`, and `ENOENT` on the open means the `tun`
/// module is not loaded -- three different things to do about it, so they are
/// not flattened into one message.
pub fn create(name: &str, mode: Mode, owner: Option<u32>, group: Option<u32>) -> io::Result<()> {
	if name.is_empty() || name.len() >= libc::IFNAMSIZ {
		return Err(io::Error::new(
			io::ErrorKind::InvalidInput,
			format!("`{name}` is not a name the kernel would take for a link"),
		));
	}

	let file = std::fs::OpenOptions::new()
		.read(true)
		.write(true)
		.open(CLONE_DEVICE)
		.map_err(|error| {
			io::Error::new(
				error.kind(),
				format!("cannot open {CLONE_DEVICE}: {error}; is the `tun` module loaded?"),
			)
		})?;
	let fd = OwnedFd::from(file);

	let mut request = IfReq {
		name: [0; libc::IFNAMSIZ],
		flags: mode.flags(),
		padding: [0; 22],
	};
	for (slot, byte) in request.name.iter_mut().zip(name.as_bytes()) {
		#[allow(clippy::cast_possible_wrap)]
		{
			*slot = *byte as libc::c_char;
		}
	}

	// SAFETY: `TUNSETIFF` takes exactly one pointer to a `struct ifreq`, which
	// is what is passed and which is live for the duration of the call. The
	// name is NUL-terminated by construction -- the array is zeroed and the
	// copy above is refused at `IFNAMSIZ - 1` bytes -- and the kernel writes
	// back at most the name it chose, which this does not read.
	let created =
		unsafe { libc::ioctl(fd.as_raw_fd(), TUNSETIFF, std::ptr::addr_of_mut!(request)) };
	if created < 0 {
		let error = io::Error::last_os_error();
		return Err(io::Error::new(
			error.kind(),
			format!("TUNSETIFF for {name}: {error}"),
		));
	}

	// Before persistence, so a device that cannot be given its owner is not
	// left behind for somebody to find: closing the descriptor here removes it.
	for (what, value, request) in [
		("TUNSETOWNER", owner, TUNSETOWNER),
		("TUNSETGROUP", group, TUNSETGROUP),
	] {
		let Some(value) = value else {
			continue;
		};
		// SAFETY: both take an integer by value rather than a pointer, which is
		// what the `_IOW('T', n, int)` encoding in the constants above says.
		let set = unsafe { libc::ioctl(fd.as_raw_fd(), request, libc::c_ulong::from(value)) };
		if set < 0 {
			let error = io::Error::last_os_error();
			return Err(io::Error::new(
				error.kind(),
				format!("{what} for {name}: {error}"),
			));
		}
	}

	// **Last, and the reason the device survives this function.** A tun device
	// exists only while something holds its descriptor; without this the close
	// below would delete what was just made, and the call would report success
	// over a machine with no such link.
	//
	// SAFETY: takes an integer by value, as above.
	let persisted = unsafe { libc::ioctl(fd.as_raw_fd(), TUNSETPERSIST, 1_u64) };
	if persisted < 0 {
		let error = io::Error::last_os_error();
		return Err(io::Error::new(
			error.kind(),
			format!("TUNSETPERSIST for {name}: {error}"),
		));
	}
	Ok(())
}
