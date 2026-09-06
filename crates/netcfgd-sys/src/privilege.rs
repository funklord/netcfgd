//! Giving away what this process holds, permanently.
//!
//! **For a child that is about to touch something hostile.** netcfgd runs as
//! root and holds `CAP_NET_ADMIN`; a captive-portal probe resolves a name and
//! reads a reply from the network it has just joined. Those two facts should
//! not be true of one process, and decision 0162 says why: `getaddrinfo` is
//! glibc's, it loads NSS modules, and it parses a DNS response chosen by the
//! network under test. CVE-2015-7547 is that shape.
//!
//! dhcpcd is the working example and netcfgd already depends on it: it parses
//! the wire somewhere that cannot touch an interface, and hands the answer to
//! something that can.
//!
//! **This is the "somewhere".** It is deliberately one direction and has no
//! inverse: everything here is irreversible for the process that calls it,
//! which is the property that makes it worth having.

use std::io;

/// `_LINUX_CAPABILITY_VERSION_3`, from `linux/capability.h`.
///
/// Version 3 is two 32-bit words per set. Passing version 1 to a kernel that
/// speaks 3 makes `capset` rewrite the header and fail, which reads as a
/// mysterious `EINVAL` rather than as "ask again".
const CAPABILITY_VERSION_3: u32 = 0x2008_0522;

/// The highest capability number worth trying to drop.
///
/// `/proc/sys/kernel/cap_last_cap` is the honest answer and this does not read
/// it: dropping a capability the kernel does not have returns `EINVAL`, which
/// costs a failed syscall and nothing else, so the loop runs to a number
/// comfortably above any kernel's and ignores the refusals. One fewer file to
/// be unable to open in a child that is giving up the ability to open files.
const CAPABILITY_CEILING: i32 = 63;

#[repr(C)]
struct CapHeader {
	version: u32,
	pid: i32,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct CapData {
	effective: u32,
	permitted: u32,
	inheritable: u32,
}

/// Give up every capability, and the ability to regain one.
///
/// Four steps, and the order matters:
///
/// 1. `PR_SET_NO_NEW_PRIVS`, first, so that nothing after this point can be
///    undone by executing something with a setuid bit.
/// 2. The ambient set, cleared. Ambient capabilities survive `execve`, which
///    is exactly why netcfgd's unit grants three of them, and exactly why a
///    child that has just been `exec`ed still holds them.
/// 3. The bounding set, dropped capability by capability. This is the ceiling:
///    once a capability leaves it, no `execve` in this process or any
///    descendant can bring it back.
/// 4. Effective, permitted and inheritable, all zeroed in one `capset`.
///
/// Doing 4 before 3 would leave the bounding set full with nothing permitted,
/// which a setuid binary could climb back through -- so `NO_NEW_PRIVS` is not
/// belt and braces here, it is what makes the order forgiving.
///
/// **Capabilities are per-thread on Linux, so this sheds for the caller's
/// thread and no other.** `capset` with a pid of 0, `PR_CAPBSET_DROP` and
/// `PR_SET_NO_NEW_PRIVS` all act on the calling thread. In the one place this
/// is used that is the whole process, because the caller is `main` in a freshly
/// `exec`ed image that has not spawned anything -- and it has to stay that way:
/// calling this from a worker in a threaded process would leave every other
/// thread holding what it held, which looks like shedding and is not.
///
/// It was measured being wrong about exactly this. A first test shed inside a
/// libtest worker thread and read `/proc/self/status`, which reports the
/// thread group leader, and reported `CapEff 1ffffffffff` -- a full set --
/// after a successful shed. Neither half was lying; they were about different
/// threads.
///
/// **The process stays root.** Dropping the uid as well is stronger and is a
/// separate decision, because it needs a uid to drop *to* and that is a
/// packaging question. What this buys without it: a compromise in the resolver
/// cannot configure an interface, load a module, open a raw socket, chroot, or
/// override a file permission -- `CAP_DAC_OVERRIDE` is a capability, so even
/// uid 0 loses it here. What it does not buy: files uid 0 owns are still uid
/// 0's to read.
///
/// # Errors
///
/// Returns the first refusal, and a caller that gets one must not go on to do
/// the thing it was dropping privilege for.
pub fn shed() -> io::Result<()> {
	// SAFETY: `prctl` with `PR_SET_NO_NEW_PRIVS` takes four ignored arguments
	// and touches no memory this crate owns. It cannot fail on a kernel that
	// has the option, and a kernel that does not is one where the rest of this
	// is worth less -- so the result is read rather than assumed.
	let set = unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
	if set != 0 {
		return Err(io::Error::last_os_error());
	}

	// SAFETY: as above. `PR_CAP_AMBIENT_CLEAR_ALL` ignores the remaining
	// arguments. `EINVAL` here means a kernel without ambient capabilities,
	// which is a kernel where there is no ambient set to clear.
	let cleared = unsafe {
		libc::prctl(
			libc::PR_CAP_AMBIENT,
			libc::PR_CAP_AMBIENT_CLEAR_ALL,
			0,
			0,
			0,
		)
	};
	if cleared != 0 && io::Error::last_os_error().raw_os_error() != Some(libc::EINVAL) {
		return Err(io::Error::last_os_error());
	}

	// **Dropping from the bounding set needs `CAP_SETPCAP`, and the caller
	// usually does not have it.** netcfgd's own unit lists six capabilities and
	// that is not one of them, so a first version of this returned `EPERM`
	// here and the helper refused to run -- on precisely the packaged install
	// it was written for, and on any machine where netcfgd is not root. Caught
	// by running the helper by hand as an ordinary user, which is a control
	// that costs one command and was nearly not run.
	//
	// So `EPERM` is tolerated, and it is safe to tolerate because of what
	// follows: `NO_NEW_PRIVS` is already set, which is what a full bounding set
	// would otherwise be a route around, and the *outcome* is verified below
	// rather than each step being trusted. `EINVAL` is the ceiling being
	// generous about capability numbers this kernel does not have.
	for capability in 0..=CAPABILITY_CEILING {
		// SAFETY: as above.
		let dropped = unsafe { libc::prctl(libc::PR_CAPBSET_DROP, capability, 0, 0, 0) };
		if dropped != 0 {
			let error = io::Error::last_os_error();
			if !matches!(error.raw_os_error(), Some(libc::EINVAL | libc::EPERM)) {
				return Err(error);
			}
		}
	}

	let header = CapHeader {
		version: CAPABILITY_VERSION_3,
		// Zero is "this thread", which is the only one this is ever called
		// for: it runs in a freshly `exec`ed child before anything spawns.
		pid: 0,
	};
	let data = [CapData::default(); 2];
	// SAFETY: `capset` reads a header and two data words at the pointers
	// given, both of which are stack locals of the right layout and live for
	// the call. glibc exposes no wrapper -- `capset` belongs to libcap -- so
	// this is the syscall, which is what libcap would issue.
	let emptied =
		unsafe { libc::syscall(libc::SYS_capset, std::ptr::addr_of!(header), data.as_ptr()) };
	if emptied != 0 {
		return Err(io::Error::last_os_error());
	}

	// **The outcome, not the steps.** Two of the calls above are allowed to
	// fail on a machine that had nothing to give up, so what the caller needs
	// promised is the end state: this thread holds nothing effective, nothing
	// permitted, and can inherit nothing. Anything else and the caller must
	// not go on -- which is the difference between a guard and a gesture.
	let held = held_capabilities().ok_or_else(|| {
		io::Error::new(
			io::ErrorKind::NotFound,
			"/proc is not mounted, so what this thread holds cannot be confirmed",
		)
	})?;
	if held != (0, 0, 0) {
		return Err(io::Error::new(
			io::ErrorKind::PermissionDenied,
			format!(
				"capabilities survived: effective {:x}, permitted {:x}, inheritable {:x}",
				held.0, held.1, held.2
			),
		));
	}
	Ok(())
}

/// The effective, permitted and inheritable sets of the calling thread.
///
/// `None` where `/proc` is not mounted. See [`effective_capabilities`] for why
/// this asks `thread-self`.
#[must_use]
pub fn held_capabilities() -> Option<(u64, u64, u64)> {
	let status = std::fs::read_to_string("/proc/thread-self/status").ok()?;
	let field = |name: &str| -> Option<u64> {
		let line = status.lines().find(|line| line.starts_with(name))?;
		u64::from_str_radix(line.split_whitespace().nth(1)?, 16).ok()
	};
	Some((field("CapEff:")?, field("CapPrm:")?, field("CapInh:")?))
}

/// The effective capability set, as the kernel reports it.
///
/// **`/proc/thread-self`, not `/proc/self`.** Capabilities are per-thread and
/// `/proc/self/status` reports the thread group leader, so a caller that has
/// just shed on a worker thread would read back the set it did not change --
/// measured, and it reported a full set after a successful shed. `thread-self`
/// is the calling thread, which is the one [`shed`] acts on. On a
/// single-threaded process the two are the same file.
///
/// Read from `/proc` rather than through `capget`, because the question is
/// "what does the kernel say this thread holds" and the file is the kernel
/// saying it. `None` where `/proc` is not mounted, which is a machine where
/// this cannot be checked rather than one where the answer is zero.
#[must_use]
pub fn effective_capabilities() -> Option<u64> {
	let status = std::fs::read_to_string("/proc/thread-self/status").ok()?;
	let line = status.lines().find(|line| line.starts_with("CapEff:"))?;
	u64::from_str_radix(line.split_whitespace().nth(1)?, 16).ok()
}

/// Die after `seconds`, whatever is happening.
///
/// **A ceiling the parent does not have to enforce.** The parent reads the
/// child's output to end of file, and end of file is the child exiting -- so
/// a child that cannot outlive its alarm is a parent that cannot block. The
/// alternative is a timer in the parent and a kill, which is two mechanisms
/// where one will do.
///
/// `SIGALRM`'s default action terminates, and this deliberately installs no
/// handler: a handler is a thing that could fail to run.
pub fn die_after(seconds: u32) {
	// SAFETY: `alarm` sets a timer for the calling process and touches no
	// memory. Its return value is any previously scheduled alarm, which there
	// is not one of here.
	unsafe {
		libc::alarm(seconds);
	}
}

#[cfg(test)]
mod tests {
	use super::{effective_capabilities, shed};

	/// **Shedding is only observable from something that had something.**
	///
	/// As an ordinary user the effective set is already empty, so an assertion
	/// of "zero afterwards" would hold without the call and prove nothing --
	/// the vacuous pass this tree keeps finding. It refuses to claim anything
	/// unless it started from a non-empty set, which is what `unshare -r` gives
	/// it and how `make live` runs it.
	///
	/// **In a thread, and that is the point rather than a convenience.**
	/// Capabilities are per-thread, so shedding here confines the loss to this
	/// worker and leaves the rest of the run intact -- which is also why the
	/// reader has to ask `/proc/thread-self`. An earlier version spawned a
	/// child process instead: it took ninety seconds, reported a full set
	/// after a successful shed, and needed two fixes before it was measuring
	/// the thread it had changed.
	#[test]
	fn a_thread_that_sheds_holds_nothing_afterwards() {
		let before = effective_capabilities().expect("/proc is mounted");
		if before == 0 {
			eprintln!(
				"privilege: skipping -- this thread starts with no capabilities \
				 (CapEff 0), so dropping them proves nothing. `unshare -r` gives \
				 a full set, which is how `make live` runs this."
			);
			return;
		}

		let after = std::thread::spawn(|| {
			shed().expect("shedding must succeed where there is something to shed");
			effective_capabilities().expect("/proc is mounted")
		})
		.join()
		.expect("the shedding thread did not panic");

		assert_eq!(
			after, 0,
			"started with {before:x} and the thread kept {after:x}"
		);
	}

	/// And the thread that shed took nothing from the one that did not.
	///
	/// The other half of "per-thread": without it, a passing test above would
	/// be equally consistent with the whole process having been disarmed,
	/// which is the thing the doc comment promises does not happen.
	#[test]
	fn shedding_in_one_thread_leaves_another_alone() {
		let before = effective_capabilities().expect("/proc is mounted");
		if before == 0 {
			eprintln!("privilege: skipping -- nothing to keep");
			return;
		}
		std::thread::spawn(|| shed().expect("shed"))
			.join()
			.expect("no panic");
		assert_eq!(
			effective_capabilities().expect("/proc is mounted"),
			before,
			"this thread kept what it had"
		);
	}
}
