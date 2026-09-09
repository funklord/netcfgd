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
/// **Capabilities are per-thread on Linux and credentials are not, so how much
/// of a threaded process this disarms depends on which outcome it reaches.**
/// `capset` with a pid of 0, `PR_CAPBSET_DROP` and `PR_SET_NO_NEW_PRIVS` all
/// act on the calling thread alone. The uid change does not: POSIX makes
/// credentials a property of the process, so glibc's `setuid` signals every
/// other thread to make the same change -- nptl calls it setxid -- and a
/// thread that never called it comes out at the new uid with its capabilities
/// gone. Measured: a worker calling `setuid(65534)` took the main thread from
/// `uid 0 CapEff 000001ffffffffff` to `uid 65534 CapEff 0`.
///
/// So `Shed::Fully` disarms the whole process and `Shed::CapabilitiesOnly`
/// disarms one thread, and **the weaker of those is the one to design
/// around**: where there is no id to become -- `unshare -r`, every rootless
/// container -- a worker that sheds leaves every other thread holding what it
/// held, which looks like shedding and is not.
///
/// In the one place this is used the question does not arise, because the
/// caller is `main` in a freshly `exec`ed image that has not spawned anything
/// -- and it has to stay that way.
///
/// It was measured being wrong about exactly this. A first test shed inside a
/// libtest worker thread and read `/proc/self/status`, which reports the
/// thread group leader, and reported `CapEff 1ffffffffff` -- a full set --
/// after a successful shed. Neither half was lying; they were about different
/// threads.
///
/// **It stops being root too, and the id comes from the kernel rather than
/// from a convention.** Capabilities alone leave uid 0, which can still read
/// what uid 0 *owns* -- `/etc/netcfgd/secrets` is 0600 and root's, so a
/// compromise in the resolver could read every wifi passphrase and 802.1X
/// credential on the machine. `CAP_DAC_OVERRIDE` being gone does not help: an
/// owner needs no override.
///
/// The id is `/proc/sys/kernel/overflowuid`, defaulting to 65534. That is the
/// id the kernel itself substitutes for one it cannot map, so it is a non-root
/// id on every Linux by construction -- and asking for it costs one file read
/// rather than a `getpwnam`, which would mean NSS, which is the C library this
/// whole exercise exists to keep away from the privileged process. It is the
/// same 65534 that `nobody` is on a Debian or Alpine machine; this arrives at
/// it without a user database.
///
/// **Not a dedicated `netcfgd` user**, and that is deliberate rather than
/// lazy: the packaging creates a *group* for the control socket and no user,
/// so requiring one would be a change to four init systems and two package
/// formats for a child that owns nothing, opens nothing and lives for
/// milliseconds. What it needs is not to be uid 0, which this gives it.
///
/// Supplementary groups go first, then the gid, then the uid -- once the uid
/// has left root neither of the other two can be set. A `setuid` away from
/// root also clears the permitted and effective sets by itself, so the capset
/// below is belt to that braces; both are done because the verification at the
/// end has to be able to pass on a machine where this was never root at all.
///
/// # Errors
///
/// Returns the first refusal, and a caller that gets one must not go on to do
/// the thing it was dropping privilege for.
pub fn shed() -> io::Result<Shed> {
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
	// **Before the capabilities, because it needs two of them.** Clearing the
	// supplementary groups and setting the gid want `CAP_SETGID`, and the uid
	// wants `CAP_SETUID` -- both of which the bounding-set loop below is about
	// to make unavailable. netcfgd's unit grants both, for dhcpcd's privsep,
	// so they are there to be spent.
	let mut reached = Shed::Fully;
	if is_root() {
		let id = unprivileged_id();
		// SAFETY: `setgroups` with a count of zero reads no memory from the
		// pointer, which is why null is the conventional argument. It empties
		// the supplementary set, which a uid change does not touch.
		let groups = unsafe { libc::setgroups(0, std::ptr::null()) };
		// SAFETY: both take an id and touch no memory. The order is fixed:
		// after the uid leaves root the gid can no longer be set.
		let group = unsafe { libc::setgid(id) };
		// SAFETY: as above.
		let user = unsafe { libc::setuid(id) };
		if groups != 0 || group != 0 || user != 0 {
			// **There is no id to become, and that is a real place to be.**
			// A user namespace with one mapping -- `unshare -r`, and every
			// rootless container -- maps uid 0 and nothing else, so 65534
			// does not exist to move to and the kernel refuses. Being uid 0
			// there is not being the machine's root: it is a mapped id with
			// no authority outside the namespace, so capabilities-only is
			// the whole of what privilege there was.
			//
			// Reported rather than swallowed. A caller that needs the
			// stronger answer can insist on it; the portal probe does not,
			// because the weaker one is already everything that namespace
			// had to give.
			reached = Shed::CapabilitiesOnly;
		}
	}

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
	if reached == Shed::Fully && is_root() {
		return Err(io::Error::new(
			io::ErrorKind::PermissionDenied,
			"still uid 0 after a drop that reported success",
		));
	}
	Ok(reached)
}

/// How far [`shed`] got.
///
/// Two answers rather than a boolean success, because the weaker one is
/// legitimate and the difference matters to whoever reads it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Shed {
	/// No capabilities, and no longer uid 0.
	Fully,
	/// No capabilities, still uid 0 -- there was no unprivileged id to become.
	/// A user namespace with a single mapping is the case that produces this.
	CapabilitiesOnly,
}

impl Shed {
	/// A sentence for a diagnostic.
	#[must_use]
	pub fn describe(self) -> &'static str {
		match self {
			Self::Fully => "no capabilities and not root",
			Self::CapabilitiesOnly => "no capabilities, still uid 0: no unprivileged id to become",
		}
	}
}

/// Whether this process is root, by any of the three uids.
///
/// All three, because a saved-set uid of 0 is a way back: a process that has
/// only `seteuid`ed away can `seteuid` back. The check that matters after
/// [`shed`] is that none of them is 0.
#[must_use]
fn is_root() -> bool {
	let (mut real, mut effective, mut saved) = (u32::MAX, u32::MAX, u32::MAX);
	// SAFETY: `getresuid` writes three `uid_t` through the pointers given,
	// which are stack locals of that type and live for the call, and it reads
	// nothing.
	if unsafe { libc::getresuid(&raw mut real, &raw mut effective, &raw mut saved) } != 0 {
		// Unknowable is treated as root, because the caller uses this to
		// decide whether to drop and the safe answer to "am I privileged" is
		// yes.
		return true;
	}
	real == 0 || effective == 0 || saved == 0
}

/// The id to become: the kernel's own substitute for one it cannot map.
///
/// `/proc/sys/kernel/overflowuid`, and 65534 when it cannot be read -- which
/// is the kernel's compiled-in default and what `nobody` is on a Debian or an
/// Alpine machine. Read rather than assumed, because it is tunable.
#[must_use]
fn unprivileged_id() -> u32 {
	std::fs::read_to_string("/proc/sys/kernel/overflowuid")
		.ok()
		.and_then(|text| text.trim().parse().ok())
		.filter(|id| *id != 0)
		.unwrap_or(65534)
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

	use super::{effective_capabilities, shed, Shed};

	/// **Shedding is only observable from something that had something, and a
	/// process can be measured shedding exactly once.**
	///
	/// One test rather than two, because `shed` is irreversible: whichever
	/// test shed first left the binary with `CapEff 0`, so the second could
	/// only skip. It did -- as real root under `--test-threads=1` the sibling
	/// this was merged from printed "nothing to keep" and asserted nothing,
	/// which is the vacuous pass this tree keeps finding. One shed read from
	/// both sides cannot go quiet that way, and it retires the mutex that used
	/// to serialise the two: what that was guarding against was one test
	/// taking away the state the other was asserting about.
	///
	/// As an ordinary user the effective set is already empty, so an assertion
	/// of "zero afterwards" would hold without the call and prove nothing. It
	/// refuses to claim anything unless it started from a non-empty set, which
	/// is what `unshare -r` gives it -- and is why `make live` runs this
	/// binary, since `cargo test` as a person does not.
	///
	/// **In a thread, and that is the point rather than a convenience.**
	/// Capabilities are per-thread, which is why the reader has to ask
	/// `/proc/thread-self` rather than `/proc/self`. An earlier version
	/// spawned a child process instead: it took ninety seconds, reported a
	/// full set after a successful shed, and needed two fixes before it was
	/// measuring the thread it had changed.
	///
	/// **What the shed takes from the threads that did not call it follows the
	/// uid, and this asserted the wrong thing about that.** It read "the other
	/// thread kept what it had" unconditionally and failed as real root, for a
	/// reason that is the C library's rather than netcfgd's: POSIX makes
	/// credentials a property of the process, so glibc's `setuid` signals
	/// every other thread to make the same change -- nptl calls it setxid --
	/// and a thread that never called it loses its uid and every capability
	/// with it. Measured outside this crate, one thread calling `setuid` while
	/// the main thread read `/proc/thread-self`:
	///
	///     main before: uid 0     CapEff 000001ffffffffff
	///     main after:  uid 65534 CapEff 0000000000000000
	///
	/// So which outcome `shed` reached decides how much of the process is
	/// disarmed, and that is a fact about the environment rather than about
	/// the code -- which is why it is reported and branched on rather than
	/// asserted:
	///
	///   * `Fully` -- there was an id to become, the broadcast went out, and
	///     the whole process is disarmed. **Stronger than per-thread, not
	///     weaker.** It is also why every test that runs after this one in a
	///     root run is running as 65534.
	///   * `CapabilitiesOnly` -- `unshare -r` maps uid 0 and nothing else, so
	///     there is no id to move to and nothing is broadcast. Only the
	///     calling thread's capabilities go. That is the case `shed`'s rule
	///     exists for: call it before anything is spawned, because there a
	///     worker that sheds looks like it has disarmed a process it has not.
	#[test]
	fn a_shed_leaves_its_own_thread_nothing_and_the_others_what_the_uid_allows() {
		let before = effective_capabilities().expect("/proc is mounted");
		if before == 0 {
			eprintln!(
				"privilege: skipping -- this thread starts with no capabilities \
				 (CapEff 0), so dropping them proves nothing. `unshare -r` gives \
				 a full set, which is how `make live` runs this."
			);
			return;
		}

		let (reached, inside) = std::thread::spawn(|| {
			let reached = shed().expect("shedding must succeed where there is something to shed");
			(reached, effective_capabilities().expect("/proc is mounted"))
		})
		.join()
		.expect("the shedding thread did not panic");
		let outside = effective_capabilities().expect("/proc is mounted");

		eprintln!("privilege: reached {}", reached.describe());

		assert_eq!(
			inside, 0,
			"started with {before:x} and the thread that shed kept {inside:x}"
		);
		match reached {
			Shed::Fully => {
				assert_eq!(
					outside, 0,
					"the uid change is broadcast to every thread, so this one lost \
					 what it held without asking"
				);
				assert!(
					!super::is_root(),
					"and its uid, which is the mechanism that took the capabilities"
				);
			}
			Shed::CapabilitiesOnly => assert_eq!(
				outside, before,
				"nothing was broadcast, so this thread kept what it had"
			),
		}
	}

	/// **The id to become is the kernel's, and it is never root.**
	///
	/// The question actually asked was which user. Not `nobody` by name --
	/// that means `getpwnam`, which means NSS, which is the C library this
	/// whole exercise keeps away from the privileged process -- but
	/// `/proc/sys/kernel/overflowuid`, the kernel's own substitute for an id
	/// it cannot map. 65534 here, and what `nobody` is on Debian and Alpine.
	#[test]
	fn the_unprivileged_id_is_the_kernels_and_is_not_root() {
		let id = super::unprivileged_id();
		assert_ne!(id, 0, "becoming root is not dropping privilege");
		let published = std::fs::read_to_string("/proc/sys/kernel/overflowuid")
			.ok()
			.and_then(|text| text.trim().parse::<u32>().ok());
		match published {
			Some(kernels) if kernels != 0 => {
				assert_eq!(id, kernels, "the kernel's answer is the one used");
			}
			// A machine publishing 0, or nothing: the compiled-in default.
			_ => assert_eq!(id, 65534),
		}
	}
}
