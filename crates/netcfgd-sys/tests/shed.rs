//! Shedding privilege, in a process of its own.
//!
//! **This test disarms the process it runs in, so it may not share one.**
//! Where `shed` reaches `Fully` there is an unprivileged id to become, and
//! POSIX makes credentials a property of the *process*: glibc broadcasts the
//! change to every thread, so the whole binary is uid 65534 from that moment.
//! Rust runs tests as threads in one process, which made that everybody else's
//! problem -- `crates/netcfgd-sys/src/privilege.rs` has said so in a comment
//! since the day the test was written, and nothing acted on it.
//!
//! What it cost, measured rather than supposed: an intermittent `chmod:
//! PermissionDenied` in a test about file modes, and **thirty seconds on the
//! clock of every run of this crate's tests** -- a `kill` of a root-owned
//! child returning `EPERM` after the broadcast, leaving `wait` blocked on a
//! `sleep 30` that nothing could signal. Neither failure mentions privilege.
//!
//! An integration test is a binary of its own. Decision 0262.

use netcfgd_sys::privilege::{effective_capabilities, shed, Shed};

/// Root by any of the three uids, read from the kernel rather than asked of
/// libc.
///
/// The crate's own `is_root` is private and uses `getresuid`; this is the same
/// question put to `/proc/thread-self/status`, whose `Uid:` line is real,
/// effective, saved and fsuid in that order. A saved-set uid of 0 is a way
/// back, so all of them have to be zero-free for a shed to have meant
/// anything.
fn root_by_any_uid() -> bool {
	let Ok(status) = std::fs::read_to_string("/proc/thread-self/status") else {
		// Unknowable is treated as root, which is what the crate's own
		// version does: the safe answer to "am I privileged" is yes.
		return true;
	};
	let Some(line) = status.lines().find(|line| line.starts_with("Uid:")) else {
		return true;
	};
	line.split_whitespace()
		.skip(1)
		.filter_map(|field| field.parse::<u32>().ok())
		.any(|uid| uid == 0)
}

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
				!root_by_any_uid(),
				"and its uid, which is the mechanism that took the capabilities"
			);
		}
		Shed::CapabilitiesOnly => assert_eq!(
			outside, before,
			"nothing was broadcast, so this thread kept what it had"
		),
	}
}
