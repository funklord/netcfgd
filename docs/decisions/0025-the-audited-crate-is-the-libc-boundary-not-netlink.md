# 0025: The audited crate is the libc boundary, not netlink

Status: accepted
Date: 2026-07-30
Milestone: M6

## Context

`ncfg tui` needs raw terminal mode. Terminal attributes are an ioctl, `std` has
no API for them, and no escape sequence turns off canonical input -- so it is
`tcgetattr` and `tcsetattr`, which are `extern "C"`, which Rust requires
`unsafe` to call.

Constraint 4 puts `unsafe` in one crate: `netcfgd-netlink`. So the question
looked like "does the TUI need an exception?", and three answers were on the
table: amend constraint 4 for a second audited crate, shell out to `stty`, or
give up full-screen mode.

## Decision

**None of them. The termios calls go in `netcfgd-netlink`, and constraint 4 is
unchanged.**

The question was wrong because the crate's name is wrong. It already holds
`inotify.rs` -- `inotify_init1`, `inotify_add_watch`, `poll` -- and `peer.rs`,
which is `SO_PEERCRED` through `getsockopt`. Neither is netlink. What that
crate actually is, and has been since M2, is **the one place libc FFI lives,
audited, with a `SAFETY` comment on every block**.

Constraint 4's purpose is that raw kernel-boundary code sits somewhere a
reviewer can read in one sitting. Terminal control is exactly that kind of
code, and putting it anywhere else would create a second such place, which is
the thing the constraint exists to prevent.

## Why this is a smaller step than it sounds

`unsafe` here is the FFI marker, not a risk assessment. It means the compiler
stops checking, because it cannot see a foreign function's contract -- not that
the operation is dangerous.

The whole surface is three calls and a stack struct:

```rust
let mut term: libc::termios = unsafe { std::mem::zeroed() };
unsafe { libc::tcgetattr(fd, &mut term) };
term.c_lflag &= !(libc::ICANON | libc::ECHO | libc::ISIG);
unsafe { libc::tcsetattr(fd, libc::TCSAFLUSH, &term) };
```

The crate already had fourteen blocks of that shape, including
`std::mem::zeroed()` for `sockaddr_nl`, which is a larger and more delicate
struct than `termios`. This is not new machinery; it is one more of a thing
already there.

## What was checked, and how

Raw mode returning `Ok` proves nothing. It was verified from outside the
process: a pty was opened, the flags read before, during and after.

| | ECHO | ICANON | ISIG | OPOST |
|---|---|---|---|---|
| before | on | on | on | on |
| while held | **off** | **off** | **off** | **off** |
| after | on | on | on | on |

`TIOCGWINSZ` was checked the same way -- the pty was set to 40x132 and the
process reported 40x132 rather than the 80x24 fallback.

## Consequences

**`ISIG` is off, so `^C` arrives as a byte.** That is what keeps cleanup
reachable: a signal would abort past the destructor and leave the operator's
shell with no echo. The TUI treats `^C` and `q` as the same key.

**A panic still leaves the terminal raw.** The release profile is
`panic = "abort"`, so destructors do not run on that path. Stated in the
module rather than papered over; the mitigation is that every ordinary exit
restores, and `^C` is an ordinary exit.

**The crate's name now misdescribes it twice over.** `netcfgd-netlink` holds
netlink, inotify, socket credentials and terminal control. A rename would
touch every crate in the workspace and is not worth doing mid-milestone, but it
should happen -- `netcfgd-sys` is what it is.

## Alternatives considered

**Amend constraint 4 for a second audited crate.** Rejected: it would make two
places to review instead of one, to hold three FFI calls, and the constraint's
whole value is that there is one.

**Shell out to `stty raw -echo`.** No `unsafe`, and rejected anyway. It makes a
tool a runtime dependency, which 0014 and 0022 both refused in other contexts
-- and on the OpenWrt-class device this project targets, `stty` is a busybox
applet that an image can be built without. A TUI that works on a desktop and
silently misbehaves on an appliance is worse than one that needs three FFI
calls.

**Line-oriented interactive mode, no raw terminal.** Rejected: it is not what
design section 7.2 describes, and the plan-preview pane -- edit, see the diff,
press a key to apply -- is the reason the TUI exists.
