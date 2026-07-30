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

## Amendment: the drawing is ncurses, and the reasoning above was half right

Date: 2026-07-30

The record above is still correct about where FFI lives. It was wrong by
omission about what should be behind it: it treated hand-rolled ANSI as the
obvious thing and asked only where the three termios calls belonged.

The author's objection: *rolling your own ncurses will only produce
incompatibilities and bugs.* The hand-rolled version had already produced
three, all found within hours of shipping it:

- **No escape-sequence decoding at all.** It read one byte and switched on it,
  so every arrow key did nothing and the trailing bytes fell through as unbound
  keys.
- **A buffered-read bug.** Rust's `Stdin` is `BufReader`-backed; a one-byte
  read drained the kernel buffer into userspace, after which `poll` on the
  descriptor truthfully reported nothing readable while the next keystroke sat
  where it could not be seen. Two keys typed together arrived a second apart.
- **No signal handling.** `kill` left the operator's shell with `ECHO` and
  `ICANON` both off.

A fourth was found while replacing it, and is the one that makes the argument:
`sigprocmask` sets the *calling thread's* mask, and the signal watcher was
created after the event-subscription thread was spawned. That thread inherited
an unblocked mask and could take the signal with default disposition.
`SIGHUP` killed the process outright; `SIGTERM` survived only by luck of which
thread the kernel picked.

None of these are novel. All of them are things ncurses, or a correct
signal-blocking order, has had right for decades.

### The constraint did not forbid it, and saying it did was the mistake

An earlier version of this reasoning held that netcfgd could not link ncurses.
Constraint 3 says "**Core** has no mandatory dependencies beyond libc and the
kernel. No D-Bus, no glib, no polkit, no systemd" -- a bar on heavyweight
system integration, in a project that links serde and serde_json without
trouble. It never forbade a library, and the TUI is not core: design section
10.2 has always listed the TUI as removable from the embedded tier.

So the honest reading is that hand-rolling was a *choice*, and dressing it as
a constraint made a worse decision look like a forced one.

### What is behind the feature flag, and why the flag exists

`ncfg tui` is a cargo feature, on by default. With it off nothing links
ncurses and the binary is byte-for-byte the size it was before any TUI existed
-- 1,743,384, against 1,772,056 with it on. That is what keeps constraint 3
true for a build that wants it: the operator of an appliance gets a client with
no dependency beyond libc, and everyone else gets a TUI that works.

The 28,672-byte difference is exactly seven pages, and that is not a
coincidence about the code -- the linker pads to page boundaries, so this
project's size gate cannot see a change smaller than 4 KB. Worth knowing before
reading meaning into a size that did not move.

### What stayed this project's own

Each pane's *content* is still four pure functions from a JSON answer to a list
of lines, tested with no terminal at all. Only the painting went to ncurses.
That split is what let the layout tests survive the rewrite unchanged in
substance.

### Two things the replacement taught, both worth writing down

**ncurses only decodes escape sequences in blocking mode.** Given a
non-blocking or timed read it sees the `ESC`, cannot wait out `ESCDELAY` for
the rest, and hands back raw bytes. Measured: with a 50 ms timeout, Down
arrived as 27, 91, 66. Blocking is safe here because `poll` gates it and
because ncurses reads the descriptor a byte at a time rather than slurping it
-- so nothing is stranded where `poll` cannot see it, which is exactly the trap
the hand-rolled version fell into.

**A pty is not a terminal emulator.** `smkx` puts the terminal into application
cursor mode, where xterm's `kcud1` is `\EOB` rather than `\E[B`. A test
driving a bare pty has to send what a real terminal in that mode would send.
Half an hour was spent hunting a decoding bug that did not exist because the
test sent the normal-mode sequence; a minimal C program using ncurses directly
behaved identically, which is what finally located it.
