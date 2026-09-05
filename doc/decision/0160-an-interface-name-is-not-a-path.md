# 0160: an interface name is not a path

Status: accepted
Date: 2026-09-06
Milestone: found by an exhaustive sweep of the core networking paths

## Context

`Client::connect_within` reaches the supplicant by joining an interface name
onto its control directory:

```rust
let remote = dir.join(interface);
if !remote.exists() {
    return Err(io::Error::new(io::ErrorKind::NotFound,
        format!("no control socket at {}: is wpa_supplicant running on {interface}?",
                remote.display())));
}
...
socket.connect(&remote).map_err(|error| io::Error::new(error.kind(),
    format!("cannot reach {}: {error}", remote.display())))?;
```

The name arrives from a request. **`Path::join` with an absolute path replaces
the base rather than extending it**, so the whole filesystem is addressable and
no `..` is even needed. And the two errors say different things: one for a path
that is not there, one for a path that is there and cannot be connected to.

That pair is an existence oracle, and `WifiStatus` is `observe` -- the tier that
exists so a status display need not run as root, and the one a desktop policy
opens to `any` or to a group. Measured, as an ordinary user, against a daemon
with `control { observe = "any" }`:

```text
/etc/shadow            cannot reach /etc/shadow: Permission denied (os error 13)
/etc/nonexistent-xyz   no control socket at /etc/nonexistent-xyz: ...
/root                  cannot reach /root: Permission denied (os error 13)
/tmp                   cannot reach /tmp: Connection refused (os error 111)
../../etc/passwd       no control socket at <dir>/../../etc/passwd: ...
```

Absent, present-and-unreadable, and present-and-a-directory are three distinct
answers. Against the real daemon, which runs as root, they separate further:
`ENOTSOCK` for a regular file where an unprivileged reader gets `EACCES`.

Four requests reach it -- `WifiScan`, `WifiStatus`, `WifiConnect`,
`WifiDisconnect`. The other interface-carrying requests do not: `ApStations`
looks the name up in the document first, and `RadioSet` looks it up in the
observation. That population was enumerated from the `Request` enum rather than
grepped for, because "which requests carry an interface" is exactly the kind of
question a pattern answers about the shape it was given.

## Decision

**An interface name is validated as a name, at the point where it becomes a
path.**

`netcfgd_model::interface::usable_name` is `dev_valid_name` from the kernel's
`net/core/dev.c`, transcribed rather than approximated: non-empty, shorter than
`IFNAMSIZ`, not `.` or `..`, and free of `/`, `:` and whitespace. Agreeing with
the kernel is cheaper to keep true than a subset somebody has to reason about,
and the `/` and `..` clauses are the two that carry the security property.

**In `Client::connect_within`, not at the four call sites.** That is where the
name becomes a path, so it is where the guard cannot be forgotten by a fifth
caller -- and this crate is a library whose contract should be "an interface
name" rather than "whatever you have".

The refusal is `InvalidInput` and quotes the name back. Quoting what the caller
sent tells them nothing they did not already know; what they no longer learn is
anything about the machine.

## What this does not fix, and it is the same defect one tier up

**The compiler does not validate interface names at all.** Measured:

```text
device "../../etc/evil" { kind = "dummy" }   ->  plans link.create ../../etc/evil
device "aaaa...40 chars" { kind = "dummy" }  ->  plans link.create aaaa...
```

The kernel refuses both names, so the link never appears -- but a document name
reaches the filesystem in dozens of places before and around that: a pid file,
a generated config, a hook script, a lease script, a control socket. As root.
Documents are written by root or by an `admin`-tier caller over `ConfigPut`,
and this project records that **`admin` is not root and that is load-bearing**,
so that is a boundary and not a formality.

It is left here rather than fixed because it is a different entry point at a
different tier, and refusing a document is a compile-behaviour change that
wants deciding on its own terms. `usable_name` is the function it would use;
`netcfgd-compile`'s private `IFNAMSIZ_MAX` is half of the same rule and would
fold into it.

## Consequences

- `usable_name` returns `&'static str`, matching `wifi_profile::usable_id`.
  That is not only tidiness: with `String` the fix pushed the release binary
  4096 bytes past its size ceiling, and `&'static str` put it back to the byte.
  `escape_debug` and its Unicode tables were the suspect and, measured, cost
  nothing.
- The length message spells `15` out, since there is nothing to interpolate
  into, so a `const _: () = assert!(IFNAMSIZ_MAX == 15, ...)` beside the
  constant keeps the two copies honest. Verified by changing it to 16 and
  watching the build refuse.
- `tests/live/remote_socket.sh` becomes `tests/live/control_exposure.sh`: it
  now covers two findings about what the control sockets expose to a local
  caller, and the old name described one of them.
