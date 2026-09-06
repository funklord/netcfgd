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

## The document is the other door, and it is now the same rule

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

This was recorded as open when the request half was fixed, and closed the same
day on the holder's instruction. `netcfgd-compile` refuses such a name with a
span, through the same `usable_name`, at every position a document names a
link: the `device` and `interface` labels, `master`, `iif`, `oif`, an access
point's `device`, the four `parent`/`dev` spellings, a veth `peer`, and each
word of a `members` list. Ten positions, enumerated from the model's fields
rather than found by pattern.

Nothing is refused that the kernel would have accepted, so no working
configuration changes; what changes is that a name the kernel would reject is
reported with a span instead of failing later with the name already joined into
half a dozen paths.

**A `members` word needed its own check.** A member with no `device` block of
its own gets a device synthesised for it, so a word in a list becomes a device
name -- which the control test found rather than the review. Every bad word is
reported rather than only the first; the span is the list's, because `as_words`
gives each word the value's span, so the diagnostic quotes the word instead.

**What is still not checked is whether a reference resolves.** `master = "brx"`
naming no declared device plans `link.set_master brx` as before. That is a
different question -- a name being well-formed against a name existing -- and
it wants its own record.

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
