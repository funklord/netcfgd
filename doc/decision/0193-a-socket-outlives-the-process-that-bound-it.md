# 0193: a socket outlives the process that bound it

Status: accepted
Date: 2026-09-10
Milestone: M8; found while auditing wifi roaming, in the directory the roam
watcher walks

## What was there

`/run/wpa_supplicant` on the reporting machine held twenty `netcfgd-<pid>-<n>`
reply sockets. Sixteen belonged to processes that no longer existed.

A datagram client must bind an address to be replied to, and it binds it in the
control directory because that is the one place both ends can write. `Drop`
removes it, and the comment on `Drop` has always said why:

```rust
// The bound path is a real file. Leaving it behind fills
// `/run/wpa_supplicant` with dead sockets, and the next reader of that
// directory cannot tell which are live.
```

The comment was right about the consequence and wrong about the mechanism being
sufficient. **netcfgd installs no `SIGTERM` handler**, so the default
disposition kills the process outright, nothing unwinds, and `Drop` does not
run -- and a `SIGKILL` would skip it even if a handler existed.

Measured rather than reasoned about: an ordinary `systemctl restart netcfgd`
took the directory from 18 entries to 20. **Two per daemon lifetime, for ever.**
Client requests do not leak -- two `ncfg wifi` calls left the count at 18 -- so
what survives is whatever was held at the moment the process was signalled.

## Why nothing had noticed

0112 taught every reader of that directory to skip these entries, because the
roam watcher used to connect to them and wait out its whole timeout against a
process that would never answer. That fix was correct and it made the litter
invisible to exactly the code walking past it. The watcher lists all twenty
entries on every pass and correctly ignores nineteen of them.

It is not a correctness fault. It is a runtime directory that only ever grows,
belonging to `wpa_supplicant` rather than to netcfgd, and "the daemon leaves
two files behind every time you restart it" is a thing somebody eventually has
to explain.

## Not a signal handler

The obvious fix is to catch `SIGTERM` and let `Drop` run. It is the wrong one
here, twice over. It does nothing for `SIGKILL`, a crash, or a test harness's
cleanup trap -- which is most of what was actually in that directory. And
netcfgd's shutdown is deliberately *not* a teardown: `KillMode=process` exists
so that `wpa_supplicant` and the DHCP client survive a restart with the
association and the lease intact, which they did while this was being tested.

A staleness rule covers every case the handler would and every case it would
not, in one bounded sweep, and needs no signal handling at all. Same shape as
the lock file's.

## The rule, and why it parses

`reap_reply_sockets(dir)` runs once, at daemon startup, before the watcher
starts listing that directory. Startup is the whole of the schedule: the set
can only grow when a process dies, and sweeping on each connect would be a
`read_dir` for every command netcfgd sends.

**Because it deletes, it parses rather than prefix-matches.**
`is_reply_socket()` is a prefix test and that is right for a reader deciding
what to skip; it is not enough for something removing what it finds. Five
things must hold:

1. the name is exactly `netcfgd-<pid>-<serial>`, both digits;
2. it is a socket, by `symlink_metadata` so a symlink is never followed;
3. the pid is not this process;
4. `/proc/<pid>` does not exist -- how the rest of this tree asks whether a pid
   is alive, and it needs no `unsafe`, so `client.rs`'s promise that there is
   none in it still holds;
5. `/proc/self` *does* exist.

**The last is the one that matters.** Without `/proc` mounted, rule 4 answers
"dead" for every pid on the machine, including the live ones -- and the reaper
would delete the reply sockets of running clients, which is the failure it
exists to prevent, committed wholesale. Where it cannot tell, it removes
nothing.

A pid reused by an unrelated process keeps its socket. Wrong in the direction
that costs one stale entry rather than one live connection.

## Verification

A unit test putting seven entries in one directory and asserting exactly one
comes out -- the dead one. The other six are each a way of being wrong: this
process' own socket, **a living process' socket** (pid 1), the interface socket
the directory is actually for, a regular file with a reply socket's name, a
name whose serial is not a number, and a bare prefix match with no serial.

Written as one directory rather than one case per run on purpose: what this has
to get right is not "does it delete" but "does it delete *only* that", and a
test with a single candidate cannot fail in the way that matters.

**The first version of that test was not evidence.** Removing the liveness
check entirely left it passing, because every entry in it was excluded by name,
by type, or by being ours -- the rule the whole function turns on was covered by
nothing. The pid 1 case is what makes the sabotage land, and it landed: 2
removed against 1 expected. Dropping the socket-type check removes the regular
file; replacing the parse with a prefix match removes two more.

Three checks in `tests/live/wifi_trouble.sh` cover the wiring, which a unit
test cannot see: two sockets planted before the daemon starts, one from pid 0
and one from pid 1, and the interface socket beside them. Removing the call
from startup takes the first red.
