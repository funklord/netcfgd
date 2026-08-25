# 0078: a record is a memory, and a process is a fact

Status: accepted
Date: 2026-08-03
Milestone: the question 0071 and 0074 both left open

## Context

`ObservedBackend::running` came from `/run/netcfgd/state.json` -- netcfgd's own
record of what it started -- and nothing ever checked it against the machine. So a
daemon that **died on its own** was invisible:

- a tunnel killed by the OOM killer, or by an operator, or by a crash;
- an odhcp6c that exited when its interface went away;
- a radvd that failed on a `SIGHUP` after a renumbering.

In every case the record still said `running: true`, the planner asked
`backend_running`, got `true`, and had nothing to do. **A document saying the
tunnel should be up, a machine where it is not, and a reconciler reporting
convergence.**

[0071](0071-a-client-with-no-socket-is-stopped-by-the-pid-it-wrote.md) named it
("nothing notices a daemon that died on its own"),
[0074](0074-a-daemon-that-cannot-answer-is-still-running.md) sharpened it -- netcfgd
now *has* a pid for a tunnel, which is the thing an observation would need -- and
noted that what it did not have was any pass that looks. This is that pass.

It is the fourth answer to the question section 10 keeps finding new places to ask.
The first three compared a daemon to the file it was started with (0052), a kernel
object to what the kernel reports (0054), and a secret to its digest (0055). This
one asks something simpler and, it turns out, more basic: **is it still there at
all?**

## Decision

**The observation checks the pid of every backend it can, and only those.**

`netcfgd_apply::backend_pid_file(kind, run, iface)` says where a daemon of that
kind records its pid and what marks the process as being that daemon -- in the
crate that *starts* them, because "how do I find this one" and "how do I start
one" are the same knowledge. The observer asks it, then asks
`netcfgd_sys::process::pid_of`, and clears `running` when the file names a process
that is gone or is somebody else's. The planner already restarts a backend that is
not running; nothing there changed.

**`None` is not `false`, and here that rule is load-bearing rather than tidy.**
Two kinds have no handle:

- **A `DHCPv4` client may be dhcpcd**, whose pid file lives in dhcpcd's own
  compiled run directory rather than anywhere netcfgd chose. Where netcfgd runs
  udhcpc there *is* a file, so the same `BackendKind` answers differently by
  machine -- and reading "no file" as "not running" would start a second dhcpcd
  beside a perfectly live first one, on every machine that uses one.
- **A supplicant and an access point** are reached through control sockets, and a
  socket that exists does not prove a process does. Asking one costs a round trip
  in the reconcile loop, which is what `acl.sh` already measures a deadline for.

So a missing handle, and a missing file, both leave the record exactly as it was.
That is the third session in a row where this rule has decided a design, and the
first where getting it wrong would have started a duplicate daemon rather than
merely reporting badly.

**One rule for ownership, in one place.** `pid_of(path, marker)` reads the pid,
reads `/proc/<pid>/cmdline` NUL-separated, and requires `marker` to be a whole
argument. It replaces four hand-written copies -- pppd's, radvd's, the DHCP
clients', and the tunnel's from 0074 -- which is not tidiness either: this check
is what stands between netcfgd and signalling a process somebody else started, and
four copies is how two of them come to disagree about what counts as ownership.

The marker is as specific as each caller can make it, and the doc comment says so:
a path netcfgd chose (a management socket, a generated configuration, an options
file) is unique to one daemon on one machine, while an interface name is a short
string an unrelated command line could contain and is what to use only where there
is nothing better -- which is the case for `udhcpc -i eth0` and `odhcp6c ... eth0`.

## What the test is worth

`tests/live/openvpn.sh` kills the tunnel with `SIGKILL` -- deliberately, because
what is under test is netcfgd noticing something it did not do, and because a
`kill -9` gives openvpn no chance to remove its own pid file:

```
ok   the tunnel is up and netcfgd has nothing to do
ok   the pid file outlived the process, which is why it is checked
ok   netcfgd notices the tunnel is gone
ok   and starts it again
ok   and then there is nothing to do again
```

The second line is the one that makes the rest mean something: the file is still
there, so a check that trusted its existence would report a running tunnel. And
the last line is the idempotence half -- a pass that noticed a dead daemon and
then kept restarting a live one would be worse than the defect.

Removing the pass fails the third and fourth, and prints what an operator would
have seen: `was 811055, now 811055` beside `nothing to do`.

## Consequences

- A daemon that dies is restarted on the next reconcile, which is what a
  reconciler is for. On a machine running the netcfgd daemon that is within
  seconds; with `ncfg apply` it is the next apply.
- **The pid check runs on every observation**, which is every netlink event. It is
  two file reads per backend that has a pid file -- no round trips, nothing that
  can block. That was a deliberate constraint: the hostapd ACL read is the one
  observation that asks another process, and it needed a deadline and a decision
  record of its own.
- `+0 KB`.

## What is still open

**A supplicant and an access point are still unchecked**, for the reason above.
The handle exists -- hostapd takes `-P`, and netcfgd could pass it -- so this is a
decision waiting to be made rather than a thing that cannot be done: whether the
observation should hold a pid for a daemon it currently reaches only through a
socket.

**A daemon that is alive and wedged is still "running".** The pid says the process
exists, not that it is doing its job. That is the shape 0052 answered for
configuration and nothing answers for behaviour -- and a health check in the
reconcile loop is exactly the round trip this pass avoided.

**Restarting is unconditional.** A tunnel whose daemon exits immediately -- bad
credentials, a server that is gone -- is restarted on every reconcile, forever.
Nothing here backs off, and the first time somebody notices will be a log full of
starts. A backoff needs state, and state needs a decision about where it lives.
