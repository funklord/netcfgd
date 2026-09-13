# 0224: a pid is not a liveness test

Status: accepted
Date: 2026-09-13
Milestone: M9; the wifi supplicant control socket audit

## What was already right

This module is careful, and most of the classic faults are already closed. The
reply-socket confusion of 0112 -- another client's `PING` landing in a reply
queue and being returned as an answer -- is handled by `is_reply_socket`. Event
interleaving, which is *the* classic bug in a wpa_supplicant client, is handled
in `request`: events are skipped rather than returned as the answer to a
command, with a deadline so a talkative radio cannot hold a caller for ever.
`Drop` sends `DETACH` rather than asking for it, because cleanup that can block
is worse than cleanup that can be missed. A command containing a newline is
refused as a backstop against a second, unreviewed command.

Two things were wrong, and the first had been sitting on the reporting machine
in plain sight for three days.

## /proc says a reused pid is alive

`reap_reply_sockets` removes reply sockets left behind when `Drop` does not run
-- which is every `SIGKILL` and every default-disposition `SIGTERM`, so it is
the ordinary case rather than the exceptional one. It decided what was dead by
asking whether `/proc/<pid>` exists.

A pid is a name that gets reused. Found in `/run/wpa_supplicant`, seven days
into a boot:

```text
srwxrwxr-x root root Sep 10 22:43 netcfgd-8-0
srwxrwxr-x root root Sep 10 22:43 netcfgd-8-1
$ ps -p 8 -o comm=
kworker/R-netns
```

Three days old, no owner, and skipped by every reap in between -- the daemon had
restarted many times, running this function on each start. `/proc/8` exists,
because pid 8 is a kernel thread, so the reaper concluded the creator was alive
and moved on. It will conclude that until the machine reboots.

The function's own documentation had predicted this and filed it as acceptable:
*"A pid that has been reused by an unrelated process leaves its socket in place.
Wrong in the direction that costs one stale entry rather than one live
connection."* The cost is not one stale entry. **The pids most likely to be
reused are the low ones, which belong to kernel threads that live as long as the
boot** -- and netcfgd's own live tests run it in a pid namespace, where it gets
exactly those numbers. A low-pid socket is not unlikely to be missed; it is
guaranteed to be.

## Ask the kernel, which knows

"Does anyone have this address open" is a question the kernel answers directly.
Connecting to a unix datagram address gives `ECONNREFUSED` when nobody has it
bound. Measured against the three real cases on the reporting machine:

```text
netcfgd-8-0          ECONNREFUSED   nobody has it bound     -> remove
netcfgd-4026892-1    EPERM          bound, connected to a peer
wlp0s20f3            connects       bound and unconnected
```

`EPERM` is the kernel refusing to connect a datagram socket to one that is
already connected somewhere else, which every live reply socket is. So the live
case answers *loudly* rather than by the absence of an error -- which matters,
because a reaper that removed everything it could not connect to would take
every live client on the machine.

The predicate is `nothing_is_listening`, which already existed in this file,
already meant exactly this, and was used by two other callers and not by the
reaper. Anything it does not recognise leaves the file alone.

Dropping `/proc` also removed the guard that existed because of it: the old
version refused to act at all where `/proc` was not mounted, since there the pid
test would have called every process on the machine dead and deleted every live
client's socket. There is nothing to guard now.

## A datagram is truncated silently

`recv` into a buffer smaller than the datagram keeps what fits and discards the
rest, with no error and no flag. The real length is only available through
`MSG_TRUNC`, which std does not expose and which would cost the `unsafe` this
file's header promises not to use.

So an oversized `SCAN_RESULTS` comes back as a shorter list of access points,
the last row cut mid-field, and nothing says the list is incomplete. **A network
missing from a scan because it was truncated off the end looks exactly like a
network that is not there** -- and that is the same silence this crate keeps
writing comments about, one layer down.

Measured against wpa_supplicant 2.10 on the reporting machine, largest first:

```text
GET_CAPABILITY freq       1647 bytes
STATUS                     359
GET_CAPABILITY channels    297
SCAN_RESULTS               110   (one access point in range)
```

8192 is comfortable for all of it, and `SCAN_RESULTS` is the one without a
bound: a row is roughly 70 to 110 bytes, so the buffer holds something like
seventy-five to a hundred access points. Whether the supplicant's own reply
buffer caps it lower first is a property of *its* build, and netcfgd cannot know
it -- which is the argument for detecting the case rather than for picking a
bigger number and hoping.

A reply that exactly fills the buffer is therefore treated as truncated. It
could be a genuine 8192-byte reply; that is far less likely than a cut one, and
an error somebody can see beats a scan list quietly missing its tail.

## The fixture that modelled the opposite of the thing

The existing reaper test bound a socket at `netcfgd-0-7` and called it the dead
one, because `/proc/0` never exists. **A socket left behind by a dead process is
a file with nothing bound to it** -- the opposite of what the fixture built. It
passed against the pid proxy and could not have passed against any test of what
was actually being asked.

Binding a `UnixDatagram` and dropping it gives the real article: closing does
not unlink the path. The test now uses that, and gained the two live shapes as
separate entries -- one merely bound, one bound and connected -- because they
produce different errno and both must survive.

This is the third fixture in three audits built from the code rather than from
the thing modelled (0222 had two). The pattern is worth naming: **when a test
constructs its subject by reading the implementation, it can only confirm the
implementation.**

## Sabotage

| reverted | test | result |
| --- | --- | --- |
| back to the `/proc/<pid>` proxy | `a_dead_socket_under_a_live_pid_...` | FAILED |
| reap anything that refuses a connect | `only_sockets_of_dead_processes_...` | FAILED |
| accept the truncated reply | `a_reply_that_fills_the_buffer_...` | FAILED |

The third of those was written only after the first sabotage run found it
missing: the truncation check shipped for several minutes with nothing holding
it, which is the fault 0222 had just recorded about somebody else's fix.

## The gates were reaching into the running machine

The plan was to leave the two stale sockets in place so that installing the
build would test the fix against evidence predating it. **They were gone before
the install**, and finding out why is the rest of this record.

A planted socket -- bound and closed, under pid 1, so only the new reaper could
remove it -- was run past each gate in turn:

```text
adapters     survived      footprint    survived
conformance  survived      linkage      survived
client-test  survived      gui          REAPED IT
rss          REAPED IT
```

Two gates start a real `netcfgd`. Both give it `--config-dir` and `--run-dir`
pointing into a scratch directory, which reads as complete isolation and is not:
**the wpa_supplicant control directory is a third path.** It defaults to the
host's `/run/wpa_supplicant`, and `NCFG_WPA_CTRL_DIR` exists precisely so a test
does not share it -- `ctrl_dir`'s own documentation says why, in as many words:
*"a network namespace is not a mount namespace, so without this a test would
share `/run/wpa_supplicant` with whatever the host is running."*

Neither gate set it. So a memory-measurement gate and a Qt test were reaching
into the running machine's directory twice over:

- **leaving reply sockets behind on every run.** The `kill` that ends the
  measured daemon is a SIGTERM, netcfgd installs no handler, so `Drop` never
  runs -- which is the same fact the reaper exists for, arriving from the
  gate's side.
- **sweeping the host's entries on startup**, which is what consumed three days
  of evidence during a run that was only supposed to be measuring how much
  memory the daemon uses.

The second half was invisible while the reaper could not identify a stale
socket. Fixing the reaper is what made it visible: a sweep that removes nothing
has no observable side effect, and one that works does.

Fixed by redirecting the third directory in `Makefile`'s `rss` recipe and in
both GUI tests, and verified the way it was found -- a witness socket planted in
the real directory, a full `make check`, entry count unchanged at five and the
witness still there.

**The shape is worth naming.** The isolation idiom in this tree is "set
`NCFG_CONFIG_DIR` and `NCFG_RUN_DIR`", it is written out by hand at each site,
and every site that wrote it missed the same third variable. Partial isolation
that looks total is worse than none, because nobody re-checks it.

## Demonstrated on the machine

```text
netcfgd: [supplicant] !: removed 5 reply socket(s) in /run/wpa_supplicant
                          left by processes that are gone
```

Five, including the one planted under pid 1 -- alive, and therefore
untouchable by the version this replaces. The live supplicant sockets were not
among them.
