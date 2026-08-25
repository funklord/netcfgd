# 0100: `kill -0` calls a zombie alive

Status: accepted
Date: 2026-08-04
Milestone: what running the suite on Alpine found

## Context

[0099](0099-a-package-installs-netcfgd-and-changes-nothing.md) built an apk and
closed by saying what it had not done:

> Nothing here has been evaluated on Alpine beyond installing. No live test has
> been run on musl, and the suite's namespace tests have never executed there.

Running them found one defect, and it is not on musl and not on Alpine.

netcfgd builds and its 696 unit tests pass under Alpine's rust against musl.
The live suite passes too — with one script failing every run after the first:

```
FAIL a daemon stopped before it could listen is stopped anyway
       pid 378 is still running, and netcfgd said:
       ok   backend.stop vpn0  openvpn: <absent> (was OpenVpn)
```

netcfgd said it stopped the daemon and the script said the pid was still there.
One of them was wrong.

**netcfgd was right.** Running the same container with a reaping pid 1
(`docker run --init`) makes all five runs pass, which says the subject is not
musl but **what happens to a dead process nobody reaps**. A daemon netcfgd
stops is a child of a short-lived `ncfg apply`, so it is orphaned to pid 1 —
and a container's pid 1 is whatever the image was told to run. A shell never
reaps, so the process stays a zombie: dead, with its pid and its `/proc` entry
intact.

`kill -0` reports a zombie as alive. Measured:

```
/proc/<pid>/cmdline: b''
/proc/<pid>/stat:    b'... (sleep) Z ...'
kill -0 says:        alive
```

netcfgd's own liveness check reads `/proc/<pid>/cmdline` and asks whether that
pid still names this daemon (0078). A zombie has no command line, so netcfgd
answers "not running" — **correct by construction**, and it had been correct all
along.

`delegation.sh` had already worked this out and written it down, in its header
and beside its own check. Nothing swept the other scripts.

## Decision

**A live script asks `/proc/<pid>/cmdline`, never `kill -0`.**

Seven scripts changed: `openvpn.sh`, `dot1x.sh`, `dhcp.sh`, `dhcpcd.sh`,
`slaac.sh`, `pppoe-session.sh`, `helper.sh`. Each gets the predicate inline
rather than in a shared file, because a live script here is deliberately
self-contained — it is the unit somebody runs by hand.

**The wrong answer goes in both directions, and one of them is worse.** Four of
the seven assert a process is *gone*, where a zombie is a false failure — loud,
and what was found. Three assert a process is *alive*:

- `pppoe-session.sh` checks that netcfgd left somebody else's `pppd` alone;
- `slaac.sh` checks the test's own router came up;
- `helper.sh` checks the modem monitor is still running.

Those are children of the script, which become zombies between being killed and
being waited for — so `kill -0` would answer "alive" for a process that
something had wrongly killed. **That is a false pass on exactly what the check
exists to catch, and it does not need a container to happen.** None of the three
was observed failing, which is the point: nothing would have.

**The guard is not decoration.** `/proc/0` does not exist, so a predicate that
only asks about `/proc` answers "not running" for a pid that was never captured
— and every "is it gone?" check passes vacuously. `delegation.sh` says this
already; `dhcp.sh` had no such guard and has one now, reported as a failure with
its own sentence rather than folded into the answer.

## What building it found

**`< /proc/<pid>/cmdline` is not the same as `cat ... 2>/dev/null`.** The first
version used a redirection, and when the file is absent it is the *shell* that
complains — its message does not go through the `2>/dev/null` attached to the
command. `slaac.sh` printed `cannot open /proc/1624650/cmdline: No such file`
into the middle of its own output. `delegation.sh` had used `cat` and this had
copied the idea rather than the line.

## The gates

The suite, on both distributions, with **no reaping init** — which is now the
hostile case rather than an accident:

- Alpine, musl, busybox `ash`, in a container whose pid 1 is a shell: **23
  passed, 0 failed, 13 skipped**. Every skip is a package the image does not
  have.
- Debian, glibc, dash, on the host: the affected scripts pass, and `slaac.sh`
  fails for a reason older than this change (dnsmasq does not start in this
  machine's namespace) with its output no longer corrupted by shell errors.

The break: put `kill -0` back in `openvpn.sh` and the named check goes red
again, in the container, on the first run.

## What this does not change

netcfgd. Not one line of the daemon moved: the code this went looking at turned
out to be right, and the tests were wrong about it. Worth stating plainly,
because a suite that fails on a new platform reads like a port being needed.

## What is left on Alpine

Thirteen scripts skip on packages the image lacks — hostapd, wpa_supplicant,
dnsmasq, openvpn, dhcpcd, ppp, wireguard-tools, nmcli, odhcp6c. They are skips
rather than failures, and this ran with the ones Alpine does have. Installing
the rest is a bigger image and a longer run, not a different decision. The skip
messages still name Debian packages, which is now advice given on a machine
where it is wrong.
