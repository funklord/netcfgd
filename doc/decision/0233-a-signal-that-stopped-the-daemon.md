# 0233: a signal that stopped the daemon

Status: accepted
Date: 2026-09-14
Milestone: M9; reported fault

## What was reported

A machine switched wifi networks. `/etc/resolv.conf` still held the previous
network's settings and the GUI still showed the previous network as connected.

## What had happened

```text
11:11:35  netcfgd: [netlink] Error: netlink watch failed:
                   Interrupted system call (os error 4)
11:11:37  wpa_supplicant: CTRL-EVENT-CONNECTED ... EMP-XYLEM
11:11:46  dhcpcd: leased 10.78.60.134, adding default route via 10.78.63.254
```

Two seconds before the new association, a signal arrived while the netlink
socket was blocked in `recv`. `EINTR` means "call it again" and nothing else.
The watcher treated it as a failure:

```rust
Err(error) => {
    netcfgd_sys::log_error!("netlink", "netlink watch failed: {error}");
    return;
}
```

The thread returned, and with it went two things rather than one. netcfgd
stopped seeing kernel changes -- and because that same thread produced
`Command::Tick`, it stopped reconciling at all.

Fifty-two minutes later the process was still `active`, still answering client
requests, and had used **no measurable CPU** since. Its main thread sat in
`futex_wait`. `observed.json` was frozen at 10:26; `/run/netcfgd/dns/` still
held the values written on **10 September**. A plan run by hand was not empty:

```text
0  dns.apply  dns: write_resolv_conf (was <absent>)
1  dns.apply wlp0s20f3  dns: write_resolv_conf (was <absent>)
2  backend.stop wlp0s20f3  route.metric: 200 (was 100)
3  backend.start wlp0s20f3  route.metric: 200 (was 100)
```

netcfgd knew what to do and had no way left to notice it should.

**Why `ncfg wifi status` looked right.** It asks the supplicant over the control
socket rather than reading the observation, so it reported the new network
correctly while everything derived from the observation -- the GUI included --
was three days stale. The command that looked healthiest was the one that did
not depend on the broken part.

**Why the signal arrived.** netcfgd spawns children: `wpa_supplicant`, `dhcpcd`,
hooks. `SIGCHLD` is delivered to the process and can interrupt a blocking
syscall in any thread. There is nothing unusual about the moment it chose; it is
reachable whenever a child exits.

## The two fixes, because there were two faults

**`EINTR` is not a failure.** Fixed where the classification already lives.
`wait_for_change` had exactly this argument written for two other cases -- a
timeout becomes the caller's tick, and `ENOBUFS` becomes a *change* because "a
watcher that treated it as a failure would stop watching precisely when the most
was happening". A signal belongs in that company and was not in it. It is
reported as "nothing yet", the same answer a timeout gets, so the caller's
existing loop simply asks again.

Split into `change_from` so the classification can be asked without a socket,
which is what makes it testable at all.

**A backstop that the thing it backs up can switch off is not a backstop.**
`TICK_MS`'s own comment says the tick "catches anything neither netlink nor the
config watcher reports, and it is what makes a missed event cost seconds rather
than forever" -- and its only source was the netlink thread. The loop now takes
its heartbeat from its own wait, with `recv_timeout`, so no thread's death can
remove it. That also covers the case this fault never reached: if the netlink
socket cannot be opened at startup the thread returns immediately, and before
this the daemon would never have ticked at all.

The netlink thread still sends `Tick` on its socket timeout. Left alone: it
arrives before the loop's own deadline and costs nothing, and removing it would
be a change with no benefit to justify it.

## Sabotage

| reverted | test | result |
| --- | --- | --- |
| `EINTR` fatal again | `only_a_real_failure_is_reported_as_one` | FAILED |
| `ENOBUFS` demoted to "nothing yet" | `only_a_real_failure_is_reported_as_one` | FAILED |
| the loop waits for ever again | `the_loop_keeps_its_own_time` | **hung until killed** |

The third is the fault itself, reproduced in a test harness: with the deadline
taken out, the test does not fail, it stops -- which is what the daemon did.

## What this says about the audits

Eleven rounds of auditing wifi went past this. It is worth being clear about
why, because the answer is not "the area was not covered".

The netlink watcher is not wifi. Every round took a subject -- roaming,
scanning, the supplicant socket, passphrases, regulatory domains -- and read the
code that implements it. This is the loop those subjects are delivered *to*, and
nothing in a list of wifi topics names it.

The one round that came closest was the supplicant control socket (0224), which
found the same *shape* one layer over: `Err(_)` treated as "the supplicant went
away" when it could also mean "this message was too big". 0225 then split that
into "gone" and "unreadable" for the supplicant's socket and did not ask the
same question of the kernel's.

**The question that would have found it** is not about wifi at all: *which
threads must stay alive for this daemon to keep working, and what happens to
each if it returns?* That is a subject in its own right and has not been
audited.
