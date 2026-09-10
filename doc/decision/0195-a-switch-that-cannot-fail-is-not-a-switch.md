# 0195: a switch that cannot fail is not a switch

Status: accepted
Date: 2026-09-10
Milestone: M8; reported as "switching is still completely broken"

## What was measured

Two switches on the reporting machine, both of which the script called
successful.

**To netcfgd.** `netcfgd_select.sh netcfgd` printed

```
netcfgd_select.sh: netcfgd is now this machine's network daemon
```

at 20:33:08. The lease arrived at 20:33:20. **Twelve seconds** in which the
sentence was false.

**To NetworkManager.** The same line at 20:38:07. The machine then had **no
default route until 20:51:08 -- thirteen minutes** -- and what ended it was a
person running `nmtui`:

```
20:50:57  agent-manager: agent[...,/nmtui/0]: agent registered
20:51:08  device (wlp0s20f3): Activation: successful, device activated.
```

NetworkManager was running the whole time. It had tried once, at 20:38:10, and
stopped:

```
Activation: (wifi) access point 'OpenPC.se' has security, but secrets are required
no secrets: No agents were available for this request.
state change: need-auth -> failed (reason 'no-secrets')
```

The profile carries `psk-flags=1`, which means the passphrase is agent-owned
rather than stored in it, so NetworkManager must ask a secret agent -- and
outside a desktop session there is none. **None of that is netcfgd's doing.**
What is netcfgd's doing is that the program which had just rearranged this
machine's networking announced success and exited 0, and nothing anywhere said
the machine was off the network.

## The two things that made it invisible

**The announcement was unconditional.** `bring_up` ran, and the next statement
printed "<manager> is now this machine's network daemon". That is a true
statement about a unit and says nothing about a network, which is the only
thing the person running it cares about.

**`run` swallows everything**:

```sh
run() { ... "$@" >/dev/null 2>&1 || true; }
```

Every `systemctl` in the script has its output discarded and its failure
ignored. That is deliberate and mostly right -- masking a unit that does not
exist, killing a pid that has gone, and removing a file that is not there are
all ordinary here. But it means no individual step can report anything, so the
outcome check is the *only* place the truth can come from.

## The rule

**A default route, and nothing else.** It is what was missing in both
measurements, it is what every manager in `unit_of` exists to install, and it
is the one fact that does not depend on which manager was selected.

A global address is explicitly not the test. `docker0` has one -- 172.17.0.1,
on this machine -- so "some interface has a global address" is true on a laptop
with no network at all, and a check that passes while the machine is offline is
worse than no check.

`confirm_online` waits up to `--wait-online=N` seconds, default 30, then says
what is true. On failure it names the primary unit's state, points at
`journalctl -u <unit>`, and **exits 1**. For NetworkManager it names the trap
that produced this decision, because a manager that is running and has
configured nothing is nearly always waiting for something it cannot ask for.

## Waiting, without starting the wait-online unit

0190 declined to start `<manager>-wait-online.service` from this script, on the
grounds that it blocks until the network is up and that is not what selecting a
daemon means. That still holds and this does not contradict it: that unit gates
`network-online.target` for the *next* boot and has no deadline of its own,
whereas this waits a bounded time and reports either way. `--no-wait` restores
the old behaviour for anyone who wants it.

## Verification

Six checks in `tests/live/select.sh`, in a fresh network namespace -- which has
exactly no default route until one is put there, making it the right place for
both halves.

Offline: the success line is **not** printed, "the network is not up" is, and
the exit status is 1. Online, after `ip link set lo up; ip route add default
dev lo`: the success line **is** printed and the exit status is 0. A default
route through loopback is a real default route, which is all this check claims
to read.

Both directions, because a confirmation that cannot pass is as useless as one
that cannot fail -- and the sabotage proves each is load-bearing: hard-wiring
the check true takes the three offline assertions red, hard-wiring it false
takes the two online ones red.

`select.sh` passes `--no-wait` everywhere else. Its namespace has no network by
construction, so without the flag every existing invocation would sit out the
deadline and then correctly report failure.
