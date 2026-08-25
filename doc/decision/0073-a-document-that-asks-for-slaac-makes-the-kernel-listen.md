# 0073: a document that asks for SLAAC makes the kernel listen

Status: accepted
Date: 2026-08-03
Milestone: the laptop list, and the one item on it a router hits harder

## Context

`net.ipv6.conf.<iface>.accept_ra` has three values and the default is the one that
reads as safe and is not:

```
0  never act on a router advertisement
1  act on one unless this interface forwards      <- the kernel's default
2  act on one even when this interface forwards
```

So `config = "slaac"` on an interface that forwards obtains **no address at all**.
The document asked for something, `ncfg apply` succeeded, `ncfg status` showed a
link-local and nothing else, and nothing anywhere said why. That is every router's
WAN, and it is also every container -- a container image usually arrives with IPv6
forwarding on whether anybody wanted it or not.

It is written down in this repository already, in a comment in
`tests/live/delegation.sh`: *"an environment that starts with forwarding on -- a
container usually does -- makes the kernel ignore every advertisement while
`ip addr` shows nothing to explain it. That cost an hour."* The test worked around
it. netcfgd did not know about it.

This is [0061](0061-a-key-that-compiles-does-something-or-says-it-does-not.md)'s
disease in its worst form. `slaac` is not a key that compiles and does nothing --
it compiles, does the right thing on a laptop, and does nothing on a router.

## Decision

**netcfgd writes `accept_ra` where a document asks for SLAAC and the kernel would
otherwise ignore the advertisement**, and nowhere else.

- **Only where it would be ignored.** An interface that already acts on
  advertisements is left alone, so an ordinary laptop has no sysctl written and no
  line in its plan. Writing `2` everywhere would have been simpler to describe and
  would have touched a sysctl on every machine to change nothing.
- **`2`, not `1`.** `1` is what is already there and is what does not work; and
  netcfgd may itself turn forwarding on for the same interface, which would make a
  `1` written here untrue a moment later.
- **Never `0`.** Switching advertisements off is a thing an operator may have
  chosen and no document here asks for. The same rule
  [0062](0062-a-blocked-radio-is-reported-and-not-unblocked.md) applies to a
  radio: netcfgd does not correct a switch nobody asked it to touch.
- **Handed back only where netcfgd wrote it.** An interface that stops asking for
  SLAAC gets `1` -- the kernel's own default -- and an interface netcfgd never
  wrote is left exactly as it is, `0` included. The record is a list of names in
  `/run`, the same one `privacy_applied` is, so "back" can only mean the default:
  netcfgd does not record the value it found. That is a limit, and it is written
  here rather than left to be discovered.

**And it is written before `link.up`, which is not tidiness.** The kernel decides
whether to solicit a router when the interface comes up, and **it does not solicit
on an interface whose advertisements it would ignore** -- so a sysctl written
afterwards leaves the interface waiting for the router's own unsolicited timer.
Measured: flipping `accept_ra` on a live interface produced an address **14.2
seconds** later, against a dnsmasq told to advertise every five, and a real router's
`MaxRtrAdvInterval` runs to minutes. So the pass moved ahead of the one that emits
`link.up`, and the live test asserts the two lines in that order rather than
trusting it -- a `depends_on` edge with no assertion on it is decoration, which this
repository has already paid to learn.

**The warning that used to be here is gone.** `plan_interface_contents` warned that
an interface "both forwards and asks for slaac ... and netcfgd does not manage that
sysctl -- set `net.ipv6.conf.<iface>.accept_ra=2`". True when it was written and
false the moment this landed. It was also reading the *document's* `forwarding`
field, so it never fired for the commonest case of all: a container that forwards
without anybody asking it to. Nothing was testing it. Grepping for the sentence that
wrote down a gap, when the gap is closed, is the habit project.md section 10 asks
for -- and this is the fourth time it has found something.

**The reading is two files, and neither answers alone.** `accept_ra` on its own is
the same value on a working laptop and a broken router. So the observation carries
both halves -- the value, and whether an advertisement would actually be acted on
-- computed in the observer where both are already in hand. Only the answer
travels, which is the rule every comparison in this project has had to learn
([0052](0052-a-daemon-is-compared-to-what-it-was-started-with.md) onwards).

The forwarding read for this is the **IPv6** one alone. `ObservedLink::forwarding`
is `Some(true)` only when both families forward, which is the right answer to a
different question: a machine with IPv6 forwarding on and IPv4 off ignores
advertisements while that field says `false`.

## What the test is worth

`tests/live/slaac.sh` puts a real dnsmasq on the far end of a veth pair, advertising
a prefix, and an interface that forwards on the near end. `privacy.sh` deliberately
does not wait for an address -- there the sysctl is all netcfgd owns -- and here the
address is the whole point, because the defect is that it never arrives.

The netcfgd half deliberately starts with the interface **down**, so netcfgd is what
brings it up: that is the ordinary path, and the one where the ordering above
matters. Putting the sysctl back after `link.up` fails the ordering assertion and
*passes* everything else, which is exactly why the assertion is there.

**The negative check needed the wire proved first.** "No address arrives at
`accept_ra 1`" is satisfied by nothing advertising at all, and that is exactly what
happened on the first run: dnsmasq had exited at startup and the check passed for
the wrong reason. So the script sets `accept_ra=2` by hand first, watches an
address arrive, and only then puts the sysctl back and asserts the address does
*not* return -- waiting twice as long as the arrival took, which is the
self-calibrating bound `dhcpcd.sh` needed for the same reason
([0072](0072-dhcpcds-own-hooks-are-replaced-or-silenced.md)).

**And dnsmasq will not start under `unshare -rn`.** It drops privileges at startup,
and an unprivileged gid mapping writes `deny` to `/proc/self/setgroups`, so
`setgroups` fails and it exits before it advertises anything -- with the reason in
its log file and nowhere else. The script makes its own namespace, exactly as
`dhcpcd.sh` does for dhcpcd's privilege separation. That is two daemons in two days
that a single-uid namespace cannot run, which is worth knowing before writing a
third.

## Consequences

- `config = "slaac"` works on a router's WAN and in a container.
- A plan that writes it says which half is wrong: `accept_ra 1, and wan0 forwards
  -- advertisements ignored`. "accept_ra 1" alone reads as the state that works.
- A kernel with no `accept_ra` -- IPv6 disabled, or a container without
  `/proc/sys` -- is reported and not written to, the same answer `use_tempaddr`
  gives.
- The observed schema gains a field and the plan gains an op, so both witnesses
  moved and were blessed. Minor, not major: nothing that existed changed shape.
- `+4 KB`, ratcheted in `size-budget.txt`.

## What is still open

**`accept_ra_defrtr`, `accept_ra_pinfo` and the rest of the family are untouched.**
They are switches with defaults that work, and no document here asks anything of
them. This decision is about the one whose default is a trap.

**Nothing does this for `dhcp6`, and that was measured rather than assumed.** A
`DHCPv6` client solicits routers itself, in userspace, so the kernel's sysctl does
not gate it: `dhcpcd -6` on an interface with `forwarding=1` and `accept_ra=1` --
the exact state that leaves SLAAC with nothing -- took a lease from a real dnsmasq
in three seconds. So `config = "dhcp6"` is not covered here, and if some other
client ever turns out to depend on the kernel's own RA processing, this is the pass
that would grow the case.
