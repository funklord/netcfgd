# 0264: the dhcpcd hook is dhcpcd's requirement and not every client's

Status: accepted
Date: 2026-10-03
Milestone: M9. Refines
[0178](0178-a-generated-hook-cannot-live-where-it-cannot-run.md), which stands
in substance; what moves is where its refusal is asked.

## The defect

0178 made netcfgd refuse to start a DHCP client when its shipped hook is
absent, because a lease whose nameservers cannot be reported writes a resolver
that resolves nothing, and 10.68 is what that cost on a real machine. The
refusal is right. It was placed above the code that decides *which* client to
use:

```quote from=crates/netcfgd-apply/src/kernel.rs
The hook is dhcpcd's requirement and not every client's
```

`start_backend` for `Dhcp4` tries three candidates in turn -- `dhcpcd`,
`udhcpc`, then `busybox udhcpc` -- treating `NotFound` as "try the next". The
hook was demanded before any of that, with `?`, so **a machine with busybox and
no dhcpcd could start no v4 client at all**, and failed naming a file it would
never have used:

    FAIL backend.start cli  addressing[0]: Dhcp4
         the dhcpcd hook is not installed at /usr/libexec/netcfgd/dhcpcd-hook

That population is not hypothetical: it is the one
[0065](0065-udhcpc-needs-a-script-and-netcfgd-writes-it.md)'s fallback
exists for, and the reason the fallback exists at all is that Debian ships
busybox as one binary with no `udhcpc` symlink beside it.

## Decided

**dhcpcd is offered as a candidate only where its hook can be found**, and the
other two are offered regardless. A tree without the hook therefore gets a
working client rather than a refusal.

**Skipping dhcpcd is said out loud**, at warning, naming the reason. 0178's
entire cost was that nothing said anything, and a machine that quietly stopped
using the client its operator installed is that same fault wearing the other
shoe.

**The refusal still arrives where nothing else could be used.** When no
candidate starts, the message carries both halves -- that udhcpc and busybox
are not installed, *and* why dhcpcd was not used -- because a dhcpcd-only
machine, which is most of them, would otherwise be told to install a client it
already has.

**The `Dhcp6` arm keeps its unconditional `?`**, deliberately. There dhcpcd is
the only client there is, so demanding its hook before anything else is
demanding the only thing that could work.

## What found it, and what it says about the suite

`tests/live/dhcp.sh`, which builds a PATH with every dhcpcd removed precisely so
that it drives the client it is written for. It had been failing with
`apply failed` since 0178 landed, and nothing noticed because `make live` halts
at its first failure and the four scripts before this one were failing for their
own reasons (10.160).

So the test was right the whole time and the product had regressed under it.
Proven by sabotage: restoring the unconditional demand turns `dhcp.sh` red again
and takes exactly one of `exec_refused.sh`'s two new checks with it -- the one
asserting the *combined* message, since the old message mentioned the hook too.
That is the check doing the discriminating.
