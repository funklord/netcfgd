# 0135: the kernel holds the ownership record

Status: accepted
Date: 2026-08-25
Milestone: M8; the second question out of the restart-without-dropping-the-link
requirement, after [0134](0134-an-unannounced-stop-holds.md)

## Context

[0134](0134-an-unannounced-stop-holds.md) settled that an unannounced stop
holds the network. That leaves the question it explicitly deferred: **holding
the network does not help if netcfgd cannot tell which parts of it are its
own.**

The record is `/run/netcfgd/owned.json` -- created links, addresses, routes,
backends, DNS scopes, sysctls netcfgd changed. The unit sets
`RuntimeDirectory=netcfgd`, and `systemd.exec(5)` says the default
`RuntimeDirectoryPreserve=no` means those directories "are always removed when
the service stops". **So every restart deletes it**, and the daemon that comes
back has the network but not the note.

## What was actually measured

A dummy interface, a static address and a default route, the daemon stopped,
`owned.json` deleted, the config changed to ask for neither, the daemon
restarted. Then the same run with the file left in place as a control.

| | address | route |
|---|---|---|
| record kept | removed | removed |
| record deleted | **held** | **held** |

**Under-claiming was the safe direction and it was not a working one.** A
netcfgd that cannot recognise its own work can never remove it either, so a
network deleted from the config stays on the machine for ever and `ncfg apply`
reports success having done nothing. That is the daemon quietly ceasing to
reconcile, which is what [0132](0132-netcfgd-applies-its-configuration.md)
exists to prevent. `read_owned`'s own comment called under-claiming "the safe
direction", and it is -- for a single apply. Across a restart it is a daemon
that has stopped working while reporting that it has not.

## The diagnosis, which was not where it looked

The first reading was that netcfgd fails to use the kernel tag it stamps. That
was wrong, and worth recording because the correct answer is one field over.

`address_ownership` is already tag-primary exactly as
[0002](0002-object-ownership-tagging.md) intended: where the
kernel supports `IFA_PROTO`, an address wearing 110 is `Ownership::Ours` and a
stale record cannot claim one back. Routes read `rtm_protocol` directly on
every supported kernel. **Ownership already survived the loss of `/run`.**

What did not survive is **`origin`** -- `Static`, `Dhcp4`, `Slaac`,
`Delegated`. It came only from the record, and every teardown path gates on it
*before* it gates on anything else:

    if !address.ownership.may_remove() { continue; }
    if address.origin != Some(Origin::Static) { continue; }

So the restarted daemon read the address as its own and then declined to touch
it, because with no record the origin was `None`. **It could tell the address
was its own and not that it was allowed to remove it.**

## Decision

**The kernel tag implies the origin, and `/run` becomes the fallback it was
always documented to be.**

Where nothing is recorded, an object wearing netcfgd's protocol tag is read as
`Origin::Static`:

    fn tagged_origin(proto: Option<u8>) -> Option<Origin> {
        (proto == Some(NETCFGD_PROTO)).then_some(Origin::Static)
    }

applied with `.or_else(...)`, so **a recorded origin always wins**. That is
what keeps it a fallback: a pre-5.18 kernel has no `IFA_PROTO` to read, and a
DHCP address recorded as `Dhcp4` stays `Dhcp4`.

### Why the inference is sound

**The tag has exactly one producer per object kind.** `Op::AddrAdd` is the only
call site of `add_address` in the tree, `Op::RouteAdd` the only call site of
`add_route`; both stamp `NETCFGD_PROTO` and both record `Origin::Static`. An
object wearing the tag was therefore put there by netcfgd from config, and
there is no other way for it to be wearing it. A lease's address belongs to the
DHCP client, which installs it itself under its own protocol number.

**That is a property of the tree, not of the function that depends on it**, so
it is asserted by `tool/tag_producer_gate.py` rather than believed. A second
producer -- an address built from a delegated prefix, a route some future
backend path installs -- would wear the same tag, be read back as static, and
let the planner remove somebody's lease to satisfy a config that never asked
for it. Nothing in `tagged_origin` would look wrong; it would simply have
stopped being true. The gate fails on a second call site and on a call site
that stops recording `Origin::Static`, and both were verified by making each
happen.

### And the record is kept across a restart anyway

`RuntimeDirectoryPreserve=restart` in the unit. Not because the above needs it
-- `tests/live/adopt.sh` runs the whole cycle with the file deleted -- but
because the record still carries everything the kernel has nowhere to stamp:
which sysctls netcfgd changed, which links it created, which DNS scopes it
delivered. Losing those means netcfgd stops putting them back, which holds
rather than breaks, and is avoidable across a restart.

`restart` rather than `yes`, so a deliberate stop still cleans up. An operator
stopping the service is not mid-upgrade, and a directory left behind for ever
would make a reboot look like a restart.

## The reboot case answers itself

Recorded because it was flagged as "the same question in its hardest form" and
turned out to be the easiest. After a reboot `/run` is empty **and so is the
kernel state**: no addresses, no routes, nothing to own. Both sides are cleared
together, consistently, and the machine is a cold start with nothing to adopt.

**The dangerous case was only ever the restart**, where the kernel state
survives and the record does not -- which is precisely the asymmetry this
record removes.

## What is still not derivable, and what that costs

| | evidence | survives a wiped `/run`? |
|---|---|---|
| routes | `rtm_protocol`, every supported kernel | yes |
| addresses | `IFA_PROTO`, 5.18 and up | yes |
| backends | pid file plus `/proc/<pid>/cmdline` | **no, as written -- see below** |
| addresses, pre-5.18 | the record | no |
| created links | the record | no |
| sysctls: forwarding, privacy, `accept_ra` | the record | no |
| DNS scopes, qdisc, ingress | the record | no |

### Corrected, 2026-08-26: the backends row was false, and it was a vacuous pass

**This table said backends survive a wiped `/run` and cited `revive.sh` for
it. Both halves were wrong**, and the citation is the part worth dwelling on:
`revive.sh` kills the supplicant and removes its *control socket*, leaving the
pid file in place. That is 0080's dead-supplicant case. `adopt.sh` removes
only `owned.json`, again leaving the pid file. **No test in the suite deleted
the pid file while the process lived**, which is the one thing the row claimed
to be safe -- so the row was evidence-free in exactly the way `evidence.md`
warns about, and I wrote it.

The mechanism the row got wrong: a pid file is not a mark on an object, it is
a **handle to a live process**, and it lives in the directory
`RuntimeDirectory=` deletes. The process survives the stop (0134 wants that);
the handle does not. netcfgd then cannot recognise its own supplicant,
`start_supplicant` falls through to the foreign-supplicant refusal, and it
blames NetworkManager for a process it started itself -- for ever, because the
error returns before the restart counter is touched so 0079 never gives up
either.

Measured on a real machine: an orphaned supplicant and an orphaned `dhcpcd`
fought NetworkManager for one radio, the DHCP client taking a fresh lease
roughly once a minute and consuming thirteen addresses.

**Fixed in [0140](0140-a-handle-must-be-recoverable-from-the-process.md)**, and
`tests/live/orphan.sh` is the test this row should have had.

**The residue fails toward holding, which is 0134's direction**, so none of it
is a hazard: netcfgd leaves a sysctl set rather than putting it back. It is a
leak rather than a fault, and it is bounded by
`RuntimeDirectoryPreserve=restart` in the case that matters.

### Corrected, 2026-08-25: the table overstated two rows and understated one fix

**DNS is not residue at all.** The table lists DNS scopes beside the sysctls as
something netcfgd stops putting back, and there is nothing to put back:
`Op::DnsApply` is the only DNS operation in the tree and there is no teardown
path. `observed.dns` is an idempotence check, not an ownership check, so losing
it costs one identical rewrite of a file netcfgd was going to keep writing
anyway. It was grouped with the sysctls because it sits beside them in
`OwnedState`, which is a fact about a struct rather than about behaviour.

**`RuntimeDirectoryPreserve=restart` was not the systemd-only patch this record
treated it as.** Neither the OpenRC script nor the procd one removes
`/run/netcfgd` -- OpenRC creates it in `start_pre` with `checkpath`, procd with
`mkdir -p` in `start_service`, and neither has a stop hook that touches it. So
systemd was the *only* init deleting the record, and fixing systemd closes the
restart exposure everywhere rather than on one init.

**Which leaves the sysctls, qdisc and ingress, and their exposure is smaller
than it looked.** They are genuinely not derivable -- a value has no field to
stamp and no property list to mark -- but the two cases now both answer:

- **A restart keeps the record** on all three inits, as above.
- **A reboot clears both sides together.** Sysctls return to their kernel
  defaults and a qdisc goes with the link it was on, so a netcfgd that has
  forgotten it set forwarding is running on a machine where forwarding is no
  longer set. The same symmetry that makes the reboot case safe for addresses.

`tests/live/sysctl.sh` holds this still. It asserts the door closes with the
record intact, **and asserts the limit** -- that with the record gone netcfgd
plans nothing and leaves the sysctl alone. Both directions were verified by
breaking them: forgetting the record fails the first, and reverting regardless
of ownership fails the second. If a later change makes netcfgd revert an
unrecorded sysctl, that test fails and the change gets read against 0134 before
it ships.

**A kernel-visible marker for created links is the obvious next step and is not
taken here.** An altname would do it, and adding one is a change to what
netcfgd puts on the machine rather than to how it reads it back. Worth its own
decision, not this one's tail.

## Consequences

**`/run` is genuinely derived again.** Constraint 1 says runtime state is
derived and disposable, and before this the sentence was aspirational for
addresses and routes: deleting the file changed behaviour. It no longer does
for the two categories that carry a tag, which is most of what a machine has.

**The tag is now load-bearing in a second way.** 0002 chose it so that
ownership would be legible without netcfgd running; it now also carries origin.
The `rt_protos.d` file that makes `ip route show` print `proto netcfgd` is
worth more than it was.

**A future producer of tagged objects has a gate in its way**, which is the
intended cost. Anything that installs an address or route wearing netcfgd's tag
must decide what origin it implies, and cannot avoid deciding.

## Alternatives considered

**Preserve the record and stop there.** Rejected as the whole answer, though it
is kept as part of one. `RuntimeDirectoryPreserve=restart` is systemd's alone,
and netcfgd ships OpenRC and procd scripts that manage the directory
themselves; a correctness property that holds on one init and not the others is
not a property. It also does nothing for a record lost any other way.

**Persist the record outside `/run`, in `StateDirectory`.** Rejected, and it is
the tempting one. It would survive a reboot -- and surviving a reboot is
exactly wrong: the kernel state is gone, so a persisted record claims ownership
of objects that no longer exist, and the first thing it can do is match a
stale claim against an identical address some other tool installed since. It
also makes runtime state authoritative, which contradicts constraint 1 rather
than satisfying it.

**Re-derive origin by matching the observation against the config.** Rejected.
An address the config asks for is static by construction, but the case teardown
cares about is the address the config *stopped* asking for, which by definition
matches nothing -- the derivation is empty in exactly the case that needs it.

**Treat a tagged object with no recorded origin as removable regardless of
origin.** Rejected: it drops the distinction 0006 rule 7 depends on, and a
DHCP address whose record was lost would be removed by the planner rather than
withdrawn by its client.
