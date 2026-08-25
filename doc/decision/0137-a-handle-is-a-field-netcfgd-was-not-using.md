# 0137: a handle is a field netcfgd was not using

Status: accepted
Date: 2026-08-25
Milestone: M8; the last two rows of the residue table

Finishes what [0135](0135-the-kernel-holds-the-ownership-record.md) started and
[0136](0136-a-link-carries-its-own-mark.md) continued: ownership that lives in
the machine rather than in a file a restart deletes.

## Context

The residue after 0136 was the sysctls, the root qdisc and the ingress
redirect. The sysctls are settled -- a value has nothing to stamp, the record
survives a restart on all three inits, and a reboot clears both sides together.

The `tc` objects looked like the same case and are not. **A qdisc has a handle,
and netcfgd was letting the kernel assign it.** The field was there, netcfgd
controls it, and it was carrying nothing.

The cost of leaving it that way is the shape the planner already names: a qdisc
netcfgd set and cannot prove it set is a one-way door. It stays installed, and
`ncfg apply` reports success having decided it may not touch it.

## Decision

**The root qdisc takes handle `6e:` -- major 110, minor 0.** The ingress
redirect's `matchall` filter takes handle `110`. Both are read back and merged
with the record.

That is the third and fourth use of 110, after `rtm_protocol` and `IFA_PROTO`
(0002) and the `netcfgd:` alternative name (0136). One number, four shapes,
greppable across the tree.

### The handle and not the priority

netcfgd's redirect filter takes priority 1 because a redirect that runs after
another filter has already stolen the packet does nothing. **That is a
correctness constraint**, and overloading it with a marker would trade it for a
bookkeeping one. A handle carries no ordering at all.

Measured rather than assumed: `matchall` takes a plain caller-chosen handle,
not `u32`'s `htid:hash:node` encoding. A 6.12 kernel reports it back as
`handle 0x6e`. The first version of this record said otherwise and was wrong.

### Merged with the record, not replacing it

`marked_or_recorded` takes the union, which is the difference from
`address_ownership`, where the kernel is authoritative and a stale record must
not be able to claim an address back.

**An unmarked address is legible and an unmarked qdisc is not.** An address
netcfgd did not install carries somebody else's tag or none, and both say
"not ours". An unmarked qdisc is ambiguous: somebody else's, or one an older
netcfgd installed before it stamped handles. Dropping the record would make
every one of those foreign on the day this ships, and netcfgd would stop being
able to reset a qdisc it had set itself.

## What it cost, which is the part worth reading

**Naming a handle breaks changing the scheduler in place**, and this was found
by the change failing six checks in `qdisc.sh` that had nothing to do with
ownership.

Naming a handle turns `NLM_F_REPLACE` into a change of the qdisc already
wearing it, and a qdisc cannot change kind. Replacing `fq_codel 6e:` with
`cake` at the same handle returns `EINVAL`. **`tc` fails identically** --
`tc qdisc replace dev X root handle 6e: cake` over an `fq_codel 6e:` answers
"Invalid qdisc name" -- so this is the kernel's rule and not a netcfgd bug.
Without a handle the same replace succeeds and the kernel assigns `8037:`.

Two facts narrowed it:

- **A rate change on the same scheduler works** at a fixed handle, and that is
  the common case: `cake 6e:` at 100Mbit becomes `cake 6e:` at 50Mbit with no
  complaint.
- **Only a change of scheduler fails**, which is a config edit somebody made
  rather than something netcfgd does on its own.

So `set_root` catches `EINVAL`, removes the root, and retries. That reopens the
window `NLM_F_REPLACE` was chosen to close -- one netlink round trip of
unshaped traffic -- **and only when the scheduler changes.** A re-apply, a rate
change and a reconcile all keep the single-message path.

**That trade is the whole decision.** It buys a qdisc out of being a one-way
door, and it pays with a brief unshaped window on an operation an operator
initiated. If that is the wrong way round for a shaped uplink carrying voice,
this is the record to argue with.

## Consequences

**`tc qdisc show` says whose qdisc it is.** `qdisc fq_codel 6e: root` is legible
with netcfgd not running, which is 0002's second argument arriving for a third
object kind.

**Somebody who installs their own qdisc as `handle 6e:` is indistinguishable
from netcfgd.** The same residual risk 0002 accepted for `proto 110`, and the
same answer: it is a deliberate collision with a number this project
documents.

**The constants are duplicated into `netcfgd-sys`** because that crate may
depend on nothing but libc and the kernel, and a test holds the copies
together -- the same arrangement, and the same failure if it lapses, as the
protocol number. Disagreement means netcfgd stamps one handle and looks for
another, and every qdisc it installs becomes foreign to it.

## Alternatives considered

**Put the mark in the filter's priority.** Rejected above: priority is load
bearing for a redirect.

**Delete and re-add the qdisc every time, so the handle always applies.**
Rejected: it makes the unshaped window unconditional, including on a rate
change and on every reconcile, to avoid a special case in one function.

**Pass the currently-installed kind into `Op::QdiscSet` so the executor knows
when to expect the failure.** Rejected: it widens an operation's shape, and
therefore the schema witnesses, to carry something the kernel will tell us for
free by refusing.

**Leave the `tc` objects record-only, as the sysctls are.** Tempting, since the
restart exposure is already closed on all three inits and a reboot clears both
sides. Rejected because the sysctls are record-only for a *reason* -- there is
no field -- and a qdisc had one all along. Declining to use it would have left
the residue table looking the same while the two rows in it had different
causes, which is how a limit gets copied forward as though it were a law.
