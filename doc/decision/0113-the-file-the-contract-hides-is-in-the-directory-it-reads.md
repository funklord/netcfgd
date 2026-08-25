# 0113: the file the contract hides is in the directory it reads

Status: accepted
Date: 2026-08-06
Milestone: sweeping every directory listing after 0112

## Context

0112's lesson was that a `read_dir` is an interface and had no schema. That
generalises, so every listing in the tree was read for one.

Most have a schema. Config drop-ins filter on a `.conf` extension and sort
lexically, and `writable_files` deliberately repeats the same enumeration so
that `ncfg reset` removes exactly what the loader reads. The rfkill scan reads
sysfs, whose names the kernel controls.

The interface report is different, and it is the one that matters most, because
`doc/interface-report.md` is a **contract with writers netcfgd did not write**.

## What it found

The contract tells every writer, in its own words:

> Write it atomically -- write a temporary file in the same directory and
> `rename(2)` it over the target -- because netcfgd may read at any moment and a
> half-written file is a file it will believe.

The same directory is not negotiable: a rename is atomic only within one
filesystem. So the contract requires the half-written file to exist in the
directory netcfgd reads, and then never said what to call it -- while the reader
took **every entry** as an interface name.

Measured, with a writer caught mid-write:

```
report interface: '.eth0.tmp.1234' -> nameservers: ['192.0.2.53']
report interface: 'eth0'           -> nameservers: ['198.51.100.53']
```

A report for an interface that does not exist, carrying a nameserver read out of
a file that was still being written -- which is precisely the outcome the
sentence above exists to prevent, one name away.

**And it is netcfgd's own writers doing it.** All four scripts netcfgd generates
-- the two `pppd` hooks, the `dhcpcd -c` script, the `udhcpc` script and the
odhcp6c prefix hook -- staged at `"$report.tmp"`. netcfgd created the artefact
its own reader misread, in the directory its own contract names, on every lease
renewal on every machine.

**The live test was already right, which is why nothing caught it.** `report.sh`
stages at `.wwan0.tmp`, with a comment quoting the contract's own sentence. The
fixture followed a convention the product did not, and did the rename
immediately, so no window ever existed inside the test.

## Decision

**A staging file is named with a leading dot, and readers skip anything dotted.**
`staged_report` produces the name and `is_staging` recognises one, beside
`report_dir` in `netcfgd-apply` -- which already exists as "the one definition of
this path" precisely so the writing crate and the reading crate cannot spell it
differently. This is the same shape as 0112's `is_reply_socket` and for the same
reason: the name a producer chooses and the name a consumer skips are one fact.

`is_staging` is deliberately broader than `staged_report`'s own output. It skips
anything beginning with a dot rather than only `.<interface>.tmp`, so a
third-party writer is safe by following the contract's *wording* rather than by
matching netcfgd's spelling exactly.

**A leading dot rather than a `.tmp` suffix**, and this is a collision argument
rather than a stylistic one. Dots are ordinary inside an interface name -- a VLAN
is `eth0.100` -- so a rule about the suffix would silently drop the report of an
interface somebody legitimately named `eth0.tmp`. That is the same defect
pointing the other way. A name that *begins* with a dot is pathological as an
interface, and `.` and `..` fall out for free.

Rejected: **a staging subdirectory**. It needs no reader change at all, since
`read_to_string` already fails on a directory and the reader says so out loud.
But it costs every writer a `mkdir`, and a third-party writer that skips it
fails exactly as before -- the failure mode stays, and only netcfgd's own
writers get safer.

Rejected: **ignoring reports for interfaces netcfgd does not know**. The
contract lets writers run ahead of netcfgd, and a report for a link that has not
appeared yet is a legitimate thing to hold.

**All four readers of a `/run` listing skip staged names**, not just the one that
was measured: `reported/`, both levels of `reported.d/`, and `prefixes/` -- whose
writer is the odhcp6c hook, staging the same way.

## The gates

**Live, in `report.sh`.** A staging file is left in place rather than renamed,
standing in for the instant between the write and the rename, and no report may
appear for an interface whose name begins with a dot. Removing the reader's
filter turns it red with `expected: 0, actual: 1`.

**A unit test covers all five generated scripts at once**, because what they
shared was the bug. It asserts the whole staged path rather than "contains a
dot", so a writer staging under a dotted name in the *wrong directory* still
fails -- the rename has to be within one filesystem, which means within this
directory. Renaming the staged file back turns it red with `ppp ip-up does not
stage at /run/netcfgd/reported/.eth0.tmp`.

Both were checked by breaking each half separately, because they fail
independently: a reader that filters correctly hides a writer that stages wrong,
and the live check alone would have stayed green while every generated script
was still wrong.

## What this says about the method

**A contract can create the artefact it warns about.** The atomicity rule is
correct, is the only way to publish a file whole, and had been read many times.
What nobody read was its consequence: it *requires* a half-written file to exist
in the directory the reader scans, so the reader owes it a rule. The document
described what writers must do and never described what netcfgd would then see.

**And the fixture being right is not the product being right.** `report.sh` had
staged under a dot since it was written, quoting the contract while doing
something the contract does not actually say. A test that is more careful than
the code it exercises will never fail -- it is testing its own good manners.
