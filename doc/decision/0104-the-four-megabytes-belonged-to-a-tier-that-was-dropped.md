# 0104: the four megabytes belonged to a tier that was dropped

Status: accepted
Date: 2026-08-04
Milestone: the last number this session left recorded as a gap

## Context

[0098](0098-a-supplicant-that-bound-its-socket-and-stopped-answering.md) pointed
`make rss` at the release binary rather than the debug one, and closed by
recording what that surfaced:

> the shipped daemon is ~4.3 MB resident, which is over section 10.4's stated
> 4 MB.

[0099](0099-a-package-installs-netcfgd-and-changes-nothing.md) repeated it, and
so did `project.md` and the Makefile. It was wrong twice over, and both errors
are the same kind: a number cited as a requirement without checking what it was
a requirement *for*, or where it was measured.

## What section 10.4 actually says

> **RAM:** target < 4 MB RSS steady-state **for nano**.

For nano. [0021](0021-no-nano-tier.md) dropped the nano tier.

`size-budget.txt` has carried exactly this distinction since M5, in its own
opening paragraph:

> These are NOT section 10.2's tier budget. [...] It also set nano at 400 KB;
> decision 0021 dropped that tier. What is built today is the full tier [...]
> What this file does instead is ratchet.

The size gate learned it. The RSS gate did not, and quoted the tier target as
though the full-tier daemon were failing a requirement written for a build that
does not exist.

## What it actually costs

Measured, on both C libraries, three runs each:

|  | VmHWM | RssAnon | Pss |
| --- | --- | --- | --- |
| glibc, Debian | ~4210 kB | ~520 kB | ~2465 kB |
| musl, Alpine | ~2920 kB | ~205 kB | ~2530 kB |

**On musl — which is what the size posture targets and what the apk ships — the
daemon peaks at ~2.9 MB.** Even taking the nano figure at face value, netcfgd
meets it on the platform the figure was about. The glibc number is larger
because glibc is larger: a bigger libc mapping, and allocator arenas worth about
300 kB more of anonymous memory for the same work.

**RssAnon is what netcfgd allocated: ~205 kB on musl, ~520 kB on glibc.** The
rest is text — the binary's own pages plus the C library's, most of the latter
shared with every other process on the machine, which is why Pss is a little
over half of VmHWM.

The TUI was measured too, since it is the one feature the daemon links and never
uses: `--no-default-features` drops `libncursesw` and `libtinfo` entirely and
saves ~88 kB of peak. Real, and not the difference between 2.9 and 4.2.

## Decision

**The RSS gate is a ratchet on a measurement, and says so** — the same sentence
the size budget has carried for a year, in the file that needed it and did not
have it.

**It prints three numbers and gates on one.** VmHWM stays the gated figure: it
is the pessimistic one and the honest thing to ratchet. Beside it now go
RssAnon and Pss, because a gate whose only number moves when the C library
changes underneath it invites exactly the reading this record is correcting.

```
rss: netcfgd peak 4328 KB of 4608 limit
rss:   of which 512 KB is netcfgd's own; 2458 KB is this process' share
```

**No optimisation follows from this**, and that is the point. There was nothing
over budget to fix; there was a citation to check. The work was measuring the
thing on the platform it was specified for, which took one container and
would have taken the same container at any point since the claim was first
written.

## What this does not change

The limit. 4608 kB was set from the observed glibc peak plus a noise band and
is still the right ratchet for the machine the gate runs on. Nothing about the
daemon moved.

## The lesson worth keeping

**A requirement quoted without its scope is a requirement invented.** Section
10.4's four megabytes had a qualifier three words long, in the same sentence,
and it survived being copied into a Makefile comment, two decision records and
`project.md` — by me, in one session, while I was busy being careful about the
measurement itself. The number was measured correctly every time. Nobody
checked what it was a number *for*.
