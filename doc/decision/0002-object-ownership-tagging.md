# 0002: netcfgd tags its routes and addresses with protocol 110

Status: accepted
Date: 2026-07-28
Milestone: M1

## Context

`project.md` §8 question 2, and §2.3. Drift detection is meaningless unless
netcfgd can tell an object it installed from an object somebody else
installed, so both halves need a tag.

**Routes.** `rtm_protocol` is a `u8`. `linux/rtnetlink.h` says values `>=
RTPROT_STATIC` (4) are not interpreted by the kernel and are passed from
userspace and back unchanged, which makes the field available but also makes
the header itself the de-facto registry. Currently allocated there: 0–18, 42
(Babel), 99 (Open/R), 186–189 (BGP, ISIS, OSPF, RIP), 192 (EIGRP). Everything
else is unassigned, and the established practice for a daemon that wants one
is to pick from a gap and ship a drop-in for `ip route show` to name it —
FRR does exactly this with `tool/etc/iproute2/rt_protos.d/frr.conf`.

**Addresses.** `IFA_PROTO` is the equivalent for addresses. It was added by
commit `47f0bd503210` ("net: Add new protocol attribute to IP addresses",
2022-02-17) and first shipped in **v5.18** — verified against the tags: the
attribute and its `IFAPROT_*` constants are present in `v5.18`'s
`include/uapi/linux/if_addr.h` and absent from `v5.17`'s. The kernel uses
0–3; the rest are free.

## Decision

**One constant, 110 (`0x6e`), used for both `rtm_protocol` and `IFA_PROTO`.**
It lives in `netcfgd-model` as `NETCFGD_PROTO` and nothing else defines it.

110 sits mid-gap in 100–185, the largest unallocated run, far from the dense
low cluster and from the routing-daemon cluster at 186 and up. Using the same
number for both attributes is not required by anything, but a single constant
is one thing to document, one thing to grep for, and one thing to get wrong.

Ship `/etc/iproute2/rt_protos.d/netcfgd.conf` containing `110 netcfgd`, so
`ip route show` prints `proto netcfgd` and the tag is legible without
netcfgd running. This file is outside `/etc/netcfgd/` and is package
integration, so principle 12 (the filesystem reflects use, not capability)
does not reach it.

Once the project is public, send a patch adding `RTPROT_NETCFGD 110` to
`linux/rtnetlink.h`. Being in the header is what stops a future daemon
picking the same number, and it costs one patch.

**Minimum supported kernel is 5.10**, which is OpenWrt 22.03 and Debian 11.
OpenWrt 23.05 is 5.15 and 24.10 is 6.6, so requiring 5.18 for `IFA_PROTO`
would exclude every OpenWrt release before 24.10 — the reference target from
design §10.1. `IFA_PROTO` is therefore used when available and the recorded
`/run` prior state is the fallback, as §2.3 anticipated.

**Availability is detected by read-back, never by version number.** Set
`IFA_PROTO` on an address, dump it, and see whether it comes back. A kernel
older than 5.18 ignores the unknown attribute silently rather than failing,
so a write that "succeeds" proves nothing; and a distro backport makes
`uname` unreliable in the other direction. Probe once at startup, cache the
answer in `/run`, and have `ncfg explain` name which mechanism produced its
conclusion — §2.3 already requires that, and this is why.

## Consequences

**Changing the constant orphans every route already installed.** They carry
the old tag and become foreign objects to the very code that put them there.
So it is not an ordinary knob: a `global { route_protocol = N }` escape hatch
exists for a site with a genuine collision, and `ncfg apply` refuses to change
it while objects tagged with the old value are present. Migrating or flushing
is an explicit operator action.

**A collision with a daemon nobody has heard of remains possible**, and if it
happens netcfgd eats it — reconciling away somebody else's routes is the worst
failure this project has. The `rt_protos.d` file at least makes it
diagnosable: `ip route show proto netcfgd` listing routes we did not install
is the symptom, and it is visible without any netcfgd tooling.

**On pre-5.18 kernels address drift detection is weaker**, and measurably so:
an address added by hand that happens to match our recorded prior state cannot
be distinguished from ours. Those get reported, never reconciled away. The
asymmetry is deliberate — under-claiming ownership loses a little
convenience, over-claiming it deletes a user's address.

The per-address attribution that the fallback needs in `/run` is the same
state decision 0006 rule 7 needs to tell a missing static address from a
missing lease. One mechanism, two consumers; build it once.

## Alternatives considered

**A value in 19–41 or 43–98.** Equally valid. 100–185 is simply the biggest
gap, and past allocations have clustered low or at 186+, so the middle of the
largest run is where a future allocation is least likely to land.

**Reuse `RTPROT_STATIC` (4).** Rejected. That is what NetworkManager,
systemd-networkd and a bare `ip route add` all use, so it means "some human or
tool, once" and answers precisely the question being asked.

**Track ownership only in `/run`, tag nothing.** Rejected on two counts. It
cannot distinguish our route from an identical one added by hand, which is the
case drift detection exists for. And it makes `ip route show` unable to answer
"whose is this?" without netcfgd running, when the whole product thesis is
that the system is inspectable with ordinary tools.

## Sources

- [`linux/uapi/if_addr.h` commit history](https://api.github.com/repos/torvalds/linux/commits?path=include/uapi/linux/if_addr.h)
  — `47f0bd503210`, 2022-02-17.
- [`if_addr.h` at v5.18](https://raw.githubusercontent.com/torvalds/linux/v5.18/include/uapi/linux/if_addr.h)
  and [at v5.17](https://raw.githubusercontent.com/torvalds/linux/v5.17/include/uapi/linux/if_addr.h).
- [iproute2 `rt_protos`](https://github.com/iproute2/iproute2/blob/main/etc/iproute2/rt_protos)
  and [FRR's `rt_protos.d` drop-in](https://github.com/FRRouting/frr/blob/master/tools/etc/iproute2/rt_protos.d/frr.conf).
- [OpenWrt 24.10 release notes](https://www.cnx-software.com/2025/02/08/openwrt-24-10-released/)
  for the kernel-version mapping.
