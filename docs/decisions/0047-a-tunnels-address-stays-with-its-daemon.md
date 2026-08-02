# 0047: A tunnel's address stays with its daemon

Status: accepted
Date: 2026-08-02
Milestone: answers what 0046 deferred

## Context

Decision 0046 named this and did not settle it: OpenVPN and `pppd` both
configure their own interface, so netcfgd is the single writer everywhere
*except* the two places where a daemon got there first. The obvious repair is
`--route-noexec --ifconfig-noexec` plus a script reporting through `/run` --
the contract `docs/modem-report.md` already defines, which says nothing
modem-specific.

0046 also guessed that answering it for both tunnel types at once was worth
more than answering it for either. That guess is wrong, and checking is what
showed it.

## The two are not symmetric, and cannot be made so

| | address | routes |
|---|---|---|
| `openvpn` | `--ifconfig-noexec` | `--route-noexec` |
| `pppd` | **nothing** | `nodefaultroute` |

`pppd` has no option that negotiates an address and leaves netcfgd to set it.
`noip` is the nearest thing and it "disable[s] IPCP negotiation and IP
communication" -- not "negotiate and let somebody else apply it", but no IP at
all. The address a PPP link has is IPCP's result applied by `pppd`, and that is
the protocol's design rather than a gap in the option list.

So symmetry is unreachable. Any decision that takes OpenVPN's address away from
its daemon makes the two tunnel types behave differently, which is the thing
0046 said was worth avoiding.

## The address stays with the daemon, and there is a precedent

**Decision 0004 already made this call for DHCP.** netcfgd does not implement a
DHCP client; `dhcpcd` sets the address and netcfgd observes it, does not fight
it, and does not remove it. Rule 7 of decision 0006 is built on that: a missing
`Dhcp4` address is not re-added, because "the lease is what is gone".

A tunnel is the same shape. The daemon negotiates something netcfgd was not
party to, and the result is the daemon's to apply and withdraw. Making OpenVPN
the exception would mean two answers to one question in the same codebase.

**And the address on a tunnel is not contested**, which is what constraint 1 is
actually about. Nothing else wants to address a `tun` device that netcfgd's own
daemon created. The single-writer rule exists because two writers fight; here
there is only ever one, and the question is merely which.

### What taking it would cost

Worth stating, because it is not zero and it is not obvious.

`--ifconfig-noexec` means the tunnel comes up **with no address at all** until
netcfgd's next reconcile applies one. netcfgd reconciles on netlink events, and
the `tun` device appearing is one -- but the report arrives after that event,
not with it, so the ordering is a race in the wrong direction. An operator whose
VPN connects and then does not work for a second or two, with `ip addr` showing
nothing, has been given a worse tool in exchange for an internal consistency
they cannot see.

## Routes are different, and are the part worth taking

A route is contested where an address is not.

netcfgd already arbitrates between uplinks: `interface.preference` becomes a
route metric, and a link that loses carrier has its routes withdrawn so the
kernel starts using another one. A VPN that installs its own default route walks
into the middle of that with a metric netcfgd did not choose, and neither side
knows the other is there. That is two writers on one routing table, which is
exactly the failure the rule is about.

Both daemons can be told to stop: `--route-noexec` and `nodefaultroute`. So the
routes *can* be netcfgd's for both, which is the symmetry that actually matters,
and the asymmetry above does not reach it.

**This record does not implement that.** What it settles is which half is worth
the mechanism, so that whoever builds it is not also deciding it. What the work
needs:

- `--route-up` for OpenVPN and `/etc/ppp/ip-up` for `pppd`, each writing the
  report format `docs/modem-report.md` already defines -- which is why that
  document was written without a modem in it.
- A metric for a tunnel's default route that composes with `preference`
  (decision 0006 rule 3), rather than whatever the server pushed.
- The report arriving *after* the interface, which is the same later-reconcile
  ordering PPPoE already documents and warns about.

## What this changes today

Nothing, which is the point. `openvpn` and `pppd` configure their own tunnels
and netcfgd observes, as both already do -- and that is now a decision with a
reason rather than the state nobody had got to yet.

One thing is left crooked deliberately. `docs/modem-report.md` and
`/run/netcfgd/modem/<interface>` are named for a modem, and the contract is not
a modem's -- it is the contract for *anything* that knows an interface's
addressing and is not netcfgd, which is why that document contains nothing
modem-specific.

Renaming both is right and is **not** done here, because doing it well means
the path, the document, the `AddressSource` variant and the config keyword
moving together, and doing half of it leaves two names for one idea instead of
one wrong one. It should happen when the second writer exists, which is when the
name starts actively misleading somebody rather than merely being narrow -- and
that is the same work this record defers, so it arrives with it.
