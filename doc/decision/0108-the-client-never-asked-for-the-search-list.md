# 0108: the client never asked for the search list

Status: accepted
Date: 2026-08-05
Milestone: found by porting a test to a second server

## Context

`make live` could not complete on Alpine. `dhcp.sh` serves its lease with
`busybox udhcpd`, chosen in the script's own words because it

> needs no package that a build machine would not have if it has busybox at all

and Alpine falsifies that: the most busybox-native distribution there is builds
`udhcpc` and `udhcpc6` and **no server at all**, with no other package providing
one. `dhcpcd.sh` skipped behind it for the same reason, and `NCFG_LIVE=1` turns
a skip into the failure that stopped the suite.

Adding dnsmasq as a fallback server was meant to be scenery. It found a defect
in netcfgd instead.

## What it found

With dnsmasq answering, the lease arrived, the nameserver arrived, and **four
checks about search suffixes failed**. dnsmasq's own log says why:

```
requested options: 1:netmask, 3:router, 6:dns-server, 12:hostname,
                   15:domain-name, 28:broadcast, 42:ntp-server
```

**Option 119 is not in busybox `udhcpc`'s default request list**, and netcfgd
passed no `-O`. A server that honours the request list therefore never sends a
search list, and never had.

[0067](0067-a-search-suffix-is-not-a-routing-domain.md)'s search suffixes
worked here for one reason: `busybox udhcpd` pushes every configured option
whether it was asked for or not. Against dnsmasq, ISC dhcpd, or any domestic
router, netcfgd's busybox client path asked for nothing and got nothing --
silently, since a lease with no option 119 is indistinguishable from a network
that sends none.

Option 15 (`domain`) *is* in the default list, so a single domain always
arrived. That is what made this invisible: the feature looked like it worked.

## Decision

**netcfgd asks for it: `-O search`.** One flag, and the whole of the fix.

Confirmed on the wire rather than reasoned about -- with the flag, the same
dnsmasq logs `requested options: ... 119:domain-search` and the client's script
reports `search='a.example b.example'`.

**`dhcp.sh` falls back to dnsmasq where busybox has no server.** A fallback and
not a replacement: where the applet exists nothing changes and no package is
needed. The two servers hand out the same lease and the same six options, and
that equivalence is written twice rather than abstracted -- two short blocks
that read against each other beat one that has to be decoded.

**The script picks its own namespace now, so the Makefile runs it bare.** Which
namespace it needs depends on which server it found: `udhcpd` drops no
privileges and a plain `unshare -rn` suffices, while dnsmasq does drop them and
`unshare -rn` writes `deny` to `/proc/self/setgroups`, so the drop fails and it
exits before answering. Nesting cannot rescue that -- once inside a user
namespace with setgroups denied, no further unsharing gets it back -- which is
why `slaac.sh` and `dhcpcd.sh` already make their own. The udhcpd path still
needs no `newuidmap` and no `/etc/subuid` entry, exactly as before.

## The gates

`udhcpc_start_args` is a function now, for the same reason `dhcpcd_start_args`
beside it is one: the argument list needs somewhere to be asserted. A unit test
pins `-O search` and the three flags that were already load-bearing -- `-s`,
`-p`, `-R` -- so a rewrite cannot quietly drop one. Removing the request turns
it red with the whole list printed.

Live, on both servers and both distributions: Debian through `busybox udhcpd`,
Alpine through dnsmasq, all checks passing on each. The Alpine half is the one
that could not run at all before.

## What this says about the method

**A test with one implementation of its scenery tests that implementation too,
without saying so.** Nothing here was wrong with the code that reads a search
list, the code that delivers it, or the test that checks it -- the gap was in
what netcfgd asked the network for, and no amount of reading either side would
have shown it, because both sides were correct about the option they had. It
took a second server, which was added for an unrelated reason.

The same shape as `tunnel.sh` against openvpn 2.7 (0102) and the fake supplicant
against 0080's liveness check (0105): a fixture that agreed with exactly one
implementation, and stopped being evidence the moment a second one appeared.
