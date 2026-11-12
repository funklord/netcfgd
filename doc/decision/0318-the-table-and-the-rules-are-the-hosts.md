# 0318: the nftables table and the policy rules are the host's, and are put back

Status: accepted
Date: 2026-11-12
Milestone: M5 (routers)
Extends: [0165](0165-the-file-netcfgd-owns-is-defended.md)'s list of host-wide configuration

## What happened

On OpenWrt 25.12, `/etc/init.d/firewall stop` runs `fw4 flush`, which deletes **every**
nftables table on the machine -- netcfgd's `inet netcfgd` with the rest -- and `restart` is
a stop and a start. The router guide tells a person to stop `firewall` once netcfgd's
`firewall` block does its work. Measured in `hull-armsr` (project.md 10.820): after it, a
router's NAT, port forwards and `firewall` block were gone, `ncfg plan` listed
`nftables.replace` as the repair, and no drift pass made it. The masquerade came back only
when the next edit of the document forced an apply, minutes later.

A drift pass keeps an action only if its interface reconciles, or if the op is one
`ncfg_op_is_host_wide_config` names (0165). `nftables.replace` names no interface -- the table
is one object for the whole host, which is why no guard on an uplink may refuse it -- and was
not on 0165's list, so every pass dropped it. `rule.add` and `rule.del` are the same: a policy
rule is selected by `iif`/`oif`/`from` and owned by none of them, and a rule deleted under
netcfgd stayed deleted.

## What this decides

**`nftables.replace`, `rule.add` and `rule.del` are host-wide configuration**, beside
`dns.apply` and `hostname.set`: a drift pass keeps them when the global drift policy is
`reconcile`, the default. Still an allow-list rather than "names no interface", for 0165's
reason: `commit.arm`, `commit.confirm` and `commit.revert` name none either and must never be
swept into a drift pass.

**0165's measured risk was a rewrite loop on a false difference**, and it is measured again:
with nothing touching either, zero re-applies of the table or the rule in 25 idle seconds; and
on the router, a second plan says "nothing to do" with the table, a port forward and its
reflection installed. Deleted, each is back within one 5 s tick.

## Found with it, and fixed in the same change

**`--no-apply-on-start` was never released in a daemon with a node.** The hold ends when an
apply arrives (`ncfg_reconcile_releases_hold`), asked of the requests a pass is handed -- and
since 0311 every daemon has a node, whose requests fuzznet's loop hands straight to
`ncfg_main_answer`, so its passes are handed none. A daemon started held, as the first-run
guide starts it, therefore repaired no drift at all, interface addresses included, until it
was restarted. An answered apply now releases the hold as well. Each of the two fixes,
reverted alone, turns `tests/live/nat.sh`'s new check red.

## Rejected

- **Watching nftables for deletions** (the `NFNLGRP_NFTABLES` group) to repair at once
  rather than at the next tick. Five seconds is the backstop every other kind of drift
  already lives with, and a second wake source for one kind is a second thing to keep
  right; it can come if five seconds is ever measured to matter.
- **Telling people not to stop `firewall`.** That was the guide's fault to fix as well, and
  it is fixed, but the table is netcfgd's to keep: anything else running `nft flush
  ruleset` -- a script, another tool -- does the same.
