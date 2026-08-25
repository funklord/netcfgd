# 0058: A change carries the whole nest, minus what the kernel refuses

Status: accepted; macvlan, tunnel and VXLAN are done, the VLAN is still named and
not built
Date: 2026-08-03
Milestone: the rest of [0057](0057-a-link-kind-is-compared-like-a-daemon.md)'s list

## Context

0057 compared a bridge and a bond against what the kernel reports and left four
kinds named: a macvlan's mode, a tunnel's endpoints, a VXLAN's id and a VLAN's
id. It also left a table of seven measurements and one instruction: **ask the
kernel before writing any of them, because no two families answered alike.**

Asking again was worth it. Two of the seven entries in that table are wrong as
written, and the question that decided the shape of this work is not in the table
at all.

## What the kernel actually does

Measured in a namespace on 6.12, one attribute at a time, with `ip` and -- where
`ip` gets in the way -- with raw `RTM_NEWLINK` requests carrying exactly one
attribute.

| kind | attribute | what the kernel does |
|---|---|---|
| macvlan | `mode`, among `private`, `vepa`, `bridge` | changes it |
| macvlan | `mode`, into or out of `passthru` | **refuses**, `EINVAL` |
| macvlan | parent (`IFLA_LINK`) | **accepts and ignores** |
| gre, gretap, ip6gre | `local`, `remote`, `ttl`, `key` | changes it |
| ipip, sit, ip6tnl | `local`, `remote`, `ttl` | changes it |
| geneve | `remote` in the family it already has, `ttl` | changes it |
| geneve | id -- which netcfgd spells `key` | **refuses**, `EOPNOTSUPP` |
| geneve | `remote` in the other family | **refuses**, `EOPNOTSUPP` |
| vxlan | `local`, `remote` | changes it |
| vxlan | `id` | **refuses** when the value differs |
| vxlan | `port` | **refuses whenever it is present**, at any value |
| vlan | `id`, `protocol` | **accepts and ignores** |

Three corrections to 0057's table, and the third is the one that changed the
design:

- **A macvlan's mode is not simply settable.** Three of the four modes move
  freely; `passthru` cannot be entered or left. `macvlan_changelink` compares the
  requested mode against the current one and answers `EINVAL` if exactly one of
  them is `passthru`.
- **A VXLAN refuses its `port` on presence, not on difference.** Restating the
  port it already has fails the whole message with `EOPNOTSUPP`. A change request
  built out of the same nest creation uses could therefore never correct a VXLAN
  endpoint -- it would fail forever, with the plan looking correct.
- **A VLAN's `protocol` is ignored as silently as its `id` is.** 0057 measured
  the id; the same request with a different tag protocol also succeeds and
  changes nothing.

## The question that was not asked before

**What happens to the attributes a change request leaves out?** The families
disagree, and it decides whether a partial update is even a thing:

| family | an attribute the request omits |
|---|---|
| gre, gretap, ip6gre, ipip, sit, ip6tnl | **reset to its default** |
| geneve, vxlan | kept |

A request carrying only `IFLA_GRE_REMOTE` leaves the tunnel with no local
address, no TTL and no key: `ipgre_netlink_parms` fills a zeroed struct from
whatever arrived. `ip6tnl` loses its encapsulation limit the same way -- a field
netcfgd does not model at all.

**`ip` hides this**, which is why the obvious experiment gives the wrong answer.
`ip link set tun0 type gre remote X` reads the device first and refills every
field before it sends anything, so the key and the local address survive and the
kernel looks like it merges. It does not. This was settled with a raw request
carrying one attribute, after the `ip` result had already suggested the opposite.

## Decision

**A change sends the whole nest, through the same function creation uses, minus
exactly the attributes the kernel refuses on a device that exists.**

`NewLink::info_data` gains one parameter saying whether the device already
exists. Three attributes come out when it is set: a VXLAN's `id` and `port`, and
a geneve tunnel's id. Everything else goes as it would at creation.

Two properties fall out, and both are the point:

- **The device ends up matching what a freshly created one from this document
  would be.** That is true whether the family resets what is absent or keeps it,
  so the rule does not depend on which family this is.
- **A refused attribute cannot take its neighbours with it.** 0057 learned that
  from the bond: `RTM_NEWLINK` is one message, so an attribute the kernel will
  not take fails the whole request. Here the attributes that would be refused are
  simply not in the message, which is what lets an edited VXLAN endpoint be
  applied while the `id` beside it is only reported.

**What cannot be corrected is said, not attempted.** The bond's answer, three
more times: an edit to a `passthru` macvlan mode, a geneve VNI, a VXLAN id or a
VXLAN port produces a sentence naming what the config says, what the kernel has,
and what to do about it. Nothing is planned, so nothing fails and nothing is
planned again on the next reconcile.

**Only what the document states is compared.** 0052's rule, now met for the
fourth, fifth and sixth time. A tunnel with no `ttl` in its block means
"whatever the kernel chose"; a VXLAN with no `port` means the same.

**Each family decodes with its own numbering.** Three decoders for seven kinds,
and the kind string is matched exactly rather than by substring -- the writing
half may ask whether a kind contains `gre` because it is only ever handed one of
seven names netcfgd chose, while the reading half is handed whatever link kinds
the machine has.

## Two smaller findings worth keeping

**A GRE key of zero is not "no key".** The kernel emits `IKEY` and `OKEY` for
every GRE tunnel, zero included, so the value alone cannot say whether there is a
key. The `GRE_KEY` bit in `IFLA_GRE_IFLAGS` is what distinguishes them, and
reading it is what stops a document asking for `key = 0` from differing from
itself forever.

**The fallback tunnel devices refuse every change.** `gre0`, `gretap0`, `tunl0`,
`sit0`, `ip6tnl0` and `ip6gre0` are created by their modules in every network
namespace, and `ip_tunnel_changelink` refuses to touch one: `EINVAL`, whatever is
asked. An operator who names an interface after one gets an apply that fails
rather than a silent no-op, which is an improvement on what happened before this
and is still worth knowing. It is not special-cased -- there is no marker in the
dump that says "this is the fallback", only six names that are a module's
convention, and hard-coding them would be a guess dressed as a check.

## What is deliberately left

**The VLAN, and it is not the same shape as anything here.** Its id is accepted
and ignored, so netcfgd would report a change nobody made -- worse than a
refusal, because nothing fails. Correcting one means deleting the interface and
recreating it, which drops its addresses and routes and interacts with the
planner's creation pass. That is its own session, as 0057 said.

**A macvlan's parent**, for the same reason: `IFLA_LINK` on a live macvlan is
accepted and ignored.

**A veth's peer**, because there is nothing to compare: the peer is what creation
means.

## Consequences

- Editing a macvlan's mode, a tunnel's endpoints, TTL or key, or a VXLAN's
  endpoints is planned, applied and reported. Each is disruptive -- moving a
  tunnel's endpoint stops everything inside the tunnel until the far end agrees
  -- so `--allow-disruption` gates them like any other interruption.
- Three ops rather than one: `link.set_macvlan`, `link.set_tunnel` and
  `link.set_vxlan`, matching the per-kind ops 0057 added. None carries values;
  the executor reads them from the document it was given.
- None has an inverse, for the reason `link.set_bridge` has none: an inverse
  built from the document would re-apply what the document says *now*.
- The plan schema gains three ops and the observed schema gains three structs;
  both witnesses moved. Minor additions.
- `+16 KB` installed, recorded in `size-budget.txt` with what it bought.
- The observation now carries a tunnel's local and remote endpoints, which is
  what NM's `.Device.IPTunnel` wants. That interface becomes projectable as a
  side effect of a local justification, which is the direction constraint 6
  requires -- and the same road a bridge, a bond and a WireGuard device took.
