# 0284: the ruleset is netcfgd's, and rules arrive in five layers

Status: accepted
Date: 2026-10-23
Milestone: M6
Follows: [0283](0283-firewall-and-queuing-are-in-scope.md)

## What the holder decided

Asked which ownership model and which rule language, 2026-10-23:

> zones can mean many things, and netcfgd owns the whole ruleset, with
> exceptions it might have to make for the other software that clobber
> netfilter rules. 1. We need to be able to configure a single host and
> manipulate its rules manually 2. we need to be able to apply custom presets
> on a host 3. we need to have zones that apply distributed rules on multiple
> hosts with a more abstract purpose-driven syntax 4. we may have dynamically
> driven rules that are triggered by a subsystem that handles network
> failure/failover/segmenting/auth or other distributed modification of rules
> in real time. 5. Likely more necessary aspects that I can't think of now. But
> look at the possibilities that are enabled by something like Unifi,

Two decisions and a shape. **netcfgd owns the whole ruleset**, which reverses
0022's "own one table and never touch another" -- netcfgd is the firewall on a
host it configures, and coexistence becomes an explicit exception rather than
the default. And **"zone" in netcfgd means the distributed, purpose-driven
layer**, not a firewalld or `fw4` per-interface zone; that is the
disambiguation "zones can mean many things" asks for, and it is settled here so
the word stops being ambiguous in this tree.

## The five layers are not alternatives

They differ in **who writes them, how abstract they are, and how long they
live**, and that is what makes them layers rather than competing models:

| | written by | subject | lifetime |
|---|---|---|---|
| 1 host rules | the operator, on the host | interfaces, addresses, ports | until edited |
| 2 presets | the operator, from a library | the same, named and reusable | until replaced |
| 3 zones | a controller, for many hosts | purposes -- "guest", "iot", "trusted" | until the policy changes |
| 4 dynamic | a subsystem, in real time | identities and memberships | seconds to hours |
| 5 unknown | -- | -- | -- |

**The compilation direction is one way and the fast path is separate.** Zones
compile to per-host rules; presets expand into the same per-host rules; manual
rules sit beside them. Layer 4 does *not* recompile anything -- a failover or
an authentication cannot wait for a ruleset rebuild, and rebuilding on every
membership change would make the ruleset churn under traffic.

So layer 4 wants nftables **sets and maps** rather than rules: a set's elements
change atomically, with per-element timeouts, while the rules referring to the
set stand untouched. That is the mechanism the real-time layer should be
designed onto, and it is also what makes layer 4 revocable -- clearing a set
removes an authorisation without touching policy.

**Precedence between layers has to be stated before any of them is written**,
because a host with a manual rule, a preset, a zone and a live membership has
four authorities over one packet. It is not decided here.

## What exists to build this on, which is more than it looks

- **The distributed layers need no new listener.** 0269 and design section 11.3
  fix that the daemon never grows one: `bridge/netcfgd-remote` links `fuzznet`,
  holds an ordinary local socket connection, and netcfgd's own authorisation
  does the security-critical work. A controller pushing zones and a subsystem
  pushing memberships both arrive that way.
- **An authorisation model is already there.** Tiers (0175) and the remote
  policy that `tests/live/remote_tiers.sh` exercises: a caller gets `observe`,
  `wifi` or `admin`, locally or remotely. Layer 4 needs a narrower authority
  than `admin` -- "may add an element to this set and nothing else" -- which is
  a tier question rather than a new mechanism.
- **The nftables mechanism from 0022 carries over unchanged**: netlink rather
  than `nft`, tag what you own, replace atomically, and tolerate a vocabulary
  that moves (0283).
- **Identity is where the firewall and the queue meet.** A per-client rate
  limit and a per-client filter name the same subject, so the zone and identity
  model serves both and netcfgd should not grow two. This is the strongest
  argument for doing the queuing half with the firewall rather than after it.

## The exceptions, which are the hard half of whole-ruleset ownership

Docker, podman and libvirt add tables while netcfgd runs; `fw4` and `firewalld`
own rulesets where they are installed. Owning the whole ruleset means netcfgd
decides what happens to those, and the holder's words allow for it: "exceptions
it might have to make".

What that needs, and none of it is decided here: a carve-out that is **named
rather than inferred**, because a pattern that guesses will one day keep the
wrong table; a policy for a carved-out writer whose rules contradict netcfgd's;
and an answer for the case 0022 was most afraid of -- a container runtime
adding a table *between* netcfgd's dump and its transaction, which is the same
race 0283 names and which the ruleset generation can detect.

## Unifi is the yardstick, not the specification

The holder named it as the possibility set. What it enables, as requirements to
measure a design against rather than features to copy:

- **policy whose subject is a client**, not an address -- a device identified by
  MAC, by lease, by authentication, or by a group it belongs to;
- **networks as segments**, VLAN-backed, with purposes: guest, IoT, corporate,
  each with reachability stated between them rather than per rule;
- **client isolation inside a segment**, which is a rule about a segment and
  not about a pair of hosts;
- **per-client rate limits and smart queues**, which is the queuing half with
  the firewall's subjects;
- **schedules**, so a rule's subject includes time;
- **port forwards and traffic routes**, which 0022 excluded as "not derivable
  from addressing" and which this reopens;
- **site-to-site and multi-site**, so a zone spans more than one network;
- **enforcement that survives the controller going away.** A Unifi device keeps
  its policy when the controller is unreachable. For netcfgd that is a
  requirement with teeth: layer 3 and 4 state must persist on the host, and the
  behaviour when a controller is absent must be stated rather than emergent --
  **and it must not fail open**, because a firewall that forgets its rules when
  a controller reboots is worse than no firewall, since nobody is watching.

## What is not decided here

The rule language's grammar, the precedence between layers, the carve-out
syntax, the tier that layer 4 uses, how a zone names a host, whether a
controller is netcfgd on another host or a separate program, and the size
question 0283 leaves open. Each is a decision rather than a detail, and this
record exists so that none of them is answered by accident while something else
is being implemented.
