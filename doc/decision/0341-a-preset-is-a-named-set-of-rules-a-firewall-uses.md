# 0341: a preset is a named set of rules a firewall uses

Status: accepted
Date: 2026-11-23
Milestone: the firewall's layer two ([0284](0284-the-ruleset-is-netcfgds-and-rules-arrive-in-five-layers.md))
Follows: [0339](0339-live-rules-win-and-there-is-no-controller.md), which put presets last

## The grammar

A preset is a top-level block holding chains of rules in layer one's own
grammar ([0294](0294-layer-one-is-named-rules-in-netcfgds-own-table.md)), and a
firewall names the presets it uses:

    preset "web-server" {
        input {
            accept "http"  { protocol = "tcp"; port = [80, 443] }
        }
    }

    firewall {
        presets = ["web-server"]
        input { policy = "drop"; accept "ssh" { protocol = "tcp"; port = 22 } }
        forward { policy = "drop" }
        output { policy = "accept" }
    }

- **A preset holds rules and nothing else.** No `policy`, no `slot`: a chain's
  policy is the host's answer for what nothing matched, and a preset that set
  it would decide the host's posture from a library; a slot is opened by the
  host that is written into.
- **The library is the configuration's layers.** A preset is an ordinary
  block, so the factory layer can ship one, a drop-in can add one, and
  `override preset "NAME"` replaces a shipped one, by the merge rules every
  block already has. No second file format and no second search path.
- **A preset used and not defined is refused**, by name. One defined and not
  used is nothing.

## How it compiles: after every written rule

A used preset's rules are appended to their chain after the firewall's own
rules, in the order `presets` names them -- 0339's precedence, a preset being
the most general thing on the host and so the fallback. Zones, when they
exist, go between the two.

**A preset's rule is named `PRESET/RULE`** in the compiled document, so it
cannot collide with a written rule, `ncfg status` and a red row say where it
came from (0294 anticipated this), and the same preset used by two hosts
names its rules alike. A `/` is not a character a written rule's name can
need, and is refused in one, so the prefix is unambiguous.

Rejected: expanding a preset where it is named, among the written rules. The
operator would be choosing the precedence rule by rule, which is the order
0339 fixed.

## Where it travels

A preset is a library entry, and a library is what a group shares; 0284
expected presets to be where group scope belongs. But a preset's keys are a
chain's and a rule's, nested, and the kind registry has no numbers for them.
**Host-private until it does** -- the narrow direction, since widening a scope
publishes what nobody offered -- and giving presets their numbers is the step
that lets them travel.

## What the document holds

The compiled document holds the expanded rules, which are what the kernel
is given and what the planner compares -- a preset edited in the library shows
in the plan as the rules it changed -- and the `presets` list, so it renders
as written: the renderer writes each listed preset back as a block holding
its prefixed rules under their own names, an empty one where it contributed
none.
