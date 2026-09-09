# 0186: a configuration that cannot work is refused, or said out loud

Status: accepted
Date: 2026-09-09
Milestone: M8; the seventh audit, after writes, reads, execs, sockets, races
and resources

## The question

> now check the config parsing and validation errors too

## What the compiler already does, which is most of it

Thirty-two malformed configurations were put through `ncfg show`. **Twenty-nine
were refused**, every one naming the file, the line, the column and the
specific fault: an octet of 300, a prefix length of 99, a metric that is a
string, a negative metric, a metric past `u32`, an unknown key in every block
kind, an unknown top-level block, an unclosed block, an unterminated string,
a `via` with no address, a name too long for the kernel, a boolean given a
number, a list key given a number, a secret reference with no name, an IPv6
prefix length on an IPv4 address, a duplicate `interface` block, and a
passphrase written in the clear rather than as a reference.

That is the front end working as designed, and the audit is mostly a record
that it does.

## The three that were accepted

**A route destination that is neither `default` nor a network.**
`parse_route` canonicalised anything that parsed as a prefix and let
everything else through untouched, on the grounds that `default` is not a
prefix. So `routes = ["not-a-prefix via 10.0.0.254"]` compiled, planned, and
failed at `route.add` -- measured, **after three other actions had already
been carried out**, leaving the machine half configured over a spelling. The
apply side takes `default` or what `parse_cidr` takes; the compiler now
refuses exactly the rest, before anything has been done.

**A network with no name.** `network "" { }` compiled into a document holding
a network nothing can join. `Ssid::new` allows an empty SSID deliberately --
a hidden access point beacons a zero-length one, so an *observation* has to
be able to hold it -- and that is exactly why the rule belongs in the
compiler rather than the model: what may be **seen** and what may be
**written down** are different questions.

**A `device` block with no `interface` block.** The planner walks interfaces,
so a device on its own is inert. `netcfgd.conf.example` says so in prose,
added after a configuration written from an earlier version of that example
"started no supplicant and joined nothing" -- device block, network block,
passphrase, no interface block. **The example was corrected and the product
still said nothing**: measured against a present device with a network
configured, `nothing to do`.

That one is a warning rather than a refusal. The configuration is legal, and
an operator may be building one up a block at a time -- but an inert block is
worth a sentence, and the sentence names the line that would make it live.

## What was accepted and is correct

* `config = []` -- an empty addressing list is `null` spelled another way,
  which is what a bridge member wants. Refusing it would refuse a real state.
* The same key twice in one block appends rather than replacing, which is the
  documented list semantics: "`config` is a list and every entry contributes".
  Two lines and one two-element list mean the same thing, and drop-in merging
  depends on that being true.

## What is checked

Unit tests beside the compiler for both refusals, and beside the planner for
the warning -- including the negative case, because a warning that fires on
every ordinary wireless machine is one an operator learns to read past.
Sabotage confirms each: removing a check reddens its test and nothing else.

The whole suite passed unchanged, which is its own small finding: **nothing
in the tree -- no fixture, no example, not the shipped `netcfgd.conf.example`
compiled by the test suite -- was relying on any of the three.**
