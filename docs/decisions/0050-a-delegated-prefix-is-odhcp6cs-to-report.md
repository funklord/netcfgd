# 0050: A delegated prefix is odhcp6c's to report

Status: accepted
Date: 2026-08-02
Milestone: closes a hole in M4's `Delegated` (0009)

## Context

Decision 0009 makes a delegated prefix an indirection: the document carries a
`PrefixRef`, a `DHCPv6` client reports the prefix it was given, and **netcfgd**
derives the addresses -- `subnet` selects a sub-prefix, `suffix` supplies the
host part and the resulting length. Decision 0004 delegates the client itself,
so netcfgd runs somebody else's and reads a file.

`start_dhcp6` therefore wrote a hook and offered two clients: `odhcp6c` with
`-s <hook>`, or `dhcpcd`. The comment said dhcpcd read the script from a
directory "installed there by `write_pd_hook`".

None of that worked, and nothing could have noticed. There was no test that ran
a `DHCPv6` client at all -- the hook was tested by running it with variables set
by hand, which is a test of the shell script and not of anything a client does.

## What a real exchange showed

`kea-dhcp6` on one end of a veth pair, `dhcpcd` on the other, in a namespace.
The exchange is real: SOLICIT, then a REPLY carrying `IA_PD` with
`2001:db8:1234::/56`, allocated and logged by the server, and dhcpcd logging
`wan0: delegated prefix 2001:db8:1234::/56`.

Three separate things were wrong, each invisible without that:

1. **dhcpcd was never told about the hook.** netcfgd ran `dhcpcd -b -6 <iface>`
   and nothing else. dhcpcd's own hook directory is not netcfgd's `/run`, so
   the script sat there unread. `-c, --script` exists and would have fixed
   this one.
2. **dhcpcd never asked for a prefix.** A `DHCPv6` client solicits `IA_PD` only
   when an `ia_pd` line appears in a config file, in an `interface` block.
   netcfgd passed no config file, so the model's `prefix_delegation` reached
   nothing at all.
3. **And with both of those fixed, there is still no prefix to read.** dhcpcd
   sets `$new_delegated_dhcp6_prefix`, and `dhcp6.c` fills it from the
   addresses whose `delegating_prefix` is set -- that is, **the addresses
   dhcpcd itself derived**, on an interface it was told to delegate to. Told to
   delegate nowhere, it derives nothing and the variable is empty. Told to
   delegate somewhere, it installs addresses on that interface, which is the
   deriving 0009 makes netcfgd's and a second writer besides.

The variable the hook actually read, `$new_dhcp6_prefix`, is not one dhcpcd
sets under any configuration.

## And nothing could ask for one anyway

Found while writing the refusal: **the DSL has no way to request a prefix.**
`PdRequest` is in the model, frozen at M4 as 0009 asked, and no `config` entry
sets it -- `dhcp6` compiles to `Dhcp6::default()` and there is no spelling for
the rest. The consuming half exists (`@pd:wan0/0::1/64` resolves a `PrefixRef`);
the requesting half was never written.

Meanwhile `start_dhcp6` passed `-P 0` to odhcp6c unconditionally, so every
`config = "dhcp6"` solicited a delegation nobody had written down -- an ISP
handing out a prefix that nothing on the machine would ever use. That is fixed
here: the flag is passed only when the document asked, which today means never.

The syntax is deliberately not added in this record. It would be config-language
surface that nothing here can exercise end to end -- odhcp6c is not packaged for
Debian, so the client that serves the feature cannot be run on the machine this
was written on -- and a language addition tested only against itself is how a
keyword gets frozen in the wrong shape.

## Decision

**Prefix delegation is odhcp6c's.** `odhcp6c -P 0 -s <script>` reports the
prefix in `$PREFIXES`, which is the whole of what this needs, and the reference
device for the feature -- an OpenWrt router -- ships it.

**A document that asks dhcpcd for a prefix is refused, by name and with the
reason.** Not warned about: a client that takes a lease from the ISP and
reports nothing is worse than one that does not start, because the lease is
real, the ISP believes it is in use, and nothing on the machine shows it.

**An ordinary `DHCPv6` address is unaffected.** dhcpcd serves those and always
did; it is only the prefix that it cannot report.

## Alternatives considered

**Let dhcpcd delegate, and read the addresses it derived.** This is what
`$new_delegated_dhcp6_prefix` is for, and it is the shape dhcpcd is built
around. Rejected: it makes dhcpcd the second writer on every interface a prefix
reaches, moves the `subnet`/`suffix` arithmetic out of the document and into
dhcpcd's `sla_id`, and leaves `ncfg plan` unable to say why an address is what
it is. 0009 exists to prevent exactly that.

**Ask dhcpcd for the lease instead of being told.** `dhcpcd -U <iface>` dumps a
lease as shell variables, so netcfgd's hook could ask on every event. Rejected
for now rather than on principle: it turns a report into a poll, it needs
dhcpcd's control socket to be reachable from the hook, and it would be the only
place netcfgd interrogates a client rather than reading what the client wrote.
Worth revisiting if odhcp6c's absence from Debian and its relatives becomes the
thing that stops somebody using this.

**Write a dhcpcd configuration file, as netcfgd does for pppd.** That is what
fixes (1) and (2) and it is genuinely small. It is not written, because (3)
makes it pointless on its own -- and a client that solicits a prefix nobody can
read is the failure this record is about.

## Consequences

- Prefix delegation now needs odhcp6c, which Debian does not package. That is a
  real cost and the error message names it rather than leaving somebody to
  discover a lease that goes nowhere.
- The refusal cannot be reached from a config file until the request syntax
  exists, so it is a pure function with a unit test rather than a branch nobody
  can make fire. Whoever writes that syntax gets the refusal already working.
- The hook script reads `$PREFIXES` and nothing else, and says so.
- The test that asserted dhcpcd's variable was read now asserts the opposite,
  which is the more useful assertion: it fails if somebody adds a variable back
  without a client that sets it.
- Nothing here is a claim about ordinary `DHCPv6`. Only the prefix is refused.
