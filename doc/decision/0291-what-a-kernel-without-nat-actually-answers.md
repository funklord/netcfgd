# 0291: what a kernel without NAT actually answers

Status: accepted
Date: 2026-10-24
Milestone: M6
Follows: [0022](0022-netcfgd-may-own-one-nftables-table.md), [0283](0283-firewall-and-queuing-are-in-scope.md), [0287](0287-a-rule-carries-its-own-standing.md)

## The guess both of the records above rest on

0283 names "refusing legibly where the kernel cannot do what was asked" as a
thing netcfgd does not do, and says what the useful behaviour would be:

> `EOPNOTSUPP` from a statement is a feature difference, not a malformed
> message, and it is the one error whose remedy ("this kernel is too old for
> X") an operator can act on.

0287 builds its red row on the same premise -- "translating `EOPNOTSUPP` from a
construct into a named capability is the half 0283 records as missing".

**Neither was measured, and the errno is not `EOPNOTSUPP`.** The first
capability sentence written against those records keyed on `ENOENT` and
`EOPNOTSUPP` together and said in its own comment that which one a kernel gives
"was not measured and cannot be here" -- true of this host, which has
`nft_chain_nat` and `nft_masq`, and false of the workspace: a vm has a kernel
of its own.

## What was measured

The copyright holder, 2026-10-24: *"If you need to thoroughly test this kind of
stuff you can use a hull VM with a custom kernel."*

No kernel had to be built. A hull `(backend vm)` guest boots with an empty
module table and its own `/proc/sys/kernel/modprobe`, so blocking autoload
leaves a construct unreachable **by the same lookup that fails when it was
never compiled**: `nf_tables` asks for the chain type, asks the module loader
for it, asks again, and returns its own error without regard for why the module
never appeared. `tests/hull/natcap/` is that rig, 22 checks. Kernel 6.12,
Debian 13:

| state | what the kernel said |
|---|---|
| `nf_tables`, no `nft_chain_nat` | `NFT_MSG_NEWCHAIN` refused, **`ENOENT`** |
| `nf_tables` and `nft_chain_nat`, no `nft_masq` | `NFT_MSG_NEWRULE` refused, **`ENOENT`** |
| no nftables module at all | the socket will not open, `EPROTONOSUPPORT` (93) |

Two controls, because three refusals are not evidence that the rig can tell
anything apart: a guest with the modules loadable applies NAT and all four
actions report `ok`, and with autoload blocked a module nothing has loaded
cannot arrive (`ip link add type dummy` is refused with "Unknown device type").
Each failing state also asserts that its plan contained the `nat.replace`,
since a converged machine plans nothing and would report an empty success.

**`EOPNOTSUPP` arrived in no reachable state.** It is gone from the hint, and
`apply_kernel_test` holds it gone: an arm for a code nothing produces is an
untested arm wearing caution's clothes, and its presence was what made the
sentence hedge between two causes.

## Which settles a different question than the one being asked

`ENOENT` is the answer, and `ENOENT` **cannot carry the diagnosis**.
`kernel_nat.c` has always noted that deleting a table which is not there is
`ENOENT`, and that delete is in the transaction whenever the dump saw the
table -- so a `netcfgd` table that vanished in the gap 0283 describes lands on
the identical code. One errno, three faults, three different remedies: install
a module, build a kernel, ignore a race.

**The discriminator arrived with the error and was being thrown away.** An
`NLMSG_ERROR` carries the header of the message that caused it, and
`socket.c` already decoded it to spell `RTM_NEWLINK` -- it had no name for
anything on the netfilter protocol, so every nftables refusal read "a netlink
request failed". `ncfg_nft_message_text` gives the eleven messages netcfgd
sends or reads their kernel names, and the refusal now reads
`NFT_MSG_NEWCHAIN failed` or `NFT_MSG_NEWRULE failed`, which is precisely the
difference between "no `nat` chain type" and "no masquerade".

No protocol is threaded through to make that work, and that is a measurement
rather than a hope: an nftables message is `(NFNL_SUBSYS_NFTABLES << 8) | kind`
and so 2560 or more, while the largest `RTM_*` these headers define is 108.
The one ambiguity is `NFNL_MSG_BATCH_BEGIN`, subsystem 0 type 16, which is
`RTM_NEWLINK` exactly; a marker asks for no acknowledgement and was refused in
none of the four states, so it is written down rather than guarded.

## What this decides

1. **The capability sentence keys on the measured code**, `ENOENT`, and on
   nothing else.
2. **It names what an operator can act on and does not assert a cause the
   number cannot establish.** It names `nft_chain_nat` and `nft_masq`, points
   at the refused message for which step failed, and says a vanished table
   fails here too.
3. **A capability claim is tested where the capability is absent**, which for
   netcfgd means a vm rig rather than a unit test. 0287's red rows are claims
   of this kind; each one wants a state in `natcap`.

## What is not decided here

**Whether a probe should replace the refusal.** A hint explains a failure that
has already happened; 0287's red row before an apply would need netcfgd to ask
a kernel what it supports, and nftables publishes no "list the expression types
you have" request. The generation read (0283, 0284) is the only capability
question netcfgd asks today. Asking by *attempting* -- a transaction into a
throwaway table, rolled back -- is the obvious shape and is the holder's call,
because it writes to the kernel to answer a question about it.

**Whether the remaining ruleset op kinds get sentences now.** `nat.replace` is
one op. The rest of 0283's five layers will each want one, and each wants a
state in the rig rather than a guess -- which is what this record is for.

**Whether `natcap` should pin a kernel.** hull declares `(kernel "path:...")`
in its own spec and has not built it (hull's §1188); the guest runs the host's
kernel today. A pinned kernel would let the rig say "this is what 5.4 answers"
rather than "this is what the host's kernel answers", and the module-blocked
state is the same lookup either way. Worth having, nobody's to decide here.
