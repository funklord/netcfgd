# 0292: a compiled-out construct answers like a blocked one

Status: accepted
Date: 2026-10-24
Milestone: M6
Follows: [0283](0283-firewall-and-queuing-are-in-scope.md), [0287](0287-a-rule-carries-its-own-standing.md), [0291](0291-what-a-kernel-without-nat-actually-answers.md)
Supersedes: 0291's third open question, "whether `natcap` should pin a kernel"

## The argument 0291 rested on, and the experiment it predicted

0291 measured what a kernel answers when it cannot do nftables NAT by
**blocking module autoload** in a vm guest, and claimed that this is the same
state as a kernel compiled without the construct:

> blocking autoload leaves a construct unreachable **by the same lookup that
> fails when it was never compiled**

That is reasoning, not a measurement, and `running-code.md` is explicit about
the difference: naming the experiment that would confirm a comfortable story
and running it is what removes a branch. The holder asked for it the same day
-- *"If you need to thoroughly test this kind of stuff you can use a hull VM
with a custom kernel"* -- and `tests/kernel/` is that experiment.

## What was built and what it answered

Three kernels from Debian's `linux-source-6.12` (6.12.113), differing in two
options, **`CONFIG_MODULES` off in all three** so that there is no loader at
all and "absent" cannot be confused with "blocked":

| kernel | config | netcfgd's apply |
|---|---|---|
| k0 | `NFT_NAT=y`, `NFT_MASQ=y` | **applies NAT**, `ok nat.replace` |
| k1 | neither | `NFT_MSG_NEWCHAIN` refused, **ENOENT** |
| k2 | `NFT_NAT=y`, no `NFT_MASQ` | `NFT_MSG_NEWRULE` refused, **ENOENT** |

**Identical to the autoload-blocked rig, state for state and message for
message.** `EOPNOTSUPP` again appeared nowhere. So 0291's claim is confirmed
rather than merely plausible, and the cheap rig is load-bearing evidence
rather than an approximation of it.

**k0 is the control and it is what makes the other two mean anything.** A
kernel this small refusing NAT is consistent with any of the things
`x86_64_defconfig` minus modules leaves out; the same kernel with the two
constructs restored applying NAT is what narrows the cause to the constructs.
The guest also reads `/proc/config.gz` and derives its own expectation from
it, so a run against the wrong bzImage fails rather than passing quietly --
`CONFIG_IKCONFIG_PROC` is in the config for that reason alone.

## What it corrected in netcfgd's own sentence

**There is no `CONFIG_NFT_CHAIN_NAT`.** `net/netfilter/Makefile` has
`obj-$(CONFIG_NFT_NAT) += nft_chain_nat.o`, so the module an operator loads
and the option a kernel builder selects are spelled differently. The hint
named only the module, which sends anyone configuring a kernel to search for
a symbol that does not exist -- found by making exactly that mistake, when
this tier's own config check refused a kernel configured with the invented
symbol. The sentence now carries both spellings for both constructs, and
`apply_kernel_test` holds it to that.

This matters more than it looks: netcfgd targets embedded routers, where a
kernel is built rather than modprobed, so the config symbol is the actionable
half for the audience most likely to meet the refusal.

## What this decides

1. **The blocked-loader rig is the standing test, and the kernel tier is the
   occasional control.** `make hull-natcap` runs in minutes and guards the
   sentences; `make kernel-natcap KERNEL_SRC=...` is by hand, wants a 1.6 GB
   source tree and three builds, and answers "is a blocked loader really the
   same as a kernel without it". Both stay.
2. **`natcap` does not pin a kernel**, which closes 0291's third open
   question. hull boots `/boot/vmlinuz-<release>` (`engine/qemu.c:1029`) and
   its `vm.kernel` `path:` form is declared but unbuilt (hull's §1188), so a
   pinned kernel cannot be expressed there today. The kernel tier drives qemu
   directly instead and collapses into another `tests/hull/` rig the day that
   key lands. Signalled to hull's inbox, 2026-10-24.
3. **A capability sentence is tested where the capability is absent, and an
   absence is arranged rather than waited for.** Blocking a loader is the
   cheap arrangement; compiling the construct out is the expensive one. The
   cheap one is enough once the expensive one has agreed with it, which is the
   general shape this record exists to record.

## What is not decided here

**Whether the kernel tier grows.** It has one payload and measures one op.
The remaining ruleset kinds from 0283 want sentences, and each wants a state
in the blocked-loader rig; whether any of them also wants a kernel is a
question per sentence, not a standing policy.

**Which kernel versions to claim.** Everything above is 6.12. netcfgd says
nothing about what 5.4 answers, and the version the sentence was written
against is not recorded in the sentence. A rig that boots several kernels
would need hull's `path:` form, so this waits on the same thing as point 2.
