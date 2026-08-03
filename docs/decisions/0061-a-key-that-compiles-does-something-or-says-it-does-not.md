# 0061: A key that compiles does something, or says it does not

Status: accepted
Date: 2026-08-03
Milestone: asked from outside -- "what is missing to use this as a daily driver?"

## Context

The question was what a laptop still needs. Answering it honestly meant reading
the config surface rather than the feature list, and four keys turned out to
compile and do nothing at all:

| key | what happened |
|---|---|
| `global { hostname = ... }` | lowered into the document, never applied |
| `wifi { portal_check = true }` | lowered into the policy, never read |
| `device { match { ... } }` | **no syntax at all** -- a compile error |
| slaac `privacy` | **no syntax at all** -- a compile error |

The last two are honest by accident: the model carries the field, the language
has no way to reach it, and an operator who tries gets an error naming the line.
The first two are the bad kind. `ncfg plan` said nothing, the apply succeeded, and
the machine did not do what the file asked.

**And the `ethtool` block already had the right answer**, field by field: "`wol`,
`rx_ring` in the ethtool block are recognised but not applied by this build". That
warning is why the ethtool gap has never confused anybody, and its absence is the
whole of this decision.

## Decision

**Two are implemented, two are reported, and the reporting says why.**

### `slaac privacy prefer_temporary` -- implemented

RFC 4941 temporary addresses, which is the one of the four with a real answer for
a laptop: the host generates a second address from a random interface identifier
and prefers it outbound, so a server on the far side does not see one stable value
for weeks.

It is `net.ipv6.conf.<iface>.use_tempaddr`, written per interface, with the
`forwarding` sysctl's shape at every layer -- observation, comparison, `/run`
record of what netcfgd itself set, and the withdraw direction that only fires
where netcfgd is what set it. A machine whose `sysctl.conf` prefers temporary
addresses globally keeps them.

**`2`, and only `2`, is what the document can ask for.** The kernel's `1`
generates a temporary address and still prefers the stable one, which is a state
nothing here can request -- so the observation reads `== 2` rather than `!= 0`,
and an interface sitting at `1` is corrected. A reader that accepted anything
non-zero would agree with a kernel that is not doing what was asked.

**What netcfgd owns is the sysctl, not the address.** The kernel builds the
temporary address when it next processes a router advertisement. Nothing here
waits for one, and a test that did would be testing radvd.

### `hostname = "name"` -- implemented

`/proc/sys/kernel/hostname`, which is the running value. Not `sethostname(2)`,
which would be an `unsafe` FFI call in a crate that forbids it, and not
`/etc/hostname`, which is what the init system reads at boot and is not netcfgd's
to write. So it does not survive a reboot on its own: the first apply after boot
is what puts it back, which is the honest behaviour rather than netcfgd taking
over a file the distribution owns.

One direction only. There is no withdraw, because the value to restore would be
whatever `/etc/hostname` said, which netcfgd does not know and must not guess.

The name is validated at compile time -- letters, digits, hyphens, dots, RFC 1035
lengths -- because the kernel's refusal is an `EINVAL` on a file write that names
neither the key nor the line.

### `hostname = "dhcp"` -- reported

netcfgd delegates DHCP ([0004](0004-dhcpv4-client-sourcing.md)) and never sees the
lease, so the name a server offered is known only to the client. It is also the
class of thing [0049](0049-a-server-may-name-resolvers-not-where-queries-go.md)
already decided: a remote server may hand out configuration, and changing the
machine's *identity* is not configuration it gets to apply by connecting.

The plan says that, and names the mechanism that does exist -- a hook with the
client's environment.

### `portal_check` -- reported

A captive portal check means fetching a URL and looking at what comes back.
**netcfgd will not have a hard-coded one.** A network daemon that reaches out to a
fixed address to decide whether the internet works is a decision for the operator:
it is a third party learning when the machine joins a network, and it is the
wrong default however carefully the address is chosen.

If this becomes a feature it is `portal_check = "https://example.com/generate_204"`
-- an operator's URL, or an operator's hook -- and not a boolean with a default
inside netcfgd. Until then the plan says it does nothing.

## What the same pass found, which is bigger

**Nine of the eleven hook phases are recognised and never run.** Only `pre_up` and
`post_up` are ever emitted. The other nine -- `up`, `pre_down`, `down`,
`post_down`, `carrier`, `lease`, `roam`, `portal`, `drift` -- are parsed,
materialised into `/run/netcfgd/hooks/`, hashed into the document, and never
executed.

That reads exactly like a working feature: the script is on disk with the name the
config gave it, and nothing anywhere says it will not run. **`PreUp`'s own
documentation pointed at two of them** as the thing to use instead, which is the
sharpest form of the problem -- a comment recommending a feature that does not
exist.

So a plan now names each unfired phase, per interface, once. Implementing them is
a separate piece of work with its own ordering questions (a `down` hook has to run
before the teardown that would take the interface away, and 0011's constraint
about what a hook can see applies again). What this decision fixes is the silence.

## Consequences

- Two new ops, `sysctl.set_privacy` and `hostname.set`, and two new observed
  fields. Both witnesses moved: minor additions.
- `hostname.set` is the first op that deliberately names no interface. A guard
  cannot refuse it, which is right -- the machine's name is not a device's.
- The `slaac` warning that said "not yet applied by this build; it lands with M4"
  is gone. It was stale (M4 shipped) and misleading (SLAAC is the kernel's own,
  and `delegation.sh` watches an address appear). What replaced it is the trap
  that is actually there: `accept_ra` defaults to ignoring advertisements on a
  *forwarding* interface, netcfgd does not manage that sysctl, and a router asking
  for `slaac` on its WAN gets nothing.
- `HookPhase::name` moved into the model. It had been two copies, one in
  `netcfgd-apply` for `NCFG_PHASE` and one in `netcfgd-host` for the materialised
  filename -- two tables whose drift would give a script an environment naming a
  phase its own file is not named after.
- `Device.match` is still unreachable from the config, and is now written down as
  such rather than looking like a feature. Implementing it means reading a driver
  name and a device path out of `/sys`, which is a feature and not a warning.
- `+8 KB` installed, with a line in `size-budget.txt`.
