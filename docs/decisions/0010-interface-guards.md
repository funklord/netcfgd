# 0010: netcfgd refuses; it does not orchestrate

Status: accepted
Date: 2026-07-28
Milestone: declaration and refusal in M1, discovery and veto hooks in M2

## Context

Something depends on an interface. The root filesystem is NFS-mounted over
it, a database is replicating across it, the operator is connected over it, a
container's veth is enslaved to it. netcfgd will happily take that interface
down because a config file changed, and the first anyone knows is that the
machine stopped.

Two mechanisms exist already and neither is sufficient.

**The veto hook.** Design section 5.2: a non-zero exit from a `pre_*` hook
aborts the transition. Real, and it is how netifrc handles this -- its default
`predown()` runs `is_net_fs /` and refuses to down an interface carrying an
NFS root. But it fires at *apply* time, which means `ncfg plan` said "will
down eth0" and then eth0 did not go down. A plan that lies is worse than no
plan, and being able to see what will happen before it happens is the product.

netifrc's version has a second problem worth naming, because it is an argument
about mechanism rather than about netifrc: the NFS-root protection lives
*inside* the default `predown()`, and net.example says plainly that "if you
specify a `predown()` function you will override that logic". So the
protection is opt-out by accident. Anyone who writes a `predown` hook for an
unrelated reason silently loses it.

**Commit-confirm.** Protects the operator from locking *themselves* out. It
does nothing about breaking something else on the machine, and the automatic
revert arrives minutes after the NFS mount has already hung.

## Decision

**An interface may declare a guard, and netcfgd refuses to plan a disruptive
action against a guarded interface.** The refusal happens in the planner, so
it is visible in `ncfg plan` before anything runs.

```
interface eth0 {
	config = "192.168.1.10/24"
	guard  = "nfs root"
}
```

Three layers, in order of how much netcfgd has to know:

**1. Declared (M1).** The operator states that something depends on this
interface, in their own words. The words matter: a refusal that says only
"refused" is not a diagnostic, and one that says "refused: nfs root" tells the
reader what to go and stop. netcfgd needs to understand nothing.

**2. Discovered (M2).** netcfgd can answer one important question by itself
without knowing what a service is: *is a network filesystem mounted over a
route that leaves this interface?* That is `/proc/mounts` plus the routing
table, and it covers the NFS- and iSCSI-root cases that netifrc hard-codes.
Discovery adds an implicit guard; it never removes a declared one.

**3. Delegated (M2).** The `pre_down` veto stays exactly as section 5.2
specifies, for everything netcfgd cannot know. But a plan containing a
guarded-phase hook now *says* it might be refused, so the plan stops lying.

### Disruption is a property of the action, not of the link

"Do not remove the interface" is too narrow. Changing the address on the
interface carrying an NFS mount breaks it exactly as thoroughly as downing the
link, and so does enslaving it to a bridge, which moves its addresses. So each
op is classified, and a guard blocks the disruptive ones:

| Disruptive | Not disruptive |
|---|---|
| `link.down`, `link.delete` | `link.create`, `link.up` |
| `link.set_master`, `link.unset_master` | `addr.add`, `route.add` |
| `link.set_mac`, `link.set_mtu` | `backend.start` |
| `addr.del`, `route.del` | `dns.apply`, `hook.run` |
| `backend.stop`, `wifi.disassociate` | the `commit.*` family |

`link.set_mtu` is on the disruptive side deliberately. Lowering an MTU
interrupts traffic in flight and raising it can black-hole a path until PMTU
discovery catches up, and a guard that permits it in order to be convenient
would be a guard nobody can rely on.

### netcfgd refuses, it does not orchestrate

It will **not** stop the thing that depends on the interface, wait for it, or
order itself against it. That is configuration management, which design
section 1.5 excludes by name, and it would mean netcfgd learning what a
service is -- which would drag in the init system that section 14 exists to
stay out of.

This is the sibling of decision 0009's rule. That one says netcfgd configures
and does not serve; this one says it refuses and does not orchestrate. In both
cases the boundary is what keeps the dependency set at libc and the kernel.

### The escape is explicit and names its target

```
ncfg apply --allow-disruption eth0
```

Not `--force`. A blanket override is the flag people alias in their shell and
then stop reading, and it consents to disrupting everything including the
interfaces they had not thought about. Naming the interface makes the operator
say which dependency they have dealt with, and leaves the other guards
standing.

## Consequences

**`ncfg plan` gains a third thing to report.** Actions, warnings, and now
refusals: what netcfgd declined to do and why. That is a first-class list
rather than a warning string, because "what did it decline?" is a question a
script needs to answer as well as a human, and because burying it in warnings
is how it gets ignored.

**A guard can wedge a machine into a state its config cannot reach.** Guard an
interface, change its address, and the plan refuses forever until somebody
passes `--allow-disruption`. That is the intended behaviour and it is still a
sharp edge, so the refusal has to print the exact command that resolves it.

**There is a race, and it is not closable.** Between deciding an interface is
unguarded and executing `link.down`, an NFS mount can appear. Discovery
narrows the window and the `pre_down` veto narrows it further, since it runs
immediately before the transition, but nothing makes it zero. Say so in the
documentation rather than implying a guarantee: guards are a safety catch
against a config change nobody thought through, not a lock.

**Drift interacts with guards and the answer is the safe one.** An interface
whose `on_drift` is `reconcile` and which is guarded does not get reconciled
if reconciling it would be disruptive. Drift reporting is unaffected --
reporting is never disruptive.

## Alternatives considered

**Rely on the `pre_down` veto alone, as netifrc does.** Rejected on the plan
argument: apply-time refusal makes `ncfg plan` wrong, and being able to see
the change before it happens is the whole product. The opt-out-by-accident
problem in netifrc's default `predown()` is a second reason not to put the
common case in a hook.

**Infer dependencies from the init system.** OpenRC has `rc_net_eth0_need` and
systemd has ordering; either could tell netcfgd what is running. Rejected:
section 14 makes netcfgd init-agnostic by construction, and this would make it
init-aware in the deepest possible way. The `pre_down` hook is where a site
that wants that binds it, in ten lines, with netcfgd knowing nothing.

**Let netcfgd stop the dependency and restart it afterwards.** Rejected under
the rule above. It is the single most requested feature of every tool that has
ever grown into a configuration manager, and it is how netcfgd would stop
being a network configuration tool.

**A boolean `critical = true` rather than a reason string.** Rejected because
the refusal text is the whole value of the feature. "eth0 is critical" sends
the reader to look for what is critical about it; "eth0: nfs root" tells them.

**Automatic waiting or retry.** Rejected: a plan that blocks is a plan that
hangs a boot. Refusing immediately with an actionable message is better
behaviour and much easier to reason about.
