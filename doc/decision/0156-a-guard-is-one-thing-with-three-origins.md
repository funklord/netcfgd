# 0156: a guard is one thing with three origins

Status: accepted
Date: 2026-09-02
Milestone: M9; model

Split out of
[0155](0155-a-link-is-the-unit-of-configuration.md), where it grew inside a
bullet about which of the two types `guard` belongs to. It stopped being a
placement question several exchanges in: what a guard *is* turned out to be a
design of its own, with an origin, a lifetime, a count, an override and a
client surface. A record that answers "where does this field go" is not the
record a reader looking for that will open.

**Everything here is pass 2 and none of it is built.** Pass 1 needed only the
placement, which 0155 keeps: a guard belongs to the link, because what depends
on a guarded interface is the connection rather than the adapter.

## The shape, in one place

    a guard is (name, reason), and a link is guarded while it holds any

    origin          lifetime                        who may remove it
    ------          --------                        -----------------
    declared        while the document says so      whoever edits the file
    scripted        while the script says so        the script, by answering
    held            until released, stop or reboot  the holder

`hold` is the verb: guards hold a link, a resync holds a guard, a guard is
taken and released.

The two are not duplicates, and four states are being asked to fit in fewer
words than there are states:

    device.managed = false   never touch this hardware at all
    link.managed   = false   never touch this connection; the device is
                             still netcfgd's
    guard                    manage this link and refuse to disrupt it
    enabled = false          keep this configuration and do not use it
    up / down                an operational action, not a configuration

**`managed` belongs on both, decided by the copyright holder 2026-09-02.**
They are not the same statement once a device carries several links. The
case that needs it: netcfgd owns `eth0` and its address, and a second
address on the same interface is a cluster VIP that keepalived moves. Today
that is inexpressible -- `managed = false` on the device hands over the
whole adapter, which is far more than was meant. As links, the VIP is one
row with `managed = false` beside a row netcfgd owns.

**`guard` belongs on both as well, and it is inherited downward.** Set by
the copyright holder 2026-09-02. A guard on a link must protect every device
that link runs over, or it protects nothing: guarding the NFS-root link and
then reconfiguring the bond underneath takes the link down by another route,
and the refusal an operator was promised never fires.

So the rule is that a guarded link guards its whole stack:

    link "nfs-root" (guarded)  ->  bond0  ->  eth0, eth1

all four refuse disruptive actions, and only the link had to say so.

A device may also be guarded in its own right, for the case where the thing
depending on it is not a link netcfgd knows about -- an adapter passed
through to a virtual machine, say.

**Inheritance is the reason this cannot be left to an operator writing
`guard` in several places.** A stack is discovered rather than declared: the
members of a bond, the parent of a VLAN, the ports of a bridge. Asking
somebody to restate a guard at every level is asking them to keep a
derivation up to date by hand, and the failure is silent.

**The override already exists and must not be duplicated.** Asked whether a
`-f`/`--force` was needed to get past a guard, the answer measured in the
tree is no: `Builder::refused` lets an op through when its interface is in
`PlanOptions::allow_disruption`, and the refusal it raises otherwise carries
`override_with: "ncfg apply --allow-disruption <iface>"` -- it hands the
operator the exact command. The help text says the design out loud:

    --allow-disruption IFACE consent to disrupting one guarded interface;
                             repeatable, and deliberately not a blanket --force

That is stronger than a force flag and the difference is tested: consent for
`eth0` releases eth0's stale address while `eth1` stays protected, which a
blanket flag could not express. `--strand-credentials DEV` is the same shape
for a different refusal. **So pass 2 adds no new escape hatch**, and anybody
reaching for one should read this paragraph first.

**What inheritance does open is whether consent inherits too, and it has no
obvious answer.** Once a guarded link protects its whole stack:

    link "nfs-root" (guarded)  ->  bond0  ->  eth0, eth1

what should `ncfg apply --allow-disruption nfs-root` release?

- **Only the named link.** Consent then does not reach `bond0`, so the
  action the operator just consented to is still refused -- by a guard they
  never wrote, inherited from the link they were talking about. The override
  fails at exactly the moment it is needed.
- **The whole stack the guard reached.** Consent then silently covers three
  devices the operator did not name. That is defensible, since the guard
  they are overriding is the one that spread there -- but it widens consent
  past what was typed, which is the property `--allow-disruption` exists to
  avoid.

**Decided by the copyright holder 2026-09-02: consent follows the guard's
derivation.** Consenting to a link releases a device only where the guard
reaching that device came from the link being consented to. A device's own
`guard`, and a guard inherited from any other link, stay in force.

It is the only one of the three that gets the two-link case right. A NIC
carrying two guarded links is protected by both, and consenting to one must
leave the other's protection standing -- which "only the named link" cannot
do (it releases nothing) and "the whole stack" cannot do either (it releases
both).

**This makes an inherited guard a set with provenance, not a flag.** A
device does not record *that* it is guarded but *by what*: each entry is the
link the guard came from and the reason that link stated. Consent removes
the entries derived from the consented link; the action is refused if any
entry remains.

**And the refusal must name the source, not the device.** This is where the
"name a command that works" constraint stops being a slogan. A refusal
raised against `eth0` because `nfs-root` is guarded has to offer

    ncfg apply --allow-disruption nfs-root

because `--allow-disruption eth0` would release nothing: eth0 has no guard
of its own, it has an entry derived from `nfs-root`. Offering the device
name is the failure this whole question exists to avoid, and it is the
natural thing to write, since the device is what the op names.

Where several entries stop one action, the refusal names all of them: an
operator told about one guard, who consents to it and is refused again, has
been sent round the loop the second option was rejected for.

**A guard is a set of named holds, and that is the mechanism rather than an
implementation detail.** Proposed by the copyright holder 2026-09-02, and it
generalises the derivation rule above rather than sitting beside it: once a
device records *which* guards reach it, the natural shape is a semaphore.
Anything that needs a link undisturbed takes a named hold; the guard lifts
when the last holder releases it.

    guard "nfs-root"    taken by the config, because a link block says so
    guard "db-replica"  taken at runtime by something that needs the link
    guard "session"     taken by the daemon for the link an operator is on

Three things fall out, and the third is the one that makes it worth doing:

- **Derivation is a holder.** A guard reaching `eth0` from `nfs-root` is the
  hold `nfs-root` placed there. Consent releases that holder's hold and
  nothing else, which is exactly the rule decided above -- so the two are
  one mechanism and not two that must agree.
- **`--allow-disruption` releases a hold by name.** It already takes a name
  and is already repeatable, so the flag does not change; what changes is
  that the name it takes is a holder rather than an interface, which is what
  the refusal already has to print.
- **A guard can be taken by something that is running**, which config alone
  cannot express. Today `guard` is a line in a file, so protecting a link
  for the duration of a database resync means editing configuration and
  remembering to edit it back. A hold can be taken and dropped by the thing
  that actually knows, and the failure mode of forgetting is visible --
  a hold nobody released is a hold with a name on it.

**`guard` is not a second concept, and should not survive as one.** Asked
why a guard is needed at all once holds exist, the answer is that it is not:
a declared guard *is* a hold whose holder is the document. This record
already says derivation is a holder; the configuration is one too, and the
only thing that distinguishes the three is where the hold came from and how
long it lasts.

    hold = (name, reason)
      name    what consent releases and what a listing shows
      reason  what the refusal prints

So "guarded" stops being a field and becomes a derived predicate -- this
link holds at least one hold -- in the same way 0154 made one ranking out of
two. Keeping both would be the same mistake a third time: two mechanisms for
one idea, each documented in terms of the other.

**And holds are not restricted to guarded links, which would be circular.**
A hold is what makes something guarded; requiring the link to be guarded
first is requiring the answer before the question. It would also defeat the
case the mechanism exists for -- a resync taking a hold on a link nobody
thought to declare in advance, which is exactly the situation configuration
cannot anticipate. **Who may take a hold is a permission question**, settled
by the tiers in 0013, and not a property of the link.

**Consent ignores holds for one apply; it never deletes one.** That falls
out of collapsing the three sources into one set, and it is the behaviour
each of them separately wants. A config-declared hold is back on the next
reconcile whatever an operator consented to, because the document still says
so -- which is right, since consent is for an action and the declaration is
a standing fact. A runtime hold belongs to whoever took it, and an override
that deleted it would have one operator silently discarding another
process's statement. So `--allow-disruption <name>` means "proceed despite
this hold", never "remove it".

**One noun with an origin, which is what this tree already does.** The doubt
worth recording, because it was raised and it is a fair one: the three
sources behave differently enough that they might deserve different words --
a declared `guard` and a runtime `hold`. They have different lifetimes,
different failure modes, and different answers to whether an operator may
remove one.

The answer is the pattern already in `Origin`. An address can come from the
configuration, a DHCP lease, a router advertisement or link-local
autoconfiguration -- different lifetimes, different removal rules -- and
netcfgd calls them all addresses with an origin recorded. It does not call
a DHCP address a lease. That type's own comment is this argument in
advance: without knowing which source produced what, "the planner would
fight the DHCP client for ownership of its own lease". Which is precisely
why the gui needs a source column, and precisely the thing an origin field
is for.

So: one noun, `guard`, carrying where it came from. Two nouns would put the
difference in the type name, where every message would have to pick one and
every document would explain each in terms of the other -- the habit this
design has already produced three times.

**`hold` survives as the verb.** Guards hold a link; a resync holds a guard;
a guard is taken and released. That keeps the semaphore vocabulary, which is
the real thing the second noun was reaching for, without a second type to
keep in step.

**The name is `guard`, and the field becomes plural.** Asked whether the
collapsed concept should be called a hold instead, the answer is no, but it
is the closest of the naming questions in this record and the argument the
other way is real.

`guard` wins on incumbency and on cost. It is what the model, parser,
renderer, planner and refusal messages already say, 0010 is cited for it, and
configurations already contain `guard { reason = ... }` -- so keeping it
means no configuration migration for this key in a pass that has plenty. It
also reads correctly for all three sources now they are one set: declared in
the configuration, taken by a resync, inherited from another link.

**The case for `hold` is that the concept is now a reference count**, and
semaphore vocabulary is acquire and release. `guard` carries singular
baggage: it is `Option<Guard>` today, one per interface, which reads as a
boolean property rather than a set. That is the thing to be careful of
rather than a reason to rename -- the field becomes `Vec<Guard>` and says
so, and the verbs carry the counting: `ncfg guard add`, `guard drop`,
`guard list`. What would read badly is `guard` staying singular while
behaving like a set.

Recorded rather than left implicit because the reasoning is what would need
revisiting: if the rename is ever right, it belongs inside pass 2, where a
configuration migration is already being paid for, rather than as a second
one later.

**The name is optional to write and never absent in the model.** Proposed by
the copyright holder: an unnamed guard is one with an empty name, dropped by
dropping without a name, so a machine that needs one guard says one thing and
a machine that needs five says five. The graduation is right and it costs no
configuration migration -- `guard { reason = "nfs root" }` keeps working
exactly as written.

**The amendment is that an empty name is safe in the configuration and not at
runtime.** There is one document, so one unnamed guard, and nothing to
collide. There are many callers, so two processes each taking "the unnamed
guard" get one slot between them -- and the first release lifts it while the
second still needs the link alone. That is the exact failure the counting
exists to prevent, arriving in the case that looks simplest.

So a runtime caller that omits a name gets one derived from the peer.
netcfgd already reads `SO_PEERCRED` to decide the tier (0013), so it knows
who asked without being told. `ncfg guard drop <link>` with no name then
means "drop mine", which is what somebody typing it means, and two anonymous
holders no longer share a slot.

**Dropping everything is possible and asymmetric, and the asymmetry has to
be said out loud.** A config-declared guard cannot be dropped at runtime:
it is recompiled from the document, so it returns on the next reconcile.
`guard drop --all` therefore means every *runtime* hold, and it has to
report what it removed -- name, reason and holder for each -- because
removing three of somebody's holds silently is how a resync gets disrupted
by an operator who thought the link was idle. An operator who runs it and
finds one guard still standing must be told it is the document's and which
file says so, or they will run it again and conclude the command is broken.

**The gui edits them, and by this program's own rule a list of things earns
a tab.** The columns are the ones a person needs to decide whether to
override: the link, the name, the reason, and the source -- and the source
is not decoration, because it says which rows the window can actually remove
and which send the reader to a file. A view that offered a delete button on
a config-declared guard would be offering an action that undoes itself on
the next reconcile.

**A guard may hinge on a script, and where it can it should.** Proposed by
the copyright holder, and it is better than what the rest of this section
had settled on. The observation behind it: changing a guard should not
change the *configuration*, because editing a file is a reconcile with side
effects -- and a guard is normally something an automated process knows,
not a decision a person makes.

    guard {
        command = "/usr/local/bin/nfs-still-mounted"
        reason  = "nfs root"
    }

**The exit status is the answer**, which is 0119's rule for probes reused
rather than reinvented: netcfgd never has to decide what "still in use"
means, because the operator's program already does. Zero means still in
use and the guard holds, which is what `mountpoint -q` already answers.

**It solves the stale-hold problem outright for the automated case.** A
runtime hold whose holder died stays until the next stop or reboot; a
scripted guard whose subject went away clears itself the next time anything
asks, because the script says no. That is the open question above answered
rather than mitigated -- for everything that can be expressed as a
question, which is most of what takes a guard automatically.

**Evaluated lazily, and that is the difference from a probe.** A probe is
monitoring, so it runs on an interval; a guard only matters when something
wants to disrupt the link, so it runs then. A `guard` with an `interval`
would be a script running every thirty seconds for ever to answer a
question nobody asked.

**A script that cannot be run holds.** This is the direction the error has
to fall, and it is worth stating because both directions look defensible on
the page: a missing or broken guard script means netcfgd does not know
whether the NFS root is still mounted, and proceeding on not-knowing is how
the mount goes away. The refusal must say *which* of the two happened --
"the guard script says the link is in use" and "the guard script could not
be run" send an operator to different places, and
`--allow-disruption` is the way past either.

**It does not replace runtime holds, and neither replaces the other.** Set
by the copyright holder: both are wanted. An earlier draft said the three
"rank rather than compete", which reads as a preference order and is wrong.
They answer different questions, and a design with only one of them fails a
case the other covers:

    declared guard    the answer is always yes while this is configured
    scripted guard    ask this program; it knows and it cannot go stale
    runtime hold      the holder knows something no program can be asked

The third is not a fallback for the second. A resync that has reached step
four of nine can say so and nothing outside it can be asked -- there is no
file to stat and no mount to test, only a process that knows. Equally the
second is not a tidier version of the third: a script survives the death of
whatever set it up, which is the whole reason it cannot go stale.

**So all three are evaluated, and the refusal names every one that holds.**
The natural implementation short-circuits on the first hold and stops, and
that is exactly the behaviour rejected above: an operator told about one
guard, who consents to it and is refused again by a second, has been sent
round the loop the derivation rule exists to prevent. The cost of asking
every guard on a link is a handful of scripts on a rare action, and the
saving is a second round trip for a person.

**A scripted guard carries a name like any other**, so consent is uniform:
`--allow-disruption nfs-root` proceeds past the guard named `nfs-root`
whether it is declared, scripted or held, and nothing about the override has
to know which kind it was.

Two things this inherits from 0119 along with the shape. Its command is
privileged configuration, for the reason every command in a document is
(0117): a file that can name a program is a file that can run one. And it
does not port to a machine with no processes, which is the question
`project.md` records for the microcontroller port -- a scripted guard is
one more thing on the list that a callback would have to replace.

**Holds live outside the configuration, because they are runtime state.**
Set by the copyright holder 2026-09-02, and it separates two things this
record had been treating as one:

    declared guard   a standing statement -- "this link carries an NFS
                     root". True across reboots, part of how the machine is
                     described. Configuration.
    hold             a running thing saying "not right now". Runtime state.

The distinction does most of the work the open question was stuck on. **A
declared guard cannot go stale**, because it is not stored anywhere: it is
recompiled from the document on every load, so a guard whose reason no
longer applies is removed by editing the file that states it, like every
other configured fact. Only a *hold* can outlive its holder, which halves
the problem.

For the half that remains, netcfgd already has the right lifetime and it was
chosen for a different reason. The unit carries
`RuntimeDirectoryPreserve=restart` (0135), so `/run/netcfgd` survives a
restart and is removed on a stop or a reboot -- which is exactly what a hold
wants:

    restart   the hold survives, and it must: a restart is precisely when a
              half-finished resync is still half-finished
    stop      the hold goes, and netcfgd is managing nothing anyway
    reboot    the hold goes, and so has the process that took it

So there are three sources and one set, and only the middle one persists:

    configuration   declared guards, recompiled every load, never stale
    /run            runtime holds, taken over the socket
    derived         the link-to-device inheritance, computed per plan

What is left open is smaller than the original question and worth stating as
the whole of it: **a holder that dies without releasing leaves a hold until
the next stop or reboot.** That is survivable rather than fatal --
`--allow-disruption <holder>` already releases one by name, and the fix is
that holds must be *listable*, with each one saying where it came from, so
an operator asked to override can see what they are overriding. A hold
nobody can enumerate is the machine nobody can reconfigure; a hold they can
read and release by name is an inconvenience.

Pass 2 or later. Does not block pass 1b.

`link.managed`, `device.guard`, the inheritance rule and this question are
all pass 2: pass 1 adds no concepts.

The last has no expression today. `enabled = false` is the nearest thing
and it is a different statement -- it edits the configuration, where an
operator taking a link down usually wants it back on the next reconcile.
That gap belongs to pass 2, where a link is a profile and "which are
active" is already the question being modelled.
