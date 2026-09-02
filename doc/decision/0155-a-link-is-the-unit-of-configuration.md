# 0155: a link is the unit of configuration

Status: accepted -- shape 3a, in two passes, decided by the copyright holder
        2026-09-02
Date: 2026-09-02
Milestone: M9; model

The copyright holder's proposal: one list called `link`, holding ethernet
connections, aliases, wifi connections, modem connections and tunnel
endpoints together. The other lists stay and hold only the configuration of
the device itself -- the hardware. Plus two concepts on top: a link may
declare whether it is a candidate for the default route, and links may be
grouped so that only one member is active at a time.

This record works that through and measures what it costs. It does not choose
between the two shapes in section 3; that is the decision to be taken against
this text.

## 1. Why the current model is wrong, measured

Not an aesthetic judgement. The two types have converged on their own:

    Interface   (21 fields): name kind enabled mtu mac addressing routes dns
                             hooks on_drift master advertise forwarding
                             ingress_redirect qdisc nat guard link_settings
                             preference probe bridge_vlans
    WifiNetwork (13 fields): id ssid hidden security metric autoconnect
                             metered bssid roam addressing routes dns hooks
    Device       (5 fields): name managed on_unmanage wifi modem

    shared by Interface and WifiNetwork: addressing, dns, hooks, routes

`WifiNetwork` did not start with those four. It grew them one at a time,
because a wifi network needs exactly what an interface needs: addresses to
obtain, routes to install, a DNS scope, hooks to run. **Two types that
independently converge on the same four fields are one concept wearing two
names.**

The ranking pair is the same drift, one step further along. An interface
carries `preference` and a network carries `metric`; both are route metrics,
both lower-wins, and until [0154](0154-one-number-ranks-a-network.md) a
network *also* carried a higher-wins `priority`. Three numbers, two
directions, one idea -- and each had to be documented in terms of the others.
0154 removed one of the three and the remaining two are still two.

Worse, the machinery built to bridge the gap exists only because of it.
[0153](0153-a-network-is-ranked-against-a-link-not-against-a-radio.md) added
an association read to the observation, and a `metric` that overrides an
interface's `preference` while a radio is on that network -- all so a
*network* could be ranked against a *cable*. Under one list they are two rows
with one number, and none of that is needed.

**And `Device` is nearly empty**: five fields, two of which (`wifi`, `modem`)
are policy about connecting rather than about hardware. The type that should
hold the hardware holds almost none of it; `mtu`, `mac`, `qdisc`,
`link_settings`, `forwarding` and `nat` all sit on `Interface`.

### The live example

A laptop with one radio and two networks currently needs three block types
across two files:

    device wlp0s20f3 { wifi { autoconnect = true } }
    interface wlp0s20f3 { config = "dhcp" }

    network "EMP-XYLEM" { wifi { eap = "peap"; identity = "..." } }
    network "OpenPC.se" { wifi { psk = "@secret:OpenPC.se" } }

`interface wlp0s20f3 { config = "dhcp" }` is the tell. It exists to say the
radio does DHCP -- but DHCP is a property of *each network joined*, not of the
radio, and a machine that wants DHCP on one network and a static address on
another cannot say so here at all.

## 2. What a link is, and what a device is

**A link is a thing that can carry traffic**, and everything that follows from
that: how to attach, what addresses to get, what routes to install, what DNS
scope it brings, what hooks to run, how it ranks, whether it can be the
default route, what probe decides it is working.

**A device is a piece of hardware and the settings that belong to the hardware
whether or not anything is connected**: MTU, MAC policy, driver and bus path,
offloads, queueing discipline, whether netcfgd manages it at all, and which
backend drives it.

The test that decides which side a field falls on: **would this still mean
something if nothing were connected?** An MTU would. An APN would not.

    device                          link
    ------                          ----
    mac, mtu, qdisc, offloads       addressing, routes, dns, hooks
    driver, path, name_glob         metric, default-route candidacy
    managed, on_unmanage            probe, enabled
    backend (which supplicant)      attachment (which device carries it)
                                    how to attach: ssid+security, apn+sim,
                                    tunnel endpoint, vlan tag

`forwarding`, `nat` and `advertise` are the awkward third category: they are
about what the machine does *with* traffic on that link rather than about
either the hardware or the connection. They should stay with the link, since
they are meaningless without one.

## 3. Two shapes, and the choice between them

### 3a. A link is a profile

Links are candidates. Which are active is observed, not configured. This
generalises what wifi already does to everything.

    device eth0  { mtu = 1492 }
    device wlan0 { wifi { autoconnect = true } }

    link "desk-lan"    { attach = "eth0"; config = "dhcp"; metric = 100 }
    link "office-wifi" { attach = wifi; ssid = "OpenPC.se"; metric = 50 }

A laptop can hold two ethernet profiles -- dock and desk -- and the ranking
picks. `attach` may name a device, a device class, or match several.

**Cost:** `interface eth0` stops meaning "the configuration of eth0". Every
place keyed by kernel name has to learn that a link has its own id and a
separate attachment.

### 3b. A link is an instance

A link is a configured, named thing that exists -- close to today's
`interface`, with wifi networks folded in as links attached to a radio.

    device eth0 { mtu = 1492 }

    link eth0 { config = "dhcp"; metric = 100 }
    link wlan0 "OpenPC.se" { ssid = "OpenPC.se"; metric = 50 }

**Cost, and it is fatal rather than merely awkward:** this shape assumes a
device has one link, with wifi as the exception. **It does not** -- an
ethernet device carries several links too, because an alias is a link: its
own address, its own routes, its own metric. So the many-to-one relationship
is not a wifi special case to be carved out, it is what every device kind
does, and 3b would special-case the general rule.

An earlier draft of this record said "ethernet is basically 1:1". That was
wrong, and it was wrong in the direction that made 3b look cheaper than it
is.

### The worker's recommendation, which is not the decision

**3a**, and the corrected cardinality above is most of the argument. Every
device kind carries several links -- aliases on ethernet, networks on a
radio, APNs on a modem -- so there is no simple one-to-one case for 3b to
preserve. Section 4 is the rest of it: failover makes sense only if a link
can be inactive, and once a link can be inactive it is a profile whatever it
is called. 3a is the larger migration and the choice is the holder's.

## 4. Grouping is failover, and it already has a shape

The holder's second added concept, and the framing is theirs: **a group is
handled the same way as bonding or any other failover.** That is the
correction that makes this cheap rather than a new mechanism.

A bond already is this, one layer down:

    members    the candidates
    mode       what to do with them -- `active-backup` is "one at a time"
    miimon     the monitor that says when the active one has stopped working

A group is the same three things above the link layer, with the *probe* where
`miimon` is:

    group "uplink" {
        members = ["desk-lan", "office-wifi", "cellular"]
        mode    = "active-backup"
        probe   = "reaches-internet"
    }

**Same vocabulary, deliberately.** `members`, `mode` and a monitor are what a
bond already says, and reusing the words is what makes a group recognisable
rather than a second thing to learn -- the "one word per concept" rule in
`code-style.md` applied to a structure instead of a name. A group that
invented `candidates`, `policy` and `check` would read as unrelated
machinery.

It also means `mode` is open rather than binary. `active-backup` is the case
being asked for; a bond's other modes have no meaning here yet, but the field
does not have to be re-invented if one ever does.

What makes this worth doing is what it *absorbs*. Four mechanisms in this tree
are the same mechanism:

- **Bonding**, which is the same *shape* at the link layer, with `miimon` --
  though a bond is not itself a group; see section 6.
- **Wifi network selection.** One radio, many configured networks, one
  associated -- steered today by a derived join order (0154).
- **SIM source cycling.** [0152](0152-a-sim-source-is-kept-until-the-probe-says-otherwise.md)
  keeps a SIM source until the probe says otherwise, then advances and stops
  at the last. That is `active-backup` with a fallback rule.
- **Uplink ranking.** Which link carries the default route.

All four are "a set of candidates, one active, re-choose when a monitor says
the active one is not working". Today three of them have their own code.
**If failover is one concept, 0152's cycling machinery is a special case of
it rather than a feature of modems**, and failover between two ethernet
uplinks -- which nothing supports today -- comes free.

Open within this: whether the fallback rule is per-group (0152's "stop at the
last rather than starting over") or global, and whether a group may be a
member of another group. A bond can be a member of a bridge, so the nesting
question has a precedent to follow rather than a decision to invent.

## 5. Default-route candidacy

The holder's first added concept. A link declares whether it may carry the
default route; ranking then applies only among candidates.

    link "management" { attach = "eth1"; config = "dhcp"; default_route = false }

This is expressible today only by omission and luck: a link with a default
route gets one, and a management LAN that must never carry it has no way to
say so. NetworkManager spells the same thing `never-default`.

**Positive rather than negative** -- `default_route = true/false` rather than
`never_default` -- because the negative form makes the common case a double
negative and reads badly beside `metric`.

The interaction with ranking is worth stating: **candidacy gates, metric
orders.** A link that is not a candidate is not ranked at all rather than
ranked last, which is the same distinction 0153 drew between an interface's
carrier gating its routes and its metric ordering them.

## 6. The four awkward cases

**Bridges, bonds, VLANs. Decided: they are devices.** Not groups, and not
links. They are created by netcfgd *and* carry traffic, so they appear in both
lists joined by name -- the device entry says to make it, a link entry says
what it does.

**A bridge is not a group, and the distinction is not a technicality.** A
group is failover: its members are *substitutes*, each able to carry the
traffic alone, and exactly one does. A bridge joins its members: they are
*components*, the aggregate carries the traffic, and no member is the thing on
its own. A bond is the same -- even in `active-backup`, where only one member
passes traffic, the members are paths to one destination rather than
alternative connections.

**The test that sorts them is whether a member has its own addressing.**

    bridge port     no address of its own -- enslaved      -> a device
    bond slave      no address of its own -- enslaved      -> a device
    group member    its own address, metric, probe, dns    -> a link

So `members` on a bridge or bond names devices; `members` on a group names
links. Same word, because it is the same relationship -- a set this thing is
made of, or chooses between -- and the sentence above is what tells a reader
which. Sharing `members`, `mode` and a monitor between them is deliberate
(section 4); being the same *concept* is not claimed.

**And a bridge cannot become the link**, which is the question that had to be
asked because collapsing the pair would be simpler. It cannot, for the reason
that settled section 3: several links may attach to one bridge, since a bridge
can hold aliases. A one-block form would have to be repeated or referenced per
address, which is two blocks again with the relationship left implicit. The
same argument rules out collapsing a bond or a VLAN.

The split admits two states the model must answer for: a device with no link
(created and unconfigured -- a bridge waiting for its addresses, which is a
real state during boot), and a link naming a device that does not exist yet.
Today `InterfaceKind` conflates device and link, so neither state is
representable and both are silently impossible.

**Modem SIM and APN.** Currently `device.modem { sim = [...], apn = "..." }`.
Under the split, the APN is a *link* -- it is how the modem attaches and gets
an address -- and the SIM list is a *group* of links, one per source, with
0152's fallback rule. The modem device keeps only what is hardware. This is
the case that most clearly improves: an APN on a device block is wrong today
and is only there because there was nowhere else to put it.

**Aliases.** Several addresses on one ethernet device. Today they are entries
in one `addressing` list, so they cannot be individually named, ranked,
probed, grouped or brought down. As links they become rows, each with its own
metric, probe and default-route candidacy.

**This is the case that settles section 3 rather than merely benefiting from
it.** An alias is a second link on a device that is not a radio, so
many-links-to-one-device is not wifi's peculiarity -- it is ordinary, and it
is already true on the plainest hardware there is.

**Tunnel endpoints.** A tunnel is already both device (it is created) and link
(it carries traffic), and it additionally *depends* on another link being up.
The split handles the first two; the dependency is a third thing neither list
expresses, and it is the case that most argues for taking this slowly.
[0047](0047-a-tunnels-address-stays-with-its-daemon.md) and
[0048](0048-a-tunnels-routes-arrive-through-the-report.md) already carve out
special handling here, and a restructure has to not lose what they settled.

## 7. Migration cost, measured

    134   sites in crates/ and backend/ keyed by an interface name
     27   of 154 decision records cite an `interface` or `network` block
      4   config block types affected: interface, network, device, access_point
      2   schema witnesses, both a MAJOR bump: fields move between types

Plus, per surface: the socket protocol (every verb naming an interface), the
C client and its struct definitions, the GUI's tabs and dialogs, the
NetworkManager adapter's mapping, secret naming (`@secret:<id>`), profile
directories, and hook references.

**Compare with what has just been done.** 0154 collapsed one field across the
tree: 33 files, 450 insertions, 173 deletions, one major schema bump. This is
larger by a wide margin -- it moves fields between types rather than removing
one -- but the same shape of work, and 0154 is a fair unit for estimating it.

**The largest single cost is not code.** It is that `interface <name>` is the
addressing scheme for the whole system, including on the wire and in
`/etc/netcfgd/conf.d`. Under 3a that stops being true.

## 8. What breaks for an existing config

The live configuration on the machine this was written on, in full:

    device wlp0s20f3 { wifi { autoconnect = true } }
    interface wlp0s20f3 { config = "dhcp" }
    network "EMP-XYLEM" { wifi { eap = "peap"; identity = "..."; password = "@secret:EMP-XYLEM" } }
    network "OpenPC.se" { wifi { psk = "@secret:OpenPC.se" } }

Under 3a it becomes:

    device wlp0s20f3 { wifi { autoconnect = true } }

    link "EMP-XYLEM" {
        attach = wifi
        ssid   = "EMP-XYLEM"
        wifi   { eap = "peap"; identity = "..."; password = "@secret:EMP-XYLEM" }
        config = "dhcp"
    }
    link "OpenPC.se" {
        attach = wifi
        ssid   = "OpenPC.se"
        wifi   { psk = "@secret:OpenPC.se" }
        config = "dhcp"
    }

Three block types become two, the orphan `interface wlp0s20f3` disappears, and
`config = "dhcp"` moves to where it is actually true -- per network, so the
two could differ.

**Every existing config needs rewriting**, and it cannot be done by a
mechanical rule in general: deciding which `interface` fields are hardware and
which are link is a judgement per field, and merging an `interface` with the
`network`s that used its radio is a judgement per machine. A converter could
do the common cases and refuse the rest, which is the shape
`evidence.md` asks for -- state the invariant, check it, refuse to write when
it fails.

**A `priority`-style diagnostic is not enough here.** 0154 could tell an
operator "write `metric` instead, and invert it". There is no one-line
instruction for this; it needs a converter and a release note.

## 9. What this does not do

**It does not fix the outage of 2026-09-02.** A laptop running netcfgd lost
carrier nine times in an hour and never recovered, and that is unexplained --
see `project.md`. This record is a design improvement and must not be allowed
to read as a response to that fault.

## 9a. Pass 1, field by field

The test from section 2, applied to every field `Interface` carries today:
**would this still mean something if nothing were connected?**

    field              to        why
    -----              --        ---
    kind               device    what to create -- a bridge exists before it
                                 carries anything
    master             device    which bridge or bond this is a port of; a
                                 port relationship, not a connection
    mtu                device    a property of the hardware
    mac                device    MAC policy belongs to the adapter
    link_settings      device    speed, duplex, autonegotiation
    qdisc              device    queueing on the egress of the device
    ingress_redirect   device    the ifb pairing; goes with qdisc
    bridge_vlans       device    per-port VLAN filtering -- a port's config

    addressing         link      the connection's addresses
    routes             link      what it installs when up
    dns                link      the scope it brings
    hooks              link      run for this connection
    probe              link      decides whether this connection works
    preference         link      how this connection ranks (becomes `metric`)
    nat                link      about traffic, meaningless with none
    advertise          link      router advertisements onto this connection
    forwarding         link      what the machine does with traffic here
    on_drift           link      policy about this configuration
    name               both      the join key between the two lists

Three are genuine judgement calls and are recorded as such rather than
presented as obvious:

- **`enabled`** goes to the **link**. It reads as an admin up/down of the
  device, and under 3a it is not: "keep this configuration and do not use it"
  is a statement about a connection, and a device that is down is a different
  thing an operator may also want to say. Splitting those two into one field
  is what makes it look like a device property.
- **`guard`** goes to the **device**. It refuses to touch a thing, and the
  thing being protected is hardware somebody else may be using -- the same
  register as `managed`, which is already on the device.
- **`forwarding`** goes to the **link**, though it is a sysctl on the
  interface. It is about what the machine does with traffic, and a machine
  with no connection forwards nothing.

**Pass 1 introduces no new concepts.** No attachment, no groups, no
default-route candidacy, no folding of `network`. Eight fields move to the
side of a line that already exists, which is what makes it a separable pass
rather than the first half of one big one.

## 10. Decided, and what is still open

**Decided by the copyright holder, 2026-09-02:**

1. **Shape 3a** -- a link is a profile. Which links are active is observed,
   not configured.
2. **Two passes**, at the price of two migrations for anybody who has written
   a config:
   - **Pass 1: separate device from link.** Move `mtu`, `mac`, `qdisc`,
     `link_settings` and the rest of the hardware fields off `Interface` and
     onto `Device`, which today holds five fields and almost none of the
     hardware. No new concepts, no `network` folding: this pass only puts
     existing fields on the right side of a line that already exists.
   - **Pass 2: fold `network` into `link`**, and introduce attachment,
     default-route candidacy and groups.
3. **Bridges, bonds and VLANs are devices** -- section 6.

**Still open, and not blocking pass 1:**

- Whether groups land in pass 2 or a third pass. They are the best argument
  for the restructure and also the largest new mechanism, and pass 2 is
  already large without them.
- Whether a group's fallback rule is per-group or global, and whether a group
  may be a member of another group.
- How a tunnel's dependency on another link being up is expressed. Neither
  list says it today and the split does not add it.
