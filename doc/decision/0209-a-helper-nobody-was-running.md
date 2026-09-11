# 0209: a helper nobody was running

Status: accepted
Date: 2026-09-11
Milestone: M9; putting netcfgd on a two-SIM LTE board

netcfgd has had cellular support since
[0044](0044-the-modem-helper-is-contained-the-way-an-adapter-is.md): three
helpers, a quirks table, an ordered SIM list, probe-driven fallback, and an
`ncfg modem` that reports what is in use. Asked whether netcfgd could actually
be put on a board with an EG916Q-GL and a two-SIM mux, the honest answer was
"most of it, and nothing starts the helper".

That is the gap this record closes. **Not by making netcfgd start it** -- 0044
is explicit that netcfgd starts and supervises backends and does neither here,
and that is still right. By making it possible to run, findable, and hard to
run wrongly.

## The AT port has no stable name

`/dev/ttyUSB3` is where the port was the first time somebody looked. The number
is assigned in enumeration order and a cellular module is reset as part of
ordinary operation -- **a SIM switch is a modem reset** -- after which the whole
block may land elsewhere.

So `packaging/udev/71-netcfgd-modem.rules` matches the module and the USB
interface number, neither of which moves, and gives the port a name that does
not either: `/dev/netcfgd-modem-at`.

The same rule sets `ID_MM_PORT_IGNORE=1`. ModemManager takes **both** AT ports
once the modem registers -- `ttyUSB2` only while unregistered, `ttyUSB3` as well
afterwards -- which is precisely when the PDP context first has an APN and
resolvers worth reading. Without the rule, `netcfgd-modem-at` loses the port at
the moment it becomes useful and reports the granted APN as "not known" for the
rest of the module's life ([0208](0208-the-apn-register-that-answers-with-the-question.md)).

**The rule is data about modules, and so is `modem-quirks`.** Two files holding
one fact is how the quirk somebody reads stops being the quirk that runs, so
`tool/modem_rules_gate.py` fails when they disagree -- including on the spelling
that looks right and matches nothing: the table's `at=3` is udev's `"03"`, and
`"3"` matches no device while reading correctly. `udevadm verify` runs beside
it for the syntax, because a rules file that does not parse fails silently and
leaves the port unnamed with no message anywhere.

## And nothing ran the helper

`packaging/systemd/netcfgd-modem-at@.service`, instanced on the interface the
module presents. It is installed and enabled by nobody, which is the same
standing as `sim-select.example`: a worked example that happens to be correct,
rather than an integration netcfgd grew.

Two settings are deliberate and both have precedent in the daemon's own unit.
`Restart=always` rather than `on-failure`, because the helper exits *cleanly*
when its port goes away and that is what a modem reset looks like from here --
`on-failure` would leave the modem down after exactly the event it exists to
recover from. And `StartLimitIntervalSec=0`, because a board switching SIM
twice in quick succession would otherwise spend systemd's five-starts budget
and end with no modem helper and nothing that will ever try again
([0188](0188-a-network-daemon-does-not-give-up-restarting.md)).

## The selector's gate found the part that was missed

`tool/select_gate.py` refused the new unit: every unit this project installs
must be named by a `unit_of` arm, or no selection can stand it down.

**It was right.** A modem helper left running while a machine switches to
NetworkManager is two masters on one module, which is the failure the whole
script exists to prevent. It is now in netcfgd's arm, **last**, because
`bring_up` enables and starts only the first name -- and which interface a
module presents is the operator's to say, not something selecting netcfgd
should switch on.

Standing down a template needed `stand_down` to grow a case: a template never
runs, its instances do, and they are named for something the script cannot
know. So the instances are stopped and disabled by glob -- systemctl(1) matches
globs against units in memory, and silently skips when none are -- and the
*template* is masked, which is what stops any future instance starting.

## The race that ordering does not fix

The helper takes the APN from the file netcfgd publishes. netcfgd writes that
file when it **reconciles**, not when it starts, so an init system starting
both together loses the race however the units are ordered.

With no APN the helper sets none, and on a module that dials its own context
the moment it registers that means attaching on whatever the network gives a
blank request -- which, measured, answers ICMP everywhere and routes almost
nothing. Half a second of ordering produces a link that looks up and carries
no traffic.

So the helper **waits** for the file, bounded, and carries on either way. The
file's existence is what separates "netcfgd has not spoken yet" from "netcfgd
has nothing to say": a device with no `modem` block never gets one, and holding
a modem down for ever over a file that is not coming would be worse than
attaching without an APN. `After=netcfgd.service` is in the unit too, because
it costs nothing and makes the wait the exception rather than the mechanism.

The test writes the file a second into the wait, from a subshell, so what is
checked is that the helper was still waiting rather than that it was lucky.
With the wait removed it attaches on a stale context instead.

## What is still not possible

**Switching SIM still needs a hook somebody writes.** netcfgd chooses the
source, records what worked and publishes it; driving the mux select line is
board enablement and 0150 keeps netcfgd out of it. The example carries the
hazards measured on a real board -- a `gpioset` that holds the line and hangs
the hook, an expander that does not fail safe on release, a polarity the
schematic gives backwards -- and the two lines that matter are still the
operator's.

**And the ICCID is not visible anywhere netcfgd reports.** It is the only
reliable discriminator of which SIM source a module is actually reading, the
AT helper can read it, and `ncfg modem`, `ModemStatus` and the gui all carry
nothing about it. That is the next piece rather than one this record makes.
