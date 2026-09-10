# 0190: `network-online.target` needs something to wait on

Status: accepted
Date: 2026-09-10
Milestone: M8; the boot and startup audit, found an hour after netcfgd took
over the reporting machine

## The question

> now check the boot and startup errors too

## What was measured

`network-online.target` is a promise to the units ordered after it -- on this
machine `docker.service`, `cups-browsed.service` and `fwupd-refresh.service`
-- that the network can be reached. **Nothing in systemd makes that promise
true.** Every manager ships a helper that blocks until its own idea of "up"
holds, and the target is reached when the helper finishes.

An hour after `netcfgd_select.sh netcfgd`:

    connman-wait-online.service              masked
    NetworkManager-wait-online.service       masked   -> /dev/null (13:23)
    systemd-networkd-wait-online.service     masked   -> /dev/null (13:23)

All three masked by netcfgd's own selector, correctly -- they belong to the
daemons being stood aside -- and **netcfgd shipped no replacement**. So the
target was reached immediately at boot, with three services ordered after it
and nothing holding it.

## The two halves

**`ncfg wait-online [SECONDS]`**, which blocks until the machine has a global
address outside loopback and a default route, then exits. Thirty seconds by
default, which is `NetworkManager-wait-online.service`'s own figure.

*Online* here is deliberately not "every interface the document names": that
would keep a laptop waiting for a dock it is not plugged into. It is what the
other helpers wait for and what the services after the target actually need.
A link-local address does not count -- `169.254/16` and `fe80::/10` are what a
machine has when DHCP did **not** answer, which is the state this exists to
tell apart from success.

It observes locally rather than asking the daemon. This runs while the machine
is still coming up, and a helper that needs the control socket to be listening
cannot report on the seconds before it is.

**`netcfgd-wait-online.service`**, `Type=oneshot`, `Requires=netcfgd.service`,
`Before=network-online.target`, `WantedBy=network-online.target` -- the shape
NetworkManager's own unit has, for its reasons. `Requires` rather than `Wants`
because a machine whose network daemon failed to start is not one where
waiting for the network can succeed, and pretending otherwise moves the
failure to whatever starts next.

## Enabled by the selector, not by the package

The package installs it and enables nothing, which is 0113's rule: installing
netcfgd must not make it the machine's network daemon. **`bring_up` enables
any `*-wait-online.service` in the selected manager's unit list** and starts
none of them -- enabling puts it in `network-online.target.wants` for the next
boot, which is when it is wanted, and starting it here would block the
selector until the network is up, which is not what selecting a daemon means.

Standing netcfgd down masks it with the rest of netcfgd's units, and
`netcfgd_select.sh none` unmasks it, both through machinery that already
existed: it is in `unit_of netcfgd`, so every list that walks a manager's
units now walks this one.

## What is checked

A unit test on the predicate, which is where the judgement is: loopback is not
being online, `169.254` is not, `fe80::` is not, an address with no default
route is not, and the pair together is. Sabotage confirms -- dropping the
link-local exclusion turns it red.

`make packaging` refused the first version of this: `install-systemd` put a
file in place that `uninstall` did not remove, and the uninstall gate said so
by name. That gate is older than this decision and caught it in the first
minute.

## What is not covered

Whether the *right* interface is up. A machine with two uplinks reaches this
target when either answers, which is what every other implementation does and
is a weaker promise than it sounds. Naming an interface would need a config
key and an argument about what "the network" means on a multi-homed host;
neither is written down yet, and inventing one here would be guessing at a
question nobody has asked.
