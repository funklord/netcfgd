# The interface report

**Status: stable. This is a contract, not an implementation detail.**

Something that is not netcfgd brings an interface up -- a modem helper connects a
cellular bearer, `openvpn` negotiates a tunnel -- and writes down what the far
end gave it. netcfgd reads that file and treats it the way it treats a lease. The
two halves do not otherwise know about each other -- no library, no socket, no
bus.

This document is the whole interface. If you are writing something that reports,
you should not need to read netcfgd's source, and if you find you did, that is a
bug in this page.

Decisions [0044](decisions/0044-the-modem-helper-is-contained-the-way-an-adapter-is.md)
and [0045](decisions/0045-the-contract-is-the-decision-and-the-helper-is-plural.md)
say why it is shaped this way, and
[0047](decisions/0047-a-tunnels-address-stays-with-its-daemon.md) says why it is
not called the modem report even though a modem helper wrote the first one:
nothing in it is a modem's, and a name that says otherwise sends the next writer
looking for a document that does not exist.

## Where

```
/run/netcfgd/reported/<interface>
```

One file per interface, named for the network interface reported on -- `wwan0`,
`vpn0`, `ppp0`, whatever the kernel called it. That is the same shape as
`/run/netcfgd/prefixes/<interface>`, which a `DHCPv6` client's hook already
writes.

`/run/netcfgd` is netcfgd's run directory and moves with `$NCFG_RUN_DIR`, which a
writer should honour so it can be tested somewhere other than `/run`.

## What

Lines of `key=value`. Not JSON.

That is deliberate and is the same call the prefix file makes: the thing writing
this is very often a shell script -- wrapped around `umbim` or `mbimcli`, or
handed its values in the environment by `openvpn` or `pppd` -- and a shell script
that has to emit valid JSON is a shell script that will one day emit invalid
JSON. This is a format a writer cannot get wrong.

```
# wwan0, connected 2026-07-31T14:02:11Z via three.co.uk
address=10.64.1.23/30
gateway=10.64.1.24
dns=8.8.8.8
dns=2001:4860:4860::8888
```

```
# vpn0, connected 2026-08-02T09:14:55Z to vpn.example.com
route=10.0.0.0/8 via 10.8.0.1
route=192.168.44.0/24 via 10.8.0.1
dns=10.0.0.53
```

| key | repeats | meaning |
|---|---|---|
| `address` | yes | An address the network assigned, in CIDR form. IPv4 or IPv6. |
| `gateway` | yes | A next hop for a default route. IPv4 or IPv6; give both on a dual-stack link. |
| `dns` | yes | A nameserver. IPv4 or IPv6. |
| `route` | yes | A route the far end handed over: `<destination>`, optionally followed by `via <gateway>`. |

A `route` line is spelled the way a `routes` line in a netcfgd config is, so
that somebody reading a report and somebody reading a config are reading the
same thing:

```
route=10.0.0.0/8 via 10.8.0.1     # through a next hop
route=192.168.5.0/24              # out of this interface, no next hop
route=default via 10.8.0.1        # the same thing `gateway=` says
```

Nothing else is accepted on the line. **A metric is netcfgd's**, not the
reporter's: it comes from the interface's `preference` so that a tunnel and a
wired link and a bearer can be ranked against each other by one number an
operator wrote down. A `metric` in a `route` line does not override that and
does not silently pass -- the whole line is skipped, because a route with a
metric the writer thought it had chosen is worse than no route.

`default`, `0.0.0.0/0` and `::/0` all mean the same route and all three are
accepted. netcfgd stores one spelling for it, which is the one the kernel gives
back.

Rules, all of which a writer can follow without thinking hard:

- **Blank lines and lines beginning `#` are ignored.** Put whatever you like in
  a comment; netcfgd will not read it and neither will it complain.
- **Whitespace around the key and the value is trimmed.** `address = 10.0.0.1/32`
  is the same as `address=10.0.0.1/32`.
- **Unknown keys are ignored, and this is a promise.** A writer may report
  `mtu=`, `apn=`, `operator=` or anything else it knows; a netcfgd that does not
  understand a key skips it rather than rejecting the file. That is what lets
  writers run ahead of netcfgd instead of waiting for it.
- **A malformed value is skipped, not fatal.** One unparseable address does not
  discard the rest of the file. A bearer that came up with a usable v4 address
  and a mangled v6 one should still get the v4.
- **Order does not matter**, except among repeats of the same key, which are
  kept in the order written.

## When

**Write the file once the link is up and you know its configuration.**
Write it atomically -- write a temporary file in the same directory and
`rename(2)` it over the target -- because netcfgd may read at any moment and a
half-written file is a file it will believe.

**Truncate it to empty when the link goes down.** An empty file and a missing
file both mean "no addresses", and they differ only in that the empty one says
so deliberately. Prefer the empty file while the writer is running: it
distinguishes "connected to nothing" from "nobody is watching this interface".

**Remove it when the writer stops.** A file left behind is a report nothing is
maintaining, and the next person to read it will believe it.

## What netcfgd does with it

**`address=`** is applied, when the document asks for it. An `interface` block
saying `config = "reported"` gets the reported addresses installed, tagged as
netcfgd's, and withdrawn again when the report stops naming them -- so
truncating the file when the link drops really does take the address off the
interface.

**`gateway=`** becomes a default route on the interface, one per reported
gateway, so a dual-stack link gets one each way. The route is installed
`onlink`, because a reported next hop is routinely outside every address the
interface was given -- a /30 or a /32 with the gateway elsewhere is the ordinary
shape of a cellular link, and the kernel refuses such a route otherwise. It is
withdrawn with the address when the report empties: a default route down a link
that is gone black-holes traffic another interface would have carried.

**`route=`** is installed the same way, with the same metric and the same
withdrawal. It is `onlink` when the line names a next hop and an ordinary device
route when it does not. Nothing about it is a special case: a reported route
goes through the same planner path a route out of the config file does, so the
carrier check that stops a dead link keeping a route, the ordering that puts
`addr.add` first, and the teardown all apply to it unchanged.

**`dns=`** is delivered, when the host manages DNS at all. The reported servers
join the interface's DNS scope, after any the document wrote for it -- so a
server an operator chose is consulted before one the network handed out. The
delivery mode is not a choice: every scope in one delivery has to agree about
it, so the reported servers go out however the rest of the host's DNS does.

A host whose `global { dns { } }` sets no mode manages no resolver, and a report
arriving is not a reason for it to start. The servers are read and shown and
nothing is delivered.

netcfgd will not configure the interface at all until a document gives it a
reason to believe the report. There are two, and both are the same question
asked of different documents:

- **The interface says `config = "reported"`.** This is how a modem helper's
  report is claimed. netcfgd did not start that helper and has no idea it
  exists, so an operator has to say the file is meant.
- **Or netcfgd started the writer.** A tunnel reports through a script netcfgd
  generated, run by a process netcfgd started, on an interface the document
  named. There is nothing left to opt into, and requiring the word anyway would
  mean a tunnel that silently kept none of its routes until somebody added it
  ([0048](decisions/0048-a-tunnels-routes-arrive-through-the-report.md)).

A report for an interface the document says nothing about is read, shown, and
otherwise ignored. A writer must not assume its report has been applied, and
must never apply the addresses itself: two writers on one interface is the
failure this whole project is arranged to avoid.

## What writes one

Anything at all. For a cellular bearer, three are known to be possible and none
of them is privileged by netcfgd:

- **`mbimcli`** from `libmbim-utils`. **There is one in this repository**:
  `helpers/netcfgd-modem-mbim`, a shell script, installed by
  `make install-modem-mbim`. It is a reference rather than a blessed
  implementation -- netcfgd does not know it exists.
- **`umbim`** on OpenWrt -- `+libubox +kmod-usb-net-cdc-mbim +wwan`, no glib and
  no D-Bus, on hardware where nothing heavier fits.
- **ModemManager**, over D-Bus, on a machine already running it -- which is
  where the vendor quirk handling for non-conforming modems lives.

netcfgd does not start, supervise or speak to any of them. It reads a file.

A tunnel is the other half, and there netcfgd *does* start the daemon -- but the
report reaches it by the same road, written by a script `openvpn` or `pppd`
calls. netcfgd knowing how a process was started tells it nothing about what the
far end handed over.

## Where the APN lives

In the helper, not in netcfgd's document.

Connecting the bearer is the helper's job, so its parameters are the helper's
too. netcfgd is told the *result* and never asked for the inputs -- which is
what keeps the contract one-way and lets a helper be replaced without touching
a netcfgd config. The reference helper takes them on its command line:

```
netcfgd-modem-mbim monitor -d /dev/cdc-wdm0 -i wwan0 -a internet
netcfgd-modem-mbim connect -d /dev/cdc-wdm0 -i wwan0 -a internet
netcfgd-modem-mbim disconnect -d /dev/cdc-wdm0 -i wwan0
netcfgd-modem-mbim stop -i wwan0
```

**`monitor` is the one to run from a service manager.** It connects, then stays
up watching the bearer and empties the report the moment the network drops it,
exiting non-zero so the service manager restarts it. `connect` is the same
thing without the watching, which leaves a report nothing maintains.

That difference matters more than it sounds. netcfgd withdraws an address and a
default route when a report empties -- and only then. A stale report is netcfgd
holding a default route down a modem that is gone, black-holing traffic another
interface would have carried. Whatever writes reports has to keep them true.

Restarting, reconnecting and backing off are the service manager's, and
deliberately not this script's:

```
[Service]
ExecStart=/usr/bin/netcfgd-modem-mbim monitor -d /dev/cdc-wdm0 -i wwan0 -a internet
Restart=always
RestartSec=10
```
