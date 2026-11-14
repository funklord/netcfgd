# Running netcfgd on a laptop for the first time

This is the wired-first, wifi-second sequence for taking a machine that
currently runs NetworkManager. Follow it in order: every change gets a
commit-confirm window that reverts by itself if you lose the machine, and the
interface you have not handed over yet is what covers the case a revert cannot
-- see "What `revert` restores, and what it does not".

**Read the last section before you start.** netcfgd has never driven a real
radio.

## What works

Wired DHCP and static addressing. Wifi with WPA2, WPA3, OWE and enterprise
EAP. RFC 4941 temporary addresses, if you ask for them: `config = "slaac privacy
prefer_temporary"` on an interface that autoconfigures. Preference between uplinks, so the cable wins when it is plugged in and
wifi takes over when it is not, with no command run. DNS through
`resolv.conf`, `resolvconf`, openresolv, `systemd-resolved`, dnsmasq or
unbound. Drift detection, commit-confirm, and an authorisation tier that lets
an ordinary user join wifi without being able to reconfigure the machine.

## Before you start

You want two things: a way back in, and a way to see what happened.

- **A second way onto the machine**, or physical access to the console. If you
  do this over the network you are betting on the step that is least tested.
- **The interface names**, from `ip -br link`. This guide uses `enp0s31f6` and
  `wlp0s20f3`; yours will differ.

Nothing below needs root until step 4. `ncfg plan` reads the kernel and your
config and changes nothing, so run it as often as you like.

Steps 1 to 6 are `ncfg` from a root shell and need no access policy at all.
Step 7 is for when you want a client that is *not* run as root -- the TUI in
your own terminal, or the GUI -- which a default install refuses.

**This guide assumes netcfgd was installed from source** -- `make install`
and `make install-systemd` -- which installs the unit and selects nothing, so
NetworkManager is still running and still owns every interface. That is what
makes the gradual handover in steps 3 to 6 possible: NetworkManager keeps the
wifi, and it is your way back while you hand over the wire.

**The Debian package does not leave the machine in that state.** Its
`postinst` runs `netcfgd_select.sh netcfgd` on a fresh install, which stops,
disables and **masks** NetworkManager, systemd-networkd, connman,
wpa_supplicant, ModemManager and systemd-resolved before you have written a
config. It prints what it did and how to undo it. If that is how you
installed, netcfgd already owns the machine: read section 8 first, and treat
steps 3 to 6 as a description of the other route rather than as instructions.

## 1. Write a config

`/etc/netcfgd/netcfgd.conf`:

```ini
global {
	dns { mode = "write_resolv_conf" }
}

interface enp0s31f6 {
	preference = 100
	config     = "dhcp"
	dns        { }
}

device wlp0s20f3 {
	wifi {
		backend            = "wpa_supplicant"
		mac_policy         = "per_network"
		scan_randomization = true
	}
}

interface wlp0s20f3 {
	preference = 600
	config     = "dhcp"
	dns        { }
}

network "YourNetworkName" {
	wifi { psk = "@secret:home" }
}
```

`dns { }` is not decoration. It is how you say "use the nameservers this network
hands out": netcfgd owns `/etc/resolv.conf` in the mode above, and without that line
the lease's servers are reported and not used -- deliberately, because a network you
joined does not get to decide where your queries go unless you say so. `ncfg plan`
tells you when a lease offered servers and nothing asked for them.

`preference` is the whole switching feature: it becomes the route metric, so
100 beats 600 and the cable wins, and it ties each interface's routes to its
carrier so unplugging withdraws the wired route rather than leaving a black
hole with the better metric.

The passphrase does not go in this file. It goes in
`/etc/netcfgd/secrets/home`, mode 0600, with nothing but the passphrase in it
-- one trailing newline is stripped, anything more is kept. netcfgd refuses to
read a secret any other user can, and refuses an inline passphrase outright, so
the config stays safe to commit.

Any credential a config refers to is stored the same way, and there is a command
for it rather than an editor and a `chmod`:

```
sudo ncfg secret set wg-key
value for `wg-key`:
```

It asks with echo off, writes the file at 0600, and then tells you which blocks
refer to that name -- or that nothing does yet, which is how a name typed one way
in the config and another at the prompt gets caught now instead of as "no such
secret" the first time the tunnel comes up. `--replace` is needed to overwrite one
that already exists. There is no command to print a secret back: a credential goes
to the thing that needs it and nowhere else.

You do not have to write either of those two pieces by hand:

```
sudo ncfg wifi add "YourNetworkName"
passphrase for `YourNetworkName`:
```

writes the `network` block into `/etc/netcfgd/conf.d/wifi-YourNetworkName.conf`
and the passphrase into `secrets/YourNetworkName` at mode 0600, prompts without
echoing, and compiles the result before leaving it there. The passphrase is
never a command-line argument -- `ps` would show it to every user on the machine
-- so pipe it in (`printf '%s\n' "$pass" | sudo ncfg wifi add ...`) if you are
scripting. `--open` for a network with no passphrase, `--owe` for one that is
encrypted with no passphrase ("Enhanced Open", which `--open` would not join),
`--hidden` for one that does not broadcast its SSID, `--metric N` when several
are in range (lower wins), and `--id` for an SSID that is not usable as a
filename. The file it writes is
ordinary configuration: read it, edit it, commit it, or delete it to forget the
network.

## 2. Read the plan

```
ncfg plan
```

This tells you what netcfgd would do, and -- more usefully at this stage --
what else is managing your interfaces:

```
warning: NetworkManager also manages wlp0s20f3. Two daemons on one interface
will fight, and whichever applied last wins until the other notices.
```

Expect that warning for anything NetworkManager currently owns. It is the
reason for the next step.

## 3. Hand over the wired interface only

```
sudo nmcli device set enp0s31f6 managed no
ncfg plan
```

The warning for `enp0s31f6` should be gone and the one for `wlp0s20f3` should
remain. **Wifi is still NetworkManager's, and that is deliberate**: it is your
way back if the next step goes wrong.

Handing a device over does not delete NetworkManager's profile for it. `nmcli
device set enp0s31f6 managed yes` gives it straight back.

## 4. Start netcfgd, without letting it apply

Install the service file for whichever init you run -- `make install-systemd`,
`install-sysvinit` (Devuan, or Debian with `sysvinit-core`), `install-openrc` or
`install-procd`. Then start it **once** with
`--no-apply-on-start`, so it observes and changes nothing:

```
sudo netcfgd --no-apply-on-start &
```

Under systemd, add the flag to a drop-in for the first run, or just run it in a
terminal as above and start the service properly afterwards.

## 5. Make the first change, with a net

```
sudo ncfg apply --confirm-within 60
```

The change goes in and a 60-second timer starts. If you can still reach the
machine, keep it:

```
sudo ncfg confirm
```

If something is wrong and you *can* still reach it, undo it now:

```
sudo ncfg revert
```

And if you cannot reach it at all, do nothing. After 60 seconds netcfgd reverts
by itself, which is the case the whole mechanism exists for.

At this point wired should work through netcfgd and wifi should still work
through NetworkManager. `ip route show default` will show both, with the wired
route at metric 100. Now start the service normally, so it comes up at boot:

```
sudo systemctl enable --now netcfgd
```

### What "revert" restores, and what it does not

Reverting the first apply removes every address, route, link and helper netcfgd
installed, and touches nothing it did not. That is the exact undo of what it
did.

It does not put the device back on NetworkManager. Once you have run `nmcli
device set enp0s31f6 managed no`, "the way it was" *is* unconfigured -- so if
netcfgd's config was wrong, a revert leaves you with a working machine and an
idle interface, not with your old setup. Getting the old setup back is `nmcli
device set enp0s31f6 managed yes`.

That is the other reason this guide does wired first: while you are finding
this out, the wifi still works.

## 6. Hand over the wifi

Once wired has been stable for a while:

```
sudo nmcli device set wlp0s20f3 managed no
sudo ncfg apply --confirm-within 60
```

netcfgd starts a `wpa_supplicant` of its own, with no configuration file, and
supplies every network over its control socket. If you had a NetworkManager
profile for the same network, netcfgd does not read it -- the `network` block
in your config is the only thing it will join. That is the point, and it will
surprise you once: a network you could previously join from the applet is not
available until it is in the config.

At this stage, if it goes wrong, `nmcli device set wlp0s20f3 managed yes` and
`sudo systemctl stop netcfgd` puts it back.

## 7. If you want a client that is not run as root

Everything above is `ncfg` from a root shell, which needs no policy at all.
The moment you want `ncfg tui` in your own terminal, or the GUI, or its tray
icon, you hit the one thing that is not in any of the steps above: **every
tier defaults to root, and the socket's mode follows the policy.** So a client
run by you is refused before it can show anything, and the message you get
names the socket rather than the reason.

Two ways to change that, and neither is the only one.

**The group.** The packages reserve `netcfgd`, empty, and it grants nothing
until a policy points at it:

```sh
sudo ncfg control set --observe group:netcfgd --wifi group:netcfgd
sudo usermod -aG netcfgd "$USER"   # adduser on Alpine
```

Then log out and back in -- the kernel gives a session its group memberships
when it starts, so a shell you already had open still has the old set. `ncfg
control show` prints the policy at any time, and `ncfg control set` edits the
`global` block you wrote in step 1 rather than adding a second one.

**Or the client's access tab**, which does the same thing through
`Administrator Mode...`: the editors come alive inside a red frame and Apply
runs that same command as root. Use whichever you prefer; they write the same
file, and it is ordinary configuration you can read, diff and delete.

**What that does not give you is `admin`**, and the difference matters more
than it looks:

| tier | what a client can then do |
|---|---|
| `observe` | see what the network is doing |
| `wifi` | scan, join, leave, and **add** a wireless network |
| `admin` | everything else -- apply, reload, revert |

So with the two tiers above a desktop session can watch the network, switch
between networks, and add the one it is standing in front of -- which is what
a laptop actually needs. It still cannot apply an unrelated configuration
change, revert one, or reload the daemon; those are `admin`, which is root
unless you say otherwise.

Adding a network used to need `admin` as well, which meant granting a desktop
group the whole machine's networking in order to join a cafe. What changed is
[0124](decision/0124-adding-a-network-is-the-wifi-tier-because-0117-made-it-safe.md):
the request that adds a network carries an SSID and a passphrase and cannot
express anything else, so it no longer has to be trusted as though it carried
a config file.

## 8. Replacing NetworkManager entirely

Steps 1 to 7 leave both daemons installed and running, each owning different
interfaces. That is the right place to stay for a while. When you want netcfgd
to *be* the network manager, there are two halves and they are separate
decisions.

**The daemon.** Copy the drop-in the package ships as documentation:

```
mkdir -p /etc/systemd/system/netcfgd.service.d
cp /usr/share/doc/netcfgd/netcfgd-exclusive.conf \
   /etc/systemd/system/netcfgd.service.d/
systemctl daemon-reload
```

**Without systemd** -- Devuan, or anything else running sysvinit or OpenRC --
there is no drop-in, and `netcfgd_select.sh netcfgd` is the whole of this half:
it stops the other managers' init scripts and disables them at boot
(`update-rc.d disable`, or `rc-update del`), and enables netcfgd's. It is what
the Debian package runs on a fresh install, there as here.

The systemd drop-in adds `Conflicts=` for six units -- NetworkManager, systemd-networkd,
connman, wpa_supplicant, ModemManager and systemd-resolved -- so starting
netcfgd stops them. The file is the authority on that list rather than this
sentence, which has already been wrong: read
`/usr/share/doc/netcfgd/netcfgd-exclusive.conf`, which says beside each one
why it is there.

The drop-in is not installed into place by the package. That is not the same
as the package leaving your other daemons alone, and this section used to say
it was: `postinst` stops, disables and masks the competitors on a fresh
install. What the drop-in adds on top is that they stay stood down every time
netcfgd starts, rather than once at install time.

**The D-Bus interface**, if you want `nmcli`, `nmtui`, `nm-applet` or
`plasma-nm` to keep working against netcfgd. That is the `netcfgd-nm` package:

```
apt install netcfgd-nm
systemctl enable --now netcfgd netcfgd-nm
systemctl disable NetworkManager
```

Only one process can own `org.freedesktop.NetworkManager`, so the shim's unit
carries the conflict itself rather than as an opt-in.

### Getting NetworkManager back

**This is the important half, and it needs no network.** If you installed
the package, one command does it:

```
netcfgd_select.sh networkmanager
```

**Use that rather than the two `systemctl` lines below if the units are
masked, because on a masked unit `systemctl enable --now` fails outright**
with `Unit NetworkManager.service is masked.` -- and masked is what a package
install leaves them. The script unmasks first, and then does three things the
two commands do not:

- **Removes the stale runtime claims.** A stopped NetworkManager leaves
  `/run/NetworkManager/devices/<ifindex>` behind, and networkd leaves
  `/run/systemd/netif/links/<ifindex>`. netcfgd reads those to decide whether
  somebody else holds an interface, so they strand interfaces in both
  directions.
- **Clears the orphaned children.** A supplicant or DHCP client started by the
  outgoing daemon outlives it -- `KillMode=process` -- so the radio stays held
  by a process whose parent is gone.
- **Waits for a default route** and says whether one arrived, up to 30 seconds
  (`--no-wait` to skip, `--dry-run` to see what it would do first).

**`systemd-resolved` and `ModemManager` are stood down too, and nothing
starts them again.** If this machine resolved names through `systemd-resolved`
before netcfgd, it has no resolver until you start it:
`systemctl unmask --now systemd-resolved`. The same for `ModemManager` if a
modem applet was how you used cellular.

**From a source install, where nothing is masked**, the two commands are
still the whole of it:

```
systemctl disable --now netcfgd netcfgd-nm
systemctl enable --now NetworkManager
```

Why that works, and why each part is there:

- **`Conflicts=` is symmetric.** `systemctl start NetworkManager` stops
  netcfgd by itself, so you do not have to get the order right.
- **`disable`, not just `stop`.** `netcfgd.service` has `Restart=on-failure`.
  A stop from the conflict is not a failure, so starting NetworkManager does
  win -- but a *crash-looping* netcfgd restarts and takes the bus name back,
  and "netcfgd is not working" is exactly that case.
- **Nothing here is a package operation.** No `apt remove`, no diverted files,
  nothing overwritten. Reinstalling a package is the one recovery step that
  needs the network you have just lost, so the switch deliberately never
  requires it.
- **NetworkManager still knows your networks.** Neither netcfgd nor the shim
  ever reads or writes `/etc/NetworkManager/system-connections`. Its profiles
  are exactly as it left them.

If you also copied the exclusive drop-in, remove it, or netcfgd will stop
NetworkManager again the next time anything starts it:

```
rm /etc/systemd/system/netcfgd.service.d/netcfgd-exclusive.conf
systemctl daemon-reload
```

**Both daemons enabled at once is the one state to avoid.** `Conflicts=`
carries no ordering, so at boot the winner is whichever systemd reaches
first. Enable exactly one.

## 9. A cellular modem

Nothing above applies to a modem, because netcfgd does not drive one. It reads
files and configures interfaces; a **helper** talks to the module. That is
decision 0044 and it is why this section is a list of things to run rather than
a block of configuration.

It is a separate package:

```sh
apt install netcfgd-modem
```

`Architecture: all` — three helpers, the quirks table, a udev rule, a systemd
template unit and two SIM-select hook examples, none of it compiled and none of
it useful on a machine with no modem.

**Which helper is a property of the module, not a choice.** A module offering
only ECM presents no `/dev/cdc-wdm` for `mbimcli` to open, so its whole control
surface is AT over a tty. `/usr/share/netcfgd/modem-quirks` says which is which
for the modules anybody has measured:

```
2c7c:6007  data=ecm helper=at at=3 autoconnect=yes
```

`data=ecm helper=at` is the case this section covers.

### What to write

Two blocks, and note what the interface block does **not** have:

```
device wwan0 {
	modem {
		sim = ["socket", "esim"]
		apn = "internet.cxn"
	}
}

interface wwan0 {
	config = "dhcp"
	probe {
		command = "/usr/share/netcfgd/probe/default"
		args    = ["wwan0"]
	}
}
```

**No `dns { }`, and that is the setting.** On ECM the module runs a DHCP server
and hands over the address the operator assigned, so `config = "dhcp"` is
right. The same DHCP also offers nameservers, and on the module measured they
answer nothing at all -- they are on the module's own pre-attach subnet. The
resolvers that work arrive in the PDP context and change with the APN. An
interface takes its lease's nameservers only where it carries a `dns { }`
block, so leaving it off is how you say "the address, not the resolvers".

**`wwan0` is probably not what yours is called.** The ECM interface is a
`cdc_ether` device and its name is derived from the module's MAC, so it is
`enx…`. Use the real name -- and do not go looking for it by name pattern,
because the wired ports carry `enx…` altnames too. `ls -l /sys/class/net/*/device/driver`
is the honest way to find it.

### What to run

```sh
udevadm control --reload && udevadm trigger
systemctl enable --now netcfgd-modem-at@wwan0
journalctl -u netcfgd-modem-at@wwan0 -n 20 -o cat
```

The udev rule gives the AT port a stable name, `/dev/netcfgd-modem-at`, and
asks ModemManager to leave it alone. Both matter: `ttyUSB3` is not stable
across a modem reset, and a reset is ordinary operation here -- **a SIM switch
is a modem reset**. And ModemManager takes both AT ports once the modem
registers, which is exactly when the PDP context first has something worth
reading.

### Whether it worked

In increasing order of what each actually proves:

```sh
ncfg modem                       # which SIM source, and the APN asked for
ip -4 addr show dev wwan0        # the lease arrived
ip -4 route                      # and a default route
curl -4 -o /dev/null -w '%{http_code} %{size_download}\n' \
     https://deb.debian.org/debian/dists/trixie/Release
```

**Do not stop at `ping`, and do not add `-k`.** A cellular link that pings is
not a cellular link that works: asking for an APN a subscription does not carry
gets the network's own default rather than an error, and on that default ICMP
succeeds everywhere while every other address blackholes the SYN. The bearer is
up, the modem says so, and nothing useful crosses it. `-k` hides the other
half, a missing CA bundle, which fails at certificate setup and reads exactly
like the operator blocking 443.

The helper says which APN the network **granted**, which is a different thing
from the one asked for:

```
netcfgd-modem-at: attached on im.cxn
netcfgd-modem-at: THE NETWORK SUBSTITUTED THE APN
netcfgd-modem-at:   asked for `internet.cxn`, got `im.cxn`
```

That is not a fault to fix -- it is the network answering as it pleases, and
both of those carry traffic. It is here so that the case where the substituted
APN routes nothing is visible rather than silent.

### Switching SIM

netcfgd decides **which** source it wants, records what worked, falls back when
a probe fails, and publishes the choice. Making the hardware agree is a
`pre_up` hook, because the mux select line is your board's and netcfgd has no
GPIO (0150). Two examples ship:

- **`sim-select-gpiod.example`** is complete for the commonest shape -- a
  select line and a reset line on a GPIO expander, driven with `gpioset` -- and
  leaves you five values at the top: the chip, the two line names, the value
  that selects each source, and which value asserts reset.
- **`sim-select.example`** is the bare frame, for a board whose mux is not
  GPIO at all: a regulator, a vendor sysfs node, a `devmem` poke.

Both are installed non-executable under `/usr/share/netcfgd/hook/`. Copy one,
fill it in, and put it at the path your `pre_up` names.

**The five values are not guessable and the polarity is the one that bites.**
On the board these defaults came from, the reset line reaches the module
through an inverting transistor, so the schematic's net name gives the opposite
of the truth. The select line's sense was established by selecting with the
socket *empty*: a card that answered could only have been the embedded one. If
you are guessing, you have not established it, and guessing wrong is silent --
both sources look identical to everything downstream.

**The reset in that hook is not optional on every module.** Measured on the
EG916Q-GL: `+QSIMDET: 0,0`, so there is no hot-plug detection at all and a card
fitted after boot is invisible until the module is reset.

**And one SIM is visible at a time.** The mux is outside the module, so there
is no way to ask about the other card without switching to it. The ICCID is the
only reliable discriminator -- an ISD-R probe is not, reporting absent at both
mux positions including one holding an eUICC -- and the helper reports it, so
`ncfg modem` says which card each source turned out to hold:

```
wwan0  socket  fallen back
    sources: esim, socket
    apn: internet.cxn
    esim card: 8946080801619663722
    socket card: 8946080023614318322  (in use)
```

**The list fills in as sources are used, and that is the honest shape.** A
source netcfgd has never been on has no card listed, because learning what is
in the other socket costs a switch, a modem reset and the link. Nothing can
show you both at once; this shows you both once both have been tried.

## 10. An OpenWrt router

Everything here has been run on OpenWrt 25.12 in emulators -- arm64, as most routers sold
now are (`make hull-armsr`), big-endian MIPS on OpenWrt's own kernel (`make hull-malta`) and
x86 (`make hull-openwrt`) -- earlier on 24.10, and on no real router yet. A router may have no console, so the rule above matters more:
**leave the port you are connected through with netifd until the end.**

Build the program with OpenWrt's toolchain for your target, then the package. The
Makefiles call `ar` and `nm` by their plain names, so link the toolchain's under those
names ahead of this machine's on `PATH`, as `tests/hull/malta/payload.sh` does:

```sh
make -C c netcfgd-static CC=<target>-openwrt-linux-musl-gcc
sh tool/ipk.sh c/netcfgd-static <architecture> netcfgd.ipk   # `opkg print-architecture`
```

Installing starts nothing and enables nothing, so nothing has changed yet:

```sh
opkg install netcfgd.ipk
```

**On OpenWrt 25.12 there is no `opkg`**: it installs apk packages. Make one with
`make openwrt-apk`, which builds apk-tools 3 from Alpine's source the first time,
fetching it once, and gives the package of the same files:

```sh
make openwrt-apk OPENWRT_ARCH=<arch> CC=<target>-openwrt-linux-musl-gcc   # `apk --print-arch`
```

On the router, from the file -- it is not signed, so apk is told to take it:

```sh
apk add --allow-untrusted netcfgd-<version>-<arch>.apk
```

That starts and enables nothing either, and `apk del netcfgd` takes it away again,
leaving `/etc/netcfgd`.

Write `/etc/netcfgd/netcfgd.conf` for one port that you are **not** connected through,
and read the plan. Where netifd is told of the same device, the plan says so:

```
warning: netifd also manages eth1. Two daemons on one interface will fight
```

They do fight: netifd puts the device in its bridge and netcfgd takes it out again. So
take that device out of `/etc/config/network`, run `/etc/init.d/network reload`, and
only then start netcfgd, with a window:

```sh
/etc/init.d/netcfgd start
ncfg apply --confirm-within 60
ncfg confirm
```

**On wifi, OpenWrt makes no interface on a radio**, so name the radio's `phy`, from
`ls /sys/class/ieee80211`, and netcfgd makes one. Leave it out of
`/etc/config/wireless`, or disable it there:

```
device wlan0 {
	radio { phy = "phy0" }
}
```

**OpenWrt's firewall is still there.** It rejects input on a device it has no zone for,
which stops a DHCP server on it. Give the device a zone, or stop `firewall` once netcfgd's
`firewall` block does its work, and disable it so a reboot does not bring it back. `ncfg
plan` warns when another table filters at the same hooks. Know that stopping or restarting
it runs `fw4 flush`, which deletes every nftables table on the router, netcfgd's with the
rest: netcfgd puts its own back within five seconds, and for those seconds the router has
no NAT and no port forwards. When everything is handed over and confirmed, `/etc/init.d/netcfgd enable` is what
makes it survive a reboot.

**Flow offloading goes with `firewall`, and comes back with one line.** If the router had
"software flow offloading" or "hardware flow offloading" on in its firewall settings, it
was `firewall`'s, and stopping `firewall` ends it. `global { flow_offload = "software" }`
puts it in netcfgd's own table, over every interface with `forwarding` or `nat`;
`"hardware"` hands established flows to the switch where its driver can take them, and
`ncfg plan` names the devices first -- a driver that cannot refuses, and with it the whole
table, NAT included, so try `"software"` first. Decision 0319.

**A router has no screen to show a pairing code, so it takes yours.** Make the code on
the phone or desktop that runs your estate, then give it to the router over SSH, with
`remote { observe = true }` in its `global` block so its node has a port to ask from:

    ssh root@192.168.1.1 ncfg pair join -    # paste the code, then Ctrl-D

It answers with the estate it joined, or says why within two minutes. The code is used
once and lives as long as its maker said, ten minutes unless told. Decision 0320.

**IPv6 on the LAN needs a daemon to send the advertisements.** netcfgd decides what the
hosts are told -- `advertise { prefixes = ["@pd:wan0"] }` on the LAN, the prefix your ISP
delegated -- and hands the sending to radvd or to uradvd. OpenWrt 25.12 carries no radvd in
any feed, so install uradvd:

```sh
apk add uradvd
```

Its own service does nothing as shipped (`enabled '0'` in `/etc/config/uradvd`); netcfgd
starts one for each interface it advertises on. uradvd sends neither the managed nor the
other-config flag and takes only a /64, so a document asking for those is refused under it
rather than advertised as something else.

**The LAN's name server is OpenWrt's own dnsmasq**, which answers DNS on every address the
router has, the LAN's included. So `dns_forward` in a `dhcp_server` block cannot be had beside
it: netcfgd's forwarder for that LAN cannot bind port 53, and the server runs DHCP alone,
offering the router's address, while `ncfg plan` warns that the forwarder is not running. Say
so in the document instead -- leave `dns_forward` off and offer the router:

```
dhcp_server {
	dns = ["192.168.1.1"]   # this interface's own address
}
```

**DHCPv6 needs `dnsmasq-full`.** OpenWrt's stock dnsmasq is built without DHCPv6, so a
`dhcp_server` with a `range6` serves DHCPv4 alone there and `ncfg plan` says so. Router
advertisements, which is how most hosts take an IPv6 address, are `advertise`'s and need
neither.

**WireGuard needs its kernel module**, which the image does not carry: `apk add
kmod-wireguard`. netcfgd speaks to the kernel itself, so `wireguard-tools` is not needed.

**A whole router, as one document.** Each part of this is what `make hull-armsr` runs, on
its own ports: a WAN asking DHCPv4 and DHCPv6 for an address and a delegated /56, NAT out
of it, and a LAN bridge numbered from both and served -- addresses by DHCP, IPv6 by
advertisement (uradvd, above), names by OpenWrt's own dnsmasq:

```
interface wan {
	config = ["dhcp", "dhcp6 pd_length 56"]
	nat    = true
}

device br-lan {
	bridge {
		members = ["lan1", "lan2", "lan3", "lan4"]
	}
}
interface br-lan {
	config     = ["192.168.1.1/24", "@pd:wan=::1/64"]
	forwarding = true
	advertise { prefixes = ["@pd:wan"] }
	dhcp_server {
		dns = ["192.168.1.1"]
	}
}
```

The WAN's IPv6 default route comes from the ISP's router advertisement, which odhcp6c hears
and netcfgd installs; its own address and the ISP's name servers come from the same lease.
On a DSL line the WAN is a PPPoE session over the port instead, and the same DHCPv6 runs
over it:

```
device ppp0 {
	pppoe {
		parent   = "wan"
		username = "you@isp.example"
		password = "@secret:dsl"
	}
}
interface ppp0 {
	config = "dhcp6 pd_length 56"
	routes = "default"
	nat    = true
}
```

with `@pd:ppp0` in place of `@pd:wan` on the LAN. IPv4 over a session is the address IPCP
negotiates, which is pppd's, and its default route is the one `routes` names.

**A firmware upgrade keeps netcfgd**, if you keep settings. The package lists its
configuration, its store and the program itself for `sysupgrade`, because the new image
holds no netcfgd and a port you took out of `/etc/config/network` would otherwise come back
with nothing running it. `sysupgrade -n`, which keeps nothing, loses it all along with the
rest of the router's settings. What comes back is files the package manager no longer
knows. On 25.12 a later `apk add` of the package takes them over as they are; on 24.10,
`opkg install` needs `--force-overwrite`.

## 11. An IPsec tunnel

strongSwan negotiates; netcfgd owns the tunnel's device and its addressing
(decisions 0323 to 0325). The connection stays strongSwan's, in
`/etc/swanctl/conf.d/`, with its credentials, loaded by strongSwan's own service
-- netcfgd loads nothing into charon. What binds the two is an id and a script.

**netcfgd's side** -- an XFRM interface, and the addressing the tunnel reports:

```ini
device ipsec0 {
	xfrm {
		if_id         = 7
		report_writer = "ipsec"   # the account charon runs its updown as;
		                          # omit where that is root
	}
}
interface ipsec0 {
	config = "reported"
}
```

**strongSwan's side** -- three lines added to the child of the connection a
provider hands you, and one setting for charon:

```
children {
	<the child> {
		...
		if_id_in  = 7
		if_id_out = 7
		updown    = /usr/libexec/netcfgd/ipsec-updown ipsec0
	}
}
```

and in `strongswan.conf` (or a file under `strongswan.d/`):

```
charon {
	install_virtual_ip = no
}
```

so the virtual IP the server assigns is not put on whatever device charon
picks: `ipsec-updown` reports it, with the far side's subnets and nameservers,
and netcfgd puts it on `ipsec0`. When the connection carries the whole of IPv4
(`remote_ts = 0.0.0.0/0`), the tunnel takes the default route and netcfgd adds
a host route to the IKE peer by the uplink, so the tunnel's own packets do not
go into it.

**`report_writer` is the one to get right.** Alpine's charon runs the updown as
the `ipsec` account; netcfgd gives that account `ipsec0`'s report directory
when it makes the device, and without it the updown cannot write and the
interface gets nothing -- silently, because the updown never disturbs charon.
Where charon runs the updown as root, leave the key out: Debian's does
(measured in Debian 13, project.md 10.870). Debian's strongSwan service, which
loads `conf.d` as Alpine's does, is a systemd unit only; a Debian without
systemd has no script that starts it. OpenWrt's `swanctl` service loads
`conf.d` as well, beside a connection it writes from UCI, whose `if_id` and
`updown` options are these same lines; its charon carries no account to
switch to either (10.870).

Measured end to end in Alpine 3.21 with strongSwan 5.9.14 and a pre-shared key
(`tests/ipsec/e2e.sh`), and with the server proven by a certificate and the
client by EAP-MSCHAPv2, a username and a password -- the shape of a commercial
VPN profile (`tests/ipsec/eap.sh`). Authentication is strongSwan's business and
changes nothing on netcfgd's side.
`ncfg tunnel up ipsec0` and `ncfg tunnel down ipsec0` ask strongSwan to bring it
up or take it down, once the `xfrm` block names the connection and its child
(`connection = "home"`, `child = "all"`); the addressing follows through the
report as above. `start_action = start` in the connection brings it up with
charon instead. Both are in the `wifi` tier, beside joining a network.

## When something goes wrong

**Ask what netcfgd thinks it did.** `ncfg status` for what the kernel has,
`ncfg explain interface wlp0s20f3` for why, and `journalctl -u netcfgd` for
what it tried.

**What netcfgd installed is tagged, and you can ask the kernel directly.**
Routes it added carry protocol 110:

```
ip route show proto 110
```

Addresses carry the same tag, but `iproute2` prints it in hex and has no filter
for it, so it is `ip -d addr show` and look for `proto 0x6e`.

Two things are *not* tagged, and both are correct. The subnet route the kernel
derives from an address is `proto kernel`, because the kernel made it, not
netcfgd. And a DHCP lease's address and route belong to the client -- netcfgd
never claims them, which is why it will not remove them either.

**Stopping netcfgd does not undo anything.** It leaves the kernel as it is. To
go back to NetworkManager, hand the devices back with `nmcli device set DEV
managed yes` and it will reconfigure them.

**Nothing in `/etc` is written by netcfgd** except the DNS artifacts, so your
config cannot be corrupted by a failed apply.

## Rough edges to know about

**Nobody has run this against a real radio.** Association is tested against
`mac80211_hwsim` virtual radios, which exercises the whole path from config to
a completed WPA2/WPA3 handshake -- but a real card, real drivers and a real
access point have never been tried. Step 5 is the least proven thing in this
document.

**DNS changes are not reverted by a confirm window.** `ncfg plan` says so:

```
warning: dns.apply cannot be undone; commit-confirm will not revert it
```

If a revert leaves you with the wrong `/etc/resolv.conf`, fix it by hand or
re-apply a corrected config.

**A network that is not in the config cannot be joined.** `ncfg wifi connect`
takes the id of a `network` block, not an SSID from a scan -- so joining
somewhere new means adding it to the config first, which is what `ncfg wifi add`
is for (see below). `ncfg wifi scan` marks which networks in range you can
actually join.

**All eleven hook phases run.** `pre_up`, `up`, `post_up`, `pre_down`, `down`
and `post_down` are the six a plan fires as it brings an interface up or takes
it down; `carrier`, `lease`, `roam`, `portal` and `drift` fire on something the
machine noticed rather than something netcfgd planned. `ncfg plan` names each one
it finds, and warns about any phase this build does not fire -- which is now
none, and stays honest if a phase is ever added without being wired up.

Taking an interface down is five moments, not one: `pre_down` runs while the
interface still works (addresses, routes, all of it -- this is where a script
that needs the network goes), then netcfgd removes the addresses it installed,
then `down` runs with the link still up and the addresses gone, then the link
goes down, then `post_down`.

`on carrier` runs when a cable comes or goes, with `$NCFG_REASON` set to `up` or
`down` -- and once when netcfgd first looks at the interface, so a script that
configures something from the current state does not have to wait for a change. On a
gain it runs after the addressing, so the network works by then; on a loss it runs
before anything is withdrawn, so it can still stop whatever was using it.

`on lease` fires when an address arrives that netcfgd did not install, which is how
it notices a DHCP lease without seeing DHCP. `$NCFG_ADDR` carries it. It fires once
per lease, and not on the apply that starts the client -- the address arrives a
moment later, and the daemon gets there on the netlink event.

A `down` hook runs *before* the interface goes and while it still has its
addresses, which is what you want for unmounting something. If it fails, the
interface stays up: the down phases can veto.

**A lease's search suffixes come with its nameservers**, through the `dns { }`
block above -- so `ssh wiki` works on a network that sends a domain. What does *not*
come from a lease is split DNS: a rule sending `*.corp.example` to one resolver and
everything else to another is yours to write, as `dns { domains = [...] }`. A network
you joined does not get to decide that by handing out a lease.

**netcfgd replaces dhcpcd's hook scripts** while it manages an interface, which is
what stops dhcpcd writing `resolv.conf` behind netcfgd's back. If you relied on
dhcpcd's other hooks -- `ntp.conf`, `yp.conf` -- they no longer run.

**Nothing manages `accept_ra`, and its default ignores router advertisements on a
forwarding interface.** Not a laptop problem unless you turn on `forwarding` for a
container bridge or a VM host, at which point IPv6 autoconfiguration on that
interface stops and `ip addr` shows nothing that explains it.

**Captive portal detection needs a URL you choose.** `portal_check` takes an
`http://` URL and netcfgd has no default for it: a daemon that reaches out to a
fixed host to decide whether the internet works is a third party being told when
this machine joins a network. Give it one -- yours, or a `generate_204` endpoint
you trust -- and netcfgd fetches it once when the interface becomes addressed
and runs the interface's `on portal { }` hook if something else answers. Never
`https`: a portal works by intercepting the request, which is exactly what TLS
prevents, so an `https` probe reports no portal on the networks it is for.

**A blocked radio is reported and not cleared.** `ncfg status` says `radio off`,
`ncfg explain interface wlp0s20f3` says which switch and what to do, and a plan
gives the remedy -- but netcfgd will not unblock one, on purpose: your function key
turning the wifi off is you deciding, not drift to be corrected. `rfkill unblock
wifi` is the other half. The *moment* a switch flips is seen as it happens -- a
watcher reads `/dev/rfkill`'s event stream and asks for a fresh observation, which
matters most for *un*blocking, since blocking usually takes the interface down and
netlink reports that anyway. The device is never opened for writing, so "netcfgd
will not unblock your radio" is a property of the code rather than a promise.

**systemd-networkd detection is unverified.** The NetworkManager path was
checked against a running NetworkManager. The networkd equivalent was written
from its documented layout and has never been run against one, so if you run
networkd, do not trust the absence of a warning.
