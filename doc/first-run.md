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
scripting. `--open` for a network with no passphrase, `--hidden` for one that
does not broadcast its SSID, `--priority N` when several are in range, and
`--id` for an SSID that is not usable as a filename. The file it writes is
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
`install-openrc` or `install-procd`. Then start it **once** with
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

It adds `Conflicts=` for NetworkManager, systemd-networkd and connman, so
starting netcfgd stops them. It is not installed into place by the package,
deliberately: installing netcfgd must not decide that this machine's other
network daemons stop.

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

**This is the important half, and it is two commands that need no network:**

```
systemctl disable --now netcfgd netcfgd-nm
systemctl enable --now NetworkManager
```

Why it works, and why each part is there:

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
