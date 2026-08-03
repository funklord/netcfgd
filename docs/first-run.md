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

**Six of the eleven hook phases run.** `pre_up`, `post_up`, `down`, `post_down`,
`lease` and `carrier` fire; `up`, `pre_down`, `roam`, `portal` and `drift` are
parsed, written into `/run/netcfgd/hooks/` and never executed. `ncfg plan` names each
one it finds, so this is visible rather than silent.

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

**No captive portal detection.** `portal_check` is recognised and does nothing,
and says so in the plan. A hotel or a train needs a browser and patience.

**A blocked radio is reported and not cleared.** `ncfg status` says `radio off`,
`ncfg explain interface wlp0s20f3` says which switch and what to do, and a plan
gives the remedy -- but netcfgd will not unblock one, on purpose: your function key
turning the wifi off is you deciding, not drift to be corrected. `rfkill unblock
wifi` is the other half. What it cannot see yet is the *moment* a switch flips: the
block shows up on the next observation, a second or so later.

**systemd-networkd detection is unverified.** The NetworkManager path was
checked against a running NetworkManager. The networkd equivalent was written
from its documented layout and has never been run against one, so if you run
networkd, do not trust the absence of a warning.
