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
EAP. Preference between uplinks, so the cable wins when it is plugged in and
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
}

network "YourNetworkName" {
	wifi { psk = "@secret:home" }
}
```

`preference` is the whole switching feature: it becomes the route metric, so
100 beats 600 and the cable wins, and it ties each interface's routes to its
carrier so unplugging withdraws the wired route rather than leaving a black
hole with the better metric.

The passphrase does not go in this file. It goes in
`/etc/netcfgd/secrets/home`, mode 0600, with nothing but the passphrase in it
-- one trailing newline is stripped, anything more is kept. netcfgd refuses to
read a secret any other user can, and refuses an inline passphrase outright, so
the config stays safe to commit.

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
takes the id of a `network` block, not an SSID from a scan. Adding a new
network means editing the config, which needs the `admin` tier. `ncfg wifi
scan` marks which networks in range you can actually join.

**systemd-networkd detection is unverified.** The NetworkManager path was
checked against a running NetworkManager. The networkd equivalent was written
from its documented layout and has never been run against one, so if you run
networkd, do not trust the absence of a warning.
