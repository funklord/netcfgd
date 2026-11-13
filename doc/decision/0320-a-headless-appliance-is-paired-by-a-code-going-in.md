# 0320: a headless appliance is paired by a code going in, one standard way

Status: proposed -- the standard method is the holder's to adopt, and its network half is
fuzznet's to design; the code-in primitive below is built
Date: 2026-11-13
Milestone: M5 (routers), and the microcontroller trial after it
Extends: [project.md 10.720 to 10.723](../../project.md) (pairing a phone)

## Context

The holder, 2026-11-13: how does an embedded netcfgd pair -- an OpenWrt router, a hal9001
or ESP32 board -- with no display, no camera, and a serial port that is hard to reach? At
flash time? A network handshake? A printed QR code? Then: standardise on one method so
people are not confused; should an internal port carry SSH with no authentication? And:
hal9001 has no SSH and no shell, though it may get one.

Pairing today is 10.723's: `ncfg pair` draws fuzznet's invite (`FZI1:`, about 150
characters, one use, ten minutes by default and 24 hours at most) for a phone to scan.
That needs the host to show the code, which is exactly what an appliance cannot.

**What an appliance does have**, common router hardware first:

- **A button**, nearly always: reset, often WPS. OpenWrt delivers a press to
  `/etc/rc.button/NAME` with how long it was held. A microcontroller has a pin.
- **LEDs**, which OpenWrt drives from `/sys/class/leds`: enough to say "waiting".
- **A LAN port that is trusted at first boot.** OpenWrt answers on 192.168.1.1 with root and
  no password until `passwd` is run: physical access to a LAN port is its trust model.
- **A flashing step that carries files**: ImageBuilder's `FILES=`, `uci-defaults` run once
  at first boot, a `sysupgrade` backup restored. An ESP32's flasher writes an NVS partition
  over the serial line it has *while flashing*, even where nobody reaches it afterwards.
- Sometimes a USB port, a web UI (LuCI), and a vendor label printed with per-device data.

## Decision

**The code goes in, not out.** The owner's phone or desktop -- which has a screen --
makes the invite, and the appliance's node joins the owner's estate with `add join`.
Measured before deciding: netcfgd's own node, told an owner's code, joins the owner's
estate, starting itself again in place while netcfgd runs on (`c/tests/node_join.sh`).
So nothing on the appliance has to show anything, and what is missing is only a way for
150 characters to reach it.

**One standard way to carry it, proposed: a claim window on the LAN.** A node that belongs
to no estate accepts an owner's invite pushed to it from the LAN side, only while a window
is open: its first boot, a factory reset, or two minutes after its button is pressed --
WPS's push-button, which every router has and a board has as a pin. The window closes on
the first invite and after it; an LED blinks while it is open. The owner's app finds the
waiting appliance on the LAN, pushes the invite, and the person sees the appliance's key
on their phone and confirms (fuzznet's `confirm` invites already ask that of the inviting
person). That needs no shell, no SSH and no screen, so it is the same on a router and on
hal9001. **The pushing and finding are fuzznet's protocol to design**; what netcfgd brings
is the appliance's half: which interfaces are the LAN side (not an interface with `nat`,
which is the uplink), the button hook, the LED, and knowing first boot and reset.

**The other carriers are the same primitive, for appliances that have them**, not rival
methods: the code written into the image at flash time and used once at first boot; the
code pasted over SSH, `ncfg pair join CODE` (built, below); a file on a USB stick. A
person flashing their own router today can use the first two now. A 24-hour invite fits
flash-then-boot the same day; a stock image for many devices would need a longer one.

**No SSH without authentication, on any port.** It would be root on the appliance for
every device on the LAN -- a guest's phone, an IoT gadget, anything compromised -- for as
long as nobody remembers to close it, with no record of who used it. OpenWrt's own
passwordless root ends at the first `passwd`; the claim window above is the bounded,
one-use version of the same "physical access to the LAN" trust, and gives membership
rather than a shell.

**A printed QR code is a carrier for a device secret, not for the owner's code.** A
sticker would carry a per-device claim secret made at flash or manufacture time, which
proves to the owner's app that it found the right appliance before it pushes; it needs a
claim that stays valid until first use, where an invite lives 24 hours at most. That is
worth it to whoever flashes many devices -- a vendor, a batch -- and is fuzznet's to add.
For one person flashing one router, the code written into the image is the same thing
without the paper.

## Built with this

`ncfg pair join CODE`, or `-` for the code on stdin so a file written at flash time is
used without the code appearing in a process list: asks the daemon's node to join with
the owner's code and waits, up to two minutes, until the node's root is the owner's.
`c/tests/node_join.sh`, in a namespace: a non-code refused by name; the code from stdin
joins an owner's fuzznetd's estate; the root moves to the owner's; netcfgd runs through the
node's restart; and the code is in no output or log. With the join not sent, its checks
fail.

## Rejected

- **SSH with no authentication on the LAN side**, above.
- **Always claimable while unowned, with no window.** Anybody on the LAN at any time could
  take an appliance whose owner had not got to it yet -- a router left on a shelf for a week
  on a shared network.
- **A short PIN typed on the phone.** fuzznet's answer in 10.723: shorter than an invite
  needs a PAKE, which is not built.
- **Several methods offered side by side as equals.** The holder asked for one, so people
  are not confused; the fallbacks are named as carriers of the same code, behind it.
