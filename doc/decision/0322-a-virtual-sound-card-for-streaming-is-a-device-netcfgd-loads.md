# 0322: a virtual sound card for streaming is a device netcfgd loads, and a stream is the estate's

Status: accepted as the design, not built -- the receiving end is being worked on first
Date: 2026-11-13
Milestone: after 0148's Bluetooth audio, toward its handover
Extends: [0148](0148-bluetooth-is-two-backends-and-an-adapter.md), [0321](0321-real-time-traffic-is-honoured-by-the-mark-it-carries.md)

## Context

The holder streams this machine's audio to another by hand: an ALSA `dmix` on `snd-aloop`'s
playback side, and `roc-send` reading the capture side, all as the user. Asked what would be
different if netcfgd, running as root, made the virtual sound card -- a checkbox in the GUI,
"virtual audio card for streaming", and on other nodes "play this stream here".

What the user-level setup cannot have: real-time priority without `rtprio` limits for the
user (`ulimit -r` is 0 here), the CPU kept out of deep idle while a stream plays, the
stream's packets marked and queued as voice (0321), Wi-Fi power save off on the link it
uses, and a stream that outlives a login and is shared by several users.

## Decision

**The card is a device netcfgd loads, and netcfgd never touches a sample** -- 0148's line,
kept. The kernel moves the audio and a backend netcfgd supervises sends it.

- **`snd-aloop`, loaded by netcfgd, only while streaming is on.** It is mainline Linux
  (`sound/drivers/aloop.c`, `CONFIG_SND_ALOOP`). Ticking the checkbox loads it; unticking it,
  or its last stream ending, removes it, so no loopback device exists while the feature is
  off. Loaded with a high `index=` and the id `Stream`, never as card 0 and **never built
  in**: built in, it initialises before a module-loaded sound card, takes card 0, and becomes
  the default output -- the reason the holder keeps it out of the kernel -- and cannot be
  removed. ALSA's default is card 0 unless `asound.conf` says otherwise, so the real card
  keeps it.
- **netcfgd owns the module whole on a machine where this is used.** Its `index`, `id` and
  `enable` are arrays fixed at load: a card is added only by reloading it, which breaks every
  user of every loopback card. So netcfgd loads it once with what it needs, and removes it
  only when nothing holds it: its own sender stopped first, and an app still holding the
  card is named by process and waited for, never killed.
- **The audio goes from the user to root through the kernel, with nothing between.** Apps
  play to the card's playback side, an ordinary ALSA device group `audio` may write; the
  supervised sender reads its capture side. The device node's permission is the whole
  boundary -- no socket, no protocol from user to root. One `dmix` on the card, written by
  netcfgd into `/etc/asound.conf`, lets several apps and users play at once. Rejected: a
  userspace ALSA plugin handing frames to the daemon over a socket, which would put netcfgd
  in the audio path and add a hop.
- **The sender is a backend like `dnsmasq` or `hostapd`**, started and stopped by
  reconciliation, run with real-time priority, holding `/dev/cpu_dma_latency` at 0 while
  it plays, marking its packets EF (0321), and asking for Wi-Fi power save off on the link
  it uses.

**A stream is the estate's.** On the sending node, `audio "living-room" { source = "Stream" }`
publishes it; on another, `audio "living-room" { play = "hw:0" }` makes that node's netcfgd
run the receiver into its card. The receiver's clock leads and its resampler absorbs the
drift -- which is what makes a sender with no sound card, whose loopback runs on the
kernel's tick (4 ms steps at Debian's 250 Hz), work. In the GUI: the checkbox on the
sender; on every other node, "Streams in your estate", each with "Play here" and an output
to choose.

**Who may: the `wifi` tier and `admin`, as for joining a network** -- the holder's answer,
2026-11-13: `admin` is the global setting, and the user who may configure Wi-Fi may do this
too. No new tier. As with Wi-Fi ([0117](0117-adding-a-network-is-a-typed-request-not-a-written-file.md)),
they are typed requests -- make the streaming card, play stream X on output Y, stop --
carrying no configuration text, so a `wifi`-tier user turns streams on and off and cannot
write an `audio` block pointing a sender somewhere else.

**The transport is roc first, fuzznet later.** roc works today and the holder runs it; it
is plain RTP that anyone on the LAN can read or inject into. fuzznet brings membership,
encryption and redundancy sized from the loss netcfgd observes (0321), and is fuzznet's.

## Not decided yet

- **Several rooms in step** need a clock shared by the receivers -- fuzznet's time, or PTP --
  and come after one room.
- **Desktop sound servers** (PulseAudio, PipeWire) list the loopback and may pick it; keeping
  them from it is their configuration, outside ALSA-only, and is left until it bites.
- **An OpenWrt receiver** needs the loopback's kmod only for a sender; a receiver plays to the
  router's own card. A hal9001 board with a DAC is a fuzznet receiver with no ALSA at all, and
  the stream being the estate's is what makes the two look alike.
