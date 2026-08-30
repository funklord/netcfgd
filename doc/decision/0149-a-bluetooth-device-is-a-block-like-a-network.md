# 0149: a Bluetooth device is a block like a network

Status: accepted
Date: 2026-08-30
Milestone: M9; the vocabulary [0148](0148-bluetooth-is-two-backends-and-an-adapter.md) deferred

0148 settled where Bluetooth work lives and deliberately left the configuration
language alone, on the grounds that it is the operator's and outlives the
implementation. This settles it.

## The shape, and why it is not new

Wireless already says three things, and they are three different kinds of
statement:

    device wlan0   { wifi { autoconnect = true } }      the radio's policy
    network "Cafe" { wifi { psk = "@secret:cafe" } }    something it may join
    interface wlan0 { config = "dhcp" }                 addressing

**Bluetooth is the same three and needs no fourth.**

    device hci0 { bluetooth { powered = true } }        the adapter's policy
    bluetooth "headphones" {                            something it may connect
        address = "AA:BB:CC:DD:EE:FF"
        profile = "a2dp-sink"
    }
    interface bnep0 { config = "dhcp" }                 addressing, unchanged

A reader who knows the wifi vocabulary can read the Bluetooth one without being
told, which is the property worth having. An operator who learns one has
learned both.

## Why the label is a name and the address is a field

`network "Cafe"` is labelled by its SSID because that is what the network *is*.
A Bluetooth device's identity is its address, and an address is not a name a
person wants to type twice or recognise in a diagnostic. So the label is a
handle the operator chooses -- it is the filename, the block name and what
`ncfg` prints -- and `address` is the fact.

That also makes a device replaceable without rewriting anything that refers to
it: new headphones with the same purpose get the same label and a new address.

## `profile` is a closed set and one per block

    a2dp-sink     this machine plays to it        speaker, headphones
    a2dp-source   this machine receives from it   phone, another computer
    hfp           hands-free: microphone and earpiece
    pan           this machine is a client on its network
    nap           this machine serves a network to it

**Multiple in and out is multiple blocks**, which is what the holder asked for
and falls out of this rather than being added: two `a2dp-sink` blocks are two
speakers, and `bluealsa` gives each its own PCM. One block per profile per
device, because a headset used as both a sink and a hands-free unit is two
different things to the audio layer and pretending otherwise would put a mode
switch inside a block that has no other modes.

## What is deliberately absent

**No pairing state.** Whether a device is paired is not configuration: it is a
fact about the adapter's key store, it was established interactively, and
writing it in a file would be a second source of truth for something netcfgd
does not own. The document says which devices this machine *uses*; whether it
can is observed.

**No codec, no bitrate, no volume.** Those belong to `bluealsa` and to the
thing playing audio. A `network` block does not carry a data rate either.

**No PIN.** A passkey is entered once, by a person, and belongs in the same
place a wifi passphrase does -- except that unlike a passphrase it is not
reusable, so there is nothing to store.

## What this costs if it is wrong

The language is the part that cannot be changed quietly later: a `network`
block written in 2026 has to still compile. That is why this is a record rather
than a commit message, and why `profile` is a closed set from the start -- a
free-form string would have to keep accepting whatever anybody wrote.
