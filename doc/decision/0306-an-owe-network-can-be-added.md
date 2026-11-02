# 0306: an OWE network can be added

Status: accepted
Date: 2026-11-02
Milestone: the desktop client (project.md 10.655)
Amends: [0227](0227-a-scan-had-two-words-for-three-things.md)

## Context

0227 taught the scan to tell an OWE network from an open one and left one
thing open: **an OWE network could not be added over the socket.** `wifi_add`
carried a passphrase, a generation and an 802.1X arm, and nothing between "a
credential" and "none". So the GUI refused, printing the block to write by
hand -- which needs `admin`, a tier a laptop's owner usually does not hold --
and the tray's list of new networks left OWE out. A network in an airport or a
cafe that offers "Enhanced Open" was the one kind nobody could join from the
desktop without a terminal.

## Decision

`wifi_add` gains `owe`, a flag. With it the daemon writes `wifi { owe = true }`
and stores nothing; beside a passphrase, a `proto` or an `eap` block it refuses,
because OWE is its own key management and each of those is a second answer to
one question. The member is encoded last, so every request that does not carry
it is byte for byte what it was.

The same shape everywhere 0227 drew the line: `ncfg wifi add --owe`, the client
library's `ncfg_network_t.owe`, the add dialog's `set_owe()` for an OWE scan row
or a hidden network said to be one, and `ncfg_new_choices` offering OWE networks
with `owe` set.

## What was rejected

**Folding it into `open`**, as a client hint the daemon would resolve from a
scan. The daemon would then decide the security of a network from whatever it
heard last, and a request means what it says only if it says it.

**A `security` string replacing the passphrase-implies-PSK rule.** Cleaner on a
blank page, and a change to every existing request and both clients for one new
case. The flag is additive.

## The Rust

`crates/netcfgd-proto` does not carry the member. Nothing ships it (0266); it is
`make agree`'s instrument, and `agree` compares daemons, not requests.
