# 0227: a scan had two words for three things

Status: accepted
Date: 2026-09-13
Milestone: M9; the wifi scan results and BSS audit

## What was already right

`parse_scan_results` takes the SSID as the remainder of the line rather than as
one whitespace field, so a name with a tab in it survives and a column added to
the end later does not truncate names. Entries are sorted strongest first with a
stable sort, so two access points at one level keep the supplicant's order
instead of swapping between scans. The mobility domain costs a `BSS <bssid>`
round trip and is asked for only where the flags already say fast transition,
which is the difference between one extra exchange and fifty. `configured_for`
delegates to `netcfgd_model::wifi::network_for`, shared with the observation, so
"which block is this row" has one answer rather than two that can drift.

`is_secured` covers WPA, WEP and SAE. It is the one that is not enough.

## Open and OWE are not the same network

`is_secured` asks whether joining needs a credential. Opportunistic wireless
encryption needs none, so it answers false -- correctly -- and every client
stopped there:

```text
ncfg wifi scan     open
the TUI            groups it under "open"
the GUI            "open", and offers to add it
NetworkManager     no PRIVACY flag at all
```

They are not the same network. OWE is its own key management with management
frame protection required, and this tree already renders exactly that for a
document that names one -- `key_mgmt=OWE`, `ieee80211w=2` on the station,
`wpa_key_mgmt=OWE` on the access point. The scan was the one place that could
not say so, so netcfgd supported OWE everywhere except where somebody would find
out a network was OWE.

**The GUI made it worse than a wrong label.** Its add dialog takes `secured` to
decide what to ask for, so it asked for nothing and wrote an open network block
-- which does not associate. The operator gets a network in the list that never
connects, and nothing anywhere names the reason.

The fix follows the precedent already in the wire type. `enterprise` is there
with this rationale, and it is the same argument word for word:

> Sent because the daemon knows and a client cannot work it out: the scan flags
> do not cross the socket, so without this a client asking for a passphrase on a
> corporate network has no way to know it is asking the wrong question.

So `ScanEntry` gains `owe`, and the four shapes have four words: `secured`,
`enterprise`, `open`, `owe`.

## The TUI had written down the failure in advance

The TUI groups scan rows by `(name, security word)`, under this comment:

> The word itself, not the booleans behind it, so the key and the heading cannot
> come apart: a key coarser than what is displayed merges two networks under a
> heading describing one of them.

An OWE network and an open one of the same name shared a word, so they shared a
key, so they merged under a heading describing one of them. The comment was
right and the vocabulary it depended on was one word short.

## What is still not possible

**An OWE network cannot be added over the socket**, and this decision does not
change that. `Request::WifiAdd` carries a passphrase, a generation and an 802.1X
arm, with no third state between "a credential" and "none" -- its own
documentation says "the passphrase; absent means an open network". The profile
writer's `Security` enum has `Open`, `Psk` and `Eap` and no `Owe` either.

Adding it means a wire field, a variant in the writer, a daemon arm, a CLI flag
and a dialog, which is a second round's work. What this one does instead is stop
the GUI writing a block that cannot work: it says what the network is, prints
the block that does work, and does not offer to guess.

```text
`guest` uses opportunistic wireless encryption, which asks for no passphrase
and is still not an open network.

netcfgd can join one, but not add it from here yet. Put this in your
configuration:

network "guest" {
	wifi { owe = true }
}
```

**That block was wrong when it was first written**, and compiling it is what
found out: the key is inside `wifi { }`, and `network "guest" { owe = true }`
is refused with `unknown network key`. A message telling somebody what to type
is a claim about the language, and it was checked against the compiler rather
than against memory.

## Two checks that had inspected nothing

`cargo build --workspace` covered none of this round's adapter change: design
section 9.2 excludes `adapter/netcfgd-nm` from the workspace so its D-Bus stack
stays out of the core's dependency graph, so it has its own lockfile and its own
`cargo fmt`. Both the missing struct field and the formatting were invisible
until `make adapters` ran. The gate exists and found them; what was wrong was
reading a green `cargo build --workspace` as covering the tree.

And two of the three sabotages passed first time, against the CLI label and the
NM arm, because neither had a test. Both have one now, and both fail when
reverted. That makes four audits running where a fix went in with nothing
holding it until the sabotage pass asked.

## Sabotage

| reverted | test | result |
| --- | --- | --- |
| `is_owe` always false | `a_scan_row_says_which_of_the_four_...` | FAILED |
| the label calls OWE open again | `every_security_shape_has_its_own_word` | FAILED |
| the NM unconfigured OWE arm | `an_unconfigured_owe_network_is_not_...` | FAILED |

## The wire

A minor bump: `owe` is added to `ScanEntry` and defaults to false, the C client
reads it with a default so a daemon older than the field reads as "not OWE", and
the witness gained a fourth sample entry for the combination that had none. The
frozen sample's comment said it pinned "all three combinations"; there were
four.
