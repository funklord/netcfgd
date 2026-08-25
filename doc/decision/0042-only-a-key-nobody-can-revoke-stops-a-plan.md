# 0042: Only a key nobody can revoke stops a plan

Status: accepted
Date: 2026-07-31
Milestone: answers what 0037 left open

## Context

Decision 0037 gave `on_unmanage` two values and left one thing open: nothing
*warns* an operator who unmanages a device holding credentials without setting
`clear`. It named the shape that would fit -- "notice that a plan is about to
strand credentials, refuse, and make the operator say which they meant" -- and
it named three credentials: a `WireGuard` private key loaded in the kernel, a
supplicant keeping its passphrases, a running hostapd keeping its generated
configuration.

Two of those three do not belong in a refusal, and finding out why is most of
this decision.

## The test: irrevocable, and only netcfgd would remove it

A credential stops a plan only when **both** hold:

1. **It cannot be revoked from this host.** Withdrawing it is an act by
   somebody else, on machines the operator may not own.
2. **netcfgd holds the copy that matters, and `clear` is what removes it.**
   The operator's choice has to be able to change the outcome, or asking them
   to choose is theatre.

Run over every secret the model can carry:

| | Revocable from here? | Does the choice change anything? | Stops a plan |
|---|---|---|---|
| `WireGuard` private key | **No** -- its authority is the matching public key in every peer's configuration | **Yes** -- netcfgd loaded it into the kernel, and `clear` deletes the link and it with it | **Yes** |
| `WgPeer` preshared key | No | Yes, same mechanism | Rides along: a `WireGuard` interface always has a private key, so the key fires first |
| Supplicant passphrases | Yes, at the access point | **No** -- the same passphrase is in the secrets directory on the same disk, which neither policy touches | No |
| hostapd's generated config | Yes -- for a network netcfgd runs, it is one line of this document | **No** -- same, and `/run` is tmpfs | No |
| EAP client private key | No, needs a CRL | **No** -- the model carries a `SecretRef` and a path; the file stays on disk either way | No |
| PPPoE password | Yes, at the ISP | No | No |

Exactly one thing passes both.

The second column is the one 0037 missed. A supplicant's passphrases are a real
exposure, but they are a *copy* of material that is on the machine whichever
policy is chosen -- so refusing over them would be asking the operator to decide
something their decision cannot affect. A notice that fires for everything is
one people learn to pass over, and the cost of that is the single case that
matters.

## Why the `WireGuard` key is different, checked rather than assumed

Two facts, both established against a real kernel:

- **A keyless device reports no public key; a keyed one reports the key derived
  from the private one.** That is how netcfgd tells whether a key is really
  loaded, and it never asks for the private key --
  `netcfgd_sys::wg::DeviceState` has no field that could return one, which was
  already deliberate and this must not be the reason it changes.
- **The private key is readable back by root, byte for byte.** `wg show wg0
  private-key` returns exactly what was loaded. So stranding is not theoretical:
  whoever ends up with the hardware runs one command and can be this host on
  that network until every peer is updated.

That second fact is the whole argument. Revocation is not something the operator
does here; it is something each peer's administrator does, later, if told.

## Not a refusal, because there is nothing to refuse

`Stranded` is a separate type from `Refusal`, and the difference is not
cosmetic. A refusal is an *action* a guard dropped, which it can name and offer
to let through. Here nothing is dropped: `managed = false` already means netcfgd
plans nothing for the device (0035), and the hazard is that absence continuing.

So the plan carries a statement, not a gap. What is outstanding is a decision.

## The exit code is its own

`ncfg apply` exits **4**, next to the guard's **3**, rather than reusing it. The
remedies are different: a 3 is answered by re-running with
`--allow-disruption`, and a script that treated a 4 the same way would be
answering a question nobody asked while the hardware walked out of the building.

`ncfg plan` still exits 0, which is where the guard refusals already put the
line: planning succeeded at what it does, which is to say what would happen.

## Two ways to mean it, and the durable one is printed first

```
stranded: unmanaging wg0 leaves a WireGuard private key, loaded in the
          kernel on `wg0` and readable there by root
          it cannot be revoked: its authority is the matching public key in
          every peer's configuration ...
          to remove it:  device wg0 { managed = false; on_unmanage = "clear" }
          to leave it:   ncfg apply --strand-credentials wg0
```

The config change is printed above the flag on purpose. The flag consents for
one run; the config key is still there next time somebody reads the file. A
standing notice is the right behaviour for the unfixed case, and it is what a
guard already does -- it keeps refusing until the configuration says otherwise.

`--strand-credentials` names a device rather than being a blanket `--force`,
for the reason `--allow-disruption` does: an operator who agreed to leave a key
on one device has not agreed to leave one on another they had not thought about.

## Driven by the observation, not the document

The rule reads `ObservedLink::private_key_loaded` and never asks the document
which interfaces are `WireGuard`. Three reasons, and the third is a rule about
this repository rather than about `WireGuard`:

- A document that declares a key for an interface never applied strands
  nothing, and a notice about that would be a notice about a file.
- An interface block *deleted* while its `device` block still says
  `managed = false` still has the key loaded, and the document no longer
  mentions it at all.
- A `kind` check in the planner would be a branch **no test could make fail**,
  because `private_key_loaded` is set in exactly one place and only for links
  the kernel calls `wireguard`. It was written, found to be untestable by
  breaking it, and removed. A gate nobody has seen fail is not evidence, and
  neither is a guard clause.

## Schema

`Request::Apply` gains `strand_credentials`, so the socket witness moved by one
line. A **minor** bump: the field defaults to empty, so an older client that
omits it means what it always meant.

The document schema did not move. This is observation and consent, not
configuration -- the config answer already existed, and it is `on_unmanage`.

## What this found on the way

The first version of the test that says a radio's passphrases are not stranding
**passed with the rule widened to every unmanaged interface**. It asserted only
that the radio produced no notice, and the radio has no key loaded -- so the
kind check was never what excluded it. Rewritten to unmanage a radio and a
tunnel in one document and assert that exactly one is reported, it now fails at
zero notices and at two.
