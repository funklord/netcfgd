# 0052: A daemon is compared to what it was started with

Status: accepted
Date: 2026-08-02
Milestone: closes the gap 0041 recorded and 0026 created

## Context

Three of netcfgd's backends read a configuration file once and never mention it
again. hostapd is the one 0026 chose that shape for deliberately -- netcfgd
renders the file, hostapd sends the beacons -- and radvd is the same bargain for
router advertisements. `pppd` and `openvpn` differ only in that their
configuration is either netcfgd's own options file or the operator's.

That leaves a question the reconciler could not answer: **is the daemon that is
running still running what the document says?** `backend.start` is skipped when
something is running, and until now that was the end of it. An operator could
edit an SSID, a channel or an advertised prefix, run `ncfg apply`, get an empty
plan, and have the radio go on announcing the old one. project.md carried that
as a known incompatibility in as many words.

Two events forced the answer. A delegated prefix can be **renumbered** by the
ISP -- the value in the document arrives after the document does, and can arrive
again as something else -- and an edited SSID is the same shape with a person
in place of the ISP.

## Decision

**The observation carries what each daemon was started with**, read back from
the file netcfgd itself generated, in netcfgd's own vocabulary:

| backend | field | read from |
|---|---|---|
| access point | `ObservedBackend::started_with` | the generated `hostapd.conf` |
| router advertisement | `ObservedBackend::advertised` | the generated `radvd.conf` |

That file is netcfgd's record of its own past, which is what `/run` is for --
the same standing `ObservedPolicy` already has for the ACL policy hostapd was
started under, and for the same reason: hostapd cannot be asked.

**The planner compares it against what the document implies now**, and acts on
the difference. The comparison is in model terms -- an `Ssid` against an `Ssid`,
a band as the document spells it -- so the reason can name the field that moved,
and the observer does the translation from `hw_mode` on the way in.

**What the act is depends on the daemon, and the difference is not cosmetic.**
radvd re-reads its configuration on `SIGHUP` (`reload_config` in `radvd.c`;
the manual page does not mention it), so a renumbered prefix costs nothing on
the wire. hostapd has no reload that keeps clients associated, so an edited SSID
is a restart and every station is deauthenticated -- which the plan warns about
in those words. A `backend.reload` that quietly stopped and started would hide
that difference behind one verb, so every other backend refuses the op by name.

## What is deliberately not carried

**The passphrase's value.** It is not in the observation and must not be: an
`ObservedBackend` goes over the control socket, into `/run` and out of
`ncfg status --json`, and constraint 5 keeps secret material out of all three.
It is not in the document either -- what the document holds is a `SecretRef` --
so a *pure* planner has nothing to compare even in principle.

So the comparison happens **in the observer**, which is the one place both
halves are already in hand: the value hostapd was started with is in the file
netcfgd generated, and the value the store holds is a resolve away. What leaves
that function is `ObservedBackend::secret_matches`, a boolean -- the same shape
`private_key_loaded` already has, reporting the presence of a key without
carrying one. The planner stays pure and compares a boolean; nothing that
travels holds a secret.

This was written a few hours after the paragraph above said it would be, and
the paragraph is left standing because the reasoning is the record: the
alternative -- an explicit `ncfg restart` -- was smaller and was an admission
that the reconciler cannot see something it ought to.

**`None` is not `false`.** No document, no secret in the store, an unreadable
file and an open network all produce `None`, and nothing restarts on it: a
restart deauthenticates every station, and "I could not check" is not a reason
to. That distinction has its own test, because the version that treated the two
alike would have passed every other one.

## Consequences

- An access point whose SSID, channel or stated band no longer match is
  restarted, and the station lists are left alone while that is planned: the
  access point comes back with the whole file rebuilt, so converging a list on
  a daemon about to be replaced is work that fails or is undone.
- A band the document does *not* state is not compared. An absent `band` means
  "work it out from the channel", and the file records what was worked out --
  comparing those would restart the access point on every reconcile for a
  document nobody edited. That mistake was made first and caught by the test
  that asserts a matching access point plans nothing.
- The observed schema gains two fields, and its witness moved for both.
- Nothing here reaches `pppd` or `openvpn`. Their configuration is netcfgd's
  own options file, rewritten on every start, and the operator's `.ovpn`, which
  netcfgd does not read (0046) -- so neither has a comparison to make.
