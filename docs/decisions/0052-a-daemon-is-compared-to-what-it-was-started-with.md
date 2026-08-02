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

## What is deliberately not compared

**The passphrase.** It is not in the observation and must not be: an
`ObservedBackend` goes over the control socket, into `/run` and out of
`ncfg status --json`, and constraint 5 keeps secret material out of all three.
It is not in the document either -- what the document holds is a `SecretRef` --
so a *pure* planner has nothing to compare even in principle.

The consequence is worth stating plainly rather than discovering: **editing the
secret behind `@secret:guest` changes nothing until the access point is
restarted for some other reason.** Two ways out, neither taken here:

- The observer could resolve the reference and compare a hash of what hostapd
  was started with against a hash of what the store holds now, publishing the
  answer as a boolean the way `private_key_loaded` already is. That keeps the
  planner pure and the secret out of the observation, and it is the shape to
  reach for when somebody wants this.
- `ncfg` could grow an explicit "restart this access point" request. That is
  smaller, and it is also an admission that the reconciler cannot see something
  it ought to.

The first is better and neither is urgent, because rotating a passphrase is a
deliberate act with a person present -- unlike an ISP renumbering at three in
the morning, which is what this record is really about.

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
