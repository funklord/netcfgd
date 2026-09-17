# 0256: the other half of wifi

Status: accepted
Date: 2026-09-17
Milestone: M9; the window can configure the machine

## What no client could see

A `network` block is somewhere this machine joins. An `access_point` block is a
network it **runs**: netcfgd generates hostapd's configuration under `/run`,
starts it, and reports what it was started with. The block has been in the model
since M4, `ncfg wifi clients` lists who is associated with one, and **no window
could show one, let alone write one**.

So the wifi tab has a third list under the saved networks, and an editor behind
it. The two above it answer "what is around this machine" and "what has this
machine been told about"; this one answers "what does this machine offer".

## Configuration and observation, joined

The list is the document's blocks with the running half joined on, because the
two answer different halves of one question and an operator is usually asking
the second:

* `on air` is `no` for an access point that is configured and not running,
  which is the state somebody is looking for when the network they set up is
  not there, and `started, silent` for hostapd running and not answering.
* the channel column says `36 (on 6)` where hostapd took a different one --
  **a channel can be refused and hostapd then chooses**, and an access point
  beaconing somewhere other than where the block put it is a fact only the
  observation has. The editor says the same thing in a sentence when it opens.

## What the form refuses, and why each is its own sentence

* **A passphrase typed where a reference belongs.** `@secret:ap`, because the
  document type cannot hold key material -- the rule that makes a document safe
  to write to `/run`, and the same refusal the WireGuard and PPPoE editors make.
* **An empty station list with a policy.** `only these stations` with nobody on
  it admits nobody; that is a legal block and almost certainly not what was
  meant, so it is refused rather than written.
* **A two-letter regulatory domain**, which the compiler would refuse anyway,
  said beside the field instead of after a round trip.

And what it does *not* refuse, because netcfgd cannot know it: the outcome line
says the radio still needs an address. hostapd beacons and stations associate;
a station then needs an address, a route and a resolver, and **netcfgd serves no
DHCP**. An access point on a radio with no address is one every station
associates with and reaches nothing through -- the example file spends a
paragraph on it and now so does the thing that writes the block.

`eap` is deliberately not offered. On an access point it means pointing hostapd
at a RADIUS server rather than holding a credential, which is a different form;
the model's type is shared with a station profile and stays wide, and what this
offers is what it can render.

## The link-time trap this cost

`live_wifi` links `wifi_view.cpp`, and the tab growing a third table meant it
also had to link `access_point_dialog.cpp`. Without it the probe fails with
`undefined reference to vtable for ncfg_access_point_dialog` -- which reads like
a build-system problem rather than a missing source, and which was invisible
until the whole live suite was rebuilt, because the stale binary kept passing.

**Fourth stale-artifact cost in this campaign**, after 0247's sabotage pass,
0249's skipped suite and 0250's headless probes. The pattern is the same every
time: a test that was not rebuilt is a test reporting on code that no longer
exists.

## Five sabotages, all caught

The station list dropped on save; `hidden = false` stated as though it had been
chosen; an open network still writing a `psk` key; a typed passphrase accepted;
the editor opening without loading what was written.
