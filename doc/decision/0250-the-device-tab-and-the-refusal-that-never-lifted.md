# 0250: the device tab, and the refusal that never lifted

Status: accepted
Date: 2026-09-16
Milestone: M9; the window can configure the machine

## What was missing, in the operator's words

> We now have no device section and there is no way to configure IP for each
> link nor is there a way to configure the physical interfaces properly.

Both halves were true, and the second was worse than it looked.

## The device half

`device` blocks have been the model's since 0155 -- the adapter, its MTU and
MAC, ethtool settings, what drives a radio, whether netcfgd manages it at all
-- and **no window could write one**. The only key any screen reached was the
MTU, which the interface editor smuggled out as a second block inside
`interface-<name>.conf`.

So there is a `devices` tab now, beside `links` and after it: a link is where
the networking is configured, a device is what has to exist before a link can.
Its rows are a union of the kernel's adapters and the document's blocks, for
the reason the link inventory is one (0246) -- a card nobody has configured is
the commonest thing on a fresh machine, and a block whose card is out is what
somebody is looking for when nothing came up.

The editor carries `managed` and `on_unmanage`, the MTU and MAC, the ethtool
settings and offloads, and the radio and modem policies -- the last two shown
only where the device has one, because a `wifi` block on a wired card compiles
and means nothing.

**A device's `kind` is read-only here, and says so.** A bridge or a bond
carries members and a VLAN a parent and an id; a form that wrote the block back
without them would empty it. Making virtual links from the window is its own
round.

**The MTU moved and had to.** Two screens writing one `device` block into two
drop-ins is a duplicate block the loader refuses -- correctly -- so the
interface editor writes no device block at all now, and the live probes assert
both sides of that.

## The addressing half

The interface editor offered one combo for the whole `addressing` list:
`dhcp`, `dhcp+slaac`, `static` and four more. The model's own word for
addressing is a *list*, and a composition the combo did not name -- two
sources, a lease beside a fixed address -- was reported as unrepresentable.
Routes were one `default via` box, so an interface with a route to another
subnet was refused wholesale. A per-interface DNS scope had no field at all,
and neither did `on_drift`.

All four are fields now: the sources as an ordered list with add, remove, up
and down; the routes as a destination/via/metric table; the DNS scope as a mode
and three space-separated lists; `on_drift` as a combo.

## The refusal that never lifted

The editor refuses to save a block carrying a key it has no field for, which is
right: a form composed from six fields and saved with `replace = true` would
delete the rest. The list of such keys was built like this:

```quote from=client/ncfg_client.c
Is this key there at all?
```

and `ncfg_json_member` answers `NCFG_JSON_NONE` for a key that is not there.
That value is `0xffffffff`, which is **true**. So `if (member(...))` read as
"the key is present" and meant "always": every interface was reported as
carrying every key on the list, and **the interface editor could not save any
interface that existed**. That is the operator's "no way to configure IP for
each link", exactly.

Nothing caught it. Both tests that exercise that dialog open it on an interface
the document does not describe, which returns before the check -- so the live
probe wrote its drop-in happily and the headless one asserted loading and never
tried saving. The headless probe now saves, and the check is `!= NCFG_JSON_NONE`
in the seven places presence was the question.

**And the same shape was in the reader's own answer**: a DNS server is an
object carrying an address, a port and an SNI name, not a string, so the
servers a scope names arrived empty until this round read the field rather than
the element.

## The stale binary, again

The headless probes link `libncfg_client.a` and had no `PRE_TARGETDEPS` on it,
so `make -C gui test` considered them up to date after the library was rebuilt
and ran the old client. It cost a debugging round here -- a failure that had
already been fixed. The live probes' projects have carried that line, and the
comment explaining it, since the day they were written; all twelve headless
projects have it now.

Third time this campaign has paid for a stale artifact, after 0247's sabotage
pass and 0249's skipped suite.

## Seven sabotages, all caught

A key that is merely present counting as unrepresentable again; DNS servers
read as strings; `managed` written when it is the default; an empty `ethtool`
block written anyway; a toggle left alone written as `unmanaged`; the interface
editor writing a device block again; the device editor never loading what was
written.
