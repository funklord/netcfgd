# 0095: a portal check fetches the operator's URL

Status: accepted
Date: 2026-08-04
Milestone: the shape [0061](0061-a-key-that-compiles-does-something-or-says-it-does-not.md) specified, built

## Context

`wifi { portal_check = true }` compiled into the document, was read by nothing,
and — since 0061 — said so in every plan. That decision refused to implement it
and named exactly what implementing it would look like:

> **netcfgd will not have a hard-coded one.** A network daemon that reaches out
> to a fixed address to decide whether the internet works is a decision for the
> operator [...] If this becomes a feature it is
> `portal_check = "https://example.com/generate_204"` — an operator's URL, or an
> operator's hook — and not a boolean with a default inside netcfgd.

This is that, with one correction to the example.

## Decision

**`portal_check` is an `http://` URL, and there is no default.** No URL, no
probe, which is every machine that did not ask. The privacy argument 0061 made
is unchanged and is the reason there is no default to fall back on.

**`https` is refused, and 0061's own example had it wrong.** A captive portal
works by *intercepting* a request and answering it with something else — which
is precisely what TLS exists to prevent. Over `https` a portal produces a
certificate error rather than a redirect, so an `https` probe reports *no
portal* on exactly the networks it was written for. Every implementation of this
uses clear HTTP for the same reason. Accepting an `https` URL would be accepting
one that is quietly useless, so the compiler refuses it with that sentence.

**Not a plan action.** A probe is a question, not a change: as an action it
would run on every apply and no plan would ever converge, which is section 4's
promise. It fires from the daemon on a transition — the interface has a routable
address now and did not when this last looked — using the same per-interface
record `carrier`, `lease` and `drift` use (0084). That is once per joining
rather than once per netlink event, which matters more here than elsewhere:
every event would be another request to somebody else's server.

**What it decides.** The expected answer is `204`, which is what a
`generate_204` endpoint is for. Anything else that *answers* is a portal,
including an answer that is not HTTP at all — something is on port 80 and it is
not what was asked for, and reading that as "clear" would be the worst of the
three. Nothing answering is **not** a portal: a portal is a thing that replies,
and saying "captive portal" about a network with no route sends the operator to
a login page that is not there. That case is logged and runs no hook.

No HTTP library. The request is one line and the answer that matters is the
status on the first line; reading further would mean parsing a body from a host
this has already decided not to trust. Resolution is `std`'s, so no dependency
either.

## What building it found

**A link-local address is not connectivity, and treating it as one made the
feature fire exactly once.** The first version asked whether the interface had
any address. Every interface that is up has an `fe80::` one from the moment the
kernel brings it up — so "became addressed" was true at startup and never
changed again, on every real machine.

It survived the first live run because the *first* probe is the one that works.
It was caught by the second probe never happening and by printing the recorded
state, which said `addressed` while the interface plainly had no address on it.
`is_routable` now excludes IPv6 and IPv4 link-locals and loopback, with a test.

## The gates

Compiler: a URL reaches the document, `https` is refused **with the reason** —
an operator told "no https" and not why will reasonably think netcfgd is being
lazy — and a device that names nothing gets nothing.

Probe: a status line decides; a redirect and a `200` are both portals; an answer
that is not HTTP is not clear.

Live, against a real HTTP server on a real socket, with a running daemon —
because a probe is not a plan action, so no `ncfg apply` can exercise it. Seven
checks over three networks: one that answers what was asked runs no hook, one
that answers a redirect runs it and tells the script the interface, the URL and
what came back instead, and one where nothing answers runs no hook and says it
could not be checked.

Three breaks. A link-local counting as connectivity fails four checks; a clear
network running the hook fails one; calling an unreachable network a portal
fails two — **and that third break passed until the unreachable case existed**,
which is why it does now.

## What is left

`pre_down` is the last recognised-and-never-run phase, deferred with a reason
since 0063 rather than unbuilt: it and `down` fire at the same point in a plan
until there is a teardown ordering.
