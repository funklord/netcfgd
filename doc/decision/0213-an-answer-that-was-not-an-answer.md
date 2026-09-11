# 0213: an answer that was not an answer

Status: accepted
Date: 2026-09-11
Milestone: M9; the wifi captive portal audit

The portal check fires on a transition: the interface has a routable address
now and did not when this last looked. That is right, and the reasoning behind
it is sound -- a probe is not a plan action, an observation cannot answer it,
and a question asked on every netlink event is a request to somebody else's
server every time a cable moves.

What it did with the answer was not.

## An inconclusive check consumed the transition

The verdicts are three: `Clear`, `Portal`, and `Unreachable` -- and the code is
careful about the third, refusing to call a network with no route a portal
because "a portal is a thing that *replies*". It logged the difference and then
recorded all three the same way: the interface is `addressed`, and nothing
happens again until it goes bare.

So a check that could not be completed was filed as a check that had been.

**The likely case is a wifi join, and the cause is ordering inside netcfgd.**
`run_portal_checks` runs before the reconcile that delivers DNS. On a fresh
join the address arrives from the lease, the probe runs, and the resolver
netcfgd is about to write has not been written yet -- so the name does not
resolve, the verdict is `Unreachable`, and the transition is spent. On a
captive portal that is exactly the network the operator asked to be warned
about, and DNS is exactly what a portal hijacks.

Measured, before the fix: with the address never leaving the interface and the
network becoming reachable afterwards, the hook never fired again.

## Retried, and bounded

An inconclusive answer now leaves a count behind and the next pass tries again.
The bound is the other half and is not decoration: the loop has a five-second
backstop, so retrying forever is a request to somebody else's server every five
seconds for as long as the machine sits on a network with no route. Six
attempts is about thirty seconds of a quiet loop -- far longer than a reconcile
and far shorter than a nuisance -- and then netcfgd says it has given up,
rather than going quiet about a check the operator asked for.

Both halves are asserted separately, because either alone is a defect:

```text
consume the transition on Unreachable -> "checked again once it works" fails
never give up                         -> "eventually given up on" fails, and
                                         the retries do not stop
```

The second is counted rather than observed once: "it stopped" is not something
a single look can say, so the test waits for the sentence and then requires the
attempt count not to move.

## The number the whole check rests on was written down nowhere

`probe(url, 204)`. The endpoint has to answer 204, which is what a
`generate_204` URL is for -- an empty body and a status nothing produces by
accident. Anything else is reported as a portal.

Neither `netcfgd.conf.example` nor the field's own documentation said so. An
operator pointing `portal_check` at an ordinary page, which answers `200`,
gets a captive portal reported on every join of a working network and the hook
run each time.

**Not made configurable, and not guessed at.** What a URL returns is not a
property of the text, so the compiler cannot check it; and a heuristic that
accepted "any 2xx" would accept the `200` a portal's own login page returns,
which is the case this exists to catch. So it is documented in both places,
including what going wrong looks like. The verdict already names the number it
got, so the mistake is legible rather than silent -- which is what makes
documentation the proportionate answer rather than a shrug.

Whether `expect` should become a setting is a real question and is left open
rather than answered in passing: an operator whose only usable endpoint answers
`200` cannot use the feature today.

## What the audit found sound

The rest held up, and some of it is the reason this round had one finding
rather than several. The probe runs in an `exec`ed child that sheds privilege
before it resolves anything, because `getaddrinfo` in the process holding
`CAP_NET_ADMIN` is what CVE-2015-7547 turned into a root compromise. The child
bounds itself with an alarm, so reading it to end of file cannot hang. The
detail that reaches a root hook is sanitised to printable ASCII from a small
set, and the test drives `verdict` rather than `legible` precisely so that
bypassing the call site fails it. `https` is refused by name at compile time.
`is_routable` excludes link-local addresses, without which the check would fire
once at startup and never again.
