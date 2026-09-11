# 0208: the APN register that answers with the question

Status: accepted
Date: 2026-09-11
Milestone: M9; folding in what a second implementation measured

Two documents and a working tool for the same class of hardware were read
against netcfgd's modem support: a flashing-and-testing runbook, and
`cell-select`, which drives a two-SIM mux on an i.MX91 and has been run on the
metal repeatedly. Most of what they know netcfgd already knew --
[0150](0150-a-sim-source-is-chosen-the-way-an-uplink-is.md) and
[0152](0152-a-sim-source-is-kept-until-the-probe-says-otherwise.md) got the
shape of SIM selection right, the quirks table already carried the module, and
the "a link that pings is not a link that works" reasoning was already in
`netcfgd-modem-at`'s header. One thing they knew that netcfgd had backwards is
worth this record.

## The helper read the request and called it the outcome

`netcfgd-modem-at` reported the APN in force like this:

```sh
in_use=$(at "AT+CGDCONT?" | sed -n '...')
```

under a comment saying **"The APN the context has, not the one we asked
for"**, and followed by a warning that shouts when the two differ.

`AT+CGDCONT=` is what the helper writes the requested APN with, two steps
earlier. `AT+CGDCONT?` reads that same register back. So `in_use` was the
request, it always equalled `$apn`, and **the substitution warning could not
fire** -- not on any modem, not on any network. The failure the helper says it
exists to catch was the one thing it could not see.

The grant lives in the *dynamic* parameters:

```text
AT+CGDCONT?      -> ...,"internet.cxn",...     what was asked
AT+CGCONTRDP=1   -> ...,"im.cxn",...           what the network gave
```

Measured on an EG916Q-GL, same SIM, two attaches four minutes apart: one asked
for `im.cxn` and was granted `internet.cxn`, the next asked for `internet.cxn`
and was granted `im.cxn`. **The addresses came from different pools**, which is
independent of the `CGCONTRDP` string and so is corroboration that the grant
genuinely differed rather than the report being stale.

## And the fake was built to match the helper

`fake_at_modem.py` made `AT+CGDCONT=` *store the substituted APN*, so
`AT+CGDCONT?` read it back changed. No module does that -- a register answers
with what was written to it -- and the behaviour was invented to make the code
under test look right.

So the live test passed, and its header called the substitution case "the case
this file exists for". With the fake corrected, the old helper fails it:

```text
FAIL a substituted APN is reported as the one in effect
       expected to contain: attached on xlm.cxn
       actual:              netcfgd-modem-at: attached on im.cxn
```

**This is [0207](0207-a-preference-that-walks.md)'s shape in another
component**, found the same week: a check derived from the implementation it
was meant to check, agreeing with it by construction. There the assertion was
an exact number read off the code; here it is a whole simulated device. The
tell is the same -- the test was written *after* the code and *from* it, rather
than from the thing being modelled.

## Not known is not the same as as-asked

`+CGCONTRDP` is answered only once a context is active, some firmware does not
implement it, and a modem manager takes the port back on registration -- which
is exactly when there is finally something to read. Any of those leaves the
grant unread.

The helper now says so, rather than filling the gap with the request:

```text
netcfgd-modem-at: the modem did not report a granted APN,
netcfgd-modem-at:   so `im.cxn` is what was asked for and
netcfgd-modem-at:   not known to be what is in force
```

Filling it in would put the defect back in a quieter form.

## The module's own DHCP offers resolvers that do not answer

Measured: the module advertises `192.168.10.3` and `.4`, on its own pre-attach
subnet, and neither responds to a query. The resolvers that work are in the PDP
context, arrive with the attach, and change with the APN.

netcfgd needs nothing new to express this. An interface takes its lease's
nameservers only where it carries a `dns { }` block
([0007](0007-dns-scopes.md)), so **leaving that block off a cellular
interface is what `UseDNS=no` says elsewhere** -- and it is now documented as
the default in `netcfgd.conf.example`, alongside the reason.

**What the helper does not do is report them**, and that is a decision rather
than an omission. A report merges with the lease's own nameservers on the same
interface rather than replacing them, so reporting the live pair would leave
the dead pair beside it and make the scope ambiguous instead of wrong. Making
this a real report needs netcfgd to be able to say which source of nameservers
wins on one interface, which is a question worth answering on its own. Until
then the helper prints the granted pair, where it is diagnostic and cannot be
mistaken for policy.

## What was folded in without changing behaviour

`modem-quirks` gained what the same module answers vacuously or refuses, all
measured: `AT+CRSM` refused for every file including `EF_ICCID` (the control
that makes it the command rather than the file); `AT+QSIMSTAT?` reporting
"inserted" with the socket empty because `+QSIMDET` is `0,0`; no hot-plug
detection at all; an ISD-R probe that cannot tell a socket from an eUICC, so
the ICCID is the only discriminator; `AT+CFUN=1,1` rebooting the whole SoC on
one carrier and being harmless on another with the same module; a socket that
cannot read being indistinguishable from an empty one; an eUICC with no enabled
profile presenting as no SIM; and `ESM cause 33` being the subscription rather
than the APN, which is what makes a sweep of APNs against an unactivated
profile read as "every APN is wrong".

None of these changes what a helper does, which is the table's own rule: it
explains and does not decide.

## And one contradiction between two shipped files

`sim-select.example` showed the modem's interface as `config = "reported"`.
That is right for MBIM, where the helper obtains the address and writes it
down. It is wrong for an ECM module, where `netcfgd-modem-at` deliberately
writes *no* report because the module runs a DHCP server and the address
arrives as a lease -- so an interface left on `reported` waits for a file
nothing will write.

Both files were correct about their own half and neither said which case it
was describing. The example now shows both and says how to tell them apart,
which `modem-quirks` already answers with `data=`.

## What was deliberately not taken

`cell-select` drives GPIO to move a SIM mux and resets the modem over a reset
line. That is board enablement and 0150 already put it outside netcfgd, which
has no GPIO and hands the decision to a `pre_up` hook. Nothing here revisits
that; the measured facts about *what the mux does to the module* are worth
having, and the code that drives it is not netcfgd's.
