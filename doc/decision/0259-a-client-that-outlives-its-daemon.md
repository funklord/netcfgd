# 0259: a client that outlives its daemon

Status: accepted
Date: 2026-09-17
Milestone: M9; the window can configure the machine

## The report

*"Each time we update the software the tray software loses its icons."*

Two defects, and they meet at exactly that moment.

## The tray never reconnected

`ncfg_tde_tray::refresh()` reopens when the connection looks shut:

    if (!m_connection->is_open())
        m_connection->open();

and `is_open()` was `m_client != 0` -- a test of whether a client was ever
made, which is true of a dead one. Nothing set the pointer back to zero when a
request failed: `state_line()` and `daemon_reach()` returned "not reachable"
and left the client where it was.

**Every package upgrade restarts netcfgd**, which closes every socket it had.
So the first upgrade after the tray started left it asking on a socket with
nobody at the other end, for the rest of its life, reporting no daemon while
netcfgd was running.

This was not inferred from the code. On the machine that reported it, the tray
held `fd 12 -> socket:[16501929]`, which `ss -x` showed `ESTAB` with peer `0`
-- the daemon's end gone -- while the daemon listened on a newer socket.

**A client cannot tell a dead socket from a refusal by reading the error
string**, and the difference is the whole of whether to reconnect. So the C
client keeps the answer: `ncfg_client_broken` is set where the *transport*
failed -- a send that could not be written, a read that failed or returned end
of file, a line so long the stream can no longer be framed -- and not where
netcfgd said no. Reconnecting on a refusal would mean a new socket every time
somebody is told they may not do something.

`is_open()` on both front ends now asks that. The tray also reopens and asks
once more within the same tick when the state comes back as no-daemon, so a
restart between two ticks is not ten seconds of "netcfgd is not reachable"
after netcfgd is already back. Once, not in a loop: if the second attempt fails
the daemon really is not there.

The Qt window had the same shape -- `main.cpp` opens once at startup and
nothing reopened -- so `ncfg_main_window::refresh()` calls `reopen_if_broken()`
before it asks anything. It costs a connect only where the socket actually
died.

## The icon it was stuck on did not exist

Parked on the no-daemon rung, the tray asked for the glyph `network-disconnect`.
Of its four names, three are TDE icons -- `connect_established`,
`connect_creating` and `connect_no` are in crystalsvg at 16, 22 and 32 -- and
that one is from the freedesktop set. On this machine it exists only under
`/usr/share/icons/breeze*`, which is not in the theme chain TDE is using. The
loader substituted the generic `unknown` picture and said nothing, which is
what "lost its icons" describes.

Two changes. The rung asks for `messagebox_warning`, which is a fault in the
tool rather than a report about the network -- netcfgd not answering says
nothing about whether this machine can reach anything. And `state_glyph` probes
the wanted name with `canReturnNull`, which is the only way to find out whether
a theme has one, falling back to `connect_no` rather than to the question mark.

**A themed icon name is never wrong, only absent**, which is the sentence
`tool/icon_gate.py` was written around. It now also reads every themed name the
TDE front end asks for and checks that some installed theme carries it. The
check skips where no TDE icon tree is present -- TDE is not a build dependency
of this tree -- and refuses to pass on an extraction that found fewer than six
names, because a pattern that stopped matching would report nothing missing in
the same words as a real pass.

## What is tested, and where

The two transport paths are different code and are covered by different tests,
which is worth stating because each one passed the other's sabotage:

* **End of file on the read** -- `client/tests/client_test.c`. The fake daemon
  answers one request with a refusal, takes the next one, and closes without
  answering. The refusal must leave the connection usable; the silence must
  not.
* **A write to a socket nobody holds** -- `gui/tests/reconnect.cpp`, which
  starts a real daemon, opens a connection, kills the daemon, starts it again
  on the same socket, and asserts that the connection notices, reopens itself,
  and answers again -- and that a connection which is fine is left alone.

## Five sabotages, all caught

`is_open()` as a pointer test again; end of file not counted as a broken
transport; a failed write not counted either; a refusal counted as one; and the
old icon name put back.

The first sabotage pass had a hole worth recording: the reconnect probe did not
catch the end-of-file sabotage, because killing a daemon makes the *write*
fail, and the client test did not catch the write sabotage for the mirror-image
reason. Neither test was wrong; each covered one path and both were needed. The
client test's fake daemon was changed to read the request before closing, which
is what puts it on the other path.
