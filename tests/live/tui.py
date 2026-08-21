#!/usr/bin/env python3
"""The TUI against a real pty and a real daemon.

Python, and the only test here that is. A TUI needs a pseudo-terminal to say
anything about: raw mode, escape sequences and signal handling are all
invisible to a pipe, and `script(1)` cannot drive input reliably because it
forwards through a pty of its own and closes it before the child has finished
starting. `pty.openpty()` gives direct control of both ends.

It is a test-time dependency, not a runtime one. Constraint 3 is about what the
binary links, and this links nothing.

What it covers is what only a terminal can show:

  * the five panes draw, and the tab bar tracks which one is showing;
  * `q` exits cleanly;
  * `a` then `y` runs apply-then-confirm through the daemon;
  * SIGTERM, SIGHUP and SIGQUIT restore the terminal.

The last is why this file exists. It was written after reading another
project's TUI, which routes termination through the same wait as the keyboard
so that a kill leaves by the same path as the quit key. netcfgd did not, and
measured, a `kill` left the operator's shell with ECHO and ICANON both off.
"""

import fcntl
import os
import pty
import re
import shutil
import signal
import struct
import subprocess
import sys
import tempfile
import termios
import time

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
NCFG = os.path.join(REPO, "target/debug/ncfg")
NETCFGD = os.path.join(REPO, "target/debug/netcfgd")

failures = 0


def check(label, actual, expected):
	global failures
	if actual == expected:
		print(f"ok   {label}")
	else:
		print(f"FAIL {label}")
		print(f"       expected: {expected!r}")
		print(f"       actual:   {actual!r}")
		failures += 1


def skip(why):
	if os.environ.get("NCFG_LIVE"):
		print(f"tui.py: NCFG_LIVE is set but this cannot run: {why}", file=sys.stderr)
		sys.exit(1)
	print(f"tui.py: skipping: {why}")
	sys.exit(0)


def visible(text):
	"""Drop escape sequences, keep the characters a person would see."""
	return re.sub(r"\x1b\[[0-9;?]*[a-zA-Z]", "", text).replace("\r\n", "\n")


class Session:
	"""A daemon and a pty, cleaned up together."""

	def __init__(self):
		self.work = tempfile.mkdtemp(prefix="ncfg-tui-")
		os.makedirs(f"{self.work}/etc")
		os.makedirs(f"{self.work}/run")
		with open(f"{self.work}/etc/netcfgd.conf", "w") as handle:
			handle.write(
			    'interface probe0 {\n\tkind = "dummy"\n\tconfig = "10.11.0.1/24"\n}\n'
			    'interface probe1 {\n\tkind = "dummy"\n\tconfig = "reported"\n}\n'
			)
		# Something outside netcfgd, reporting an interface netcfgd has not
		# configured. `ncfg status` has marked these since the modem work and
		# the device pane did not, which made the TUI the one view where "the
		# bearer is up" and "netcfgd acted on it" looked the same.
		os.makedirs(f"{self.work}/run/reported")
		with open(f"{self.work}/run/reported/probe1", "w") as handle:
			handle.write("address=10.64.1.23/30\ngateway=10.64.1.24\n")
		self.env = dict(
		    os.environ,
		    NCFG_CONFIG_DIR=f"{self.work}/etc",
		    NCFG_RUN_DIR=f"{self.work}/run",
			# The terminal is this test's, not the caller's: it drives a pty it
			# opened and decodes xterm's sequences by hand further down. TERM is
			# unset in a container and in most CI runners, and ncurses then
			# cannot initialise at all -- fourteen checks red for a reason that
			# has nothing to do with netcfgd.
		    TERM="xterm",
		)
		self.daemon = subprocess.Popen(
		    [NETCFGD], env=self.env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT
		)
		for _ in range(100):
			if os.path.exists(f"{self.work}/run/netcfgd.sock"):
				return
			if self.daemon.poll() is not None:
				out = self.daemon.stdout.read().decode(errors="replace")
				if "Operation not permitted" in out:
					self.close()
					skip("no CAP_NET_ADMIN (run under unshare -rn)")
				self.close()
				print(f"tui.py: the daemon exited: {out}", file=sys.stderr)
				sys.exit(1)
			time.sleep(0.05)
		self.close()
		print("tui.py: the daemon never started", file=sys.stderr)
		sys.exit(1)

	def spawn(self, rows=24, columns=80):
		master, slave = pty.openpty()
		fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", rows, columns, 0, 0))
		proc = subprocess.Popen(
		    [NCFG, "tui"], env=self.env, stdin=slave, stdout=slave, stderr=slave
		)
		os.set_blocking(master, False)
		return proc, master, slave

	def close(self):
		try:
			self.daemon.terminate()
			self.daemon.wait(timeout=3)
		except Exception:
			pass
		shutil.rmtree(self.work, ignore_errors=True)


def pump(master, seconds=0.5, into=None):
	end = time.time() + seconds
	while time.time() < end:
		try:
			data = os.read(master, 65536)
			if data and into is not None:
				into.append(data.decode(errors="replace"))
		except BlockingIOError:
			time.sleep(0.02)
		except OSError:
			return  # the child closed the pty, which is how it exits


def flags(fd):
	attrs = termios.tcgetattr(fd)
	return {
	    "ECHO": bool(attrs[3] & termios.ECHO),
	    "ICANON": bool(attrs[3] & termios.ICANON),
	    # `nonl` turns these off and nothing was checking them back on. A
	    # terminal with ONLCR off is the one that prints a staircase.
	    "ICRNL": bool(attrs[0] & termios.ICRNL),
	    "ONLCR": bool(attrs[1] & termios.ONLCR),
	}


def panes(session):
	"""Each pane draws, the tab bar follows, and q exits."""
	proc, master, slave = session.spawn()
	os.close(slave)
	seen = []
	pump(master, 1.2, seen)
	check("the device pane draws the interface", "probe0" in "".join(seen), True)
	check("and its address", "10.11.0.1/24" in "".join(seen), True)
	# Reported and not applied, marked as such. Without the marker this pane
	# says an address is on an interface that does not have one.
	check("and marks what was reported rather than applied",
	      "10.64.1.23/30 [reported]" in visible("".join(seen)), True)

	# Asserted on each pane's own content, not on the tab bar. ncurses emits
	# the minimal diff, so switching from [plan] to [events] sends only the
	# changed bracket cells -- the terminal displays "[events]" while that
	# string never crosses the wire. Body text changes wholesale between panes
	# and does arrive, and it is the more meaningful thing to check anyway.
	for key, marker in (
	    (b"p", "nothing to do"),
	    (b"e", "waiting for events"),
	    (b"w", "no scan"),
	    (b"s", "associated"),
	):
		seen.clear()
		os.write(master, key)
		pump(master, 0.5, seen)
		check(f"{key.decode()} shows its pane", marker in visible("".join(seen)), True)

	# Two keys in one write, deliberately. That is what an arrow key, a paste
	# and fast typing all look like, and it is how the buffered-stdin bug was
	# found: `poll` on the descriptor saw nothing while a BufReader held the
	# second byte, so it did not arrive until the next timeout a second later.
	#
	# Apply opens a confirm window; y answers it. The message the pane shows
	# after `a` promises both keys, and promising a key that does nothing is
	# worse than not offering the window at all.
	seen.clear()
	os.write(master, b"pa")
	pump(master, 0.8, seen)
	check("a applies with a window", "60s window" in visible("".join(seen)), True)
	seen.clear()
	os.write(master, b"y")
	pump(master, 0.8, seen)
	check("y confirms it", "confirmed" in visible("".join(seen)), True)

	# Arrow keys. The whole reason this client uses ncurses rather than
	# hand-rolled ANSI: Down arrives as ESC [ B, which terminfo decodes into
	# KEY_DOWN. The hand-rolled version read one byte and switched on it, so
	# arrows did nothing at all and their trailing bytes fell through as
	# unbound keys.
	#
	# Asserted by effect rather than by looking for a marker: moving the
	# selection repaints, and an unbound key repaints nothing. That tells
	# "decoded and acted on" from "ignored" without modelling the screen.
	os.write(master, b"d")
	pump(master, 0.5)
	seen.clear()
	# ESC O B, not ESC [ B. ncurses sends `smkx` on startup, which puts the
	# terminal into application cursor mode, and xterm's terminfo then has
	# kcud1=\EOB. A real terminal honours smkx; this pty has no emulator on the
	# far end, so the test has to send what one would. Sending the normal-mode
	# sequence decodes as a bare ESC, which is a correct reading of it.
	os.write(master, b"\x1bOB")  # Down, application cursor mode
	pump(master, 0.5, seen)
	check("Down moves the selection", len("".join(seen)) > 0, True)
	seen.clear()
	os.write(master, b"Z")  # bound to nothing
	pump(master, 0.5, seen)
	check("an unbound key repaints nothing", "".join(seen), "")

	os.write(master, b"q")
	try:
		proc.wait(timeout=3)
	except subprocess.TimeoutExpired:
		proc.kill()
		proc.wait()
	check("q exits cleanly", proc.returncode, 0)
	os.close(master)


def signals(session):
	"""A kill leaves by the same path as the quit key.

	`SIGQUIT` is here because it was the one that did not. `cbreak` leaves
	`ISIG` on, so `^\\` arrives as a signal whose default dumps core and dies
	with nothing run -- and measured against this pty it left ECHO, ICANON,
	ICRNL and ONLCR all off with the alternate screen still up. It is a key a
	person can press, beside the `^C` this already covered.

	Four flags rather than two, for the same reason: ECHO and ICANON were the
	two the first version of this checked, and `nonl` turns off two more that
	nothing would have noticed. A shell with ONLCR off prints a staircase.
	"""
	for sig, name in (
	    (signal.SIGTERM, "SIGTERM"),
	    (signal.SIGHUP, "SIGHUP"),
	    (signal.SIGQUIT, "SIGQUIT"),
	):
		proc, master, slave = session.spawn()
		pump(master, 0.8)
		check(f"the terminal is raw while running ({name})", flags(slave)["ECHO"], False)
		proc.send_signal(sig)
		try:
			proc.wait(timeout=3)
		except subprocess.TimeoutExpired:
			proc.kill()
			proc.wait()
		time.sleep(0.2)
		for flag in ("ECHO", "ICANON", "ICRNL", "ONLCR"):
			check(f"{name} restores {flag}", flags(slave)[flag], True)
		os.close(slave)
		os.close(master)


def resize(session):
	"""The frame follows the terminal without a SIGWINCH handler."""
	proc, master, slave = session.spawn(rows=40, columns=132)
	seen = []
	pump(master, 1.2, seen)
	widest = max((len(line) for line in visible("".join(seen)).split("\n")), default=0)
	check("a 132-column terminal is filled", widest >= 132, True)
	os.write(master, b"q")
	try:
		proc.wait(timeout=3)
	except subprocess.TimeoutExpired:
		proc.kill()
		proc.wait()
	os.close(slave)
	os.close(master)


def main():
	for binary in (NCFG, NETCFGD):
		if not os.access(binary, os.X_OK):
			skip(f"{os.path.basename(binary)} is not built")

	# The panes below expect netcfgd to have created two dummy interfaces, which
	# needs CAP_NET_ADMIN in a namespace of its own -- the Makefile runs this
	# under `unshare -rn` for that reason. Run without it, netcfgd creates
	# nothing, every device check fails, and the output reads as a broken TUI:
	# "the device pane draws the interface: expected True, actual False", four
	# times, with nothing pointing at the invocation. Ask the question directly
	# instead, so the answer names the cause.
	probe = subprocess.run(
	    ["ip", "link", "add", "ncfgtui0", "type", "dummy"],
	    capture_output=True,
	)
	if probe.returncode != 0:
		skip(
		    "cannot create a dummy interface, so netcfgd would configure "
		    "nothing and every pane would draw empty -- run under `unshare -rn`, "
		    "as the Makefile does"
		)
	subprocess.run(["ip", "link", "del", "ncfgtui0"], capture_output=True)

	session = Session()
	try:
		panes(session)
		signals(session)
		resize(session)
	finally:
		session.close()

	print()
	if failures:
		print(f"tui.py: {failures} failed")
		sys.exit(1)
	print("tui.py: all checks passed")


if __name__ == "__main__":
	main()
