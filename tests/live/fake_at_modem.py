#!/usr/bin/env python3
"""An AT modem with no radio behind it, on a pty.

The same trade `fake_mbimcli.sh` makes and for the same reason: the one thing
this repository cannot produce on demand is hardware. What is faked is the
modem, not the wire -- this is a real character device with real termios, so
the helper's `stty`, its CR-terminated writes and its byte-at-a-time reads are
all exercised rather than stubbed.

Three things a plausible fake would get wrong and this one does not:

  - **Answers are CR-terminated, not LF.** A modem sends `\\r\\n` between the
    echo and the answer but the helper is written not to depend on LF arriving,
    and a fake that sent tidy lines would let a reader that requires them pass
    here and hang on hardware.

  - **`AT+CGATT?` reports 0 until the APN is set.** The interesting bug is a
    helper that reports success before attaching, and a modem that answered 1
    immediately could not catch it.

  - **An APN the subscription does not carry is accepted and silently
    replaced**, which is what a real network does: `--wrong-apn` makes
    `+CGDCONT?` read back a different APN from the one set. A fake that
    echoed back whatever it was given would make it impossible to test the
    one failure that matters most, because it looks like success.

Not a general AT emulator: it knows the commands this helper sends and answers
ERROR to everything else, which is what a modem does for a command it lacks.
"""

import argparse
import os
import pty
import re
import sys

parser = argparse.ArgumentParser()
parser.add_argument("--print-path", action="store_true")
parser.add_argument("--wrong-apn", default="", help="what the network substitutes")
parser.add_argument("--never-attach", action="store_true")
parser.add_argument("--iccid", default="8944000000000000000")
args = parser.parse_args()

primary, secondary = pty.openpty()
path = os.ttyname(secondary)
if args.print_path:
	sys.stdout.write(path + "\n")
	sys.stdout.flush()

state = {"apn": "", "echo": True}


def answer(text):
	os.write(primary, text.encode())


buffer = b""
while True:
	try:
		chunk = os.read(primary, 1)
	except OSError:
		break
	if not chunk:
		break
	buffer += chunk
	if not buffer.endswith(b"\r"):
		continue
	line = buffer.decode(errors="replace").strip()
	buffer = b""
	if not line:
		continue

	if state["echo"]:
		answer(line + "\r")

	if line == "ATE0":
		state["echo"] = False
		answer("\r\nOK\r\n")
	elif line.startswith("AT+CGDCONT=") and "," in line:
		wanted = re.findall(r'"([^"]*)"', line)
		# The network's substitution, which is the case worth testing: asking
		# for an APN the subscription does not carry is not refused.
		state["apn"] = args.wrong_apn or (wanted[-1] if wanted else "")
		answer("\r\nOK\r\n")
	elif line == "AT+CGDCONT?":
		answer('\r\n+CGDCONT: 1,"IP","%s",,0,0\r\n\r\nOK\r\n' % state["apn"])
	elif line == "AT+CGREG?":
		answer("\r\n+CGREG: 0,1\r\n\r\nOK\r\n")
	elif line == "AT+CGATT?":
		up = state["apn"] and not args.never_attach
		answer("\r\n+CGATT: %d\r\n\r\nOK\r\n" % (1 if up else 0))
	elif line in ("AT+CCID", "AT+QCCID"):
		answer("\r\n+CCID: %s\r\n\r\nOK\r\n" % args.iccid)
	elif line == "AT+CEER":
		answer('\r\n+CEER: "No cause information available"\r\n\r\nOK\r\n')
	else:
		answer("\r\nERROR\r\n")
