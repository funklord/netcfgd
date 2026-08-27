#!/usr/bin/env python3
"""A wpa_supplicant control socket with canned answers.

The one thing this repository cannot produce on demand is a radio. wifi.sh
already drives a *real* wpa_supplicant, which is what proves netcfgd's client
speaks the protocol correctly -- but a real supplicant with no radio finds no
networks, so nothing downstream of "the scan returned" can be exercised.

That matters for the NetworkManager shim, whose entire job downstream of a scan
is arithmetic: dBm becomes a percentage, a boolean and the configuration become
three bitfields, hex becomes octets. Those are the conversions a client
actually renders, and they are untestable against an empty list.

So this answers the four commands netcfgd sends, with results chosen to have
known answers on the other side. It is a fake radio, not a fake supplicant
protocol: the wire format here is the real one, and if netcfgd's parser changes
its mind about it, wifi.sh is what notices.

    fake_supplicant.py <ctrl-dir> <interface> [pidfile]

and, since it also has to be the supplicant netcfgd *starts*, the form netcfgd
invokes with:

    fake_supplicant.py -B -D<driver> -i <interface> -C <ctrl-dir> -P <pidfile>

That second form is why `NCFG_WPA_SUPPLICANT` exists. Everything a test could
fake before -- the radio, the control socket, the canned scan -- stopped short
of the one step that had actually broken: netcfgd deciding to start a
supplicant and starting it. A test that pre-starts the fake proves nothing
about that, and since the guard against taking over a live foreign supplicant
landed it proves less than nothing, because netcfgd correctly declines a socket
somebody else is already answering.

Speaks the same unix datagram protocol wpa_supplicant does: a client binds its
own address, sends a command, and gets one reply.
"""

import atexit
import os
import socket
import sys

# BSSID, frequency, signal (dBm), flags, ssid.
#
# The signal levels are chosen for what they become. -40 dBm is NM's top of
# scale and must give 100; -100 is the bottom and must give 0; -53 is what a
# real NetworkManager reported as 79 while the shim was written, and is the one
# cross-check available for the conversion.
NETWORKS = [
    ("00:11:22:33:44:55", 2412, -53, "[WPA2-PSK-CCMP][ESS]", "HomeFiber"),
    ("66:77:88:99:aa:bb", 5180, -40, "[ESS]", "Cafe"),
    ("cc:dd:ee:ff:00:11", 2437, -100, "[WPA2-PSK-CCMP][WPS][ESS]", "Distant"),
]

# The one this fake radio claims to be associated with.
ASSOCIATED = NETWORKS[0]


def hexify(text):
	return "".join(f"{byte:02x}" for byte in text.encode())


def scan_results():
	header = "bssid / frequency / signal level / flags / ssid"
	rows = [
	    f"{bssid}\t{frequency}\t{signal}\t{flags}\t{ssid}"
	    for bssid, frequency, signal, flags, ssid in NETWORKS
	]
	return "\n".join([header, *rows]) + "\n"


def status():
	bssid, frequency, _signal, _flags, ssid = ASSOCIATED
	return (
	    f"bssid={bssid}\n"
	    f"freq={frequency}\n"
	    f"ssid={ssid}\n"
	    "wpa_state=COMPLETED\n"
	    "key_mgmt=WPA2-PSK\n"
	)


terminating = False


def answer(command):
	if command == "PING":
		return "PONG\n"
	# **How netcfgd stops a supplicant, and the fake could not do it.**
	# `stop_backend` sends TERMINATE over the control socket rather than
	# signalling a pid -- decision 0014's rule that a daemon is stopped through
	# its own interface. This fake answered nothing to it, so it never exited,
	# and no test in the suite could verify that stopping a supplicant works at
	# all. Found when `displace.sh` asserted a released radio's supplicant was
	# gone and it was still there.
	#
	# Answer first and exit after, because a real supplicant replies OK and
	# then goes: a client that gets no reply cannot tell "stopped" from
	# "wedged", which is exactly the distinction 0141 turns on.
	if command == "TERMINATE":
		global terminating
		terminating = True
		return "OK\n"
	# A real supplicant answers OK and then sends unsolicited events to this
	# connection. Answering FAIL -- which is what this fake did before the roam
	# watcher existed -- makes a client reconnect and attach forever, which is
	# how that watcher's own behaviour under a refusing supplicant was found.
	if command in ("ATTACH", "DETACH"):
		return "OK\n"
	if command == "SCAN":
		return "OK\n"
	if command == "SCAN_RESULTS":
		return scan_results()
	if command == "STATUS":
		return status()
	if command == "LIST_NETWORKS":
		# Empty, so netcfgd adds the network rather than selecting one it
		# thinks is already there. Exercising the add is the point.
		return "network id / ssid / bssid / flags\n"
	# The association commands, answered the way a supplicant would. This is
	# what lets a test assert that a D-Bus `ActivateConnection` became a
	# `SELECT_NETWORK` on a control socket, rather than only that it returned
	# without an error.
	if command == "ADD_NETWORK":
		return "0\n"
	if command.startswith(("SET_NETWORK ", "ENABLE_NETWORK ", "SELECT_NETWORK ",
	                       "DISABLE_NETWORK ", "REMOVE_NETWORK ", "SET ")):
		return "OK\n"
	if command == "DISCONNECT":
		return "OK\n"
	# Everything netcfgd might send that this does not model. FAIL is a real
	# supplicant answer and netcfgd handles it; inventing a success would make
	# a test pass for a command that did nothing.
	return "FAIL\n"


def reply(server, sender, payload):
	"""Answer a sender that may already have gone away.

	The senders in `roam.sh` bind a socket, send one datagram and exit without
	waiting for anything back -- so by the time this replies, the process is
	often gone and the reply gets ECONNREFUSED. Unguarded, that raised OSError
	out of the receive loop, where the outer handler caught it and let the fake
	shut down *cleanly*: no traceback, no message, just a supplicant that had
	stopped answering. Every send after it then failed, and the report said only
	that a socket was missing.

	Caught once in a full `make live` in a container, after roam.sh was changed
	to say which precondition had failed rather than raising FileNotFoundError
	from a heredoc. A reply nobody is waiting for is not a reason to stop
	serving.
	"""
	if not sender:
		return
	try:
		server.sendto(payload, sender)
	except OSError:
		pass


def _unlink(path):
	try:
		os.unlink(path)
	except OSError:
		pass


def parse_netcfgd_argv(argv):
	"""netcfgd's own command line, or None if this is the positional form.

	Only the flags netcfgd passes, and it is deliberately not a general
	getopt: a fake that accepted more than the real caller sends would let a
	change in that caller go unnoticed here, which is the whole reason this
	file exists rather than a mock.
	"""
	if not any(argument.startswith("-") for argument in argv):
		return None
	interface = ctrl_dir = pidfile = None
	daemonise = False
	rest = list(argv)
	while rest:
		flag = rest.pop(0)
		if flag == "-B":
			daemonise = True
		elif flag == "-i" and rest:
			interface = rest.pop(0)
		elif flag == "-C" and rest:
			ctrl_dir = rest.pop(0)
		elif flag == "-P" and rest:
			pidfile = rest.pop(0)
		elif flag.startswith("-D"):
			continue  # the driver; a fake radio has none
		else:
			print(f"fake_supplicant: unhandled flag {flag}", file=sys.stderr)
			return False
	if not interface or not ctrl_dir:
		print("fake_supplicant: -i and -C are required", file=sys.stderr)
		return False
	return (ctrl_dir, interface, pidfile, daemonise)


def main():
	parsed = parse_netcfgd_argv(sys.argv[1:])
	if parsed is False:
		return 2
	if parsed is not None:
		ctrl_dir, interface, pidfile, daemonise = parsed
		if daemonise:
			# `-B` means background, and netcfgd waits for the control socket
			# to appear rather than for the process -- so the parent must not
			# exit before the child has bound it. Forking here and letting the
			# parent return is what a real supplicant does; the socket is
			# created below, in the child.
			if os.fork() > 0:
				return 0
			os.setsid()
		return serve(ctrl_dir, interface, pidfile)

	if len(sys.argv) not in (3, 4):
		print(__doc__.strip().splitlines()[-3], file=sys.stderr)
		return 2
	return serve(sys.argv[1], sys.argv[2], sys.argv[3] if len(sys.argv) == 4 else None)


def serve(ctrl_dir, interface, pidfile):
	# An optional pid file, because since 0080 a control socket does not prove a
	# supplicant is running and netcfgd is right about that: it asks whether the
	# pid file at $run/supplicant/<iface>.pid names a live process *whose own
	# command line contains that path*. A fake offering only a socket is one
	# netcfgd correctly decides is not there -- so it starts a real
	# wpa_supplicant, which binds this same socket path and answers scans from a
	# radio that does not exist. Every wireless check downstream then reads
	# blank, which is what nm.sh did for as long as 0080 has been in the tree.
	#
	# Passing the path as an argument is what makes the marker match; writing
	# the file is what makes the pid real. Both are needed and neither alone.
	if pidfile:
		os.makedirs(os.path.dirname(pidfile), exist_ok=True)
		with open(pidfile, "w") as handle:
			handle.write(f"{os.getpid()}\n")
		atexit.register(lambda: _unlink(pidfile))
	os.makedirs(ctrl_dir, exist_ok=True)
	path = os.path.join(ctrl_dir, interface)
	if os.path.exists(path):
		os.unlink(path)

	server = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
	server.bind(path)
	# Announce readiness on stdout so the shell can wait for it rather than
	# sleeping and hoping.
	print("ready", flush=True)

	# Who has sent ATTACH. A real wpa_supplicant sends unsolicited events only
	# to connections that asked, which is the whole reason netcfgd's roam
	# watcher has to send one -- so a fake that broadcast to everybody would let
	# a client that forgot ATTACH pass (0091).
	attached = set()

	try:
		while True:
			data, sender = server.recvfrom(4096)
			command = data.decode(errors="replace").strip()
			if command == "ATTACH" and sender:
				attached.add(sender)
			elif command == "DETACH" and sender:
				attached.discard(sender)
			# `ROAM <bssid>` is not a wpa_supplicant command. It is this fake's
			# way of being told to emit the event a real one emits when the
			# station moves, which needs two access points and a radio.
			elif command.startswith("ROAM "):
				bssid = command.split(None, 1)[1]
				event = (
				    "<3>CTRL-EVENT-CONNECTED - Connection to "
				    f"{bssid} completed [id=0 id_str=]"
				)
				for listener in attached:
					try:
						server.sendto(event.encode(), listener)
					except OSError:
						pass
				reply(server, sender, b"OK\n")
				print(command, flush=True)
				continue
			# Logged so a test can assert which commands a D-Bus call produced.
			# Secrets are redacted: `SET_NETWORK 0 psk "..."` carries the
			# passphrase, and a test fixture writing one to a log is the habit
			# this project refuses to get into.
			# Every keyword that carries key material, not just the two a
			# passphrase uses. An enterprise network sends `password` and
			# `private_key`, and a fixture logging one is the habit this
			# refuses to get into -- the comment above said so while the list
			# below covered only WPA-Personal.
			first = command
			for keyword in (" psk ", " sae_password ", " password ",
			                " private_key ", " private_key_passwd "):
				first = first.split(keyword)[0]
			print(first, flush=True)
			reply(server, sender, answer(command).encode())
			# TERMINATE was answered above; going now is the other half. The
			# socket is removed on the way out, as a real one does, so a client
			# that reconnects gets "no such file" rather than a socket nothing
			# is behind -- which is 0080's case and a different fault to
			# diagnose.
			if terminating:
				break
	except (KeyboardInterrupt, OSError):
		pass
	finally:
		server.close()
		if os.path.exists(path):
			os.unlink(path)
	return 0


if __name__ == "__main__":
	sys.exit(main())
