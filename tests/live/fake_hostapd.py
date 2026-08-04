#!/usr/bin/env python3
"""A hostapd control socket with stations on it.

The same trade as fake_supplicant.py, for the same reason: the one thing this
repository cannot produce on demand is a radio, and without one no station ever
associates. ap.sh drives a *real* hostapd -- which is what proves netcfgd
generates a file it accepts -- but a hostapd with no radio has no clients, so
nothing downstream of "who is connected" can be exercised against it.

This is a fake radio, not a fake protocol. The wire format is the real one and
the replies are copied from hostapd 2.10's own `hostapd_ctrl_iface_sta_mib` and
`hostapd_get_sta_info` in `src/ap/ctrl_iface_ap.c`, including the two things a
plausible fake would get wrong:

  - a station whose driver statistics could not be read prints none of them,
    so `signal=` and `rx_bytes=` are simply absent rather than zero
  - the walk ends with an *empty* reply, because the MIB printer returns zero
    bytes for a null station

The access control lists are real state here rather than a command that answers
OK, for the same reason. `hostapd_ctrl_iface_acl_show_mac` prints
`MACSTR " VLAN_ID=%d\n"` per entry and *nothing at all* for an empty list, and
`ADD_MAC`/`DEL_MAC` are idempotent -- adding an address already present and
deleting one that is absent both answer OK. A fake that answered OK to
everything would let a converger pass while sending the same command forever.

    fake_hostapd.py <ctrl-dir> <interface> [--deny addr,addr] [--accept addr,...]
                                           [--wedged]

`--wedged` binds the socket and answers nothing, ever. That is the state
decision 0085 is about and it is not the same as a dead daemon: the process is
there, the pid file is right, the socket accepts a datagram and no reply comes
back. Nothing else in this repository can produce it, which is why it is a flag
here rather than a second fake.
"""

import os
import socket
import sys

# address, authorized, and whether the driver could be read for it.
#
# Three stations covering the cases that render differently: an ordinary
# authorized client with full statistics, one that is associated but has not
# finished authenticating, and one the driver would not answer about.
STATIONS = [
    ("00:11:22:33:44:55", True, True),
    ("aa:bb:cc:dd:ee:ff", True, False),
    ("66:77:88:99:aa:bb", False, True),
]

# hostapd's two in-memory lists, seeded from the command line. Both exist
# whatever `macaddr_acl` says -- `hostapd_check_acl` consults the accept list
# first and the deny list second, and `macaddr_acl` decides only what happens to
# an address in neither -- so a fake with one list would hide the case where a
# stale accept entry overrides the deny list that is meant to be refusing it.
ACL = {"deny": [], "accept": []}


def mib(index):
	"""One station's block, exactly as hostapd orders it."""
	address, authorized, has_stats = STATIONS[index]
	flags = "[AUTH][ASSOC][AUTHORIZED][SHORT_PREAMBLE][WMM][HT]" if authorized \
	    else "[AUTH][ASSOC]"
	block = (
	    f"{address}\n"
	    f"flags={flags}\n"
	    "aid=1\n"
	    "capability=0x431\n"
	    "listen_interval=10\n"
	    "supported_rates=02 04 0b 16 0c 12 18 24 30 48 60 6c\n"
	    "timeout_next=NULLFUNC POLL\n"
	)
	if not has_stats:
		# hostapd_get_sta_info returns 0 without writing anything when
		# hostapd_drv_read_sta_data fails. The station is still listed.
		return block
	return block + (
	    "rx_packets=1234\n"
	    "tx_packets=5678\n"
	    f"rx_bytes={100000 * (index + 1)}\n"
	    f"tx_bytes={200000 * (index + 1)}\n"
	    "inactive_msec=40\n"
	    f"signal={-52 - index * 9}\n"
	    "rx_rate_info=650 mcs 7 shortGI\n"
	    "tx_rate_info=650 mcs 7 shortGI\n"
	    f"connected_time={3600 * (index + 1)}\n"
	)


def index_of(address):
	for index, (candidate, _, _) in enumerate(STATIONS):
		if candidate.lower() == address.strip().lower():
			return index
	return None


def answer(command):
	if command == "PING":
		return "PONG\n"
	if command == "STA-FIRST":
		# Empty when nobody is associated, which is the same answer as the end
		# of the walk. Both are "no station", and hostapd does not distinguish.
		return mib(0) if STATIONS else ""
	if command.startswith("STA-NEXT "):
		index = index_of(command[len("STA-NEXT "):])
		if index is None:
			# An address hostapd does not know. It answers FAIL, and the walk
			# has to stop rather than treating it as a station.
			return "FAIL\n"
		if index + 1 >= len(STATIONS):
			return ""
		return mib(index + 1)
	if command.startswith("STA "):
		index = index_of(command[len("STA "):])
		return mib(index) if index is not None else "FAIL\n"
	for prefix, name in (("DENY_ACL ", "deny"), ("ACCEPT_ACL ", "accept")):
		if command.startswith(prefix):
			return acl(name, command[len(prefix):])
	if command.startswith("DEAUTHENTICATE "):
		return "OK\n"
	# Everything else. FAIL is a real hostapd answer; inventing a success would
	# make a test pass for a command that did nothing.
	return "FAIL\n"


def acl(name, rest):
	"""One of hostapd's two lists, changed the way ctrl_iface.c changes it."""
	held = ACL[name]
	if rest == "SHOW":
		# `hostapd_ctrl_iface_acl_show_mac` writes nothing for an empty list, so
		# this returns zero bytes rather than an empty line -- which is what the
		# reader has to cope with, and what a plausible fake gets wrong.
		return "".join(f"{addr} VLAN_ID=0\n" for addr in held)
	if rest == "CLEAR":
		held.clear()
		return "OK\n"
	if rest.startswith("ADD_MAC "):
		address = rest[len("ADD_MAC "):].strip().lower()
		if not valid(address):
			# `hwaddr_aton` failing is the one way these answer FAIL.
			return "FAIL\n"
		if address not in held:
			held.append(address)
			# hostapd qsorts the list on every add.
			held.sort()
		return "OK\n"
	if rest.startswith("DEL_MAC "):
		address = rest[len("DEL_MAC "):].strip().lower()
		if not valid(address):
			return "FAIL\n"
		# Deleting an address that is not there is not an error, and neither is
		# deleting from an empty list -- `hostapd_ctrl_iface_acl_del_mac`
		# returns 0 for both.
		if address in held:
			held.remove(address)
		return "OK\n"
	return "FAIL\n"


def valid(address):
	parts = address.split(":")
	return len(parts) == 6 and all(
	    len(part) == 2 and all(c in "0123456789abcdef" for c in part)
	    for part in parts
	)


def main():
	if len(sys.argv) < 3:
		print("fake_hostapd.py <ctrl-dir> <interface> [--deny a,b] [--accept a,b]",
		      file=sys.stderr)
		return 2
	ctrl_dir, interface = sys.argv[1], sys.argv[2]
	# What hostapd read out of its configuration file at startup, which is the
	# state a converger has to reconcile against.
	rest = sys.argv[3:]
	wedged = "--wedged" in rest
	for flag, name in (("--deny", "deny"), ("--accept", "accept")):
		if flag in rest:
			value = rest[rest.index(flag) + 1]
			ACL[name] = sorted(a for a in value.split(",") if a)
	os.makedirs(ctrl_dir, exist_ok=True)
	path = os.path.join(ctrl_dir, interface)
	if os.path.exists(path):
		os.unlink(path)

	server = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
	server.bind(path)
	# Announce readiness on stdout so the shell waits rather than sleeping.
	print("ready", flush=True)

	try:
		while True:
			data, sender = server.recvfrom(4096)
			command = data.decode(errors="replace").strip()
			print(f"cmd: {command}", flush=True)
			if wedged:
				# Read and dropped. A wedged hostapd is not one that refuses
				# the connection -- it is one that takes the request and never
				# gets round to it, which is why netcfgd needs a deadline
				# rather than an error to notice.
				continue
			try:
				server.sendto(answer(command).encode(), sender)
			except OSError:
				# The client went away between its request and our reply, which
				# is ordinary for a one-shot command.
				pass
	except KeyboardInterrupt:
		pass
	finally:
		server.close()
		if os.path.exists(path):
			os.unlink(path)
	return 0


if __name__ == "__main__":
	sys.exit(main())
