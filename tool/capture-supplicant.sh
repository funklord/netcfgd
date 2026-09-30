#!/bin/sh
# Capture what a REAL wpa_supplicant says, so the fake can stop guessing.
#
#     sudo sh tool/capture-supplicant.sh doc/capture/<name> [seconds]
#
# ## Why this exists, and why it is urgent exactly once
#
# `tests/live/fake_supplicant.py` models a supplicant's control protocol, and
# `evidence.md` names what that costs: *"a stand-in reproduces the half of a
# tool you have seen."* Its `STATUS` fields, its `SCAN_RESULTS` header, its
# `LIST_NETWORKS` flags and the shape of its events were written from the runs
# their author happened to have met. Every one of them is checkable against a
# real radio, and only while there is one.
#
# `mac80211_hwsim` is in the stock kernel package, so virtual radios survive a
# machine with no wifi. What does not survive is a real driver, a real access
# point, and a real association failure -- so what this captures is the part
# that cannot be recovered later.
#
# ## What it does to the machine: nothing
#
# Five read commands over the control socket and a passive attach for events.
# `STATUS`, `SCAN_RESULTS`, `LIST_NETWORKS` and `PING` change no state, and
# `wpa_cli` is only ever asked to listen. **It never sends `SELECT_NETWORK`,
# `DISCONNECT`, `REMOVE_NETWORK`, `SET_NETWORK` or `SCAN`** -- the last because
# a scan is a state change on a radio somebody is using, and the results of the
# one the supplicant did on its own are what a fake needs anyway.
#
# It stops on its own: the event capture is a `timeout`, everything else is one
# command each.
#
# ## What to do with the output
#
# Read it, then correct `fake_supplicant.py` against it. A field the fake emits
# that no real supplicant does, and a field it omits that one always sends, are
# both defects a green suite cannot see.
set -eu

out=${1:-}
seconds=${2:-120}

if [ -z "$out" ]; then
	echo "usage: sudo sh tool/capture-supplicant.sh <output-directory> [seconds]" >&2
	exit 2
fi
case "$seconds" in
[0-9]*) ;;
*) echo "the second argument is a number of seconds" >&2; exit 2 ;;
esac
# **Zero is not "do not listen", it is "listen for ever.**" GNU `timeout` reads
# 0 as no timeout at all, so the obvious way to ask for the read commands
# without the event capture is the one way to leave a process running until
# somebody notices. Refused by name.
if [ "$seconds" -eq 0 ]; then
	echo "0 seconds means no timeout to timeout(1), which would listen for ever" >&2
	echo "use 1 for the read commands alone" >&2
	exit 2
fi

# **Resolved rather than assumed on PATH.** Debian ships it in `/usr/sbin`, so
# `command -v wpa_cli` is false for an ordinary user's PATH and true under
# `sudo` -- which reads as "not installed" to whoever tried it first without
# root, on a machine where it is installed. Measured here.
wpa_cli=$(command -v wpa_cli 2>/dev/null || true)
for candidate in /usr/sbin/wpa_cli /sbin/wpa_cli; do
	[ -n "$wpa_cli" ] && break
	[ -x "$candidate" ] && wpa_cli=$candidate
done
[ -n "$wpa_cli" ] || {
	echo "wpa_cli is not installed: it is in the wpasupplicant package" >&2
	exit 1
}

# netcfgd tells its supplicant where to put the socket, so ask netcfgd rather
# than guessing: `-C /run/wpa_supplicant` is what the running one was given.
ctrl=${NCFG_WPA_CTRL_DIR:-/run/wpa_supplicant}
[ -d "$ctrl" ] || { echo "no control directory at $ctrl" >&2; exit 1; }

# **Which socket is the radio, which this got wrong first and loudly.**
#
# The first version took `ls "$ctrl" | head -1`, which on any machine netcfgd
# is running on returns `netcfgd-<pid>-<n>` -- netcfgd's own CLIENT socket,
# which it binds in the same directory to talk to the supplicant. Every command
# then failed with "Failed to connect to non-global ctrl_ifname ... Operation
# not permitted", the script printed a success line for each, and the capture
# was six files of one error. A directory listing's first entry is not the
# thing you wanted; it is the thing that sorted first.
#
# So: skip what netcfgd binds, skip the p2p control socket wpa_supplicant makes
# beside the real one, and keep only names that are actual links on this
# machine. **Refuse rather than choose** where more than one survives -- a
# machine with two radios is exactly where picking would be wrong and silent.
iface=${NCFG_CAPTURE_IFACE:-}
if [ -z "$iface" ]; then
	candidates=
	for entry in "$ctrl"/*; do
		[ -S "$entry" ] || continue
		candidate=$(basename "$entry")
		case "$candidate" in
		netcfgd-*|p2p-dev-*) continue ;;
		esac
		[ -d "/sys/class/net/$candidate" ] || continue
		candidates="$candidates $candidate"
	done
	set -- $candidates
	case $# in
	0) echo "no supplicant control socket under $ctrl that names a link" >&2; exit 1 ;;
	1) iface=$1 ;;
	*)
		echo "more than one radio answers under $ctrl:$candidates" >&2
		echo "name one with NCFG_CAPTURE_IFACE=<interface>" >&2
		exit 1
		;;
	esac
fi
[ -S "$ctrl/$iface" ] || { echo "no control socket at $ctrl/$iface" >&2; exit 1; }

mkdir -p "$out"

# **The control, before anything is captured.** Every `ask` below writes
# whatever came back, error included, and reports a filename -- so a run that
# could not talk to the supplicant at all printed six success lines and
# captured six copies of one refusal. That is a vacuous pass in a tool whose
# whole job is to bring evidence back, and the fix is one command that must
# answer before the rest are trusted.
if ! "$wpa_cli" -p "$ctrl" -i "$iface" PING 2>&1 | grep -q PONG; then
	echo "the supplicant on $iface does not answer on $ctrl/$iface" >&2
	echo "  (run as root: the socket is root-owned and mode 0770)" >&2
	"$wpa_cli" -p "$ctrl" -i "$iface" PING 2>&1 | sed 's/^/  /' >&2
	exit 1
fi

ask() {
	printf '# %s\n' "$1" > "$out/$2"
	"$wpa_cli" -p "$ctrl" -i "$iface" "$1" >> "$out/$2" 2>&1 || true
	printf '  %-16s -> %s\n' "$1" "$out/$2"
}

{
	printf '# captured %s on %s\n' "$(date -u +%FT%TZ)" "$(uname -srm)"
	printf '# interface %s, control directory %s\n' "$iface" "$ctrl"
	("$(dirname "$wpa_cli")/wpa_supplicant" -v 2>&1 || true) | head -3
} > "$out/version"
printf '  %-16s -> %s\n' "version" "$out/version"

# **Four, not six.** `STATUS-VERBOSE` and `GET_CAPABILITY key_mgmt` both
# answered `Unknown command` on wpa_supplicant 2.10, which is what this machine
# runs -- so they were two files of noise wearing a capture's name. Asked for,
# measured, removed.
ask STATUS status
ask SCAN_RESULTS scan-results
ask LIST_NETWORKS list-networks
ask MIB mib

# **The events, which are the half nothing else can recover** -- a join, a
# switch, a failed authentication, verbatim, including the `id=` that separates
# a roam from a network change and any `ASSOC-REJECT status_code=`.
#
# NOT `wpa_cli` INTERACTIVE, AND THE REASON IS A MEASURED HANG
#   The first version ran `timeout 1 wpa_cli -p ... -i ...`. With no command
#   argument `wpa_cli` enters interactive mode and reads the terminal -- and
#   not being the foreground process group it took SIGTTIN and STOPPED. Then
#   `timeout` sent SIGTERM after one second and nothing happened, **because a
#   stopped process does not act on SIGTERM**. The capture sat there until it
#   was killed by hand.
#
#   `running-code.md` has that mechanism already, from a crash handler
#   attaching gdb: *"a stopped process ignores SIGTERM -- which means pkill
#   will appear to work and clean up nothing."* Same ending, different route.
#
#   So this attaches to the control socket itself, the way netcfgd does. It
#   reads no terminal, so there is no signal that can stop it; its deadline is
#   its own; and `timeout -k` is the belt, because SIGKILL is the one signal a
#   stopped process cannot ignore.
echo
echo "listening for $seconds seconds -- move between networks now, and let one fail if you can"
timeout -k 5 "$((seconds + 10))" python3 - "$ctrl" "$iface" "$seconds" > "$out/events" 2>&1 </dev/null <<'PYLISTEN' || true
import os, socket, sys, time

ctrl, iface, seconds = sys.argv[1], sys.argv[2], int(sys.argv[3])
remote = os.path.join(ctrl, iface)
# In the control directory, because that is where the supplicant can reply to
# and where a unix path still fits 108 bytes. Named for this process so two
# captures never collide, and never `netcfgd-*`, which is netcfgd's own.
local = os.path.join(ctrl, "capture-%d" % os.getpid())

sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
try:
	try:
		os.unlink(local)
	except OSError:
		pass
	try:
		sock.bind(local)
	except OSError as why:
		# The control directory is root-owned, so this is where an unprivileged
		# run stops -- before the connect, and with a different reason. Said in
		# its own words rather than as a stack trace.
		print("# cannot bind a reply socket at %s: %s" % (local, why), flush=True)
		raise SystemExit(1)
	try:
		sock.connect(remote)
	except OSError as why:
		# A sentence rather than a traceback: the reason a capture found no
		# supplicant is the most useful line in the file, and a stack trace
		# buries it under this script's own frames.
		print("# cannot reach %s: %s" % (remote, why), flush=True)
		raise SystemExit(1)
	sock.settimeout(1.0)
	sock.send(b"ATTACH")
	try:
		if b"OK" not in sock.recv(4096):
			print("# the supplicant refused ATTACH", flush=True)
	except socket.timeout:
		print("# the supplicant did not answer ATTACH", flush=True)

	print("# attached %s" % time.strftime("%FT%TZ", time.gmtime()), flush=True)
	deadline = time.monotonic() + seconds
	while time.monotonic() < deadline:
		# One second at a time, so the deadline is checked even on a quiet
		# radio: a blocking read with no timeout is the hang this replaced.
		try:
			data = sock.recv(4096)
		except socket.timeout:
			continue
		except OSError as why:
			print("# stopped: %s" % why, flush=True)
			break
		if not data:
			continue
		print("%s %s" % (time.strftime("%FT%TZ", time.gmtime()),
		                 data.decode("utf-8", "replace").rstrip()), flush=True)
	print("# detached %s" % time.strftime("%FT%TZ", time.gmtime()), flush=True)
	try:
		sock.send(b"DETACH")
	except OSError:
		pass
finally:
	sock.close()
	try:
		os.unlink(local)
	except OSError:
		pass
PYLISTEN
printf '  %-16s -> %s\n' "events" "$out/events"

echo
echo "captured into $out"
echo "read it, then correct tests/live/fake_supplicant.py against it."
