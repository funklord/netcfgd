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

# One radio, named rather than searched for where the caller knows: a machine
# with two would otherwise capture whichever sorted first.
iface=${NCFG_CAPTURE_IFACE:-}
if [ -z "$iface" ]; then
	iface=$(ls "$ctrl" 2>/dev/null | head -1)
fi
[ -n "$iface" ] || { echo "no interface under $ctrl" >&2; exit 1; }

mkdir -p "$out"
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

ask STATUS status
ask 'STATUS-VERBOSE' status-verbose
ask SCAN_RESULTS scan-results
ask LIST_NETWORKS list-networks
ask 'GET_CAPABILITY key_mgmt' capability-key-mgmt

# **The events, which are the half nothing else can recover.** A join, a
# switch, a failed authentication: what a real supplicant sends, verbatim,
# including the `id=` that separates a roam from a network change and any
# `ASSOC-REJECT status_code=`.
#
# Bounded by `timeout`, and `wpa_cli` in this mode only listens.
echo
echo "listening for $seconds seconds -- move between networks now, and let one fail if you can"
timeout "$seconds" "$wpa_cli" -p "$ctrl" -i "$iface" > "$out/events" 2>&1 || true
printf '  %-16s -> %s\n' "events" "$out/events"

echo
echo "captured into $out"
echo "read it, then correct tests/live/fake_supplicant.py against it."
