#!/bin/sh
# rfkill against a real radio, read-only.
#
# The mapping is two reads and a search -- `/sys/class/net/<iface>/phy80211/name`
# to find the phy, then the rfkill entry whose `name` matches -- and the unit tests
# in `netcfgd-observe` cover it against a sysfs tree under a temporary directory.
# What they cannot cover is a real one: whether a real driver registers a switch
# under the name a real phy has, on a machine where a person can press the button.
#
# **Nothing here changes a switch.** Blocking a radio to watch netcfgd notice would
# mean switching off the wifi of whoever is running the test, and on the machine
# this was written on that is the connection the test is being read over. So this
# checks that netcfgd's answer matches the kernel's files, in whatever state the
# machine happens to be in, and the deliberate-block half is left to a privileged
# container with `mac80211_hwsim` -- named in decision 0062 rather than pretended
# away.
#
# Runs unprivileged and outside a namespace: it reads the host's real /sys, which
# `unshare -rn` does not change.

set -eu

repo=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)

skip() {
	if [ -n "${NCFG_LIVE:-}" ]; then
		# Not a failure even with NCFG_LIVE set: a machine with no radio cannot
		# run this, and most build machines have none. The other scripts skip on
		# a missing *tool*, which is an install away; a wifi card is not.
		echo "rfkill.sh: skipping (NCFG_LIVE is set, but this needs hardware): $1"
		exit 0
	fi
	echo "rfkill.sh: skipping: $1"
	exit 0
}

[ -x "$repo/target/debug/ncfg" ] || skip "ncfg is not built"

# The first interface with a phy, which is the only kind that has a switch. Absent
# on most build machines, which is why the second half of this script needs none.
radio=
phy=
if [ -d /sys/class/rfkill ]; then
	for path in /sys/class/net/*/phy80211/name; do
		[ -r "$path" ] || continue
		candidate=$(basename "$(dirname "$(dirname "$path")")")
		# **sysfs is not filtered by network namespace unless it is remounted**,
		# and `unshare -rn` does not remount it -- so inside a namespace this
		# directory still lists the *host's* interfaces. `ip link show` goes to
		# netlink, which is namespaced, and disagrees:
		#
		#     /sys/class/net/wlp0s20f3   exists
		#     ip link show wlp0s20f3     does not
		#
		# Taking sysfs at its word therefore found a radio that is not here,
		# and the check below then failed because netcfgd -- which observes
		# through netlink -- correctly reported no such interface. The Makefile
		# runs this script bare for that reason and says so; the failure only
		# appears when somebody runs it under `unshare -rn` anyway, which is
		# easy to do and reads as a broken feature rather than a wrong
		# invocation.
		ip link show "$candidate" >/dev/null 2>&1 || continue
		radio=$candidate
		phy=$(cat "$path")
		break
	done
fi

work=$(mktemp -d "${TMPDIR:-/tmp}/ncfg-rfkill.XXXXXX")
trap 'rm -rf "$work"' EXIT INT TERM
mkdir -p "$work/etc" "$work/run"

export NCFG_CONFIG_DIR="$work/etc"
export NCFG_RUN_DIR="$work/run"
ncfg="$repo/target/debug/ncfg"

failures=0
check() {
	if [ "$2" = "$3" ]; then
		echo "ok   $1"
	else
		echo "FAIL $1"
		echo "       expected: $3"
		echo "       actual:   $2"
		failures=$((failures + 1))
	fi
}

# What the kernel says, straight from the files netcfgd reads.
switch=
if [ -n "$phy" ]; then
	for entry in /sys/class/rfkill/rfkill*; do
		[ -r "$entry/name" ] || continue
		if [ "$(cat "$entry/name")" = "$phy" ]; then
			switch=$entry
			break
		fi
	done
fi

if [ -z "$switch" ]; then
	echo "rfkill.sh: no radio with a switch on this machine, so the real half is"
	echo "rfkill.sh:   skipped -- the fabricated half below runs anyway"
else

# A document that names the radio and asks for nothing. Only `status` and `plan`
# are run, so this cannot touch the machine's network however it is configured --
# and `config = "null"` says so in the file as well.
cat > "$work/etc/netcfgd.conf" <<CONF
device $radio { wifi { } }
interface $radio { config = "null" }
CONF

soft=$(cat "$switch/soft")
hard=$(cat "$switch/hard")
echo "rfkill.sh: $radio is on $phy, soft=$soft hard=$hard"

# netcfgd's own answer, out of the observation rather than out of a log line.
observed=$("$ncfg" status --json 2>/dev/null |
	tr -d ' \n' |
	sed -n "s/.*\"name\":\"$radio\".*/&/p")
case "$observed" in
*"\"switch\":\"$phy\""*) echo "ok   the observation names the phy's own switch" ;;
*)
	echo "FAIL the observation names the phy's own switch"
	echo "       expected to contain: \"switch\":\"$phy\""
	failures=$((failures + 1))
	;;
esac

# And it agrees with the kernel about the state, whichever state that is. This is
# the half a fake sysfs cannot give: a real driver's switch, under a real phy name.
expected_soft=$([ "$soft" = "1" ] && echo true || echo false)
expected_hard=$([ "$hard" = "1" ] && echo true || echo false)
soft_seen=false
hard_seen=false
case "$observed" in *'"soft":true'*) soft_seen=true ;; esac
case "$observed" in *'"hard":true'*) hard_seen=true ;; esac
check "and agrees about the soft block" "$soft_seen" "$expected_soft"
check "and about the hard block"        "$hard_seen" "$expected_hard"

# The plan says something only when the radio is off, and the machine decides
# which case this is. Both directions are asserted rather than one, because a
# check that only ever sees an unblocked radio would pass with the warning deleted.
plan=$("$ncfg" plan 2>&1 || true)
if [ "$soft" = "1" ] || [ "$hard" = "1" ]; then
	case "$plan" in
	*"switched off at $phy"*) echo "ok   a blocked radio is named in the plan" ;;
	*)
		echo "FAIL a blocked radio is named in the plan"
		echo "       actual: $plan"
		failures=$((failures + 1))
		;;
	esac
else
	case "$plan" in
	*"switched off"*)
		echo "FAIL a working radio was reported as off"
		echo "       actual: $plan"
		failures=$((failures + 1))
		;;
	*) echo "ok   a working radio is not reported as off" ;;
	esac
	echo "rfkill.sh: the radio is on, so the blocked half was not exercised here --"
	echo "rfkill.sh:   the fabricated tree below covers it, and 0062 says what is left"
fi

fi

# ---------------------------------------------------------------------------
# The blocked half, without blocking anything. `NCFG_SYS_ROOT` points the
# observation at a fabricated tree, which is faking a *file layout* and not a
# radio -- the distinction section 9 draws about `fake_supplicant.py`. What is
# under test here is the rendering and the warning, which the checks above cannot
# reach on a machine whose wifi is working.
#
# The loopback is the vehicle, because it is the one interface that exists on every
# machine, and because only `status` and `plan` are run: neither changes anything,
# so a document naming `lo` cannot do it any harm.
fake=$work/sys
mkdir -p "$fake/class/net/lo/phy80211" "$fake/class/rfkill/rfkill0"
echo phy-fake > "$fake/class/net/lo/phy80211/name"
echo phy-fake > "$fake/class/rfkill/rfkill0/name"
echo wlan     > "$fake/class/rfkill/rfkill0/type"

cat > "$work/etc/netcfgd.conf" <<'CONF'
interface lo { config = "null" }
CONF

for kind in soft hard; do
	if [ "$kind" = soft ]; then
		echo 1 > "$fake/class/rfkill/rfkill0/soft"
		echo 0 > "$fake/class/rfkill/rfkill0/hard"
		expected="software block at phy-fake"
		remedy="rfkill unblock wifi"
	else
		echo 0 > "$fake/class/rfkill/rfkill0/soft"
		echo 1 > "$fake/class/rfkill/rfkill0/hard"
		expected="hardware block at phy-fake"
		remedy="nothing in software can clear"
	fi

	status=$(NCFG_SYS_ROOT="$fake" "$ncfg" status 2>/dev/null)
	case "$status" in
	*"$expected"*) echo "ok   status names a $kind block" ;;
	*)
		echo "FAIL status names a $kind block"
		echo "       expected to contain: $expected"
		failures=$((failures + 1))
		;;
	esac

	plan=$(NCFG_SYS_ROOT="$fake" "$ncfg" plan 2>&1 || true)
	case "$plan" in
	*"$remedy"*) echo "ok   and the plan gives the remedy for a $kind block" ;;
	*)
		echo "FAIL and the plan gives the remedy for a $kind block"
		echo "       expected to contain: $remedy"
		echo "       actual: $plan"
		failures=$((failures + 1))
		;;
	esac
done

echo
if [ "$failures" -eq 0 ]; then
	echo "rfkill.sh: all checks passed"
else
	echo "rfkill.sh: $failures failed"
	exit 1
fi
