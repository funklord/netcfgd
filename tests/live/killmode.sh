#!/bin/sh
# What systemd does to netcfgd's backends when the unit stops.
#
# WHY THIS FILE EXISTS
#   Decision 0134 says an unannounced stop holds: netcfgd tears nothing down,
#   so an upgrade does not take a VPN over wifi away. It argued that from
#   netcfgd's own source -- no SIGTERM teardown in the daemon, no ExecStop in
#   the unit -- and skipped the init, which kills the backends anyway.
#   systemd's `KillMode=` defaults to `control-group`, and the packaged unit
#   set none, so `systemctl stop netcfgd` reaped every process netcfgd had
#   started.
#
#   **0134's own tests could not have caught that.** `orphan.sh` and
#   `revive.sh` run netcfgd as a plain child of the script, inside a namespace
#   with no systemd cgroup at all, so they observe the daemon's behaviour and
#   never the system's. That is a true statement about netcfgd standing in for
#   a false one about the machine -- and it was believed for a day.
#
# WHAT THIS CAN AND CANNOT CHECK
#   It cannot start a systemd unit: the suite runs unprivileged, and a test
#   that needed root would be skipped on every machine that runs `make live`.
#   **So it checks the declaration, not the behaviour**, and says so rather
#   than implying more.
#
#   That is worth having anyway, because the defect was an *absent* setting.
#   A unit with no `KillMode=` reads as though nobody considered it; one that
#   names a value has had the decision made, and this fails if the line goes
#   away again.
#
# POSIX sh, not bash: this runs wherever the project does.

set -eu

repo=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
unit="$repo/packaging/systemd/netcfgd.service"
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

[ -r "$unit" ] || { echo "killmode.sh: cannot read $unit" >&2; exit 1; }

# The whole point: absent is what it was, and absent is what must not recur.
check "the unit declares KillMode rather than inheriting the default" \
	"$(grep -c '^KillMode=' "$unit")" "1"

value=$(sed -n 's/^KillMode=//p' "$unit")
check "and names a value systemd accepts" \
	"$(case "$value" in control-group|process|mixed|none) echo yes ;; *) echo "no: $value" ;; esac)" "yes"

# `none` would mean netcfgd's backends survive AND systemd never cleans up
# after a failed stop, which is the one value nothing here wants: the manual
# calls it not recommended, and netcfgd has no teardown of its own to make up
# for it.
check "and not the one systemd tells you not to use" \
	"$([ "$value" = "none" ] && echo none || echo ok)" "ok"

# The record and the unit have to agree about which value is set, because the
# reason for the value lives in the record and a reader who finds them
# disagreeing cannot tell which is stale.
record="$repo/doc/decision/0142-systemd-kills-what-netcfgd-holds.md"
if [ -r "$record" ]; then
	# The record's own `Set:` line, not a mention anywhere in its prose. The
	# record has to discuss the value it does NOT set, so a loose match
	# passes whichever value the unit carries -- measured: with the unit on
	# `process` and the record declaring `control-group`, a prose grep still
	# said they agreed.
	check "the record's Set: line names the value the unit sets" \
		"$(grep -c "^    Set: KillMode=$value\$" "$record")" "1"
else
	echo "FAIL the decision record 0142 is missing"
	failures=$((failures + 1))
fi

echo
if [ "$failures" -eq 0 ]; then
	echo "killmode.sh: all checks passed"
else
	echo "killmode.sh: $failures failed"
	exit 1
fi
