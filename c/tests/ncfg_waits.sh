#!/bin/sh
# ncfg_waits.sh -- `ncfg` waits for a daemon that is running but not answering
# yet, and only for one (project.md 10.873). Run by `make test`.
#
# The daemon holds `netcfgd.lock` from its start and answers only once its node
# is open -- a few seconds on a router (10.872). `flock(1)` stands for a daemon
# in that window, since it takes the same kind of lock on the same file:
#
#   - nobody holds the lock: ncfg fails at once, as it always did;
#   - the lock is held and nothing opens: ncfg waits about ten seconds, then
#     says the daemon is running and has not opened;
#   - the lock is held, then a real daemon takes over and binds its socket:
#     ncfg, asked during the hold, gets the daemon's answer.
#
# HOW IT STOPS: everything runs in one user and network namespace under
# `timeout -k 2 80`; every process it starts is under a timeout of its own and
# killed by pid at the end. The directory is mktemp's, checked by shape, and
# removed at the end.
here=$(cd "$(dirname "$0")/.." && pwd)
if [ "$1" != inside ]; then
	if ! unshare -Urn true 2>/dev/null; then
		echo "ncfg_waits: no user namespaces here, so nothing was looked at"
		exit 1
	fi
	if ! command -v flock >/dev/null 2>&1; then
		echo "ncfg_waits: no flock(1) to stand for a starting daemon, so nothing was looked at"
		exit 1
	fi
	exec timeout -k 2 80 unshare -Urn sh "$0" inside
fi
N=$here/netcfgd
C=$here/ncfg
R=$(mktemp -d /tmp/ncw.XXXXXX) || exit 1
case "$R" in /tmp/ncw.?*) ;; *) echo "ncfg_waits: odd scratch $R"; exit 1;; esac
pids=
# TERM, which timeout passes on to what it runs; KILL would stop the timeout
# and leave the daemon under it holding the run directory, measured.
trap 'kill -TERM $pids 2>/dev/null; wait 2>/dev/null; rm -rf "$R"' EXIT
mkdir -p "$R/run" "$R/conf" "$R/wpa"
: > "$R/conf/netcfgd.conf"
: > "$R/run/netcfgd.lock"
unset NCFG_FUZZNET_SOCKET NCFG_RUN_DIR

failures=0
check() { # $1 what, $2 0 for a pass
	if [ "$2" -eq 0 ]; then
		printf '%-72s ok\n' "$1"
	else
		printf '%-72s FAILED\n' "$1"
		failures=$((failures + 1))
	fi
}
now() { date +%s; }

# Nobody holds the lock.
started=$(now)
timeout 15 "$C" reload --run-dir "$R/run" > "$R/alone" 2>&1
rc=$?
took=$(($(now) - started))
check "with no daemon, ncfg fails" "$([ $rc -ne 0 ] && echo 0 || echo 1)"
check "  at once (${took}s)" "$([ $took -le 2 ] && echo 0 || echo 1)"
check "  and does not claim a daemon is running" \
	"$(grep -q 'is running on' "$R/alone" && echo 1 || echo 0)"

# The lock held, and nothing opens.
# A holder that ends by itself, and is waited for: killing a `timeout` around
# it leaves the flock holding the lock, which the third case then meets.
flock "$R/run/netcfgd.lock" sleep 12 &
holder=$!
sleep 0.5
started=$(now)
timeout 20 "$C" reload --run-dir "$R/run" > "$R/held" 2>&1
rc=$?
took=$(($(now) - started))
wait "$holder" 2>/dev/null
check "with the lock held and nothing open, ncfg fails" "$([ $rc -ne 0 ] && echo 0 || echo 1)"
check "  after waiting for it (${took}s)" "$([ $took -ge 9 ] && [ $took -le 13 ] && echo 0 || echo 1)"
check "  and says the daemon is running" \
	"$(grep -q 'netcfgd is running on' "$R/held" && echo 0 || echo 1)"

# The lock held, then a real daemon takes it and answers.
timeout 10 flock "$R/run/netcfgd.lock" sleep 1.5 &
holder=$!
sleep 0.5
timeout 20 "$C" reload --run-dir "$R/run" > "$R/later" 2>&1 &
asker=$!
wait "$holder" 2>/dev/null
NCFG_WPA_CTRL_DIR=$R/wpa timeout -k 2 30 "$N" --run-dir "$R/run" --config-dir "$R/conf" \
	--no-apply-on-start > "$R/daemon" 2>&1 &
pids="$pids $!"
wait "$asker"
rc=$?
check "asked while the lock was held, ncfg gets the daemon's answer" "$rc"
[ $rc -eq 0 ] || sed 's/^/    /' "$R/later" "$R/daemon" | head -10

if [ "$failures" -eq 0 ]; then
	echo "ncfg_waits: all checks passed"
else
	echo "ncfg_waits: $failures check(s) failed"
	exit 1
fi
