#!/bin/sh
# node_store_trouble.sh -- fuzznet in trouble is seen and said (0316): a store that
# fills or is read-only leaves the host working from RAM, which `get node` says and
# which is then an error in netcfgd's log and a line in `ncfg status`. The line goes
# when the trouble does. One that will not open at all is said too. By `make test`.
#
# HOW IT STOPS: all of it runs in a user and mount namespace under `timeout -k 2
# 170`, the store a 2 MB tmpfs that namespace owns, so the filling is bounded by
# the filesystem. The daemon is under a timeout of its own and killed by pid, and
# waits are counts of 0.5 s looks. The directory is mktemp's, checked by shape.
here=$(cd "$(dirname "$0")/.." && pwd)
if [ "$1" != inside ]; then
	if ! unshare -Urmn true 2>/dev/null; then
		echo "node_store_trouble: no user namespaces here, so nothing was looked at"
		exit 1
	fi
	exec timeout -k 2 170 unshare -Urmn sh "$0" inside
fi
N=$here/netcfgd
C=$here/ncfg
R=$(mktemp -d /tmp/nst.XXXXXX) || exit 1
case "$R" in /tmp/nst.?*) ;; *) echo "node_store_trouble: odd scratch $R"; exit 1;; esac
pids=
trap 'kill -KILL $pids 2>/dev/null; umount "$R/store" 2>/dev/null; rm -rf "$R"' EXIT
failed=0
check() { # $1 0 for ok, $2 what
	if [ "$1" -eq 0 ]; then printf '%-72s ok\n' "$2"; else printf '%-72s FAILED\n' "$2"; failed=1; fi
}
ask() { # $1 line: one reply line from fuzznet's socket
	timeout 10 python3 -I -c '
import socket, sys
s = socket.socket(socket.AF_UNIX); s.settimeout(5); s.connect(sys.argv[1])
s.sendall((sys.argv[2] + "\n").encode()); out = b""
while not out.endswith(b"\n"):
    b = s.recv(4096)
    if not b: break
    out += b
print(out.decode(errors="replace").strip())' "$R/fz.sock" "$1" 2>&1
}
says() { # $1 pattern: wait for `ncfg status` to say it
	n=0
	until timeout 5 "$C" status --run-dir "$R/run" 2>&1 | grep -q "$1" || [ $n -gt 50 ]; do
		sleep 0.5
		n=$((n + 1))
	done
	[ $n -le 50 ]
}
start() { # $1 log
	timeout -k 5 110 "$N" --run-dir "$R/run" --config-dir "$R/conf" --no-apply-on-start \
		--fuzznet-dir "$R/store" --fuzznet-serve --fuzznet-arg "--socket=$R/fz.sock" \
		> "$R/$1" 2>&1 &
	daemon=$!
	pids="$pids $daemon"
}
ip link set lo up
mkdir "$R/store" "$R/run" "$R/conf"
printf 'global {\n\tcontrol {\n\t\tobserve = "any"\n\t}\n}\n' > "$R/conf/netcfgd.conf"
mount -t tmpfs -o size=2m tmpfs "$R/store" || { echo "node_store_trouble: no tmpfs here"; exit 1; }

start a.log
n=0
until [ -S "$R/fz.sock" ] || [ $n -gt 40 ]; do sleep 0.5; n=$((n + 1)); done
[ -S "$R/fz.sock" ]
check $? "a daemon with a healthy store serves fuzznet"
! timeout 5 "$C" status --run-dir "$R/run" 2>&1 | grep -q 'IN TROUBLE'
check $? "  and \`ncfg status\` says no trouble"

# What an operator on another host reads: fuzznet's events, held from here.
timeout 80 python3 -I -c '
import socket, sys
s = socket.socket(socket.AF_UNIX); s.connect(sys.argv[1]); s.sendall(b"get events\n")
out = open(sys.argv[2], "wb", buffering=0)
while True:
    b = s.recv(4096)
    if not b: break
    out.write(b)' "$R/fz.sock" "$R/events" &
listener=$!
pids="$pids $listener"
sleep 0.5

dd if=/dev/zero of="$R/store/filler" bs=64k count=64 2>/dev/null
ask 'add record t/full one' | grep -q '^ok'
check $? "a store that has filled still takes a record, as RAM"
says 'IN TROUBLE.*on ram'
check $? "a store that fills is said in \`ncfg status\`"
grep -q 'fuzznet is in trouble.*on ram' "$R/a.log"
check $? "  and logged"
[ -d "/proc/$daemon" ]
check $? "  and the daemon is still up"
truncate -s 0 "$R/store/filler"
n=0
# Pressure comes down a step per 30 s, so this is a longer wait than going up.
while timeout 5 "$C" status --run-dir "$R/run" 2>&1 | grep -q 'IN TROUBLE' && [ $n -lt 120 ]; do
	sleep 0.5
	n=$((n + 1))
done
[ $n -lt 120 ] && grep -q 'on its disk again' "$R/a.log"
check $? "  and when it has room the line goes, and the log says so"
n=0
until grep -q 'net-store-ok' "$R/events" 2>/dev/null || [ $n -gt 10 ]; do sleep 0.5; n=$((n + 1)); done
grep -q 'net-store-bad' "$R/events" && grep -q 'net-store-ok' "$R/events"
check $? "  and fuzznet's events said both, for another host ($(tr '\n' ' ' < "$R/events" | cut -c1-50))"
kill -KILL $listener 2>/dev/null

# Read-only under a running daemon cannot be staged here: it holds files open for
# writing, so the remount is refused as busy. Starting on one is the case to hold.
kill -TERM $daemon
wait $daemon
mount -o remount,bind,ro "$R/store"
rm -f "$R/fz.sock"
start r.log
n=0
until [ -S "$R/fz.sock" ] || [ $n -gt 40 ]; do sleep 0.5; n=$((n + 1)); done
[ -S "$R/fz.sock" ]
check $? "a host opens on a read-only filesystem"
ask 'add record t/ro one' | grep -q '^ok'
check $? "  and takes a record, as RAM"
says 'IN TROUBLE.*on ram'
check $? "  and that is said in \`ncfg status\`"
kill -TERM $daemon
wait $daemon
mount -o remount,bind,rw "$R/store"

# One that will not open: a file where the store's directory should be.
umount "$R/store"
rmdir "$R/store"
: > "$R/store"
start b.log
says 'IN TROUBLE.*did not open'
check $? "a store that will not open is said in \`ncfg status\`"
grep -q 'no fuzznet node' "$R/b.log"
check $? "  and logged"
kill -TERM $daemon
wait $daemon

if [ $failed -ne 0 ]; then
	sed 's/^/  a.log: /' "$R/a.log" | tail -15
	sed 's/^/  b.log: /' "$R/b.log" 2>/dev/null | tail -15
	echo "node_store_trouble: some checks FAILED"
	exit 1
fi
echo "node_store_trouble: all checks passed"
