#!/bin/sh
# node_ram_host.sh -- what netcfgd needs of fuzznet, on a host whose store will not
# write (0316, fuzznet secs 916 and 917). A has joined an estate; it is stopped, its
# store made read-only, and started again, so its rows are read and every write is
# held in RAM. A daemon with a node binds no `netcfgd.sock`, so nothing here can be
# answered by anything but fuzznet. Run by `make test`.
#
# HOW IT STOPS: all of it runs in a user, mount and network namespace under `timeout
# -k 2 200`. The daemons are under timeouts of their own and killed by pid, client
# calls are under `timeout`, and waits are counts of 0.5 s looks or a wall-clock
# deadline. The directory is mktemp's, checked by shape.
here=$(cd "$(dirname "$0")/.." && pwd)
if [ "$1" != inside ]; then
	if ! unshare -Urmn true 2>/dev/null; then
		echo "node_ram_host: no user namespaces here, so nothing was looked at"
		exit 1
	fi
	exec timeout -k 2 200 unshare -Urmn sh "$0" inside
fi
N=$here/netcfgd
C=$here/ncfg
F=$here/fuzznet-build/fuzznetd
R=$(mktemp -d /tmp/nrh.XXXXXX) || exit 1
case "$R" in /tmp/nrh.?*) ;; *) echo "node_ram_host: odd scratch $R"; exit 1;; esac
pids=
# TERM, as `timeout` hands that on to its child, where KILL would leave the child up.
trap 'kill -TERM $pids 2>/dev/null; wait 2>/dev/null; umount -l "$R/a" 2>/dev/null; rm -rf "$R"' EXIT
failed=0
check() { # $1 0 for ok, $2 what
	if [ "$1" -eq 0 ]; then printf '%-72s ok\n' "$2"; else printf '%-72s FAILED\n' "$2"; failed=1; fi
}
ask() { # $1 socket, $2 line: one reply line from a fuzznet local socket
	timeout 10 python3 -I -c '
import socket, sys
s = socket.socket(socket.AF_UNIX); s.settimeout(5); s.connect(sys.argv[1])
s.sendall((sys.argv[2] + "\n").encode()); out = b""
while not out.endswith(b"\n"):
    b = s.recv(4096)
    if not b: break
    out += b
print(out.decode(errors="replace").strip())' "$1" "$2" 2>&1
}
PA=33950
PB=33951
start_a() { # $1 log
	timeout -k 5 170 "$N" --run-dir "$R/run" --config-dir "$R/conf" --no-apply-on-start \
		--fuzznet-dir "$R/a" --fuzznet-arg "--socket=$R/a.sock" --fuzznet-arg --no-log-file \
		--fuzznet-arg "--udp-port=$PA" --fuzznet-arg --fuzznet-service=1 \
		--fuzznet-arg --fuzznet-product=1 > "$R/$1" 2>&1 &
	a=$!
	pids="$pids $a"
	n=0
	until [ -S "$R/a.sock" ] || [ $n -gt 40 ]; do sleep 0.5; n=$((n + 1)); done
}
ip link set lo up
mkdir "$R/a" "$R/b" "$R/run" "$R/conf" "$R/xdg"
chmod 700 "$R/xdg"
mount -t tmpfs -o size=8m tmpfs "$R/a" || { echo "node_ram_host: no tmpfs here"; exit 1; }
printf 'global {\n\tcontrol {\n\t\tobserve = "any"\n\t\tadmin = "any"\n\t}\n\tremote {\n\t\tobserve = true\n\t\tadmin = true\n\t}\n}\n' \
	> "$R/conf/netcfgd.conf"

timeout 20 "$F" --fuzznet-dir="$R/a" --new-root --fuzznet-service=1 --fuzznet-product=1 \
	> "$R/root.out" 2>&1
check $? "A's store is made the root of an estate"
start_a a1.log
XDG_RUNTIME_DIR=$R/xdg timeout -k 5 170 "$F" --fuzznet-dir="$R/b" --no-log-file \
	"--udp-port=$PB" --fuzznet-service=1 --fuzznet-product=1 > "$R/b.log" 2>&1 &
pids="$pids $!"
B=$R/xdg/fuzznet/fuzznetd.sock
n=0
until [ -S "$B" ] || [ $n -gt 40 ]; do sleep 0.5; n=$((n + 1)); done
prekey=$(ask "$B" 'get prekey' | sed -n 's/^ok \([^ ]*\)$/\1/p')
card=$(ask "$R/a.sock" "add peer $prekey delegable" | sed -n 's/^ok \([^ ]*\)$/\1/p')
echo "$card" > "$R/card"
joined=$(ask "$B" "add join $R/card 127.0.0.1 $PA")
[ "${joined%% *}" = ok ]
check $? "B joins A's estate"
n=0
until ask "$B" status 2>/dev/null | grep -q '^ok ' || [ $n -gt 60 ]; do sleep 0.5; n=$((n + 1)); done
host=$(ask "$R/a.sock" 'get prekey' | sed -n 's/^ok \(.*\)$/\1/p' | cut -c5-68)
deadline=$(( $(date +%s) + 50 ))
until XDG_RUNTIME_DIR=$R/xdg timeout 20 "$C" status --at "$host" --json 2>/dev/null | grep -q '"links"' ||
	[ "$(date +%s)" -ge $deadline ]; do sleep 1; done

# Read-only with nothing writing it: the daemon goes first, as a remount is refused
# while it holds files open.
kill -TERM $a
wait $a
mount -o remount,bind,ro "$R/a"
rm -f "$R/a.sock"
start_a a2.log
[ -S "$R/a.sock" ]
check $? "A starts again on its store gone read-only"
[ ! -e "$R/run/netcfgd.sock" ]
check $? "and binds no netcfgd.sock, so only fuzznet can answer below"

said=$(ask "$R/a.sock" 'add record t/ram one')
[ "${said%% *}" = ok ]
check $? "a write is taken, as RAM ($said)"
ask "$R/a.sock" 'get node' | grep -q 'store ram'
check $? "\`get node\` says so ($(ask "$R/a.sock" 'get node' | cut -c1-70))"

L="--run-dir $R/run"
timeout 10 "$C" status $L --json > "$R/status" 2>&1
grep -q '"links"' "$R/status"
check $? "\`status\` over the local socket ($(head -c 40 "$R/status"))"
timeout 10 "$C" plan $L > "$R/plan" 2>&1
check $? "\`ask\`: \`ncfg plan\` ($(tail -1 "$R/plan" | cut -c1-40))"
timeout 10 "$C" hosts $L > "$R/hosts" 2>&1
check $? "\`hosts\`: \`ncfg hosts\` ($(tail -1 "$R/hosts" | cut -c1-40))"
ask "$R/a.sock" 'list peer' | grep -q '^ok'
check $? "\`list peer\`"
ask "$R/a.sock" 'call eventlog 0' | grep -q '^ok'
check $? "\`eventlog\`"
timeout 12 python3 -I -c '
import socket, sys
s = socket.socket(socket.AF_UNIX); s.settimeout(10); s.connect(sys.argv[1]); s.sendall(b"get events\n")
print(s.recv(4096).decode(errors="replace"))' "$R/a.sock" > "$R/events" 2>&1
grep -q '^ok' "$R/events"
check $? "\`get events\` holds ($(head -c 30 "$R/events"))"

deadline=$(( $(date +%s) + 40 ))
said=
while [ "$(date +%s)" -lt $deadline ]; do
	said=$(XDG_RUNTIME_DIR=$R/xdg timeout 20 "$C" status --at "$host" --json 2>&1)
	echo "$said" | grep -q '"links"' && break
	sleep 1
done
echo "$said" | grep -q '"links"'
check $? "the remote hop: \`status --at A\` from B ($(echo "$said" | head -c 40))"
XDG_RUNTIME_DIR=$R/xdg timeout 40 "$C" apply --at "$host" --confirm-within 60 > "$R/apply" 2>&1
check $? "and an apply with a window from B ($(tail -1 "$R/apply" | cut -c1-40))"
XDG_RUNTIME_DIR=$R/xdg timeout 20 "$C" confirm --at "$host" > "$R/confirm" 2>&1
check $? "and its confirm"
python3 -I -c 'print("# " + "x" * 3000)' > "$R/long"
XDG_RUNTIME_DIR=$R/xdg timeout 40 "$C" config put big --at "$host" < "$R/long" > "$R/put" 2>&1
[ "$(cat "$R"/conf/conf.d/big* 2>/dev/null | wc -c)" -gt 3000 ]
check $? "\`askpart\`: a request past one line lands whole ($(tail -1 "$R/put" | cut -c1-40))"

! grep -q 'runtime error\|Sanitizer' "$R/a2.log"
check $? "A's log carries no sanitizer report"
if [ $failed -ne 0 ]; then
	sed 's/^/  a2.log: /' "$R/a2.log" | tail -15
	echo "node_ram_host: some checks FAILED"
	exit 1
fi
echo "node_ram_host: all checks passed"
