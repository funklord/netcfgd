#!/bin/sh
# node_fleet.sh -- an operator of the estate asks a netcfgd node for its
# status (decision 0311, project.md 10.691). Run by `make test` and `make
# node-fleet-test` against the program the build made; needs no privilege.
#
# Two hosts on localhost, as fuzznet's own `tool/live_ext.py` phase c sets
# them up: A is netcfgd serving its node, made the estate's root by
# `fuzznetd --new-root`; B is a plain fuzznetd, the operator's own, serving
# on this user's default socket under a scratch XDG_RUNTIME_DIR. B joins A's
# estate by verbs (`add peer ... delegable` at A, `add join` at B). Then:
#   - `ncfg status --at A` through B, the third of fuzznet's models, answers
#     A's observation, judged by A's `remote` block: open here;
#   - a host that is no member is refused rather than waited on for ever;
#   - with A's `remote` observe tier closed, A denies it and names the tier;
#   - and a key that is not one is refused before anything is asked.
#
# HOW IT STOPS: every wait is bounded (socket waits by a count of 0.5 s
# looks, the status by a 90 s deadline), each client call is under
# `timeout`, both daemons are under `timeout -k 5 150`
# and killed by pid at the end on every path (`trap`). The directory is
# mktemp's, checked by shape, and removed at the end.
here=$(cd "$(dirname "$0")/.." && pwd)
N=$here/netcfgd
F=$here/fuzznet-build/fuzznetd
C=$here/ncfg
R=$(mktemp -d /tmp/ncf.XXXXXX) || exit 1
case "$R" in /tmp/ncf.?*) ;; *) echo "node_fleet: odd scratch $R"; exit 1;; esac
failed=0
pids=
stop() {
	for p in $pids; do kill -TERM "$p" 2>/dev/null; done
	for p in $pids; do wait "$p" 2>/dev/null; done
	rm -rf "$R"
}
trap stop EXIT
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
# Two ports in the ephemeral range, from the pid, as fuzznet's live tests
# keep theirs (its sec 743).
PA=$((33000 + ($$ % 400) * 2))
PB=$((PA + 1))

mkdir "$R/a" "$R/b" "$R/run" "$R/conf" "$R/xdg"
chmod 700 "$R/xdg"
printf 'global {\n\tcontrol {\n\t\tobserve = "any"\n\t}\n\tremote {\n\t\tobserve = true\n\t}\n}\n' \
	> "$R/conf/netcfgd.conf"

timeout 20 "$F" --fuzznet-dir="$R/a" --new-root --fuzznet-service=1 --fuzznet-product=1 \
	> "$R/root.out" 2>&1
check $? "A's store is made the root of an estate"

timeout -k 5 150 "$N" --run-dir "$R/run" --config-dir "$R/conf" --no-apply-on-start \
	--fuzznet-dir "$R/a" --fuzznet-arg "--socket=$R/a.sock" --fuzznet-arg --no-log-file \
	--fuzznet-arg "--udp-port=$PA" --fuzznet-arg --fuzznet-service=1 \
	--fuzznet-arg --fuzznet-product=1 > "$R/a.log" 2>&1 &
pids="$pids $!"
XDG_RUNTIME_DIR=$R/xdg timeout -k 5 150 "$F" --fuzznet-dir="$R/b" --no-log-file \
	"--udp-port=$PB" --fuzznet-service=1 --fuzznet-product=1 > "$R/b.log" 2>&1 &
pids="$pids $!"
B=$R/xdg/fuzznet/fuzznetd.sock
n=0
until { [ -S "$R/a.sock" ] && [ -S "$B" ]; } || [ $n -gt 120 ]; do sleep 0.5; n=$((n + 1)); done
[ -S "$R/a.sock" ] && [ -S "$B" ]
check $? "netcfgd serves A's node, and B's fuzznetd this user's default socket"

prekey=$(ask "$B" 'get prekey' | sed -n 's/^ok \([^ ]*\)$/\1/p')
card=$(ask "$R/a.sock" "add peer $prekey delegable" | sed -n 's/^ok \([^ ]*\)$/\1/p')
[ -n "$prekey" ] && [ -n "$card" ] && echo "$card" > "$R/card"
joined=$(ask "$B" "add join $R/card 127.0.0.1 $PA")
[ "${joined%% *}" = ok ]
check $? "B joins A's estate ($(echo "$joined" | cut -c1-40))"
# The join restarts B on its own command line; it is back when it answers.
n=0
until ask "$B" status 2>/dev/null | grep -q '^ok ' || [ $n -gt 60 ]; do sleep 0.5; n=$((n + 1)); done

host=$(ask "$R/a.sock" 'get prekey' | sed -n 's/^ok \(.*\)$/\1/p' | cut -c5-68)
# Until the estate has carried B's membership to A: a wall-clock deadline,
# since each try may itself take a call's wait.
deadline=$(( $(date +%s) + 90 ))
said=
while [ "$(date +%s)" -lt $deadline ]; do
	said=$(XDG_RUNTIME_DIR=$R/xdg timeout 30 "$C" status --at "$host" --json 2>&1)
	echo "$said" | grep -q '"links"' && break
	sleep 1
done
echo "$said" | python3 -I -c 'import json, sys; d = json.load(sys.stdin); sys.exit(0 if "links" in d else 1)'
check $? "ncfg status --at A, through B, answers A's observation"

other=$(printf '%064d' 7)
XDG_RUNTIME_DIR=$R/xdg timeout 60 "$C" status --at "$other" > "$R/other.out" 2>&1
code=$?
[ $code -ne 0 ] && [ $code -ne 124 ]
check $? "  a host that is no member is refused, not waited on ($(head -c 60 "$R/other.out"))"
XDG_RUNTIME_DIR=$R/xdg timeout 10 "$C" status --at "not-a-key" 2>&1 | grep -q '64 lower-case hex'
check $? "  and a key that is not one is refused before anything is asked"

# A's remote tier closed: the same ask is denied by A, naming the tier.
# A restarted on its store keeps the estate, and B stays a member.
apid=${pids# }
apid=${apid%% *}
kill -TERM "$apid" 2>/dev/null
wait "$apid" 2>/dev/null
printf 'global {\n\tcontrol {\n\t\tobserve = "any"\n\t}\n\tremote {\n\t\tobserve = false\n\t}\n}\n' \
	> "$R/conf/netcfgd.conf"
timeout -k 5 120 "$N" --run-dir "$R/run" --config-dir "$R/conf" --no-apply-on-start \
	--fuzznet-dir "$R/a" --fuzznet-arg "--socket=$R/a.sock" --fuzznet-arg --no-log-file \
	--fuzznet-arg "--udp-port=$PA" --fuzznet-arg --fuzznet-service=1 \
	--fuzznet-arg --fuzznet-product=1 > "$R/a2.log" 2>&1 &
pids="$pids $!"
deadline=$(( $(date +%s) + 60 ))
while [ "$(date +%s)" -lt $deadline ]; do
	said=$(XDG_RUNTIME_DIR=$R/xdg timeout 30 "$C" status --at "$host" 2>&1)
	echo "$said" | grep -q 'denied' && break
	sleep 1
done
echo "$said" | grep -q 'denied.*observe'
check $? "with A's remote observe tier closed, A denies it, naming the tier"

! grep -q 'runtime error\|Sanitizer' "$R/a.log" "$R/a2.log"
check $? "netcfgd's log carries no sanitizer report"

if [ $failed -ne 0 ]; then
	for f in a.log b.log root.out; do sed "s/^/  $f: /" "$R/$f" | tail -15; done
	echo "node_fleet: some checks FAILED"
	exit 1
fi
echo "node_fleet: all checks passed"
