#!/bin/sh
# node_user.sh -- `ncfg node`: this user's node, with no fuzznetd installed, and
# then beside one on the same store (project.md 10.734). Run by `make test`.
#
# fuzznetd is here as any other fuzznet program is: the holder's word is that
# all of them have their full function and coexist on the same files and the
# same estate, so it is run as fuzzypickles' number, not as netcfgd's.
#
# The one process this cannot hold a pid of from the start is the node `--at`
# starts itself; it is asked of the socket and killed by that pid.
#
# HOW IT STOPS: the whole of it runs in one network namespace under `timeout -k
# 2 90`; every process it starts is under a timeout of its own and killed by
# pid; waits are counts of 0.5 s looks. The directory is mktemp's, checked by
# shape, and removed at the end.
here=$(cd "$(dirname "$0")/.." && pwd)
if [ "$1" != inside ]; then
	if ! unshare -Urn true 2>/dev/null; then
		echo "node_user: no user namespaces here, so nothing was looked at"
		exit 1
	fi
	exec timeout -k 2 90 unshare -Urn sh "$0" inside
fi
N=$here/netcfgd
C=$here/ncfg
F=$here/fuzznet-build/fuzznetd
R=$(mktemp -d /tmp/ncf.XXXXXX) || exit 1
case "$R" in /tmp/ncf.?*) ;; *) echo "node_user: odd scratch $R"; exit 1;; esac
pids=
trap 'kill -KILL $pids 2>/dev/null; rm -rf "$R"' EXIT
failed=0
check() { # $1 0 for ok, $2 what
	if [ "$1" -eq 0 ]; then printf '%-72s ok\n' "$2"; else printf '%-72s FAILED\n' "$2"; failed=1; fi
}
gone() { # $1 pid
	kill -TERM "$1" 2>/dev/null
	wait "$1" 2>/dev/null
}
ip link set lo up
ip addr add 192.0.2.7/24 dev lo
ip route add default dev lo

mkdir -p "$R/a" "$R/run" "$R/conf" "$R/home" "$R/xdg"
chmod 700 "$R/a" "$R/xdg"
printf 'global {\n\tremote {\n\t\tobserve = true\n\t}\n}\n' > "$R/conf/netcfgd.conf"
timeout -k 2 80 "$N" --run-dir "$R/run" --config-dir "$R/conf" --no-apply-on-start \
	--fuzznet-dir "$R/a" --fuzznet-arg --no-log-file > "$R/host.log" 2>&1 &
host=$!
pids="$pids $host"
n=0
until [ -S "$R/run/fuzznet.sock" ] || [ $n -gt 12 ]; do sleep 0.5; n=$((n + 1)); done

# This person, with nothing of theirs on this machine yet.
export HOME="$R/home" XDG_RUNTIME_DIR="$R/xdg"
U=$R/xdg/fuzznet/fuzznetd.sock
unset NCFG_FUZZNET_SOCKET

timeout 5 "$C" nodes > "$R/none" 2>&1
[ $? -ne 0 ] && grep -q 'ncfg node' "$R/none"
check $? "with no node up, \`ncfg nodes\` says how to start one ($(head -1 "$R/none" | cut -c1-30))"

timeout -k 2 70 "$C" node --no-log-file > "$R/node.log" 2>&1 &
node=$!
pids="$pids $node"
n=0
until [ -S "$U" ] || [ $n -gt 12 ]; do sleep 0.5; n=$((n + 1)); done
[ -S "$U" ]
check $? "\`ncfg node\` serves this user's socket, with no fuzznetd anywhere"

timeout 40 "$C" pair --run-dir "$R/run" > "$R/pair" 2>&1 &
pair=$!
pids="$pids $pair"
n=0
until grep -q '^FZI1:' "$R/pair" 2>/dev/null || [ $n -gt 16 ]; do sleep 0.5; n=$((n + 1)); done
code=$(sed -n 's/^\(FZI1:.*\)$/\1/p' "$R/pair")
timeout 35 "$C" join "$code" > "$R/join" 2>&1
[ $? -eq 0 ] && [ "$(wc -c < "$R/join")" -eq 65 ]
check $? "\`ncfg join\` takes the code and says which host let it in"
wait $pair
key=$(cat "$R/join")

timeout 5 "$C" nodes > "$R/nodes" 2>&1
grep -q "^$key" "$R/nodes"
check $? "\`ncfg nodes\` lists that host"

at() { # $1 file: `ncfg status --at` until it answers, or 16 looks
	n=0
	until timeout 8 "$C" status --at "$key" --json > "$1" 2>&1 || [ $n -gt 16 ]; do
		sleep 0.5
		n=$((n + 1))
	done
	grep -q '"' "$1"
}
at "$R/status"
check $? "\`ncfg --at\` reaches that host through it ($(head -c 40 "$R/status"))"

# Beside another program, which took the store first.
gone "$node"
timeout -k 2 40 "$F" --no-log-file --udp-port=0 --fuzznet-service=1 --fuzznet-product=2 \
	> "$R/other.log" 2>&1 &
other=$!
pids="$pids $other"
n=0
until [ -S "$U" ] || [ $n -gt 12 ]; do sleep 0.5; n=$((n + 1)); done
at "$R/through"
check $? "another fuzznet program on this store reaches it too ($(head -c 40 "$R/through"))"

timeout -k 2 30 "$C" node --no-log-file > "$R/node2.log" 2>&1 &
node=$!
pids="$pids $node"
sleep 2
[ -d "/proc/$node" ] && [ -n "$(cat "/proc/$node/cmdline" 2>/dev/null)" ]
check $? "\`ncfg node\` started beside it follows rather than exits"
gone "$other"
n=0
until [ "$(cat "$R/home/.local/share/fuzznet/face" 2>/dev/null)" = "$U" ] &&
	timeout 8 "$C" nodes > "$R/after" 2>&1 && grep -q "^$key" "$R/after" || [ $n -gt 20 ]; do
	sleep 0.5
	n=$((n + 1))
done
grep -q "^$key" "$R/after"
check $? "and when that one goes it is the face, and the estate is still there"
at "$R/final"
check $? "and it reaches the host"

# Nobody started one: asking for a host is what starts it, and asking for this
# machine is not. The pid is the socket's own word for who holds it.
gone "$node"
n=0
until [ ! -S "$U" ] || [ $n -gt 12 ]; do sleep 0.5; n=$((n + 1)); done
timeout 5 "$C" status --run-dir "$R/run" > /dev/null 2>&1
[ ! -S "$U" ]
check $? "a verb of this machine starts no node"
at "$R/started"
check $? "\`--at\` with no node up starts one, and is answered"
started=$(python3 -I -c "
import socket, struct, sys
s = socket.socket(socket.AF_UNIX); s.connect(sys.argv[1])
print(struct.unpack('3i', s.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))[0])
" "$U")
[ -n "$started" ] && tr '\0' ' ' < "/proc/$started/cmdline" | grep -q 'ncfg node'
check $? "and it is \`ncfg node\`, left up for the next look"
kill -TERM "$started" 2>/dev/null
n=0
while [ -d "/proc/$started" ] && [ $n -lt 12 ]; do sleep 0.5; n=$((n + 1)); done

gone "$host"
exit $failed
