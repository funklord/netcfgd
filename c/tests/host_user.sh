#!/bin/sh
# host_user.sh -- `ncfg host`: this user's host, with no fuzznetd installed, and
# then beside one on the same store (project.md 10.734). Run by `make test`.
#
# fuzznetd is here as any other fuzznet program is: the holder's word is that
# all of them have their full function and coexist on the same files and the
# same estate, so it is run as fuzzypickles' number, not as netcfgd's.
#
# The one process this cannot hold a pid of is the daemon `--at` starts, which
# stops by itself when its clients have gone; the namespace outlives neither.
#
# HOW IT STOPS: the whole of it runs in one network namespace under `timeout -k
# 2 110`; every process it starts is under a timeout of its own and killed by
# pid; waits are counts of 0.5 s looks. The directory is mktemp's, checked by
# shape, and removed at the end.
here=$(cd "$(dirname "$0")/.." && pwd)
if [ "$1" != inside ]; then
	if ! unshare -Urn true 2>/dev/null; then
		echo "host_user: no user namespaces here, so nothing was looked at"
		exit 1
	fi
	exec timeout -k 2 110 unshare -Urn sh "$0" inside
fi
N=$here/netcfgd
C=$here/ncfg
F=$here/fuzznet-build/fuzznetd
R=$(mktemp -d /tmp/ncf.XXXXXX) || exit 1
case "$R" in /tmp/ncf.?*) ;; *) echo "host_user: odd scratch $R"; exit 1;; esac
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

timeout 5 "$C" hosts > "$R/none" 2>&1
[ $? -ne 0 ] && grep -q 'ncfg join' "$R/none"
check $? "not yet a host, \`ncfg hosts\` says to join ($(head -1 "$R/none" | cut -c1-40))"
timeout 5 "$C" status --at "$(printf '%064d' 1)" > "$R/none" 2>&1
[ $? -ne 0 ] && grep -q 'ncfg join' "$R/none" && [ ! -e "$R/home/.local/share/fuzznet" ] && [ ! -S "$U" ]
check $? "and \`--at\` is refused too, with no key made and no daemon started"

timeout 5 "$C" hosts --run-dir "$R/run" > "$R/roots" 2>&1
check $? "a client of this machine, with no key, reads root's estate instead"

timeout -k 2 70 "$C" host --no-log-file > "$R/node.log" 2>&1 &
node=$!
pids="$pids $node"
n=0
until [ -S "$U" ] || [ $n -gt 12 ]; do sleep 0.5; n=$((n + 1)); done
[ -S "$U" ]
check $? "\`ncfg host\` serves this user's socket, with no fuzznetd anywhere"

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

timeout 5 "$C" hosts > "$R/nodes" 2>&1
grep -q "^$key" "$R/nodes"
check $? "\`ncfg hosts\` lists that host"

mkdir -p "$R/other" "$R/otherxdg"
chmod 700 "$R/otherxdg"
HOME=$R/other XDG_RUNTIME_DIR=$R/otherxdg timeout 5 "$C" hosts --run-dir "$R/run" > "$R/roots" 2>&1
[ $? -eq 0 ] && [ -s "$R/roots" ] && ! [ -e "$R/other/.local/share/fuzznet" ]
check $? "and root's list has the host that joined, for one who has not ($(wc -l < "$R/roots"))"

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

# A code that asks first: turned away, then let in, by the person at the terminal.
mkdir -p "$R/d2" "$R/d2xdg" "$R/d3" "$R/d3xdg"
chmod 700 "$R/d2xdg" "$R/d3xdg"
device() { # $1 home, $2 runtime, $3 the code
	HOME=$1 XDG_RUNTIME_DIR=$2 timeout 20 "$C" join "$3" > "$1/join" 2>&1
}
draw() { # $1 file, $2 the answer
	(sleep 6; echo "$2") | timeout 18 "$C" pair confirm --run-dir "$R/run" > "$1" 2>&1 &
	drawn=$!
	pids="$pids $drawn"
	n=0
	until grep -q '^FZI1:' "$1" 2>/dev/null || [ $n -gt 16 ]; do sleep 0.5; n=$((n + 1)); done
	code=$(sed -n 's/^\(FZI1:.*\)$/\1/p' "$1")
}
draw "$R/pairno" n
device "$R/d2" "$R/d2xdg" "$code" &
wait $drawn
[ $? -ne 0 ] && grep -q 'asks to join' "$R/pairno" && grep -q 'turned away' "$R/pairno"
check $? "\`ncfg pair confirm\` asks, and a no turns the device away"
draw "$R/pairyes" y
device "$R/d3" "$R/d3xdg" "$code"
[ $? -eq 0 ] && [ "$(wc -c < "$R/d3/join")" -eq 65 ]
check $? "and a yes lets it in"
wait $drawn

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

timeout -k 2 30 "$C" host --no-log-file > "$R/node2.log" 2>&1 &
node=$!
pids="$pids $node"
sleep 2
[ -d "/proc/$node" ] && [ -n "$(cat "/proc/$node/cmdline" 2>/dev/null)" ]
check $? "\`ncfg host\` started beside it follows rather than exits"
gone "$other"
n=0
until [ "$(cat "$R/home/.local/share/fuzznet/face" 2>/dev/null)" = "$U" ] &&
	timeout 8 "$C" hosts > "$R/after" 2>&1 && grep -q "^$key" "$R/after" || [ $n -gt 20 ]; do
	sleep 0.5
	n=$((n + 1))
done
grep -q "^$key" "$R/after"
check $? "and when that one goes it is the face, and the estate is still there"
at "$R/final"
check $? "and it reaches the host"

# Nobody started one: asking for a host is what starts it, and asking for this
# machine is not.
gone "$node"
n=0
until [ ! -S "$U" ] || [ $n -gt 12 ]; do sleep 0.5; n=$((n + 1)); done
timeout 5 "$C" status --run-dir "$R/run" > /dev/null 2>&1
[ ! -S "$U" ]
check $? "a verb of this machine starts no node"
sleep 6 # past fuzznet's kept replies, which a host just gone left on the far side
timeout 8 "$C" status --at "$key" --json > "$R/started" 2>&1
check $? "\`--at\` with no daemon up starts one, and is answered the first time"
timeout 5 "$C" status --at "$key" --json > "$R/again" 2>&1
check $? "and a second \`--at\` straight after it"
sleep 3
[ -S "$U" ]
check $? "with no client left it lingers past the far side's kept replies"
n=0
while [ -S "$U" ] && [ $n -lt 120 ]; do sleep 0.1; n=$((n + 1)); done
[ ! -S "$U" ]
check $? "and then stops, nothing of this user's left running"

# A client still holding keeps it: a shared lock, as a window holds one.
L=$R/xdg/fuzznet/ncfg-clients.lock
timeout 18 flock -s "$L" sleep 15 &
holder=$!
pids="$pids $holder"
sleep 0.2
at "$R/held"
sleep 12
[ -S "$U" ] && timeout 5 "$C" status --at "$key" --json > /dev/null 2>&1
check $? "a daemon stays up while another client holds it"
wait $holder
n=0
while [ -S "$U" ] && [ $n -lt 120 ]; do sleep 0.1; n=$((n + 1)); done
[ ! -S "$U" ]
check $? "and stops when that client lets go"

# Typed by hand it is not a client's, and nothing stops it.
timeout -k 2 8 "$C" host --no-log-file > /dev/null 2>&1 &
hand=$!
pids="$pids $hand"
n=0
until [ -S "$U" ] || [ $n -gt 12 ]; do sleep 0.5; n=$((n + 1)); done
sleep 2.5
[ -S "$U" ] && [ -d "/proc/$hand" ]
check $? "\`ncfg host\` typed by hand stays up with nobody holding it"
gone "$hand"

gone "$host"
exit $failed
