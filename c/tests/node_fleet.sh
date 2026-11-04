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
#   - `ncfg nodes` lists A by the same key, for `--at`;
#   - `call ask at A` answers a plan and refuses an apply, by A's tiers;
#   - `ncfg modem --at A` is A's answer, `reload --at A` A's refusal, and a
#     command that works on this machine is refused with `--at`;
#   - `ncfg tui --at A` runs in a pty and says it has no event stream;
#   - a host that is no member is refused rather than waited on for ever;
#   - with A's `remote` observe tier closed, A denies it and names the tier,
#     and `reload --at estate` reports A failed rather than ok;
#   - and with its admin tier open, a configuration longer than one line,
#     put through B, goes in pieces and lands in A's conf.d whole, its reload
#     seen by `monitor --at A` from A's events cursor; and an
#     apply with a window, confirmed from B, then finds no second window,
#     and a window nobody confirms reverts by itself;
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

# The keys an operator asks by (10.692): B lists A among its estate's
# members, the same key `--at` took, so a peer's key is the host a call names.
XDG_RUNTIME_DIR=$R/xdg timeout 10 "$C" nodes > "$R/nodes.out" 2>&1
grep -qx "$host" "$R/nodes.out"
check $? "ncfg nodes, through B, lists A by the key status --at takes"
XDG_RUNTIME_DIR=$R/xdg timeout 10 "$C" nodes --json 2>/dev/null |
	python3 -I -c 'import json, sys; d = json.load(sys.stdin); sys.exit(0 if sys.argv[1] in d else 1)' "$host"
check $? "  and --json is a list of them"

# The control vocabulary as one procedure (0312, 10.693), through B, raw:
# a read under A's open `observe`, and a change under its closed `admin`,
# whose request carries a comma for fuzznet's grammar to pass through.
said=$(ask "$B" "call ask at $host 0 {\"request\":\"plan\"}")
echo "$said" | grep -q '^ok ok%20[0-9]*%200%20[0-9]*%20[0-9a-f]\{16\}%0a{"response":"plan"'
check $? "call ask at A answers a plan, A's remote observe tier open ($(echo "$said" | cut -c1-30))"
said=$(ask "$B" "call ask at $host 0 {\"request\":\"apply\",\"confirm\":90}")
echo "$said" | grep -q 'error.*admin'
check $? "  and refuses an apply, its remote admin tier closed"

# `ncfg --at` (10.694): a socket verb asked of A through B, as A's socket
# would answer it. `modem` is A's observe tier, open; `reload` its admin
# tier, closed, and A's refusal must come back as A's, naming the tier.
XDG_RUNTIME_DIR=$R/xdg timeout 60 "$C" modem --at "$host" > "$R/modem.out" 2>&1
check $? "ncfg modem --at A is answered by A ($(head -c 50 "$R/modem.out"))"
XDG_RUNTIME_DIR=$R/xdg timeout 60 "$C" reload --at "$host" > "$R/reload.out" 2>&1
[ $? -ne 0 ] && grep -q 'admin' "$R/reload.out"
check $? "  ncfg reload --at A is refused by A's closed remote admin tier"
XDG_RUNTIME_DIR=$R/xdg timeout 10 "$C" show --at "$host" 2>&1 | grep -q 'works on this machine'
check $? "  a command that works here is refused with --at, not done here"
XDG_RUNTIME_DIR=$R/xdg timeout 10 "$C" apply --at "$host" 2>&1 | grep -q 'confirm-within'
check $? "  and apply --at without a window is refused before anything is asked"

# `ncfg tui --at A` (10.700), in a pty for four seconds: drawn, then `e` for
# the events pane, which says it has no stream from another node, and `q`
# ends it. Bounded by the pty's own deadline and by `timeout`.
XDG_RUNTIME_DIR=$R/xdg timeout 30 python3 -I -c '
import os, pty, select, sys, time
pid, fd = pty.fork()
if pid == 0:
    os.execv(sys.argv[1], [sys.argv[1], "tui", "--at", sys.argv[2]])
seen = b""
def read_for(seconds):
    global seen
    until = time.monotonic() + seconds
    while time.monotonic() < until:
        ready, _, _ = select.select([fd], [], [], 0.2)
        if ready:
            try:
                seen += os.read(fd, 65536)
            except OSError:
                return
read_for(2.0)
os.write(fd, b"e")  # the events pane
read_for(2.0)
os.write(fd, b"q")
time.sleep(0.5)
try:
    os.kill(pid, 15)
except ProcessLookupError:
    pass
os.waitpid(pid, 0)
sys.stdout.write(seen.decode(errors="replace"))' "$C" "$host" > "$R/tui.out" 2>&1
grep -q 'no stream comes from another node' "$R/tui.out"
check $? "ncfg tui --at A says it has no event stream from another node"

# Nothing under --at falls back to this machine (10.694): `config put` asks
# first and writes locally only where no daemon listens, so with A's admin
# tier closed it must be A's refusal, and the local directory stays empty.
mkdir "$R/bconf"
printf 'device lo {\n\tmanaged = false\n}\n' > "$R/drop.conf"
XDG_RUNTIME_DIR=$R/xdg timeout 60 "$C" config put --at "$host" --config-dir "$R/bconf" \
	lab "$R/drop.conf" > "$R/put.out" 2>&1
[ $? -ne 0 ] && grep -q 'admin' "$R/put.out" && [ -z "$(ls -A "$R/bconf")" ]
check $? "  config put --at A is A's refusal, and nothing is written here"
XDG_RUNTIME_DIR=$R/xdg timeout 60 "$C" profile list --at "$host" --config-dir "$R/bconf" \
	> "$R/profiles.out" 2>&1
check $? "  profile list --at A is A's answer ($(head -c 40 "$R/profiles.out"))"

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
# The GUI's fleet tab (10.710) tells a refusal from a dead node by exactly this
# command's first line of standard error; its probe has only a stand-in.
XDG_RUNTIME_DIR=$R/xdg timeout 30 "$C" status --at "$host" --json 2> "$R/denied.err" > "$R/denied.out"
code=$?
[ $code -ne 0 ] && head -1 "$R/denied.err" | grep -q 'denied' && [ ! -s "$R/denied.out" ]
check $? "  status --at A --json says so on the first line of stderr ($(head -c 50 "$R/denied.err"))"

# Propagation (10.708): `reload --at estate` through B is fuzznet's `call do
# at estate`, and A, its remote admin tier closed, is reported as failed --
# not as ok, which `ask`'s page for a refusal would have read as.
key16=$(echo "$host" | cut -c1-16)
XDG_RUNTIME_DIR=$R/xdg timeout 90 "$C" reload --at estate > "$R/estate1.out" 2>&1
code=$?
[ $code -eq 1 ] && grep -q "^$key16  failed" "$R/estate1.out" &&
	grep -q '^0 of 1 netcfgd node' "$R/estate1.out"
check $? "reload --at estate reports A failed, its admin tier closed ($(head -c 40 "$R/estate1.out"))"
XDG_RUNTIME_DIR=$R/xdg timeout 10 "$C" status --at estate 2>&1 | grep -q 'brings back only whether'
check $? "  and a read across many hosts is refused before anything is asked"

# A configuration longer than one fuzznet line, put through B (10.695):
# sent in pieces with `askpart` and run by digest, under A's remote admin
# tier, open this time. It lands in A's conf.d, whole, and nothing is
# written here.
apid=${pids##* }
kill -TERM "$apid" 2>/dev/null
wait "$apid" 2>/dev/null
printf 'global {\n\tcontrol {\n\t\tobserve = "any"\n\t}\n\tremote {\n\t\tobserve = true\n\t\tadmin = true\n\t}\n}\n' \
	> "$R/conf/netcfgd.conf"
timeout -k 5 120 "$N" --run-dir "$R/run" --config-dir "$R/conf" --no-apply-on-start \
	--fuzznet-dir "$R/a" --fuzznet-arg "--socket=$R/a.sock" --fuzznet-arg --no-log-file \
	--fuzznet-arg "--udp-port=$PA" --fuzznet-arg --fuzznet-service=1 \
	--fuzznet-arg --fuzznet-product=1 > "$R/a3.log" 2>&1 &
pids="$pids $!"
{
	printf 'device lo {\n\tmanaged = false\n}\n'
	i=0
	while [ $i -lt 40 ]; do
		printf '# padding line %02d, so that this drop-in is longer than a line\n' $i
		i=$((i + 1))
	done
} > "$R/big.conf"
# Watching A's events through B while the put lands (10.703): no stream
# crosses the estate, so `monitor --at` polls A's `events` cursor, and the
# put's reload must show up in it. Under `timeout`, and killed after.
XDG_RUNTIME_DIR=$R/xdg timeout 40 "$C" monitor --at "$host" > "$R/monitor.out" 2>&1 &
mpid=$!
n=0
until grep -q '^watching' "$R/monitor.out" 2>/dev/null || [ $n -gt 60 ]; do
	sleep 0.5
	n=$((n + 1))
done
deadline=$(( $(date +%s) + 60 ))
while [ "$(date +%s)" -lt $deadline ]; do
	XDG_RUNTIME_DIR=$R/xdg timeout 60 "$C" config put --at "$host" --config-dir "$R/bconf" \
		big "$R/big.conf" > "$R/big.out" 2>&1 && break
	sleep 1
done
deadline=$(( $(date +%s) + 20 ))
until grep -qx 'reloaded' "$R/monitor.out" 2>/dev/null || [ "$(date +%s)" -ge $deadline ]; do
	sleep 0.5
done
kill -TERM $mpid 2>/dev/null
wait $mpid 2>/dev/null
grep -qx 'reloaded' "$R/monitor.out"
check $? "monitor --at A shows A reloading for the put, from A's events cursor"
[ "$(wc -c < "$R/big.conf")" -gt 1500 ] && [ -f "$R/conf/conf.d/big.conf" ] &&
	[ "$(grep -c padding "$R/conf/conf.d/big.conf")" = 40 ] && [ -z "$(ls -A "$R/bconf")" ]
check $? "a $(wc -c < "$R/big.conf")-byte config put --at A goes in pieces and lands in A's conf.d whole"

# Propagation again, the admin tier open: carried out on A. Before the
# revert below, since A then refuses a reload of the configuration it
# reverted away from until it is edited -- correctly, and as `failed`. B's
# own fuzznetd serves no netcfgd and is listed as such, not as a failure.
XDG_RUNTIME_DIR=$R/xdg timeout 90 "$C" reload --at estate > "$R/estate2.out" 2>&1
code=$?
[ $code -eq 0 ] && grep -q "^$key16  ok" "$R/estate2.out" &&
	grep -q '^1 of 1 netcfgd node(s) carried it out (2 of 2 host(s) answered, 1 serving no netcfgd)' "$R/estate2.out"
check $? "with its admin tier open, reload --at estate is carried out on A ($(tail -1 "$R/estate2.out" | cut -c1-30))"
# The remote safety path (0312): an apply from another host carries a window,
# and is confirmed from there. A's configuration changes nothing here (lo,
# unmanaged), so the apply has no actions to need privilege for.
XDG_RUNTIME_DIR=$R/xdg timeout 90 "$C" apply --at "$host" --confirm-within 60 \
	> "$R/apply.out" 2>&1
check $? "apply --at A --confirm-within arms a window on A ($(head -c 50 "$R/apply.out"))"
XDG_RUNTIME_DIR=$R/xdg timeout 60 "$C" confirm --at "$host" > "$R/confirm.out" 2>&1
grep -q 'confirmed' "$R/confirm.out"
check $? "  confirm --at A confirms it"
XDG_RUNTIME_DIR=$R/xdg timeout 60 "$C" confirm --at "$host" > "$R/confirm2.out" 2>&1
[ $? -ne 0 ] && grep -q 'no confirm window' "$R/confirm2.out"
check $? "  and a second confirm finds no window ($(head -c 60 "$R/confirm2.out"))"
# And one nobody confirms undoes itself: what stops an operator who cut
# themselves off from being cut off for good.
XDG_RUNTIME_DIR=$R/xdg timeout 90 "$C" apply --at "$host" --confirm-within 3 \
	> "$R/apply2.out" 2>&1
# Waited for by what A says, not by a sleep: the window is A's loop to close,
# and how soon it does is A's tick, which a fixed sleep would be guessing.
deadline=$(( $(date +%s) + 30 ))
until grep -qi 'revert' "$R/a3.log" || [ "$(date +%s)" -ge $deadline ]; do sleep 0.5; done
XDG_RUNTIME_DIR=$R/xdg timeout 60 "$C" confirm --at "$host" > "$R/confirm3.out" 2>&1
[ $? -ne 0 ] && grep -qi 'revert' "$R/a3.log"
check $? "  and a window nobody confirms reverts by itself ($(grep -i revert "$R/a3.log" | tail -1 | cut -c1-50))"

! grep -q 'runtime error\|Sanitizer' "$R/a.log" "$R/a2.log" "$R/a3.log"
check $? "netcfgd's log carries no sanitizer report"

if [ $failed -ne 0 ]; then
	for f in a.log b.log root.out a3.log big.out apply.out confirm.out tui.out monitor.out estate1.out estate2.out; do sed "s/^/  $f: /" "$R/$f" | tail -15; done
	echo "node_fleet: some checks FAILED"
	exit 1
fi
echo "node_fleet: all checks passed"
