#!/bin/sh
# node_serve.sh -- netcfgd as its fuzznet store's face, inside fuzznet's loop
# (project.md 10.676 to 10.684). Run by `make test` and `make node-serve-test`
# against the program the build made; needs no privilege. The daemons are
# given `--fuzznet-serve`, which 0311 retired and still accepts: serving is
# what a daemon with a node does.
#
# On a scratch store and run directory, these, each with what makes it mean
# something:
#   - fuzznet's own socket is served, and names itself in the store's `face`:
#     fzn_daemon_main is running, so netcfgd's own loop is not;
#   - a fuzznet client's `list record` and `add record` are answered by it;
#   - `ncfg reload` is answered at once -- through the mailbox's wake byte,
#     which only fuzznet's loop polls now. Without `ready` it waits for the
#     five-second backstop (measured: 4797 ms against 5);
#   - an edit to the configuration is compiled, through the inotify watch;
#   - a station a fuzznetd recorded in the store beforehand is read back
#     in-process (`fzn_daemon_local`, fuzznet sec 835) and is in
#     `ncfg status --json` -- over the socket it would be this process asking
#     its own blocked loop;
#   - SIGTERM stops it with status 0, through `fzn_daemon_stop`: `face`,
#     fuzznet's socket and `<run>/node` all gone;
#   - and its log carries no sanitizer report, for a `SANITIZE=1` run.
#
# Then beside a fuzznetd that is already the face (fuzznet sec 838), neither
# told a socket: netcfgd follows on its run directory's (10.683) and still
# answers `ncfg reload` at once and reads the station back through the face;
# when the fuzznetd stops, netcfgd takes the claim, restarts itself as the
# face there (its own command line, `restart_argv`) and answers again.
#
# HOW IT STOPS: every wait is bounded (50 looks of 0.2 s), each client call is
# under `timeout 10`, and the daemon under `timeout -k 5 60` -- the kill
# because a daemon that never reads its stop byte ignores SIGTERM. The
# directory is mktemp's, checked by shape, and removed at the end.
here=$(cd "$(dirname "$0")/.." && pwd)
N=$here/netcfgd
F=$here/fuzznet-build/fuzznetd
C=$here/ncfg
R=$(mktemp -d /tmp/ncs.XXXXXX) || exit 1
case "$R" in /tmp/ncs.?*) ;; *) echo "node_serve: odd scratch $R"; exit 1;; esac
failed=0
check() { # $1 0 for ok, $2 what
	if [ "$1" -eq 0 ]; then printf '%-72s ok\n' "$2"; else printf '%-72s FAILED\n' "$2"; failed=1; fi
}
ask() { # $1 socket, $2 line: one reply line from fuzznet's local socket
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
conf() { # the configuration, $1 an extra stanza
	printf 'global {\n\tcontrol {\n\t\tobserve = "any"\n\t\tadmin = "any"\n\t}\n}\n%s' "$1" \
		> "$R/conf/netcfgd.conf"
}

mkdir "$R/store" "$R/run" "$R/conf"
conf ''

# The record, written by a real fuzznetd as the store's face, which then goes.
timeout -k 5 30 "$F" --fuzznet-dir="$R/store" --socket="$R/fzd.sock" --no-log-file \
	--fuzznet-service=1 --fuzznet-product=1 > "$R/fzd.log" 2>&1 &
fzd=$!
n=0
until [ -S "$R/fzd.sock" ] || [ $n -gt 50 ]; do sleep 0.2; n=$((n + 1)); done
[ "$(ask "$R/fzd.sock" 'add record seen/wlan9/aa-bb-cc-00-00-07 station')" = ok ]
check $? "a fuzznetd, as the face first, keeps a seen record"
kill -TERM $fzd
wait $fzd
timeout -k 5 60 "$N" --run-dir "$R/run" --config-dir "$R/conf" --no-apply-on-start \
	--fuzznet-dir "$R/store" --fuzznet-serve --fuzznet-arg "--socket=$R/fz.sock" \
	--fuzznet-arg --no-log-file --fuzznet-arg --fuzznet-service=1 \
	--fuzznet-arg --fuzznet-product=1 > "$R/log" 2>&1 &
pid=$!
n=0
until { [ -S "$R/fz.sock" ] && [ -S "$R/run/netcfgd.sock" ]; } || [ $n -gt 50 ]; do
	sleep 0.2
	n=$((n + 1))
done
[ "$(cat "$R/store/face" 2>/dev/null)" = "$R/fz.sock" ]
check $? "fuzznet's socket is served, and the store's face names it"
[ "$(ask "$R/fz.sock" 'add record seen/test/1 hello')" = ok ]
check $? "a fuzznet client's add record is answered ok"
ask "$R/fz.sock" 'list record' | grep -q '^ok 0 2 0'
check $? "and list record shows both records"

t0=$(date +%s%N)
said=$(timeout 10 "$C" reload --run-dir "$R/run" 2>&1 | grep -v nftables | head -1)
ms=$(( ($(date +%s%N) - t0) / 1000000 ))
echo "$said" | grep -q '^reloaded' && [ "$ms" -lt 2000 ]
check $? "ncfg reload is answered through the daemon at once ($ms ms)"

conf "$(printf 'device dummy7 {\n\tkind = "dummy"\n}\n')"
n=0
until grep -q dummy7 "$R/run/desired.json" 2>/dev/null || [ $n -gt 50 ]; do
	sleep 0.2
	n=$((n + 1))
done
grep -q dummy7 "$R/run/desired.json" 2>/dev/null
check $? "an edit to the configuration is compiled"

timeout 10 "$C" status --json --run-dir "$R/run" 2>/dev/null | grep -q 'aa:bb:cc:00:00:07'
check $? "the station that fuzznetd recorded is read back in-process, in ncfg status"

# The same over fuzznet alone (10.689): with the control socket out of the
# way, only `call status` can bring the daemon's stations to `ncfg status`.
# Renamed rather than removed, so the daemon's listener is untouched.
mv "$R/run/netcfgd.sock" "$R/run/hidden.sock"
timeout 10 "$C" status --json --run-dir "$R/run" 2>/dev/null | grep -q 'aa:bb:cc:00:00:07'
check $? "  and over fuzznet's call status, with the control socket out of the way"
# Every request now (0309, 10.712), and not only `status`: with no control
# socket to reach, these can only have come through `call ask`. A request past
# one line goes in pieces.
timeout 10 "$C" plan --run-dir "$R/run" > "$R/plan.out" 2>&1
check $? "ncfg plan answers over fuzznet's call ask, the socket out of the way"
timeout 10 "$C" reload --run-dir "$R/run" > "$R/reload.out" 2>&1
check $? "  and so does a change, ncfg reload ($(head -c 40 "$R/reload.out"))"
{
	printf 'device lo {\n\tmanaged = false\n}\n'
	i=0
	while [ $i -lt 40 ]; do
		printf '# padding line %02d, so that this drop-in is longer than a line\n' $i
		i=$((i + 1))
	done
} > "$R/big.conf"
timeout 20 "$C" config put --run-dir "$R/run" --config-dir "$R/conf" big "$R/big.conf" \
	> "$R/big.out" 2>&1
[ "$(grep -c padding "$R/conf/conf.d/big.conf" 2>/dev/null)" = 40 ]
check $? "  and a request longer than a line, in pieces ($(head -c 40 "$R/big.out"))"
rm -f -- "$R/conf/conf.d/big.conf"
mv "$R/run/hidden.sock" "$R/run/netcfgd.sock"

# 0309's first verb (10.682): the observation written where the caller says,
# judged by netcfgd's own tiers on the caller fuzznet read (sec 849).
mkdir -m 700 "$R/out"
said=$(ask "$R/fz.sock" "get status $R/out/status.json")
length=$(echo "$said" | sed -n 's/^ok \([0-9]*\)$/\1/p')
[ -n "$length" ] && [ "$(wc -c < "$R/out/status.json" 2>/dev/null)" = "$length" ] &&
	python3 -I -c 'import json, sys; json.load(open(sys.argv[1]))' "$R/out/status.json"
check $? "get status PATH writes the observation there and answers its length ($said)"
said=$(ask "$R/fz.sock" "get status /tmp/netcfgd-node-serve-$$.json")
echo "$said" | grep -q "^error .*not the caller's" && [ ! -e "/tmp/netcfgd-node-serve-$$.json" ]
check $? "  and not into a directory that is not the caller's"

# The same status as a fuzznet procedure (its sec 853, 10.688): `call status
# FROM` answers `ok` and the page escaped, `ok TOTAL FROM COUNT DIGEST`
# and the bytes. This caller is the node's own user, so fuzznet lets it call.
said=$(ask "$R/fz.sock" "call status 0")
echo "$said" > "$R/out/call.txt"
echo "$said" | grep -q '^ok ok%20[0-9][0-9]*%200%20[0-9]'
check $? "call status 0 answers the status's first page ($(echo "$said" | cut -c1-24))"
said=$(ask "$R/fz.sock" "call status x")
echo "$said" | grep -q '^ok malformed'
check $? "  and an offset that is not one is malformed ($(echo "$said" | cut -c1-24))"

kill -TERM $pid
wait $pid
code=$?
[ $code -eq 0 ] && [ ! -e "$R/store/face" ] && [ ! -e "$R/run/node" ] && [ ! -e "$R/fz.sock" ]
check $? "SIGTERM stops it with status 0 ($code); face, socket, <run>/node gone"

# Under `make SANITIZE=1 node-serve-test`: UBSan only prints, and the log is
# removed below, so a report would otherwise go unread.
! grep -q 'runtime error\|Sanitizer' "$R/log"
check $? "the daemon's log carries no sanitizer report"

# ---- the observe tier open to a group: fuzznet's permit follows it ----
# (10.688) Without the grant fuzznet calls `status` for the node's own user
# alone; with it, a GUI user in netcfgd's group may. The group here is this
# user's own, since a second user needs privilege this test does not have.
g=$(id -gn)
printf 'global {\n\tcontrol {\n\t\tobserve = "group:%s"\n\t\twifi = "group:%s"\n\t\tadmin = "root"\n\t}\n}\n' \
	"$g" "$g" > "$R/conf/netcfgd.conf"
timeout -k 5 60 "$N" --run-dir "$R/run" --config-dir "$R/conf" --no-apply-on-start \
	--fuzznet-dir "$R/store" --fuzznet-arg "--socket=$R/fz.sock" \
	--fuzznet-arg --no-log-file --fuzznet-arg --fuzznet-service=1 \
	--fuzznet-arg --fuzznet-product=1 > "$R/log4" 2>&1 &
pid=$!
n=0
until grep -q "permit for .askpart." "$R/log4" 2>/dev/null || [ $n -gt 50 ]; do
	sleep 0.2
	n=$((n + 1))
done
said=$(ask "$R/fz.sock" "get setting host local/permit/status")
echo "$said" | grep -q "^ok [a-z]* group:$g=x\$"
check $? "observe = group:NAME grants that group fuzznet's call of status ($said)"
# `ask` admits a holder of any tier, netcfgd's gate judging each request behind
# it (10.712), or a GUI user of a root daemon would stay on the old socket.
said=$(ask "$R/fz.sock" "get setting host local/permit/ask")
echo "$said" | grep -q "^ok [a-z]* group:$g=x\$"
check $? "  and of ask, each grant once, the admin tier being root's ($said)"
said=$(ask "$R/fz.sock" "get setting host local/permit/askpart")
echo "$said" | grep -q "^ok [a-z]* group:$g=x\$"
check $? "  and of askpart ($said)"
kill -TERM $pid
wait $pid

# ---- the observe tier closed: the same verb denied ----
# A daemon of its own, because the control policy is read once at start (the
# socket's servers hold the same copy), so an edit would not close it. With a
# service and product named, as every phase here: without them fuzznet routes
# no request to an extension's verbs and answers its own status line instead
# (measured, 10.682).
printf 'global {\n\tcontrol {\n\t\tadmin = "any"\n\t}\n}\n' > "$R/conf/netcfgd.conf"
timeout -k 5 60 "$N" --run-dir "$R/run" --config-dir "$R/conf" --no-apply-on-start \
	--fuzznet-dir "$R/store" --fuzznet-serve --fuzznet-arg "--socket=$R/fz.sock" \
	--fuzznet-arg --no-log-file --fuzznet-arg --fuzznet-service=1 \
	--fuzznet-arg --fuzznet-product=1 > "$R/log3" 2>&1 &
pid=$!
n=0
until [ -S "$R/fz.sock" ] || [ $n -gt 50 ]; do sleep 0.2; n=$((n + 1)); done
said=$(ask "$R/fz.sock" "get status $R/out/denied.json")
echo "$said" | grep -q '^denied .*observe' && [ ! -e "$R/out/denied.json" ]
check $? "  and is denied where the observe tier is not the caller's ($said)"
said=$(ask "$R/fz.sock" "get setting host local/permit/status")
echo "$said" | grep -q '^ok absent$'
check $? "  and the status permit is cleared, the tier being root's ($said)"
kill -TERM $pid
wait $pid
conf ''

# ---- beside a running fuzznetd, then taking over from it ----
# Neither told a socket, which is the router's case. The fuzznetd takes the
# per-user default; netcfgd gives fuzznet its run directory's
# `fuzznet.sock` (10.683), so it follows on a socket of its own and becomes
# the face there when the fuzznetd goes. (Before 10.683 both took the
# default, and since fuzznet's 16830dc a follower there had no socket.)
mkdir -m 700 "$R/xdg"
D="$R/xdg/fuzznet/fuzznetd.sock"
XDG_RUNTIME_DIR="$R/xdg" timeout -k 5 60 "$F" --fuzznet-dir="$R/store" --no-log-file \
	--fuzznet-service=1 --fuzznet-product=1 > "$R/fzd.log" 2>&1 &
fzd=$!
n=0
until [ "$(cat "$R/store/face" 2>/dev/null)" = "$D" ] || [ $n -gt 50 ]; do
	sleep 0.2
	n=$((n + 1))
done
XDG_RUNTIME_DIR="$R/xdg" timeout -k 5 60 "$N" --run-dir "$R/run" --config-dir "$R/conf" \
	--no-apply-on-start --fuzznet-dir "$R/store" --fuzznet-serve \
	--fuzznet-arg --no-log-file --fuzznet-arg --fuzznet-service=1 \
	--fuzznet-arg --fuzznet-product=1 > "$R/log2" 2>&1 &
pid=$!
n=0
until [ -S "$R/run/netcfgd.sock" ] || [ $n -gt 50 ]; do
	sleep 0.2
	n=$((n + 1))
done
sleep 1
[ "$(cat "$R/store/face" 2>/dev/null)" = "$D" ] && [ -d /proc/$pid ] &&
	grep -q "following the face .*serving on $R/run/fuzznet.sock" "$R/log2"
check $? "beside a fuzznetd on the default socket, netcfgd follows it on its run directory's"
t0=$(date +%s%N)
said=$(timeout 10 "$C" reload --run-dir "$R/run" 2>&1 | grep -v nftables | head -1)
ms=$(( ($(date +%s%N) - t0) / 1000000 ))
echo "$said" | grep -q '^reloaded' && [ "$ms" -lt 2000 ]
check $? "  and still answers ncfg reload at once ($ms ms)"
# No edit, so the read-back comes from the backstop's pass -- while the loop
# below asks `status` every half second. Before 10.678 each of those requests
# restarted the five seconds and this never arrived; the first version of
# this phase blamed the reload instead and made an edit to get a pass.
n=0
until timeout 10 "$C" status --json --run-dir "$R/run" 2>/dev/null |
	grep -q 'aa:bb:cc:00:00:07' || [ $n -gt 20 ]; do
	sleep 0.5
	n=$((n + 1))
done
[ $n -le 20 ]
check $? "  and reads the station back through the face"

kill -TERM $fzd
wait $fzd
n=0
until grep -q 'starting again as the face' "$R/log2" &&
	[ "$(cat "$R/store/face" 2>/dev/null)" = "$R/run/fuzznet.sock" ] &&
	[ "$(ask "$R/run/fuzznet.sock" 'list record' | cut -c1-2)" = ok ] || [ $n -gt 75 ]; do
	sleep 0.2
	n=$((n + 1))
done
[ $n -le 75 ] && [ -d /proc/$pid ]
check $? "when the fuzznetd stops, netcfgd takes over as the face"
n=0
until timeout 10 "$C" reload --run-dir "$R/run" 2>&1 | grep -q '^reloaded' || [ $n -gt 50 ]; do
	sleep 0.2
	n=$((n + 1))
done
[ $n -le 50 ]
check $? "  and answers ncfg again, having restarted itself"

kill -TERM $pid
wait $pid
code=$?
[ $code -eq 0 ] && [ ! -e "$R/store/face" ] && [ ! -e "$R/run/fuzznet.sock" ]
check $? "  and SIGTERM still stops it with status 0 ($code), its socket gone"
! grep -q 'runtime error\|Sanitizer' "$R/log2"
check $? "  with no sanitizer report"

if [ $failed -ne 0 ]; then
	grep -v 'nftables\|supplicant\|previous configuration' "$R/log" | tail -12 | sed 's/^/  log: /'
	grep -v 'nftables\|supplicant\|previous configuration' "$R/log2" | tail -12 |
		sed 's/^/  log2: /'
fi
rm -rf "$R"
[ $failed -eq 0 ] && echo "node_serve: all checks passed" || echo "node_serve: some checks FAILED"
exit $failed
