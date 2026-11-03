#!/bin/sh
# node_serve.sh -- netcfgd as its fuzznet store's face, inside fuzznet's loop
# (project.md 10.676). Run by `make node-serve-test`, which builds with
# NODE_SERVE=1 first; needs no privilege.
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
# Then beside a fuzznetd that is already the face (fuzznet sec 838): netcfgd
# runs as a follower and still answers `ncfg reload` at once and reads the
# station back through the face; when the fuzznetd stops, netcfgd takes the
# claim, restarts itself as the face (its own command line, `restart_argv`)
# and answers again.
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

kill -TERM $pid
wait $pid
code=$?
[ $code -eq 0 ] && [ ! -e "$R/store/face" ] && [ ! -e "$R/run/node" ] && [ ! -e "$R/fz.sock" ]
check $? "SIGTERM stops it with status 0 ($code); face, socket, <run>/node gone"

# Under `make SANITIZE=1 node-serve-test`: UBSan only prints, and the log is
# removed below, so a report would otherwise go unread.
! grep -q 'runtime error\|Sanitizer' "$R/log"
check $? "the daemon's log carries no sanitizer report"

# ---- beside a running fuzznetd, then taking over from it ----
timeout -k 5 60 "$F" --fuzznet-dir="$R/store" --socket="$R/fzd.sock" --no-log-file \
	--fuzznet-service=1 --fuzznet-product=1 > "$R/fzd.log" 2>&1 &
fzd=$!
n=0
until [ "$(cat "$R/store/face" 2>/dev/null)" = "$R/fzd.sock" ] || [ $n -gt 50 ]; do
	sleep 0.2
	n=$((n + 1))
done
timeout -k 5 60 "$N" --run-dir "$R/run" --config-dir "$R/conf" --no-apply-on-start \
	--fuzznet-dir "$R/store" --fuzznet-serve --fuzznet-arg "--socket=$R/fz.sock" \
	--fuzznet-arg --no-log-file --fuzznet-arg --fuzznet-service=1 \
	--fuzznet-arg --fuzznet-product=1 > "$R/log2" 2>&1 &
pid=$!
n=0
until { [ -S "$R/fz.sock" ] && [ -S "$R/run/netcfgd.sock" ]; } || [ $n -gt 50 ]; do
	sleep 0.2
	n=$((n + 1))
done
[ "$(cat "$R/store/face" 2>/dev/null)" = "$R/fzd.sock" ]
check $? "beside a fuzznetd that is the face, netcfgd follows it"
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
until [ "$(cat "$R/store/face" 2>/dev/null)" = "$R/fz.sock" ] || [ $n -gt 75 ]; do
	sleep 0.2
	n=$((n + 1))
done
[ "$(cat "$R/store/face" 2>/dev/null)" = "$R/fz.sock" ] && [ -d /proc/$pid ]
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
[ $code -eq 0 ] && [ ! -e "$R/store/face" ] && [ ! -e "$R/fz.sock" ]
check $? "  and SIGTERM still stops it with status 0 ($code)"
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
