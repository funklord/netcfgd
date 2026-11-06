#!/bin/sh
# node_remote.sh -- a stock netcfgd has fuzznet's verbs, and listens on the
# network only where the config opens `global { remote }` (project.md 10.721).
# Run by `make test`. Each daemon runs in a network namespace of its own, so the
# fixed port cannot meet another run's; where namespaces are not allowed the
# script says so and fails, since a port not looked at is no pass.
#
# HOW IT STOPS: each daemon is under `timeout -k 2 45` and killed by pid at the
# end of its case; waits are counts of 0.5 s looks. The directory is mktemp's,
# checked by shape, and removed at the end.
here=$(cd "$(dirname "$0")/.." && pwd)
N=$here/netcfgd
R=$(mktemp -d /tmp/ncf.XXXXXX) || exit 1
case "$R" in /tmp/ncf.?*) ;; *) echo "node_remote: odd scratch $R"; exit 1;; esac
trap 'rm -rf "$R"' EXIT
failed=0
check() { # $1 0 for ok, $2 what
	if [ "$1" -eq 0 ]; then printf '%-72s ok\n' "$2"; else printf '%-72s FAILED\n' "$2"; failed=1; fi
}
if ! unshare -Urn true 2>/dev/null; then
	echo "node_remote: no user namespaces here, so the port cannot be looked at"
	exit 1
fi

# One daemon, in its namespace: `$1` the case's name, `$2` its remote block.
# Writes what `add peer` of nothing answered, and whether port 48090 is bound.
one() {
	d=$R/$1
	mkdir -p "$d/a" "$d/run" "$d/conf"
	chmod 700 "$d/a"
	printf 'global {\n%s}\n' "$2" > "$d/conf/netcfgd.conf"
	unshare -Urn sh -c '
		timeout -k 2 45 "$1" --run-dir "$2/run" --config-dir "$2/conf" \
			--no-apply-on-start --fuzznet-dir "$2/a" --fuzznet-arg --no-log-file \
			> "$2/log" 2>&1 &
		pid=$!
		n=0
		until [ -S "$2/run/fuzznet.sock" ] || [ $n -gt 12 ]; do sleep 0.5; n=$((n + 1)); done
		sleep 1
		python3 -I -c "
import socket, sys
s = socket.socket(socket.AF_UNIX); s.settimeout(4); s.connect(sys.argv[1])
s.sendall(b\"get prekey\n\"); print(s.recv(4096).decode(errors=\"replace\").strip()[:40])
" "$2/run/fuzznet.sock" > "$2/prekey" 2>&1
		cat /proc/net/udp /proc/net/udp6 > "$2/udp" 2>/dev/null
		ask() { # $1 socket, $2 line
			python3 -I -c "
import socket, sys
s = socket.socket(socket.AF_UNIX); s.settimeout(6); s.connect(sys.argv[1])
s.sendall((sys.argv[2] + \"\n\").encode()); print(s.recv(4096).decode(errors=\"replace\").strip())
" "$1" "$2" 2>&1
		}
		ip link set lo up
		ip addr add 192.0.2.7/24 dev lo
		ip route add default dev lo
		# A device beside it: `ncfg pair` draws a code and waits, and the device
		# told only the code joins, which is what ends the wait.
		mkdir -m 700 "$2/device" "$2/xdg"
		XDG_RUNTIME_DIR=$2/xdg timeout -k 2 40 "${1%netcfgd}fuzznet-build/fuzznetd" \
			--fuzznet-dir="$2/device" --no-log-file --udp-port=48123 \
			--fuzznet-service=1 --fuzznet-product=3 > "$2/device.log" 2>&1 &
		device=$!
		timeout 12 "${1%netcfgd}ncfg" pair --run-dir "$2/run" > "$2/pair" 2>&1 &
		pair=$!
		n=0
		until grep -q "^FZI1:" "$2/pair" 2>/dev/null || ! kill -0 $pair 2>/dev/null || [ $n -gt 16 ]; do
			sleep 0.5
			n=$((n + 1))
		done
		code=$(sed -n "s/^\(FZI1:.*\)$/\1/p" "$2/pair")
		if [ -n "$code" ]; then
			python3 -I -c "
import socket, sys
s = socket.socket(socket.AF_UNIX); s.settimeout(4); s.connect(sys.argv[1])
s.sendall((\"add join \" + sys.argv[2] + \"\n\").encode()); print(s.recv(4096).decode(errors=\"replace\").strip())
" "$2/xdg/fuzznet/fuzznetd.sock" "$code" > "$2/join" 2>&1
		fi
		wait $pair
		echo $? > "$2/pair.status"
		# And back out: the device reaches the host until it is revoked.
		host=$(ask "$2/xdg/fuzznet/fuzznetd.sock" "list peer" | cut -d" " -f4)
		n=0
		while ! ask "$2/xdg/fuzznet/fuzznetd.sock" "call status at $host" | grep -q "^ok" &&
			[ $n -lt 16 ]; do sleep 0.5; n=$((n + 1)); done
		ask "$2/xdg/fuzznet/fuzznetd.sock" "call status at $host" | cut -c1-2 > "$2/before"
		"${1%netcfgd}ncfg" pair list --run-dir "$2/run" > "$2/listed" 2>&1
		"${1%netcfgd}ncfg" pair revoke "$(tail -1 "$2/listed")" --run-dir "$2/run" > "$2/revoked" 2>&1
		echo $? > "$2/revoke.status"
		"${1%netcfgd}ncfg" pair list --run-dir "$2/run" > "$2/listed.after" 2>&1
		ask "$2/xdg/fuzznet/fuzznetd.sock" "call status at $host" | cut -c1-40 > "$2/after"
		kill -TERM $device 2>/dev/null
		wait $device 2>/dev/null
		kill -TERM $pid 2>/dev/null
		wait $pid 2>/dev/null
	' sh "$N" "$d"
}

# 48090 is BBDA in the hex /proc writes.
one closed ''
grep -q '^ok ' "$R/closed/prekey"
check $? "a stock netcfgd answers fuzznet's verbs ($(cut -c1-24 "$R/closed/prekey"))"
! grep -q ':BBDA ' "$R/closed/udp"
check $? "and with nothing opened it binds no port"

[ "$(cat "$R/closed/pair.status")" != 0 ] && grep -q 'ncfg pair open' "$R/closed/pair"
check $? "and \`ncfg pair\` says what to open rather than draw a code nothing answers"

one open '	remote {
		observe = true
	}
'
grep -q '^ok ' "$R/open/prekey"
check $? "with \`remote\` opened it still does"
grep -q ':BBDA ' "$R/open/udp"
check $? "and it serves its remote hop on netcfgd's port"

grep -q '^FZI1:' "$R/open/pair" && grep -q 'at 192.0.2.7,' "$R/open/pair"
check $? "and \`ncfg pair\` draws a code, saying where this machine is reached"
[ "$(cat "$R/open/pair.status")" = 0 ] && grep -q 'A device joined' "$R/open/pair"
check $? "and a device told only that code joins, which ends the wait ($(cat "$R/open/join"))"

[ "$(cat "$R/open/before")" = ok ]
check $? "and that device reaches the host's status"
[ "$(cat "$R/open/revoke.status")" = 0 ] && [ -s "$R/open/listed" ] && [ ! -s "$R/open/listed.after" ]
check $? "\`ncfg pair list\` names it, and \`ncfg pair revoke\` takes it off the list"
! grep -q '^ok' "$R/open/after"
check $? "and revoked, it reaches nothing ($(cat "$R/open/after"))"

# The one step: `ncfg pair open` against a running daemon, then its start opens.
mkdir -p "$R/opening/a" "$R/opening/run" "$R/opening/conf"
chmod 700 "$R/opening/a"
printf 'global {\n}\n' > "$R/opening/conf/netcfgd.conf"
unshare -Urn sh -c '
	d=$2
	timeout -k 2 20 "$1" --run-dir "$d/run" --config-dir "$d/conf" --no-apply-on-start \
		--fuzznet-dir "$d/a" --fuzznet-arg --no-log-file > "$d/log2" 2>&1 &
	pid=$!
	n=0
	until [ -S "$d/run/fuzznet.sock" ] || [ $n -gt 12 ]; do sleep 0.5; n=$((n + 1)); done
	"${1%netcfgd}ncfg" pair open --run-dir "$d/run" --config-dir "$d/conf" > "$d/opened" 2>&1
	echo $? > "$d/opened.status"
	kill -TERM $pid 2>/dev/null
	wait $pid 2>/dev/null
	timeout -k 2 8 "$1" --run-dir "$d/run" --config-dir "$d/conf" --no-apply-on-start \
		--fuzznet-dir "$d/a" --fuzznet-arg --no-log-file > "$d/log3" 2>&1 &
	pid=$!
	n=0
	until [ -S "$d/run/fuzznet.sock" ] || [ $n -gt 12 ]; do sleep 0.5; n=$((n + 1)); done
	sleep 1
	cat /proc/net/udp /proc/net/udp6 > "$d/udp.opened" 2>/dev/null
	kill -TERM $pid 2>/dev/null
	wait $pid 2>/dev/null
' sh "$N" "$R/opening"
[ "$(cat "$R/opening/opened.status")" = 0 ] && [ -f "$R/opening/conf/conf.d/remote.conf" ]
check $? "\`ncfg pair open\` leaves a file saying so ($(cut -c1-40 "$R/opening/opened"))"
grep -q ':BBDA ' "$R/opening/udp.opened"
check $? "and the daemon's next start serves netcfgd's port"

[ "$failed" -eq 0 ] && echo "node_remote: all checks passed"
exit "$failed"
