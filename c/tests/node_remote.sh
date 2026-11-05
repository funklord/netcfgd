#!/bin/sh
# node_remote.sh -- a stock netcfgd has fuzznet's verbs, and listens on the
# network only where the config opens `global { remote }` (project.md 10.721).
# Run by `make test`. Each daemon runs in a network namespace of its own, so the
# fixed port cannot meet another run's; where namespaces are not allowed the
# script says so and fails, since a port not looked at is no pass.
#
# HOW IT STOPS: each daemon is under `timeout -k 2 15` and killed by pid at the
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
		timeout -k 2 15 "$1" --run-dir "$2/run" --config-dir "$2/conf" \
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
		ip link set lo up
		ip addr add 192.0.2.7/24 dev lo
		ip route add default dev lo
		key=$(python3 -I -c "
import socket, sys
s = socket.socket(socket.AF_UNIX); s.settimeout(4); s.connect(sys.argv[1])
s.sendall(b\"get prekey\n\"); print(s.recv(4096).decode(errors=\"replace\").split()[1])
" "$2/run/fuzznet.sock" 2>/dev/null)
		"${1%netcfgd}ncfg" pair "$key" --run-dir "$2/run" > "$2/pair" 2>&1
		echo $? > "$2/pair.status"
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

[ "$(cat "$R/closed/pair.status")" != 0 ] && grep -q 'open `remote`' "$R/closed/pair"
check $? "and \`ncfg pair\` says what to open rather than draw a code nothing answers"

one open '	remote {
		observe = true
	}
'
grep -q '^ok ' "$R/open/prekey"
check $? "with \`remote\` opened it still does"
grep -q ':BBDA ' "$R/open/udp"
check $? "and it serves its remote hop on netcfgd's port"

# The key is the node's own here: what is tested is the drawing and the card.
[ "$(cat "$R/open/pair.status")" = 0 ] && grep -q '^FZN4:' "$R/open/pair" &&
	grep -q 'at 192.0.2.7, port 48090' "$R/open/pair"
check $? "and \`ncfg pair\` gives a card, saying where this machine is reached"

[ "$failed" -eq 0 ] && echo "node_remote: all checks passed"
exit "$failed"
