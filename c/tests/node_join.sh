#!/bin/sh
# node_join.sh -- `ncfg pair join`: a netcfgd with no screen joins an owner's
# estate with the owner's code, the code going in rather than out (0320). The
# owner is a plain fuzznetd that makes the invite, as a phone's or a desktop's
# node would; netcfgd's node is told the code and must end in the owner's estate
# with netcfgd still running. Run by `make test`, in a namespace of its own.
#
# HOW IT STOPS: both daemons run under `timeout -k 5 90` and are killed by pid;
# `ncfg pair join` bounds its own wait at two minutes and is under `timeout 60`
# here; the socket wait is a count of 0.5 s looks. The directory is mktemp's,
# checked by shape, and removed at the end.
here=$(cd "$(dirname "$0")/.." && pwd)
R=$(mktemp -d /tmp/ncf.XXXXXX) || exit 1
case "$R" in /tmp/ncf.?*) ;; *) echo "node_join: odd scratch $R"; exit 1;; esac
trap 'rm -rf "$R"' EXIT
if ! unshare -Urn true 2>/dev/null; then
	echo "node_join: no user namespaces here, so the join cannot be run"
	exit 1
fi
cat > "$R/case.sh" <<'CASE'
here=$1
R=$2
F=$here/fuzznet-build/fuzznetd
N=$here/netcfgd
C=$here/ncfg
failed=0
check() { # $1 0 for ok, $2 what
	if [ "$1" -eq 0 ]; then printf '%-72s ok\n' "$2"; else printf '%-72s FAILED\n' "$2"; failed=1; fi
}
ask() { # $1 socket, $2 line: one reply line
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
ip link set lo up
mkdir -p "$R/o" "$R/n" "$R/run" "$R/conf"
chmod 00700 "$R/o" "$R/n"
# `remote` opens the node's port, which a join asks from.
printf 'global {\n\tremote {\n\t\tobserve = true\n\t}\n}\n' > "$R/conf/netcfgd.conf"
timeout 20 "$F" --fuzznet-dir="$R/o" --new-root --fuzznet-service=1 --fuzznet-product=1 \
	> "$R/root.out" 2>&1
timeout -k 5 90 "$F" --fuzznet-dir="$R/o" --socket="$R/o.sock" --no-log-file --udp-port=34100 \
	--fuzznet-service=1 --fuzznet-product=1 > "$R/o.log" 2>&1 &
owner=$!
timeout -k 5 90 "$N" --run-dir "$R/run" --config-dir "$R/conf" --no-apply-on-start \
	--fuzznet-dir "$R/n" --fuzznet-arg --no-log-file --fuzznet-arg --fuzznet-service=1 \
	--fuzznet-arg --fuzznet-product=1 > "$R/n.log" 2>&1 &
daemon=$!
S=$R/run/fuzznet.sock
n=0
until { [ -S "$R/o.sock" ] && [ -S "$S" ]; } || [ $n -gt 60 ]; do sleep 0.5; n=$((n + 1)); done
[ -S "$R/o.sock" ] && [ -S "$S" ]
check $? "an owner's node and netcfgd's are up"
ask "$R/o.sock" "set setting host net/address 127.0.0.1 34100" > /dev/null
code=$(ask "$R/o.sock" "add invite delegable 600" | sed -n 's/^ok //p')
own=$(ask "$S" "list root")

timeout 20 "$C" pair join "not-a-code" --run-dir "$R/run" > "$R/bad" 2>&1
[ $? -ne 0 ] && grep -q 'not an invite' "$R/bad"
check $? "a word that is no code is refused by name ($(head -c 40 "$R/bad"))"

printf '%s\n' "$code" | timeout 60 "$C" pair join - --run-dir "$R/run" > "$R/joined" 2>&1
status=$?
[ $status -eq 0 ] && grep -q '^joined the estate' "$R/joined"
check $? "the code read from stdin joins the owner's estate ($(head -c 50 "$R/joined"))"
root=$(ask "$S" "list root")
[ -n "$root" ] && [ "$root" != "$own" ]
check $? "  the node's root is the owner's now, not its own"
[ -d "/proc/$daemon" ]
check $? "  and netcfgd ran through the node starting itself again"
! grep -qF "$code" "$R/joined" "$R/n.log"
check $? "  and the code is in no output and no log"

kill $owner $daemon 2>/dev/null
wait 2>/dev/null
exit $failed
CASE
unshare -Urn sh "$R/case.sh" "$here" "$R"
status=$?
[ $status -eq 0 ] && echo "node_join: all checks passed"
exit $status
