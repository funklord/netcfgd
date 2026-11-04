#!/bin/sh
# A device keyed by a value the estate holds, sealed to this host (10.709).
#
#     unshare -rn sh tests/live/c_estate_secret.sh
#
# `@secret:estate:KEY` is the one provider whose material comes through
# fuzznet, so `secrets_test`'s stand-in reader cannot say whether the real one
# answers: that the node installs it, that a sealed box opens on the loop's
# thread, and that an apply carries the value to the kernel. A WireGuard
# private key is the consumer because `wg` then reads the outcome back from the
# kernel: the public key it derives is the proof, and the private key is never
# printed. A namespace is what makes that askable.
#
# Checked: an apply before anything is set refuses and says so; sealing to a
# group nobody is in says so; the same apply after `ncfg nodes member` and
# `ncfg secret seal` carries it. Both are spoken to the socket `ncfg` finds for
# this user, under a scratch XDG_RUNTIME_DIR, as an operator's would be.
#
# HOW IT STOPS: the daemon runs under `timeout -k 5 60` and is killed by pid on
# every path; each client call is under `timeout`; the socket wait is a count
# of 0.5 s looks. The directory is mktemp's, checked by shape, and removed at
# the end. The key is generated here and dies with the directory.

set -u

repo=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
N=$repo/c/netcfgd
C=$repo/c/ncfg
F=$repo/c/fuzznet-build/fuzznetd

skip() {
	if [ -n "${NCFG_LIVE:-}" ]; then
		echo "c_estate_secret.sh: NCFG_LIVE is set but this cannot run: $1" >&2
		exit 1
	fi
	echo "c_estate_secret.sh: skipping: $1"
	exit 0
}

command -v ip >/dev/null 2>&1 || skip "no ip(8)"
command -v wg >/dev/null 2>&1 || skip "no wg(8), and it is the reader"
[ -x "$N" ] && [ -x "$C" ] && [ -x "$F" ] || skip "the C programs are not built (make -C c)"
ip link add wgprobe type wireguard 2>/dev/null || skip "this kernel has no wireguard support"
ip link del wgprobe 2>/dev/null

R=$(mktemp -d "${TMPDIR:-/tmp}/ncfg-estate.XXXXXX") || exit 1
case "$R" in */ncfg-estate.?*) ;; *) echo "c_estate_secret: odd scratch $R"; exit 1;; esac
daemon=
stop() {
	[ -n "$daemon" ] && kill -TERM "$daemon" 2>/dev/null && wait "$daemon" 2>/dev/null
	rm -rf "$R"
}
trap stop EXIT
trap 'exit 1' INT TERM

failed=0
check() { # $1 0 for ok, $2 what
	if [ "$1" -eq 0 ]; then echo "ok   $2"; else echo "FAIL $2"; failed=1; fi
}
ask() { # $1 line: one reply line from A's fuzznet socket
	timeout 10 python3 -I -c '
import socket, sys
s = socket.socket(socket.AF_UNIX); s.settimeout(5); s.connect(sys.argv[1])
s.sendall((sys.argv[2] + "\n").encode()); out = b""
while not out.endswith(b"\n"):
    b = s.recv(4096)
    if not b: break
    out += b
print(out.decode(errors="replace").strip())' "$S" "$1" 2>&1
}

mkdir "$R/a" "$R/run" "$R/conf" "$R/xdg" "$R/xdg/fuzznet"
chmod 700 "$R/xdg" "$R/xdg/fuzznet"
export XDG_RUNTIME_DIR="$R/xdg"
S=$R/xdg/fuzznet/fuzznetd.sock
cat > "$R/conf/netcfgd.conf" <<CONF
device wg0 {
	wireguard {
		private_key = "@secret:estate:wg/key"
		listen_port = 51820
	}
}
CONF

timeout 20 "$F" --fuzznet-dir="$R/a" --new-root --fuzznet-service=1 --fuzznet-product=1 \
	> "$R/root.out" 2>&1
check $? "the store is made the root of an estate"

export NCFG_RUN_DIR="$R/run" NCFG_CONFIG_DIR="$R/conf"
timeout -k 5 60 "$N" --run-dir "$R/run" --config-dir "$R/conf" --no-apply-on-start \
	--fuzznet-dir "$R/a" --fuzznet-arg "--socket=$S" --fuzznet-arg --no-log-file \
	--fuzznet-arg --udp-port=$((33900 + $$ % 90)) --fuzznet-arg --fuzznet-service=1 \
	--fuzznet-arg --fuzznet-product=1 > "$R/a.log" 2>&1 &
daemon=$!
n=0
until [ -S "$S" ] || [ $n -gt 40 ]; do sleep 0.5; n=$((n + 1)); done
[ -S "$S" ]
check $? "netcfgd serves the node"

timeout 20 "$C" apply > "$R/apply1.out" 2>&1
code=$?
[ $code -ne 0 ] && grep -q 'has no value here' "$R/apply1.out"
check $? "an apply with nothing set refuses, and says the value is the estate's ($(head -c 70 "$R/apply1.out"))"

key=$(wg genkey)
said=$(printf '%s\n' "$key" | timeout 20 "$C" secret seal zone1 wg/key 2>&1)
code=$?
[ $code -ne 0 ] && echo "$said" | grep -q 'no members'
check $? "sealing to a group nobody is in says so ($(echo "$said" | head -c 50))"
host=$(ask 'get prekey' | sed -n 's/^ok \(.*\)$/\1/p' | cut -c5-68)
timeout 20 "$C" nodes member "$host" zone1 > "$R/member.out" 2>&1
check $? "ncfg nodes member says this host is in zone1 ($(head -c 40 "$R/member.out"))"
timeout 20 "$C" nodes member "$host" 'Zone One' > /dev/null 2>&1
check "$([ $? -ne 0 ]; echo $?)" "  and refuses a group fuzznet's grammar would"
printf '%s\n' "$key" | timeout 20 "$C" secret seal zone1 wg/key > "$R/seal.out" 2>&1
check $? "ncfg secret seal seals the key to zone1 ($(head -c 44 "$R/seal.out"))"
grep -q 'to 1 member' "$R/seal.out"
check $? "  to one member"
stored=$(ask "get setting host wg/key")
case "$stored" in *"$key"*) check 1 "the store holds a box, not the key";;
*box:*) check 0 "the store holds a box, not the key";;
*) check 1 "the store holds a box, not the key ($stored)";; esac

timeout 20 "$C" apply > "$R/apply2.out" 2>&1
check $? "the same apply now carries ($(tail -1 "$R/apply2.out" | head -c 60))"
want=$(printf '%s\n' "$key" | wg pubkey)
got=$(wg show wg0 public-key 2>&1)
[ -n "$want" ] && [ "$want" = "$got" ]
check $? "the kernel derives the public key of the sealed private key"
! grep -qF "$key" "$R/a.log" "$R/apply1.out" "$R/apply2.out" "$R/seal.out"
check $? "the key is in no log and no output"

if [ $failed -ne 0 ]; then
	for f in a.log apply1.out apply2.out; do sed "s/^/  $f: /" "$R/$f" | tail -15; done
	echo "c_estate_secret.sh: some checks FAILED"
	exit 1
fi
echo "c_estate_secret.sh: all checks passed"
