#!/bin/sh
# The C port creating a WireGuard device, against a real kernel.
#
#     unshare -rn sh tests/live/c_wireguard.sh
#
# `wireguard.sh` beside this asks whether an *edited* configuration reaches a
# device that already exists. This asks the question before that one: whether
# the device the port creates carries anything at all.
#
# It did not. Nothing in an `RTM_NEWLINK` configures a WireGuard tunnel -- the
# private key, the listen port, the firewall mark and the peers all go over
# generic netlink afterwards -- and the port's create arm stopped at the link.
# So `ncfg apply` reported three green actions, `ip link` showed `wg0` up and
# addressed, and the device held no key, had no peers and could carry nothing.
# The planner emits no `wg.set_device` on a create, by design and in both
# implementations, so the two WireGuard arms that do the work were never
# reached and the key record the observer reads was never written.
#
# **This is the only place that can say so.** Everything after the netlink send
# needs `CAP_NET_ADMIN` and a kernel, so no unit check reaches it; a plan is
# identical either way, because the defect is in what the executor does with
# one. A namespace is what makes it askable at all.
#
# `wg` is not needed and is used if it is there: the independent reader here is
# **the Rust `ncfg`**, observing the same kernel through its own generic
# netlink code and its own record reader. Two implementations agreeing about a
# device one of them configured is the check section 9 asks for -- netcfgd
# agreeing with itself would be reading the port's observation of the port's
# own work.
#
# The private key is generated here, never leaves the work directory, and the
# directory is deleted on exit.

set -eu

repo=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)

skip() {
	if [ -n "${NCFG_LIVE:-}" ]; then
		echo "c_wireguard.sh: NCFG_LIVE is set but this cannot run: $1" >&2
		exit 1
	fi
	echo "c_wireguard.sh: skipping: $1"
	exit 0
}

command -v ip >/dev/null 2>&1 || skip "no ip(8)"
[ -x "$repo/c/ncfg" ] || skip "the C ncfg is not built (make -C c)"
[ -x "$repo/target/debug/ncfg" ] || skip "the Rust ncfg is not built, and it is the reader"
# A kernel without the module has no device to configure, and that is a skip
# rather than a failure -- the call `wireguard.sh` and `strand.sh` both make.
ip link add wgprobe type wireguard 2>/dev/null || skip "this kernel has no wireguard support"
ip link del wgprobe 2>/dev/null || true

work=$(mktemp -d "${TMPDIR:-/tmp}/ncfg-c-wireguard.XXXXXX")
cleanup() { rm -rf "$work"; }
trap cleanup EXIT INT TERM
mkdir -p "$work/etc/secrets" "$work/run"

export NCFG_CONFIG_DIR="$work/etc"
export NCFG_RUN_DIR="$work/run"
c_ncfg="$repo/c/ncfg"
rust_ncfg="$repo/target/debug/ncfg"

failures=0
check() {
	if [ "$2" = "$3" ]; then
		echo "ok   $1"
	else
		echo "FAIL $1"
		echo "       expected: $3"
		echo "       actual:   $2"
		failures=$((failures + 1))
	fi
}

# Thirty-two octets of kernel randomness, which is what a WireGuard private key
# is. `wg genkey` clamps; the kernel clamps what it is given, so an unclamped
# key is accepted and derives a public key exactly the same way -- and not
# needing `wg` is what lets this run where that package is absent. Generated
# rather than written down, so a key in a repository stays a thing that has not
# happened.
#
# **Both end octets are forced low, and that is the fixture doing its job.**
# The digest rule has a text door that trims bytes of `0x20` or less off each
# end, and the executor used to hand it raw octets -- so a key whose first or
# last octet was low had thirty-one of them recorded and `key_matches` could
# never come back true. That is 33 of 256 values at each end, about one key in
# four, which means a random key catches the defect a quarter of the time: this
# script was written that way first and let the sabotage through four runs out
# of five. Thirty octets of entropy is a key; the two ends are the question.
python3 -c 'import os, base64, sys
key = bytearray(os.urandom(32))
key[0] = 0x0a
key[31] = 0x1f
sys.stdout.write(base64.b64encode(bytes(key)).decode() + "\n")' > "$work/etc/secrets/wg0"
chmod 600 "$work/etc/secrets/wg0"

cat > "$work/etc/netcfgd.conf" <<CONF
device wg0 {
	wireguard {
		private_key = "@secret:wg0"
		listen_port = 51820
		fwmark      = 42
	}
}
interface wg0 {
	config = "10.0.0.5/32"
}
CONF

# ------------------------------------------------------- creating the device

"$c_ncfg" apply > "$work/apply.txt" 2>&1 || { cat "$work/apply.txt" >&2; exit 1; }

check "the device exists" \
	"$(ip link show wg0 >/dev/null 2>&1 && echo yes || echo no)" "yes"

# The record is the artifact this round is about: written from the octets that
# were sent, after the kernel took them. Absent means the key never went.
record="$work/run/wireguard/wg0.key.sha256"
check "and netcfgd recorded which key it handed over" \
	"$([ -f "$record" ] && echo yes || echo no)" "yes"
check "  as a digest and nothing else" \
	"$(tr -d '\n' < "$record" | grep -c '^[0-9a-f]\{64\}$' || true)" "1"
check "  which is not the key" \
	"$(grep -c "$(cat "$work/etc/secrets/wg0")" "$record" || true)" "0"
check "  in a file nobody else can read" \
	"$(stat -c '%a' "$record")" "600"

# ------------------------------------- what the other implementation sees

# The Rust reading the same kernel and the same record. `key_matches` is the
# answer that needs both halves to have happened: the device holds the key the
# store names, and the record says which key that was.
seen() {
	"$rust_ncfg" status --json 2>/dev/null | python3 -c 'import json,sys
document = json.load(sys.stdin)
for link in document.get("links", []):
	if link.get("name") == "wg0":
		print(json.dumps(link.get("wireguard", {}).get(sys.argv[1])))
		break
else:
	print("null")' "$1"
}

check "the Rust sees the listen port the C sent" "$(seen listen_port)" "51820"
check "and the firewall mark" "$(seen fwmark)" "42"
check "and says the key in the kernel is the one the store holds" \
	"$(seen key_matches)" "true"
# A public key at all means the private key reached the kernel: the kernel
# derives it, and a device that was never given one reports zeros.
check "which it could not do for a device carrying no key" \
	"$(seen public_key | tr -d '"' | grep -c '^AAAAAAAA' || true)" "0"

# The port's own observation of the same thing, which must not disagree with
# the reader above -- two programs pointed at one kernel.
c_seen=$("$c_ncfg" status --json 2>/dev/null | python3 -c 'import json,sys
document = json.load(sys.stdin)
for link in document.get("links", []):
	if link.get("name") == "wg0":
		print(json.dumps(link.get("wireguard", {}).get("key_matches")))
		break
else:
	print("null")')
check "and the C answers the same question the same way" "$c_seen" "true"

# ----------------------------------------------- and taking the device away

: > "$work/etc/netcfgd.conf"
"$c_ncfg" apply > "$work/delete.txt" 2>&1 || { cat "$work/delete.txt" >&2; exit 1; }

check "the device goes" \
	"$(ip link show wg0 >/dev/null 2>&1 && echo yes || echo no)" "no"
# Their absence is load-bearing: the observer reads "no record" as "netcfgd did
# not configure this device". A record that outlives its link makes the next
# `wg0`, whoever created it, read as one netcfgd knows the key of.
check "and its record goes with it" \
	"$([ -f "$record" ] && echo yes || echo no)" "no"
check "  leaving nothing behind under the run directory" \
	"$(ls "$work/run/wireguard" 2>/dev/null | wc -l)" "0"

if [ "$failures" -eq 0 ]; then
	echo "c_wireguard.sh: all checks passed"
else
	echo "c_wireguard.sh: $failures check(s) failed"
	exit 1
fi
