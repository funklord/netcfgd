#!/bin/sh
# Walking away from a key that cannot be revoked, against a real kernel.
#
#     unshare -rn sh tests/live/strand.sh
#
# Decision 0042, closing what 0037 left open. `managed = false` means netcfgd
# stops operating on a device -- and if that device is a WireGuard interface,
# stopping leaves a private key loaded in the kernel that netcfgd put there.
# Whoever ends up with the hardware can read it back and be this host on that
# network, and revoking it is an act by every peer rather than anything the
# operator can do here.
#
# This needs a real kernel and nothing less. The whole rule turns on whether a
# private key is *actually loaded*, which netcfgd decides by asking whether the
# kernel reports a derived public key -- never by asking for the private one,
# which `netcfgd_sys::wg::DeviceState` has no field to return. A fixture would
# be asserting that belief against itself. So a real key is generated, loaded
# into a real WireGuard device through netcfgd, and the observation is read
# back out of `ncfg status`.

set -eu

repo=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)

skip() {
	if [ -n "${NCFG_LIVE:-}" ]; then
		echo "strand.sh: NCFG_LIVE is set but this cannot run: $1" >&2
		exit 1
	fi
	echo "strand.sh: skipping: $1"
	exit 0
}

command -v ip >/dev/null 2>&1 || skip "no ip(8)"
[ -x "$repo/target/debug/ncfg" ] || skip "ncfg is not built"
# A kernel without the module has no WireGuard device to strand a key on, and
# that is a skip rather than a failure: nothing else in netcfgd needs it.
ip link add wgprobe type wireguard 2>/dev/null || skip "this kernel has no wireguard support"
ip link del wgprobe 2>/dev/null || true

work=$(mktemp -d /tmp/ncfg-strand.XXXXXX)
cleanup() { rm -rf "$work"; }
trap cleanup EXIT INT TERM
mkdir -p "$work/etc/secrets" "$work/run"

export NCFG_CONFIG_DIR="$work/etc"
export NCFG_RUN_DIR="$work/run"
ncfg="$repo/target/debug/ncfg"

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

# A real 32-byte key, base64. Generated here rather than hardcoded: a private
# key in a repository is a private key in a repository, even a worthless one,
# and project.md section 9 says nothing containing real secret material is
# committed -- including test data that only looks like it.
head -c 32 /dev/urandom | base64 > "$work/etc/secrets/wg0"
chmod 600 "$work/etc/secrets/wg0"

write_config() {
	cat > "$work/etc/netcfgd.conf" <<CONF
$1

interface wg0 {
	wireguard {
		private_key = "@secret:wg0"
		listen_port = 51820
		peer hub {
			public_key  = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
			allowed_ips = "10.0.0.0/24"
		}
	}
	config = "10.0.0.5/32"
}
CONF
}

# ------------------------------------------------------ bring the tunnel up

write_config ""
"$ncfg" apply > "$work/apply.txt" 2>&1 || true
check "the wireguard device exists" \
	"$(ip link show wg0 >/dev/null 2>&1 && echo yes || echo no)" "yes"

# The fact the whole rule turns on, asked the way netcfgd asks it. A device
# with no private key reports no public key; one with a key reports the key
# derived from it. Checked here against a kernel rather than believed.
"$ncfg" status --json > "$work/status.json" 2>&1 || true
check "and the kernel reports a key loaded on it" \
	"$(python3 -c '
import json,sys
links = json.load(open(sys.argv[1]))["links"]
print([l.get("private_key_loaded") for l in links if l["name"] == "wg0"][0])
' "$work/status.json" 2>/dev/null || echo unreadable)" "True"

# --------------------------------------------- walking away is not done quietly

write_config 'device wg0 { managed = false }'
"$ncfg" plan > "$work/plan.txt" 2>&1 || true
check "unmanaging it is reported as stranding a credential" \
	"$(grep -c 'stranded: unmanaging wg0' "$work/plan.txt" || true)" "1"
check "and says why it cannot simply be withdrawn later" \
	"$(grep -c 'every peer' "$work/plan.txt" || true)" "1"
# Both ways out, and the durable one first. A notice an operator cannot act on
# is a complaint. Matched on the label rather than on the config text, which
# also appears in the `managed = false` warning above it.
check "and offers the config change that removes it" \
	"$(grep -c 'to remove it:.*on_unmanage = "clear"' "$work/plan.txt" || true)" "1"
check "and the flag that consents to leaving it" \
	"$(grep -c 'to leave it:.*strand-credentials wg0' "$work/plan.txt" || true)" "1"

# The exit code rides on `apply`, not on `plan`, which is where the guard
# refusals put theirs: planning succeeded at what it does, which is to say what
# would happen. Nothing is withheld either -- `managed = false` already means no
# actions for the device, so what is outstanding is a decision rather than work.
status=0
"$ncfg" apply > "$work/apply2.txt" 2>&1 || status=$?
# 4 and not the guard's 3: the remedies differ, and a script that saw 3 and
# re-ran with --allow-disruption would be answering a question nobody asked.
check "applying it exits with the code that means an undecided credential" \
	"$status" "4"
check "the key is still loaded, because nothing was asked to remove it" \
	"$(ip link show wg0 >/dev/null 2>&1 && echo yes || echo no)" "yes"

# ------------------------------------------------------------ saying which

status=0
"$ncfg" apply --strand-credentials wg0 > "$work/consented.txt" 2>&1 || status=$?
check "consenting settles it" \
	"$(grep -c 'stranded:' "$work/consented.txt" || true)" "0"
check "and the apply is clean" "$status" "0"
# Per device, which is why the flag names one rather than being a --force.
"$ncfg" plan --strand-credentials somethingelse > "$work/wrong.txt" 2>&1 || true
check "consenting to a different device does not settle this one" \
	"$(grep -c 'stranded: unmanaging wg0' "$work/wrong.txt" || true)" "1"

# ------------------------------------------ and the answer that removes the key

# `on_unmanage = "clear"` deletes the link netcfgd created, and the key goes
# with it. That is the whole point of pointing at it.
write_config 'device wg0 { managed = false; on_unmanage = "clear" }'
"$ncfg" plan > "$work/clear.txt" 2>&1 || true
check "clearing is not reported as the problem" \
	"$(grep -c 'stranded:' "$work/clear.txt" || true)" "0"

status=0
"$ncfg" apply > "$work/apply3.txt" 2>&1 || status=$?
check "and applying it exits clean" "$status" "0"
check "and applying it takes the device, and the key, away" \
	"$(ip link show wg0 >/dev/null 2>&1 && echo yes || echo no)" "no"

echo
if [ "$failures" -eq 0 ]; then
	echo "strand.sh: all checks passed"
else
	echo "strand.sh: $failures check(s) failed"
	exit 1
fi
