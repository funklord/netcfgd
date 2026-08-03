#!/bin/sh
# An edited WireGuard configuration, against a real kernel and a real `wg`.
#
#     unshare -rn sh tests/live/wireguard.sh
#
# netcfgd configures a WireGuard device over generic netlink when it creates
# the link, and for a long time that was the only time it configured one. So an
# operator could change the listen port, the firewall mark or -- the one that
# matters -- **the peer list**, run `ncfg apply`, be told "nothing to do", and
# have the kernel go on holding the old configuration. Deleting a peer from the
# config file did not delete its access.
#
# That is the shape decision 0052 closed for hostapd and radvd, arrived at from
# the other end: not a daemon that read a file once, but a kernel object
# configured once. This is the test that says it stays closed.
#
# `wg` is the reference tool and this needs it: reading netcfgd's own view back
# through `ncfg status` would prove only that netcfgd agrees with itself, which
# is what section 9 warns about. It does not need to be installed:
#
#     apt-get download wireguard-tools libmnl0
#     for d in *.deb; do dpkg-deb -x "$d" root; done
#     PATH=$PWD/root/usr/bin:$PATH \
#     LD_LIBRARY_PATH=$PWD/root/usr/lib/x86_64-linux-gnu \
#     unshare -rn sh tests/live/wireguard.sh
#
# The private key is generated here and never leaves the work directory, which
# is deleted on exit. A key in a repository is a key in a repository, however
# worthless.

set -eu

repo=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)

skip() {
	if [ -n "${NCFG_LIVE:-}" ]; then
		echo "wireguard.sh: NCFG_LIVE is set but this cannot run: $1" >&2
		exit 1
	fi
	echo "wireguard.sh: skipping: $1"
	exit 0
}

command -v ip >/dev/null 2>&1 || skip "no ip(8)"
command -v wg >/dev/null 2>&1 || skip "wireguard-tools is not installed (see the header)"
[ -x "$repo/target/debug/ncfg" ] || skip "ncfg is not built"
# A kernel without the module has no device to configure, and that is a skip
# rather than a failure -- the same call strand.sh makes.
ip link add wgprobe type wireguard 2>/dev/null || skip "this kernel has no wireguard support"
ip link del wgprobe 2>/dev/null || true

work=$(mktemp -d /tmp/ncfg-wireguard.XXXXXX)
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
contains() {
	if printf '%s' "$2" | grep -q -- "$3"; then
		echo "ok   $1"
	else
		echo "FAIL $1"
		echo "       wanted to find: $3"
		echo "       in: $2"
		failures=$((failures + 1))
	fi
}

head -c 32 /dev/urandom | base64 > "$work/etc/secrets/wg0"
chmod 600 "$work/etc/secrets/wg0"

hub=$(wg genkey | wg pubkey)
spare=$(wg genkey | wg pubkey)

# One writer of the config, so that what changes between states is only what
# the arguments say. A second copy of this heredoc is how a test comes to
# assert a difference it introduced itself.
write_config() {
	cat > "$work/etc/netcfgd.conf" <<CONF
interface wg0 {
	wireguard {
		private_key = "@secret:wg0"
		listen_port = $1
		$2
	}
	config = "10.0.0.5/32"
}
CONF
}

# With an endpoint, which is what a real peer has and is the field the
# comparison must *not* own: the kernel rewrites it as a peer roams, so a plan
# that compared it would replace the peer list on every reconcile forever. The
# first version of this script had no endpoint anywhere, so both sides were
# absent and agreed for the wrong reason -- and the defect shipped.
peer_block() {
	printf 'peer %s {\n\t\t\tpublic_key  = "%s"\n\t\t\tallowed_ips = "%s"\n\t\t\tendpoint    = "198.51.100.%s:51820"\n\t\t}' \
		"$1" "$2" "$3" "${4:-7}"
}

# ----------------------------------------------------------- bring one up

write_config 51820 "$(peer_block hub "$hub" 10.0.0.0/24)"
"$ncfg" apply > "$work/apply.txt" 2>&1 || { cat "$work/apply.txt" >&2; exit 1; }

check "the device exists" \
	"$(ip link show wg0 >/dev/null 2>&1 && echo yes || echo no)" "yes"
check "with the listen port the document asked for" \
	"$(wg show wg0 listen-port)" "51820"
check "and the peer it named" \
	"$(wg show wg0 peers)" "$hub"

# ------------------------------------------------ what the observation says

# netcfgd's own view of the same device, which is what the planner compares
# against. Read from `ncfg status` rather than believed: a planner comparing an
# observation nobody fills in plans nothing, forever, and looks correct doing
# it.
status=$("$ncfg" status --json 2>&1 || true)
wg_state=$(printf '%s' "$status" | python3 -c '
import json, sys
link = [l for l in json.load(sys.stdin)["links"] if l["name"] == "wg0"][0]
state = link.get("wireguard")
if state is None:
	print("absent")
else:
	peers = ",".join(p["public_key"] for p in state.get("peers", []))
	print(state.get("listen_port"), peers)
' 2>/dev/null || echo unreadable)
check "the observation carries the port and the peer, not just a boolean" \
	"$wg_state" "51820 $hub"

# ------------------------------------------------------- edit the listen port

write_config 51821 "$(peer_block hub "$hub" 10.0.0.0/24)"
plan=$("$ncfg" plan 2>&1 || true)
contains "an edited listen port is planned" "$plan" "wg.set_device"
contains "and the reason names the field that moved" "$plan" "wireguard.listen_port"
"$ncfg" apply > "$work/apply2.txt" 2>&1 || { cat "$work/apply2.txt" >&2; exit 1; }
check "and the kernel has it afterwards" "$(wg show wg0 listen-port)" "51821"
check "and the next plan has nothing to do" \
	"$("$ncfg" plan 2>&1 | head -1)" "nothing to do"

# ------------------------------------------------------- delete a peer
#
# The half this whole script exists for. An operator who removes a peer from
# the config has revoked its access in their own mind; before this was planned,
# the kernel kept it and `ncfg apply` said "nothing to do".

write_config 51821 "$(peer_block spare "$spare" 10.0.0.0/24)"
plan=$("$ncfg" plan 2>&1 || true)
contains "replacing the peer list is planned" "$plan" "wg.set_peers"
"$ncfg" apply > "$work/apply3.txt" 2>&1 || { cat "$work/apply3.txt" >&2; exit 1; }

check "the peer the document names is there" "$(wg show wg0 peers)" "$spare"
check "and the one it no longer names is gone" \
	"$(wg show wg0 peers | grep -c "$hub" || true)" "0"
check "and the next plan has nothing to do" \
	"$("$ncfg" plan 2>&1 | head -1)" "nothing to do"

# ------------------------------------------------------- rotate the key
#
# The other half of a revocation. An operator who replaces the private key has
# rekeyed the tunnel in their own mind; the kernel goes on using the key it was
# handed, and every peer goes on accepting it. netcfgd cannot derive a public
# key from a private one -- that is curve25519 -- so it compares a digest of
# what it loaded against a digest of what the store holds, which is decision
# 0053's answer to the same question about a file.

before_key=$(wg show wg0 public-key)
head -c 32 /dev/urandom | base64 > "$work/etc/secrets/wg0"
plan=$("$ncfg" plan 2>&1 || true)
contains "a rotated private key is planned" "$plan" "wireguard.private_key"
# And says which way it went without printing either key, which is the whole
# reason the comparison happens in the observer.
check "and names no key while doing it" \
	"$(printf '%s' "$plan" | grep -c "$(cat "$work/etc/secrets/wg0")" || true)" "0"

"$ncfg" apply > "$work/apply4.txt" 2>&1 || { cat "$work/apply4.txt" >&2; exit 1; }
after_key=$(wg show wg0 public-key)
check "the kernel derived a different public key afterwards" \
	"$([ "$before_key" != "$after_key" ] && echo changed || echo same)" "changed"
check "and the next plan has nothing to do" \
	"$("$ncfg" plan 2>&1 | head -1)" "nothing to do"

# The record is netcfgd's own, and it is a digest rather than a key. A test
# that only checked the behaviour would not notice the day somebody makes this
# file the key itself.
check "what netcfgd wrote down is a digest, not the secret" \
	"$(grep -c "$(cat "$work/etc/secrets/wg0")" "$work/run/wireguard/wg0.key.sha256" || true)" "0"
check "and it is 64 hex characters" \
	"$(tr -d '\n' < "$work/run/wireguard/wg0.key.sha256" | grep -c '^[0-9a-f]\{64\}$' || true)" "1"
check "readable by nobody else" \
	"$(stat -c '%a' "$work/run/wireguard/wg0.key.sha256")" "600"

# --------------------------------------------- rotate a peer's preshared key
#
# The same question one level down, and the one the peer-list comparison cannot
# answer on its own: both sides say "this peer has a preshared key", because the
# kernel returns one zeroed. So the record is per peer, keyed by the public key,
# which is the only name the kernel and the document share.

cat > "$work/etc/secrets/psk" <<PSK
$(wg genpsk)
PSK
chmod 600 "$work/etc/secrets/psk"
write_config 51821 "$(printf 'peer %s {\n\t\t\tpublic_key    = "%s"\n\t\t\tallowed_ips   = "10.0.0.0/24"\n\t\t\tendpoint      = "198.51.100.7:51820"\n\t\t\tpreshared_key = "@secret:psk"\n\t\t}' spare "$spare")"
"$ncfg" apply > "$work/apply5.txt" 2>&1 || { cat "$work/apply5.txt" >&2; exit 1; }
# `wg show ... preshared-keys` prints the value, not a placeholder, which makes
# this the strongest assertion available anywhere in this script: the kernel is
# holding exactly what the store holds, compared octet for octet by a tool that
# is not netcfgd.
check "the kernel holds the preshared key the store has" \
	"$(wg show wg0 preshared-keys | awk '{print $2}')" "$(cat "$work/etc/secrets/psk")"
check "and the next plan has nothing to do" \
	"$("$ncfg" plan 2>&1 | head -1)" "nothing to do"

wg genpsk > "$work/etc/secrets/psk"
plan=$("$ncfg" plan 2>&1 || true)
contains "a rotated preshared key is planned" "$plan" "wireguard.peers.preshared_key"
contains "and the reason names which peer" "$plan" "$spare"
check "and names no key while doing it" \
	"$(printf '%s' "$plan" | grep -c "$(cat "$work/etc/secrets/psk")" || true)" "0"
"$ncfg" apply > "$work/apply6.txt" 2>&1 || { cat "$work/apply6.txt" >&2; exit 1; }
check "the kernel holds the new one afterwards" \
	"$(wg show wg0 preshared-keys | awk '{print $2}')" "$(cat "$work/etc/secrets/psk")"
check "and the next plan has nothing to do" \
	"$("$ncfg" plan 2>&1 | head -1)" "nothing to do"
check "the record is digests, keyed by public key" \
	"$(awk '{print $1}' "$work/run/wireguard/wg0.psk.sha256")" "$spare"
check "and holds no key" \
	"$(grep -c "$(cat "$work/etc/secrets/psk")" "$work/run/wireguard/wg0.psk.sha256" || true)" "0"

# ------------------------------------------------- an unchanged device is quiet
#
# The check that would have caught a comparison that always differs -- which is
# the failure mode of comparing a value the kernel normalises. A device that
# matches its document plans nothing, twice over.

check "an unchanged device plans nothing on a second look" \
	"$("$ncfg" plan 2>&1 | head -1)" "nothing to do"

echo
if [ "$failures" -eq 0 ]; then
	echo "wireguard.sh: all checks passed"
else
	echo "wireguard.sh: $failures failed"
	exit 1
fi
