#!/bin/sh
# The wireless path end to end: config file, daemon, control socket, real
# wpa_supplicant. Run by `make live` inside `unshare -rn`.
#
# What this covers that the Rust tests do not is the joins between the pieces
# -- the compiler producing a network the daemon can find, the daemon's
# response type surviving serde, the CLI rendering what comes back. Each of
# those was correct in isolation and one of them was not correct in the
# assembly, which is the whole argument for this file existing.
#
# The `wired` driver on loopback stands in for a radio. Association is the one
# thing it cannot cover; that needs mac80211_hwsim.
#
# POSIX sh, not bash: this runs wherever the project does.

set -eu

repo=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
supplicant=
for candidate in /usr/sbin /sbin /usr/local/sbin /usr/bin; do
	if [ -x "$candidate/wpa_supplicant" ]; then
		supplicant="$candidate/wpa_supplicant"
		break
	fi
done

skip() {
	if [ -n "${NCFG_LIVE:-}" ]; then
		echo "wifi.sh: NCFG_LIVE is set but this cannot run: $1" >&2
		exit 1
	fi
	echo "wifi.sh: skipping: $1"
	exit 0
}

[ -n "$supplicant" ] || skip "wpa_supplicant is not installed"
[ -x "$repo/target/debug/netcfgd" ] || skip "netcfgd is not built"

# Short, because a unix socket path has to fit in SUN_LEN (108 bytes) and a
# path under the usual scratch directories does not.
work=$(mktemp -d /tmp/ncfg-live.XXXXXX)
cleanup() {
	[ -n "${daemon:-}" ] && kill "$daemon" 2>/dev/null
	[ -n "${radio:-}" ] && kill "$radio" 2>/dev/null
	rm -rf "$work"
}
trap cleanup EXIT INT TERM

mkdir -p "$work/etc/secrets" "$work/run" "$work/ctrl"
cat > "$work/etc/netcfgd.conf" <<'CONF'
device lo {
	wifi {
		backend     = "wpa_supplicant"
		autoconnect = true
		regdom      = "SE"
	}
}

network "HomeFiber" {
	wifi   { psk = "@secret:HomeFiber"; proto = "wpa3"; priority = 30 }
	config = "dhcp"
}

network "Cafe" {
	wifi   { open = true }
	config = "dhcp"
}
CONF
printf 'hunter2hunter2' > "$work/etc/secrets/HomeFiber"
chmod 600 "$work/etc/secrets/HomeFiber"

export NCFG_CONFIG_DIR="$work/etc"
export NCFG_RUN_DIR="$work/run"
export NCFG_WPA_CTRL_DIR="$work/ctrl"
ncfg="$repo/target/debug/ncfg"
cli="$supplicant"
cli="${supplicant%wpa_supplicant}wpa_cli"

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
	case "$2" in
	*"$3"*) echo "ok   $1" ;;
	*)
		echo "FAIL $1"
		echo "       expected to contain: $3"
		echo "       actual:              $2"
		failures=$((failures + 1))
		;;
	esac
}

"$supplicant" -Dwired -i lo -C "$work/ctrl" >/dev/null 2>&1 &
radio=$!
waited=0
while [ ! -e "$work/ctrl/lo" ]; do
	waited=$((waited + 1))
	[ "$waited" -gt 50 ] && skip "no control socket appeared (CAP_NET_ADMIN?)"
	sleep 0.1
done

"$repo/target/debug/netcfgd" --no-apply-on-start > "$work/daemon.log" 2>&1 &
daemon=$!
waited=0
while [ ! -e "$work/run/netcfgd.sock" ]; do
	waited=$((waited + 1))
	if [ "$waited" -gt 50 ]; then
		cat "$work/daemon.log" >&2
		echo "wifi.sh: the daemon never bound its socket" >&2
		exit 1
	fi
	sleep 0.1
done

contains "status reaches the supplicant" "$("$ncfg" wifi status)" "lo "
contains "an empty scan says so" "$("$ncfg" wifi scan)" "no access points"

# The response types have to survive serde. An internally tagged enum cannot
# carry a bare sequence, and the failure is a daemon that answers nothing --
# so the JSON form is checked rather than assumed.
contains "a scan serialises" "$("$ncfg" wifi scan --json)" '"access_points"'

"$ncfg" wifi connect HomeFiber >/dev/null
check "the SSID arrived intact" \
	"$("$cli" -p "$work/ctrl" -i lo get_network 0 ssid)" '"HomeFiber"'
check "WPA3 means SAE" \
	"$("$cli" -p "$work/ctrl" -i lo get_network 0 key_mgmt)" "SAE"
check "WPA3 means protected management frames" \
	"$("$cli" -p "$work/ctrl" -i lo get_network 0 ieee80211w)" "2"
check "the priority carried through" \
	"$("$cli" -p "$work/ctrl" -i lo get_network 0 priority)" "30"
check "the passphrase resolved from the secrets directory" \
	"$("$cli" -p "$work/ctrl" -i lo get_network 0 psk)" "*"

# The permission boundary, from the outside: the wifi tier joins what the
# config describes and cannot be talked into anything else.
unknown=$("$ncfg" wifi connect Neighbour 2>&1 || true)
contains "an unconfigured network is refused" "$unknown" "no \`network\` block"
contains "and the refusal explains the boundary" "$unknown" "admin tier"
contains "and lists what is available" "$unknown" "Cafe, HomeFiber"

contains "disconnect works" "$("$ncfg" wifi disconnect)" "disconnected"

# Decision 0014: iwd is refused by name rather than served by wpa_supplicant.
sed 's/backend     = "wpa_supplicant"/backend     = "iwd"/' "$work/etc/netcfgd.conf" \
	> "$work/etc/netcfgd.conf.new"
mv "$work/etc/netcfgd.conf.new" "$work/etc/netcfgd.conf"
# The daemon watches the directory; give it a moment to notice.
sleep 1
contains "iwd is refused by name" "$("$ncfg" wifi scan 2>&1 || true)" "iwd backend"

# A daemon that could not serialise an answer says so rather than dropping the
# connection in silence. Nothing above should have triggered it.
if grep -q "could not serialise" "$work/daemon.log"; then
	echo "FAIL the daemon failed to serialise a response"
	cat "$work/daemon.log"
	failures=$((failures + 1))
fi

echo
if [ "$failures" -eq 0 ]; then
	echo "wifi.sh: all checks passed"
else
	echo "wifi.sh: $failures failed"
	exit 1
fi
