#!/bin/sh
# Wired 802.1X end to end: config file, plan, apply, real wpa_supplicant.
#
# Different from wifi.sh in the part that matters. There, a supplicant was
# already running and netcfgd talked to it. Here netcfgd *starts* it -- which
# is decision 0015's other half, and the half where a mistake produces a
# supplicant that runs, accepts everything, and never authenticates.
#
# Loopback stands in for a switch port. No switch answers, so the port never
# reaches AUTHENTICATED; what is checked is that the profile netcfgd built is
# the one an 802.1X port needs.

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
		echo "dot1x.sh: NCFG_LIVE is set but this cannot run: $1" >&2
		exit 1
	fi
	echo "dot1x.sh: skipping: $1"
	exit 0
}

[ -n "$supplicant" ] || skip "wpa_supplicant is not installed"
[ -x "$repo/target/debug/ncfg" ] || skip "ncfg is not built"
cli="${supplicant%wpa_supplicant}wpa_cli"

work=$(mktemp -d /tmp/ncfg-8021x.XXXXXX)
cleanup() {
	[ -e "$work/ctrl/lo" ] && "$cli" -p "$work/ctrl" -i lo terminate >/dev/null 2>&1
	rm -rf "$work"
}
trap cleanup EXIT INT TERM

mkdir -p "$work/etc/secrets" "$work/run" "$work/ctrl"
cat > "$work/etc/netcfgd.conf" <<'CONF'
interface lo {
	dot1x {
		eap      = "peap"
		identity = "dave@corp.example"
		password = "@secret:corp"
		ca_cert  = "/etc/ssl/certs/ca-certificates.crt"
		phase2   = "auth=MSCHAPV2"
	}
	config = "null"
}
CONF
printf 'corporate-secret' > "$work/etc/secrets/corp"
chmod 600 "$work/etc/secrets/corp"

export NCFG_CONFIG_DIR="$work/etc"
export NCFG_RUN_DIR="$work/run"
export NCFG_WPA_CTRL_DIR="$work/ctrl"
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

plan=$("$ncfg" plan)
contains "the plan starts a supplicant" "$plan" "backend.start lo"
contains "and says which field asked for it" "$plan" "dot1x"

# A port that has not authenticated drops everything, so a DHCP client started
# first spends its backoff talking to a switch that is not listening -- and
# reports a failure whose cause is two steps earlier.
order=$(printf '%s\n' "$plan" | grep -n -E 'link\.up|backend\.start' | cut -d: -f1)
first=$(printf '%s\n' "$order" | head -1)
second=$(printf '%s\n' "$order" | tail -1)
if [ "$first" -lt "$second" ]; then
	echo "ok   the link comes up before the supplicant starts"
else
	echo "FAIL the supplicant is planned before the link is up"
	failures=$((failures + 1))
fi

"$ncfg" apply >/dev/null 2>&1 || {
	echo "FAIL apply did not succeed"
	"$ncfg" apply || true
	exit 1
}

[ -e "$work/ctrl/lo" ] || {
	echo "FAIL netcfgd did not start a supplicant"
	exit 1
}
echo "ok   netcfgd started the supplicant itself"

get() { "$cli" -p "$work/ctrl" -i lo get_network 0 "$1"; }

# The one that separates wired from wifi. `WPA-EAP` here produces a network the
# supplicant accepts and never authenticates with: everything looks configured
# and the port stays blocked.
check "wired uses IEEE8021X, not WPA-EAP" "$(get key_mgmt)" "IEEE8021X"
# Without this the supplicant waits for WEP keys the switch never sends.
check "eapol_flags is cleared" "$(get eapol_flags)" "0"
check "the method carried through" "$(get eap)" "PEAP"
check "the identity is quoted" "$(get identity)" '"dave@corp.example"'
check "the inner method carried through" "$(get phase2)" '"auth=MSCHAPV2"'
check "the password resolved from the secrets directory" "$(get password)" "*"

# Decision 0015: the document is the only authority, and that must not rest on
# a default nobody set.
check "update_config is pinned off" \
	"$("$cli" -p "$work/ctrl" -i lo get update_config)" "0"

echo
if [ "$failures" -eq 0 ]; then
	echo "dot1x.sh: all checks passed"
else
	echo "dot1x.sh: $failures failed"
	exit 1
fi
