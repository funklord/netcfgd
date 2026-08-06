#!/bin/sh
# An access point, as far as a machine with no radio can take one.
#
# hostapd is configured by a file rather than over a socket (decision 0026), so
# the file is the interface and writing it is the whole integration. This drives
# a real apply and then asks three questions about what came out:
#
#   - is the file what netcfgd meant to write, and can hostapd read it?
#   - is the passphrase in it, at mode 0600, and *only* in it?
#   - when hostapd will not start, does netcfgd say what hostapd said?
#
# The last one is not incidental here. The access point is put on a dummy
# interface, which has no radio, so hostapd is guaranteed to fail -- and an
# apply that reported "backend.start failed" and nothing else would leave the
# operator with no way to tell a mistyped channel from a missing driver.
#
#     unshare -rn sh tests/live/ap.sh
#
# What it cannot do is beacon. Associating a station needs mac80211_hwsim and
# real root, which is what tests/live/hwsim.sh is for.

set -eu

repo=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)

skip() {
	if [ -n "${NCFG_LIVE:-}" ]; then
		echo "ap.sh: NCFG_LIVE is set but this cannot run: $1" >&2
		exit 1
	fi
	echo "ap.sh: skipping: $1"
	exit 0
}

find_hostapd() {
	for dir in /usr/sbin /sbin /usr/local/sbin /usr/bin; do
		if [ -x "$dir/hostapd" ]; then
			echo "$dir/hostapd"
			return 0
		fi
	done
	command -v hostapd 2>/dev/null
}

command -v ip >/dev/null 2>&1 || skip "no ip(8)"
[ -x "$repo/target/debug/ncfg" ] || skip "ncfg is not built"
# The same search order netcfgd uses. A test that found hostapd somewhere
# netcfgd does not look would pass while netcfgd reported it missing.
hostapd=$(find_hostapd) || skip "hostapd is not installed (apt install hostapd | apk add hostapd)"

work=$(mktemp -d "${TMPDIR:-/tmp}/ncfg-ap.XXXXXX")
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

passphrase=correct-horse-battery
printf '%s' "$passphrase" > "$work/etc/secrets/guest"
chmod 600 "$work/etc/secrets/guest"

cat > "$work/etc/netcfgd.conf" <<'CONF'
interface ap0 {
	kind   = "dummy"
	config = "192.168.9.1/24"
}

access_point "guest" {
	device  = "ap0"
	channel = 11
	regdom  = "SE"
	hidden  = true
	wifi    { psk = "@secret:guest"; proto = "wpa2" }
}
CONF

# The plan first, because it is the half that has to be honest before anything
# is written. `--oneshot` then does the work; it is expected to fail, at the
# access point and not before.
"$ncfg" plan > "$work/plan.log" 2>&1 || true
check "the plan starts a backend for the access point" \
	"$(grep -c 'backend\.start' "$work/plan.log" || true)" "1"
check "and says which block asked for it" \
	"$(grep -c 'access_point' "$work/plan.log" || true)" "1"

"$ncfg" apply --oneshot > "$work/apply.log" 2>&1 && applied=0 || applied=1
conf="$work/run/hostapd/ap0.conf"

check "the configuration was written" "$([ -f "$conf" ] && echo yes || echo no)" "yes"
# 0600 before the first byte goes in, not after. A mode set afterwards is a
# mode that was wrong once, and the window is exactly when the passphrase is
# on disk and world readable.
check "at mode 0600" "$(stat -c '%a' "$conf" 2>/dev/null)" "600"

check "the ssid is hex, not text" \
	"$(sed -n 's/^ssid2=//p' "$conf")" "6775657374"
check "the channel carried through" "$(sed -n 's/^channel=//p' "$conf")" "11"
check "2.4 GHz was inferred from the channel" \
	"$(sed -n 's/^hw_mode=//p' "$conf")" "g"
check "the regulatory domain is advertised, not just recorded" \
	"$(sed -n 's/^ieee80211d=//p' "$conf")" "1"
check "hidden means an empty ssid in the beacon" \
	"$(sed -n 's/^ignore_broadcast_ssid=//p' "$conf")" "1"
check "the passphrase resolved from the secrets directory" \
	"$(sed -n 's/^wpa_passphrase=//p' "$conf")" "$passphrase"

# The reference tool. hostapd cannot attach to a dummy, so it will exit
# nonzero either way -- what separates a file it understood from one it did not
# is whether it complained about a line.
"$hostapd" "$conf" > "$work/parse.log" 2>&1 || true
check "hostapd parses what netcfgd wrote" \
	"$(grep -c 'errors found in configuration file' "$work/parse.log" || true)" "0"

# The other half of constraint 5's spirit: the document holds a reference, so
# the only place the value may appear is the file hostapd reads. Not the plan,
# not the apply output, not the journal, not the desired-state document in
# /run.
check "the apply did not print the passphrase" \
	"$(grep -rc "$passphrase" "$work/apply.log" || true)" "0"
check "nor did the plan" \
	"$(grep -c "$passphrase" "$work/plan.log" || true)" "0"
leaked=$(grep -rl "$passphrase" "$work/run" 2>/dev/null | grep -v '/hostapd/ap0.conf$' | tr '\n' ' ')
check "and nothing under /run holds it except that file" "$leaked" ""

# hostapd was really run, and really failed -- a dummy has no radio.
check "the apply failed" "$applied" "1"
check "and named hostapd rather than the action" \
	"$(grep -c 'hostapd' "$work/apply.log" || true)" "1"
# Its own words, not a paraphrase. "backend.start failed" cannot tell a
# mistyped channel from a driver that is not there.
check "quoting what hostapd said" \
	"$(grep -c 'nl80211\|Could not read interface\|driver initialization' "$work/apply.log" || true)" "1"
check "and the log it left behind exists" \
	"$([ -s "$work/run/hostapd/ap0.log" ] && echo yes || echo no)" "yes"

# Section 4's failure semantics, for this backend specifically. A start that
# failed must not be recorded as having happened: the next plan has to ask for
# it again, and it must not ask for a `backend.stop` of something that is not
# running.
#
# This is where the first version of this script asserted the withdrawal case
# -- delete the block, expect a stop -- and it was wrong for a reason worth
# keeping. Nothing was ever started here, so there is nothing to stop, and the
# plan was right to be empty. The withdrawal case needs a backend that really
# is running, which is `an_access_point_stops_when_its_block_goes` in the
# planner fixtures, where the observed state can simply say so.
"$ncfg" plan > "$work/plan2.log" 2>&1 || true
check "a failed start is still asked for on the next plan" \
	"$(grep -c 'backend\.start' "$work/plan2.log" || true)" "1"
check "and nothing is asked to stop" \
	"$(grep -c 'backend\.stop' "$work/plan2.log" || true)" "0"

# --------------------------------------------- the station list (decision 0036)
#
# The single-host half of Ubiquiti-style roaming: a station is forced onto one
# access point by every other access point refusing it. What is checked here is
# the part a fixture cannot check -- that hostapd accepts the two keys together
# and reads the file netcfgd pointed it at.

cat > "$work/etc/netcfgd.conf" <<'CONF'
interface ap0 {
	kind   = "dummy"
	config = "192.168.9.1/24"
}

access_point "guest" {
	device  = "ap0"
	channel = 11
	wifi    { psk = "@secret:guest"; proto = "wpa2" }
	access_control { deny = ["AA-BB-CC-DD-EE-FF", "00:11:22:33:44:55"] }
}
CONF

"$ncfg" apply --oneshot > "$work/acl.log" 2>&1 || true
acl="$work/run/hostapd/ap0.acl"

check "a deny list selects hostapd's deny file" \
	"$(sed -n 's/^macaddr_acl=//p' "$conf")" "0"
check "and points it at the list netcfgd wrote" \
	"$(sed -n 's/^deny_mac_file=//p' "$conf")" "$acl"
check "the list exists" "$([ -f "$acl" ] && echo yes || echo no)" "yes"
# Not 0600: this holds no secret, and a list only root can read is a list
# nobody debugging an access point can read either.
check "at mode 0644" "$(stat -c '%a' "$acl" 2>/dev/null)" "644"
# Normalised on the way in: written in two spellings and two cases, stored in
# the one form hostapd prints, sorted so the document is canonical.
check "the stations are normalised and sorted" \
	"$(grep -v '^#' "$acl" | tr '\n' ' ')" "00:11:22:33:44:55 aa:bb:cc:dd:ee:ff "
# The first line records which policy hostapd was started with (decision 0041).
# `macaddr_acl` is not readable over the control socket, so without this netcfgd
# could converge the lists of a running access point without knowing which one
# it consults -- and a document flipped from `deny` to `allow` would be applied
# as an open network.
check "and the policy is recorded above them" \
	"$(head -1 "$acl")" "# netcfgd policy: deny"

# The reference tool again, and the reason this check is worth its cost:
# hostapd validates `deny_mac_file` by reading it at parse time, so a path that
# is wrong or a file that is malformed is an error here rather than a silently
# unenforced ACL. That is also what makes the record above safe rather than
# merely believed to be: `hostapd_config_read_maclist` skips a line whose first
# byte is `#`, and this is the check that says so about a real hostapd instead
# of about its source.
"$hostapd" "$conf" > "$work/parse2.log" 2>&1 || true
check "hostapd accepts the acl configuration, record and all" \
	"$(grep -c 'errors found in configuration file' "$work/parse2.log" || true)" "0"
check "and read the list rather than ignoring it" \
	"$(grep -c 'Line [0-9]*: .*macaddr_acl\|Line [0-9]*: .*deny_mac' "$work/parse2.log" || true)" "0"
check "and did not mistake the record for an address" \
	"$(grep -c 'Invalid MAC address' "$work/parse2.log" || true)" "0"

# An access point whose block goes away must not leave a list behind. The next
# person to look would find an ACL and believe it.
cat > "$work/etc/netcfgd.conf" <<'CONF'
interface ap0 {
	kind   = "dummy"
	config = "192.168.9.1/24"
}

access_point "guest" {
	device  = "ap0"
	channel = 11
	wifi    { psk = "@secret:guest"; proto = "wpa2" }
}
CONF

"$ncfg" apply --oneshot > "$work/noacl.log" 2>&1 || true
check "removing the block removes the list" \
	"$([ -f "$acl" ] && echo yes || echo no)" "no"
check "and stops naming it in the configuration" \
	"$(grep -c '^macaddr_acl=\|^deny_mac_file=' "$conf" || true)" "0"

# Locking everyone out is legitimate and easy to arrive at by deleting the last
# station, so the plan says which one this is rather than leaving an operator to
# find out from the far side of a radio.
cat > "$work/etc/netcfgd.conf" <<'CONF'
interface ap0 {
	kind   = "dummy"
	config = "192.168.9.1/24"
}

access_point "guest" {
	device  = "ap0"
	channel = 11
	wifi    { psk = "@secret:guest"; proto = "wpa2" }
	access_control { allow = [] }
}
CONF

"$ncfg" plan > "$work/empty.log" 2>&1 || true
check "an empty allow list is warned about, not refused" \
	"$(grep -c 'no station can associate' "$work/empty.log" || true)" "1"

echo
if [ "$failures" -eq 0 ]; then
	echo "ap.sh: all checks passed"
else
	echo "ap.sh: $failures check(s) failed"
	exit 1
fi
