#!/bin/sh
# An OpenVPN tunnel, as far as a machine with no VPN server can take one.
#
#     unshare -rn sh tests/live/openvpn.sh
#
# Decision 0046: the `.ovpn` is the operator's and netcfgd never reads it. What
# netcfgd owns is the lifecycle, so that is what this checks -- the daemon is
# started with the arguments netcfgd chose, stopped through its own management
# socket rather than by signalling something found by name, and its own words
# are quoted when it will not start.
#
# The daemon is faked and the management protocol is not: fake_openvpn.py binds
# a real unix stream socket and speaks the real line format, including the
# `>INFO:` greeting a client that reads its first line as an answer will
# mistake for one. That mistake produces a stop which silently does nothing,
# which is the failure worth having a test for.

set -eu

repo=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)

skip() {
	if [ -n "${NCFG_LIVE:-}" ]; then
		echo "openvpn.sh: NCFG_LIVE is set but this cannot run: $1" >&2
		exit 1
	fi
	echo "openvpn.sh: skipping: $1"
	exit 0
}

command -v python3 >/dev/null 2>&1 || skip "no python3"
[ -x "$repo/target/debug/ncfg" ] || skip "ncfg is not built"

work=$(mktemp -d /tmp/ncfg-openvpn.XXXXXX)
cleanup() {
	pkill -f "$work/fake_openvpn" 2>/dev/null || true
	rm -rf "$work"
}
trap cleanup EXIT INT TERM
mkdir -p "$work/etc" "$work/run" "$work/bin"

export NCFG_CONFIG_DIR="$work/etc"
export NCFG_RUN_DIR="$work/run"
export FAKE_OPENVPN_LOG="$work/openvpn.log"
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

# netcfgd looks for `openvpn` on PATH after the sbin directories, so a fake put
# there is found the way the real one would be -- and the search order is
# netcfgd's own, not this script's guess at it.
cp "$repo/tests/live/fake_openvpn.py" "$work/bin/openvpn"
chmod +x "$work/bin/openvpn"
PATH="$work/bin:$PATH"
export PATH

# The operator's file, which netcfgd hands over and never reads. Its contents
# are deliberately not valid OpenVPN: if netcfgd ever starts parsing it, this
# test should be the thing that notices.
cat > "$work/etc/work.ovpn" <<'OVPN'
# netcfgd does not read this file, and this line proves it.
this is not valid openvpn configuration at all
OVPN

cat > "$work/etc/netcfgd.conf" <<CONF
interface vpn0 {
	openvpn { config = "$work/etc/work.ovpn" }
}
CONF

# ------------------------------------------------------------------- starting

"$ncfg" plan > "$work/plan.txt" 2>&1 || true
# The tunnel is an interface and openvpn creates the device, so nothing plans a
# link.create -- which would be an action that must fail.
check "the plan starts the daemon rather than creating a link" \
	"$(grep -c 'backend.start vpn0' "$work/plan.txt" || true)" "1"
check "and does not try to create the device itself" \
	"$(grep -c 'link.create vpn0' "$work/plan.txt" || true)" "0"

"$ncfg" apply > "$work/apply.txt" 2>&1 || true

check "netcfgd handed openvpn the operator's file" \
	"$(grep -c -- "--config $work/etc/work.ovpn" "$FAKE_OPENVPN_LOG" || true)" "1"
# The interface name is netcfgd's to choose. A .ovpn naming something else would
# otherwise produce a tunnel no plan could find.
check "and named the device from the document" \
	"$(grep -c -- '--dev vpn0' "$FAKE_OPENVPN_LOG" || true)" "1"
check "with a management socket to stop it through" \
	"$(grep -c -- "--management $work/run/openvpn/vpn0.sock unix" "$FAKE_OPENVPN_LOG" || true)" "1"
check "and --daemon, so the apply does not block on a tunnel negotiating" \
	"$(grep -c -- '--daemon' "$FAKE_OPENVPN_LOG" || true)" "1"

waited=0
while [ ! -S "$work/run/openvpn/vpn0.sock" ]; do
	waited=$((waited + 1))
	[ "$waited" -gt 50 ] && break
	sleep 0.1
done
check "the daemon is listening on it" \
	"$([ -S "$work/run/openvpn/vpn0.sock" ] && echo yes || echo no)" "yes"

# ------------------------------------------------------------------- stopping

# Deleting the block is what stops it, and it goes through the management
# socket. `signal SIGTERM` in the daemon's own log is the proof -- if netcfgd
# had killed a process by name instead, nothing would appear there, and an
# operator's own tunnels would be at risk.
cat > "$work/etc/netcfgd.conf" <<'CONF'
interface vpn0 { kind = "dummy"; config = "null" }
CONF
"$ncfg" apply > "$work/stop.txt" 2>&1 || true

check "stopping asks the daemon through its management socket" \
	"$(grep -c '^signal SIGTERM' "$FAKE_OPENVPN_LOG" || true)" "1"
waited=0
while [ -S "$work/run/openvpn/vpn0.sock" ]; do
	waited=$((waited + 1))
	[ "$waited" -gt 50 ] && break
	sleep 0.1
done
check "and the daemon goes" \
	"$([ -S "$work/run/openvpn/vpn0.sock" ] && echo yes || echo no)" "no"

# A daemon that answers ERROR is a stop that did not happen, and netcfgd has to
# say so rather than record a success. This is the only thing that reads the
# management reply -- without it the client could return any line at all and
# nothing would notice, which is exactly what breaking the parse showed.
cat > "$work/etc/netcfgd.conf" <<CONF
interface vpn0 {
	openvpn { config = "$work/etc/work.ovpn" }
}
CONF
FAKE_OPENVPN_REFUSES_SIGNAL=1 "$ncfg" apply > /dev/null 2>&1 || true
cat > "$work/etc/netcfgd.conf" <<'CONF'
interface vpn0 { kind = "dummy"; config = "null" }
CONF
FAKE_OPENVPN_REFUSES_SIGNAL=1 "$ncfg" apply > "$work/refusedstop.txt" 2>&1 || true
check "a daemon that refuses to stop is reported, not recorded as stopped" \
	"$(grep -c 'could not stop the openvpn tunnel on vpn0' "$work/refusedstop.txt" || true)" "1"
pkill -f "$work/bin/openvpn" 2>/dev/null || true
rm -f "$work/run/openvpn/vpn0.sock"

# Stopping a tunnel that is already gone is the state this was asked to
# produce, so it is success rather than an error to report.
"$ncfg" apply > "$work/stop2.txt" 2>&1 || true
check "stopping one that is already stopped is not an error" \
	"$(grep -c 'could not stop' "$work/stop2.txt" || true)" "0"

# --------------------------------------------------------------- credentials

# A server that wants a username and password. OpenVPN has no indirection for
# them -- `--auth-user-pass` reads a file with the username on the first line
# and the password on the second -- so netcfgd resolves the SecretRef into one,
# which is the same trade the hostapd passphrase already makes.
mkdir -p "$work/etc/secrets"
printf '%s' 'correct-horse-battery' > "$work/etc/secrets/vpn"
chmod 600 "$work/etc/secrets/vpn"
cat > "$work/etc/netcfgd.conf" <<CONF
interface vpn0 {
	openvpn {
		config   = "$work/etc/work.ovpn"
		username = "vpn-user"
		password = "@secret:vpn"
	}
}
CONF
"$ncfg" apply > "$work/auth.txt" 2>&1 || true

auth="$work/run/openvpn/vpn0.auth"
check "netcfgd wrote the credentials file openvpn reads" \
	"$([ -f "$auth" ] && echo yes || echo no)" "yes"
# 0600 before anything is written to it, never a chmod afterwards: the window
# between the two is a window in which the password is world-readable.
check "at mode 0600" "$(stat -c '%a' "$auth" 2>/dev/null)" "600"
check "with the username on the first line" "$(sed -n 1p "$auth")" "vpn-user"
check "and the password on the second" "$(sed -n 2p "$auth")" "correct-horse-battery"
check "and pointed openvpn at the file" \
	"$(grep -c -- "--auth-user-pass $auth" "$FAKE_OPENVPN_LOG" || true)" "1"
# Never on the command line, where every process on the machine can read it
# out of /proc.
check "never putting the password on a command line" \
	"$(grep -c 'correct-horse-battery' "$FAKE_OPENVPN_LOG" || true)" "0"
check "nor in what the apply printed" \
	"$(grep -c 'correct-horse-battery' "$work/auth.txt" || true)" "0"
# And nowhere under /run except that one file, which is the check that catches
# a password copied into the plan, the observation or the journal.
check "and nowhere under /run except the file that needs it" \
	"$(grep -rl 'correct-horse-battery' "$work/run" 2>/dev/null | grep -cv 'vpn0.auth' || true)" "0"

# The credentials go when the tunnel does. /run is tmpfs so they would go at a
# reboot anyway, but a password beside a tunnel that is not running is one
# nobody is watching.
cat > "$work/etc/netcfgd.conf" <<'CONF'
interface vpn0 { kind = "dummy"; config = "null" }
CONF
"$ncfg" apply > /dev/null 2>&1 || true
check "and are removed when the tunnel is stopped" \
	"$([ -f "$auth" ] && echo yes || echo no)" "no"

check "a username without a password is refused, not left to prompt" \
	"$(printf 'interface vpn0 { openvpn { config = "/x.ovpn"; username = "u" } }\n' \
	     > "$work/etc/netcfgd.conf"; \
	   "$ncfg" plan 2>&1 | grep -c 'both `username` and `password`' || true)" "1"

# ------------------------------------------------------------------ refusals

# A path with no file behind it. Refused by netcfgd with the path in the
# message, rather than by openvpn against a file the operator may not realise
# netcfgd chose.
cat > "$work/etc/netcfgd.conf" <<CONF
interface vpn0 {
	openvpn { config = "$work/etc/absent.ovpn" }
}
CONF
"$ncfg" apply > "$work/missing.txt" 2>&1 || true
check "a configuration that is not there is named" \
	"$(grep -c 'there is no file there' "$work/missing.txt" || true)" "1"

# And when the daemon itself refuses, its words are what the operator sees --
# not an exit status. Same treatment hostapd gets.
cat > "$work/etc/netcfgd.conf" <<CONF
interface vpn0 {
	openvpn { config = "$work/etc/work.ovpn" }
}
CONF
FAKE_OPENVPN_FAILS=1 "$ncfg" apply > "$work/refused.txt" 2>&1 || true
check "and a daemon that will not start is quoted rather than counted" \
	"$(grep -c 'Options error' "$work/refused.txt" || true)" "1"

# ------------------------------------------------------------- the compiler

check "a relative path is refused where the line is, not later" \
	"$(printf 'interface vpn0 { openvpn { config = "work.ovpn" } }\n' > "$work/etc/netcfgd.conf"; \
	   "$ncfg" plan 2>&1 | grep -c 'is not an absolute path' || true)" "1"
check "and an unknown key says where the rest belongs" \
	"$(printf 'interface vpn0 { openvpn { config = "/x.ovpn"; remote = "vpn.example" } }\n' \
	     > "$work/etc/netcfgd.conf"; \
	   "$ncfg" plan 2>&1 | grep -c 'unknown openvpn key' || true)" "1"

echo
if [ "$failures" -eq 0 ]; then
	echo "openvpn.sh: all checks passed"
else
	echo "openvpn.sh: $failures check(s) failed"
	exit 1
fi
