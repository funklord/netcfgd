#!/bin/sh
# The NetworkManager shim, driven by a real nmcli.
#
# Design section 9.1 predicted this: `nmcli` is itself a libnm client, so it
# doubles as a free scriptable conformance harness. That is worth more than it
# sounds. The shim's failure mode is not a crash -- it is answering every call
# and having the client build something different from what was meant, which no
# amount of reading the specification finds and one `nmcli device status` does.
#
#     unshare -rn sh tests/live/nm.sh
#
# ## What it does to the machine
#
# Nothing. Everything happens on a private bus started by this script, on a
# private network namespace, against a netcfgd with its own config and run
# directories. The shim is given `--session` so it claims the name there and
# not on the system bus -- where, on a developer's laptop, the name belongs to
# the NetworkManager actually running the machine.
#
# nmcli is pointed at the private bus with DBUS_SYSTEM_BUS_ADDRESS, which GDBus
# honours in place of the real system bus address. That is the whole trick, and
# it is why this can drive a real client without root and without touching
# anything.

set -eu

repo=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
shim="$repo/adapters/netcfgd-nm/target/debug/netcfgd-nm"

skip() {
	if [ -n "${NCFG_LIVE:-}" ]; then
		echo "nm.sh: NCFG_LIVE is set but this cannot run: $1" >&2
		exit 1
	fi
	echo "nm.sh: skipping: $1"
	exit 0
}

command -v ip >/dev/null 2>&1 || skip "no ip(8)"
command -v nmcli >/dev/null 2>&1 || skip "nmcli is not installed (apt install network-manager)"
command -v dbus-daemon >/dev/null 2>&1 || skip "dbus-daemon is not installed"
[ -x "$repo/target/debug/netcfgd" ] || skip "netcfgd is not built"
[ -x "$shim" ] || skip "netcfgd-nm is not built (make adapters)"

# Short, because a unix socket path has to fit in sun_path and the repo may be
# checked out somewhere deep. The first version of this used the scratch
# directory it was written in and netcfgd refused the socket outright.
work=$(mktemp -d /tmp/ncfg-nm.XXXXXX)
daemon=
bus=
shim_pid=
cleanup() {
	[ -n "${fake:-}" ] && kill "$fake" 2>/dev/null
	[ -n "$shim_pid" ] && kill "$shim_pid" 2>/dev/null
	[ -n "$bus" ] && kill "$bus" 2>/dev/null
	[ -n "$daemon" ] && kill "$daemon" 2>/dev/null
	rm -rf "$work"
}
trap cleanup EXIT INT TERM
mkdir -p "$work/etc" "$work/run"

export NCFG_CONFIG_DIR="$work/etc"
export NCFG_RUN_DIR="$work/run"

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

mkdir -p "$work/etc/secrets" "$work/ctrl"
printf 'hunter2hunter2' > "$work/etc/secrets/home"
chmod 600 "$work/etc/secrets/home"
export NCFG_WPA_CTRL_DIR="$work/ctrl"

# `radio0` is a dummy the configuration declares as a radio. netcfgd's planner
# treats any managed device with a `wifi` block as one whatever the kernel calls
# the link, so the shim does too -- which is what lets a machine with no
# wireless hardware exercise the wireless half at all.
cat > "$work/etc/netcfgd.conf" <<'CONF'
interface probe0 {
	kind   = "dummy"
	config = "10.7.7.1/24"
}

interface quiet0 {
	kind = "dummy"
}

device radio0 {
	wifi { backend = "wpa_supplicant" }
}

interface radio0 {
	kind = "dummy"
}

# WPA3 deliberately, and not the WPA2 the scan flags say. The shim guesses
# WPA2-PSK for a secured network it has no configuration for, so a configured
# network that is also WPA2 makes the "the document is consulted" check pass
# whether it is consulted or not -- which is what happened, and was found by
# removing the lookup and watching the test still pass.
network "HomeFiber" {
	wifi { psk = "@secret:home"; proto = "wpa3" }
}
CONF

# A radio, without a radio. The fake supplicant answers the four commands
# netcfgd sends with canned scan results, so everything downstream of "the scan
# returned" -- which for the shim is all of the arithmetic a client renders --
# can be checked against known inputs. wifi.sh drives a *real* supplicant and is
# what proves the protocol parsing; this proves the translation.
fake=
if command -v python3 >/dev/null 2>&1; then
	python3 "$repo/tests/live/fake_supplicant.py" "$work/ctrl" radio0 > "$work/fake.log" 2>&1 &
	fake=$!
	waited=0
	while [ ! -e "$work/ctrl/radio0" ]; do
		waited=$((waited + 1))
		[ "$waited" -gt 50 ] && break
		sleep 0.1
	done
fi

"$repo/target/debug/netcfgd" > "$work/daemon.log" 2>&1 &
daemon=$!
waited=0
while [ ! -e "$work/run/netcfgd.sock" ]; do
	waited=$((waited + 1))
	if [ "$waited" -gt 60 ]; then
		if grep -q 'Operation not permitted' "$work/daemon.log" 2>/dev/null; then
			skip "no CAP_NET_ADMIN (run under unshare -rn)"
		fi
		cat "$work/daemon.log" >&2
		echo "nm.sh: the daemon never started" >&2
		exit 1
	fi
	sleep 0.1
done
# The daemon applies on start, but the apply and the socket appearing are not
# ordered, and the shim must not be asked about a machine mid-configuration.
"$repo/target/debug/ncfg" apply > "$work/apply.log" 2>&1 || true

# Before the bus exists at all: the shim must refuse to claim NM's name when it
# cannot answer, rather than claiming it and erroring at every client. A daemon
# that is present and broken is worse than one that is absent, because clients
# stop looking for alternatives.
# Under `timeout`, so that a shim which regresses into *waiting* fails this
# test rather than hanging it. That is not hypothetical: the first version of
# the name claim queued instead of refusing, and this script hung with no
# output at all rather than reporting a failed check.
if timeout 10 env NCFG_RUN_DIR=/nonexistent "$shim" --session > "$work/norun.log" 2>&1; then
	check "the shim refuses to run without netcfgd" "it started" "it refused"
else
	check "the shim refuses to run without netcfgd" \
		"$(grep -c 'refusing to claim' "$work/norun.log" || true)" "1"
fi

# The private bus. Its address goes to the shim as the session bus and to nmcli
# as the system bus -- the same daemon wearing both hats, which is what lets an
# unmodified client talk to a shim that is not running as root.
eval "$(dbus-daemon --session --print-address=1 --print-pid=1 --fork | {
	read -r address
	read -r pid
	echo "address='$address'; bus=$pid"
})"
export DBUS_SESSION_BUS_ADDRESS="$address"
export DBUS_SYSTEM_BUS_ADDRESS="$address"

"$shim" --session > "$work/nm.log" 2>&1 &
shim_pid=$!
waited=0
until nmcli general status >/dev/null 2>&1; do
	waited=$((waited + 1))
	if [ "$waited" -gt 100 ]; then
		cat "$work/nm.log" >&2
		echo "nm.sh: the shim never answered" >&2
		exit 1
	fi
	sleep 0.1
done

devices() { nmcli --terse --fields DEVICE,TYPE,STATE device status 2>/dev/null; }
field() { devices | awk -F: -v want="$1" '$1 == want { print $2 ":" $3 }'; }

# Every link, not a subset. This is the assertion that would have caught the
# bug this test was written around: libnm builds its device cache from the
# interfaces on each object rather than from the DeviceType property, so a
# device with no per-kind interface is not a device of unknown type -- it is
# invisible. Six links were served and `nmcli` listed one.
kernel_links=$(ip -o link show | wc -l)
check "nmcli sees every link netcfgd reports" "$(devices | wc -l)" "$kernel_links"

check "a dummy is generic, and says what it really is" "$(field probe0)" "dummy:connected"
check "the loopback is a loopback, not an ethernet" "$(field lo)" "loopback:unavailable"

# State comes from what the link is doing, and the two dummies differ only in
# whether the config gave one an address. A shim that reported both the same
# would be reporting the interface list rather than the network.
check "a link with no address is not connected" "$(field quiet0)" "dummy:disconnected"

check "the mtu comes from the observation" \
	"$(nmcli --terse --fields GENERAL.MTU device show probe0 | cut -d: -f2)" "1500"
check "and so does the hardware address" \
	"$(nmcli --terse --fields GENERAL.HWADDR device show probe0 | cut -d: -f2- | tr 'A-F' 'a-f')" \
	"$(ip -o link show probe0 | sed -n 's/.*link\/ether \([0-9a-f:]*\).*/\1/p')"

# Mutual exclusion, which design section 9.3 gets for free from the bus: two
# processes cannot own one well-known name. It is the property that stops a
# machine running netcfgd and NetworkManager against the same interfaces.
if timeout 10 "$shim" --session > "$work/second.log" 2>&1; then
	check "a second shim cannot claim the name" "it started" "it refused"
else
	check "a second shim cannot claim the name" \
		"$(grep -c 'cannot claim' "$work/second.log" || true)" "1"
fi
check "and says what that means" \
	"$(grep -c 'Stop NetworkManager first' "$work/second.log" || true)" "1"

# The version is a deliberate lie (design section 9.3: clients gate behaviour
# on it). The interface that tells the truth has to exist, or the lie is the
# only thing on offer.
compat() {
	busctl --user --address="$address" get-property org.freedesktop.NetworkManager \
		/org/freedesktop/NetworkManager org.netcfgd.Compat "$1" 2>/dev/null |
		cut -d' ' -f2- | tr -d '"'
}
if command -v busctl >/dev/null 2>&1; then
	check "the compat interface names what this really is" \
		"$(compat Implementation)" "netcfgd-nm"
	# The literal, not a value read back from the shim: this is a contract with
	# clients that gate features on it, so changing it should fail a test
	# rather than pass one that compares the shim against itself.
	check "and admits which NM version it is pretending to be" \
		"$(compat ClaimedNetworkManagerVersion)" "1.44.0"
	check "which is what NetworkManager's own property says too" \
		"$(nmcli --terse --fields VERSION general 2>/dev/null)" "1.44.0"
fi

# A device that goes away must leave the object tree, not linger as a path
# whose properties quietly stop changing. Removing the link is the check;
# nmcli asks libnm's cache, which is only correct if InterfacesRemoved fired.
ip link del quiet0
waited=0
until [ -z "$(field quiet0)" ]; do
	waited=$((waited + 1))
	if [ "$waited" -gt 100 ]; then
		break
	fi
	sleep 0.1
done
check "a link that goes away leaves the device list" "$(field quiet0)" ""
check "and the others are still there" "$(field probe0)" "dummy:connected"

# ----------------------------------------------------------------- wireless

if [ -z "$fake" ]; then
	echo "nm.sh: skipping the wireless checks: no python3 for the fake radio"
else
	check "a device the config calls a radio is wifi, whatever the link kind" \
		"$(devices | awk -F: '$1 == "radio0" { print $2 }')" "wifi"

	wifi() { nmcli --terse --fields "$1" device wifi list --rescan no 2>/dev/null; }

	check "every access point the scan found is listed" \
		"$(wifi SSID | grep -c .)" "3"
	check "and the names came through" \
		"$(wifi SSID | sort | tr '\n' ' ')" "Cafe Distant HomeFiber "

	# The conversion NM clients draw signal bars from. -40 dBm is the top of
	# NM's scale, -100 the bottom, and -53 is the level that produces the 79 a
	# real NetworkManager reported while this was written.
	strength_of() {
		nmcli --terse --fields SSID,SIGNAL device wifi list --rescan no 2>/dev/null |
			awk -F: -v want="$1" '$1 == want { print $2 }'
	}
	check "the strongest is at the top of NM's scale" "$(strength_of Cafe)" "100"
	check "the weakest is at the bottom" "$(strength_of Distant)" "0"
	check "and one in between matches what a real daemon reported" \
		"$(strength_of HomeFiber)" "79"

	# Security comes from the configuration where there is one, and from a
	# guess where there is not. Both must produce something an applet can act
	# on -- an empty SECURITY column on a secured network means "open" to a
	# user, which is the one wrong answer that matters.
	security_of() {
		nmcli --terse --fields SSID,SECURITY device wifi list --rescan no 2>/dev/null |
			awk -F: -v want="$1" '$1 == want { print $2 }'
	}
	check "a configured network reports the security the config gives it" \
		"$(security_of HomeFiber)" "WPA3"
	check "an open network reports none" "$(security_of Cafe)" ""
	check "and an unconfigured secured one is guessed, not left blank" \
		"$(security_of Distant)" "WPA2"

	# Which access point the radio is on. Asserted through busctl rather than
	# through nmcli's IN-USE column: that column is populated from the active
	# *connection*, which needs Settings and ActiveConnection objects this
	# build does not have yet. ActiveAccessPoint is the property the shim
	# implements, so it is the property the test reads.
	if command -v busctl >/dev/null 2>&1; then
		radio_path=$(busctl --user --address="$address" call \
			org.freedesktop.NetworkManager /org/freedesktop/NetworkManager \
			org.freedesktop.NetworkManager GetDeviceByIpIface s radio0 2>/dev/null |
			awk '{print $2}' | tr -d '"')
		active=$(busctl --user --address="$address" get-property \
			org.freedesktop.NetworkManager "$radio_path" \
			org.freedesktop.NetworkManager.Device.Wireless ActiveAccessPoint 2>/dev/null |
			awk '{print $2}' | tr -d '"')
		# The SSID as octets, which is how NM carries it. "HomeFiber" is
		# 9 bytes starting with 72 ('H').
		ssid=$(busctl --user --address="$address" get-property \
			org.freedesktop.NetworkManager "$active" \
			org.freedesktop.NetworkManager.AccessPoint Ssid 2>/dev/null)
		check "the radio reports which access point it is on" \
			"$ssid" "ay 9 72 111 109 101 70 105 98 101 114"
	fi

	# RequestScan is a request: NM's own semantics have it return immediately
	# and the results arrive as signals. What must not happen is an error.
	check "a client can ask for a scan" \
		"$(nmcli device wifi rescan ifname radio0 2>&1 | grep -c Error || true)" "0"

	# A device that is not a radio has no Wireless interface at all, so the
	# refusal a client sees comes from libnm before the call is made. The
	# shim's own refusal is unreachable this way and is covered by a unit test
	# instead; what this asserts is that the answer is "no" rather than a scan
	# that would never produce anything.
	check "asking a non-radio to scan is refused" \
		"$(nmcli device wifi rescan ifname probe0 2>&1 | grep -ci "error\|not a wi" || true)" "1"
fi

echo
if [ "$failures" -eq 0 ]; then
	echo "nm.sh: all checks passed"
else
	echo "nm.sh: $failures check(s) failed"
	exit 1
fi
