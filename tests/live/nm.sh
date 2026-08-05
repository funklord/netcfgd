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
command -v nmcli >/dev/null 2>&1 || skip "nmcli is not installed (apt install network-manager | apk add networkmanager)"
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
# Emphatically not the host's. A network namespace is not a mount namespace, so
# without this the DNS backend writes the resolver configuration of the machine
# running the test -- which it tried to do, and was saved from only by the user
# namespace having no permission to write a root-owned file.
export NCFG_RESOLV_CONF="$work/resolv.conf"

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
# Generated, never committed: a private key in a repository is a private key in
# a repository, however worthless the network it opens.
head -c 32 /dev/urandom | base64 > "$work/etc/secrets/wg0"
chmod 600 "$work/etc/secrets/wg0"
export NCFG_WPA_CTRL_DIR="$work/ctrl"

# `radio0` is a dummy the configuration declares as a radio. netcfgd's planner
# treats any managed device with a `wifi` block as one whatever the kernel calls
# the link, so the shim does too -- which is what lets a machine with no
# wireless hardware exercise the wireless half at all.
cat > "$work/etc/netcfgd.conf" <<'CONF'
global {
	dns {
		mode    = "write_resolv_conf"
		servers = ["10.0.0.1", "2001:db8::1"]
		search  = ["vibes.se"]
	}
}

interface probe0 {
	kind   = "dummy"
	config = ["10.7.7.1/24", "2001:db8:7::1/64"]
	routes = ["default via 10.7.7.254", "10.9.0.0/16 via 10.7.7.9 metric 600"]
}

interface quiet0 {
	kind = "dummy"
}

# A bridge with something on it, for the two kinds whose NM properties are
# answerable from what netcfgd already observes.
interface port0 {
	kind   = "dummy"
	master = "br0"
}

interface br0 {
	bridge { stp = false }
	config = "10.6.6.1/24"
}

# A VLAN, which is the second link kind to leave `Generic` on its own merits
# (0077). The id and the parent are the two properties libnm asks for that
# nothing else here has, and netcfgd observes both only because 0059 and 0060
# needed them for the planner.
interface tagged0 {
	vlan { parent = "probe0"; id = 42 }
	config = "10.42.0.1/24"
}

# A tunnel, for the one link kind that is not `Generic` to the shim. The
# private key is written beside this file at run time; nothing here is a key.
interface wg0 {
	wireguard {
		private_key = "@secret:wg0"
		listen_port = 51822
		peer hub {
			public_key  = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
			allowed_ips = "10.8.0.0/24"
		}
	}
	config = "10.8.0.2/32"
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
	metered = true
	config  = "dhcp"
	wifi { psk = "@secret:home"; proto = "wpa3"; priority = 30 }
	dns { servers = ["9.9.9.9"]; search = ["quad9.example"] }
}

# A network whose credential is referenced and does not exist. Before the
# secret agent bridge this was a dead end: netcfgd said the secret was not
# found and there was nothing a desktop could do about it.
network "Prompted" {
	wifi { psk = "@secret:Prompted"; proto = "wpa2" }
}
CONF

# A radio, without a radio. The fake supplicant answers the four commands
# netcfgd sends with canned scan results, so everything downstream of "the scan
# returned" -- which for the shim is all of the arithmetic a client renders --
# can be checked against known inputs. wifi.sh drives a *real* supplicant and is
# what proves the protocol parsing; this proves the translation.
fake=
if command -v python3 >/dev/null 2>&1; then
	python3 "$repo/tests/live/fake_supplicant.py" "$work/ctrl" radio0 \
		"$work/run/supplicant/radio0.pid" > "$work/fake.log" 2>&1 &
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
devices_full() {
	nmcli --terse --fields DEVICE,TYPE,STATE,CONNECTION device status 2>/dev/null
}
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

# ------------------------------------------------------------------- bridge
#
# A bridge answers three questions NM asks of one, and the interesting one is
# the third: `Slaves` is netcfgd's `master` field read from the other end, so a
# bridge that lists its port is a bridge whose device object was built from the
# observation rather than from the config file.
#
# Read as properties rather than from a column, for the reason the wireguard
# block gives at length: nmcli renders a generic device's type description into
# the same column, and `bridge` is exactly what that description would say.

if ! command -v busctl >/dev/null 2>&1; then
	echo "nm.sh: skipping the bridge checks: no busctl to read the properties"
else
	br_path=$(busctl --user --address="$address" call \
		org.freedesktop.NetworkManager /org/freedesktop/NetworkManager \
		org.freedesktop.NetworkManager GetDeviceByIpIface s br0 2>/dev/null |
		awk '{print $2}' | tr -d '"')
	port_path=$(busctl --user --address="$address" call \
		org.freedesktop.NetworkManager /org/freedesktop/NetworkManager \
		org.freedesktop.NetworkManager GetDeviceByIpIface s port0 2>/dev/null |
		awk '{print $2}' | tr -d '"')
	brprop() {
		busctl --user --address="$address" get-property \
			org.freedesktop.NetworkManager "$br_path" \
			org.freedesktop.NetworkManager.Device.Bridge "$1" 2>/dev/null
	}
	check "a bridge says it is one in the property clients switch on" \
		"$(busctl --user --address="$address" get-property \
			org.freedesktop.NetworkManager "$br_path" \
			org.freedesktop.NetworkManager.Device DeviceType 2>/dev/null)" "u 13"
	check "and lists the port that is on it" \
		"$(brprop Slaves | awk '{print $2, $3}' | tr -d '\"')" "1 $port_path"
	check "and the port is a device in its own right, not just a path" \
		"$(printf '%s' "$port_path" | grep -c '^/org/freedesktop/NetworkManager/Devices/' || true)" "1"
	# A device that is *not* a master lists nothing, which is the check that
	# would catch `slaves_of` answering with every link it can see.
	check "a dummy that is nobody's master has no interface saying otherwise" \
		"$(busctl --user --address="$address" get-property \
			org.freedesktop.NetworkManager "$port_path" \
			org.freedesktop.NetworkManager.Device.Bridge Slaves 2>&1 |
			grep -c "Unknown interface\|No such interface" || true)" "1"
fi

# ---------------------------------------------------------------- wireguard
#
# The one link kind the shim reports as itself rather than as `Generic`, and it
# earns that by answering NM's three questions about a tunnel -- which netcfgd
# could not observe at all until decision 0054. A device that claims a type and
# cannot answer for it is the failure the `Flavour` comment warns about.
#
# Skipped rather than failed where the kernel has no module: nothing else in
# this script needs one, and `strand.sh` makes the same call the same way.

if ! ip link show wg0 >/dev/null 2>&1; then
	echo "nm.sh: skipping the wireguard checks: no wg0 (this kernel has no wireguard?)"
elif ! command -v busctl >/dev/null 2>&1; then
	echo "nm.sh: skipping the wireguard checks: no busctl to read the properties"
else
	# **Not** `nmcli device status`, and that is the whole lesson of this block.
	# The obvious check -- that the TYPE column says `wireguard` -- passes with
	# the device-type mapping deliberately broken, because nmcli prints a
	# *generic* device's `TypeDescription`, and netcfgd's type description for
	# this link is the kernel's link kind, which is the word `wireguard`. Two
	# entirely different devices render identically in that column. Watched
	# passing with `flavour_of` returning `Generic`, which is why it is gone.
	#
	# What only a real WireGuard device can answer is the interface NM defines
	# for one. A listen port the document chose is the strongest of the three:
	# it cannot arrive by accident, it is not in any other property, and it
	# comes from the observation decision 0054 added.
	wg_path=$(busctl --user --address="$address" call \
		org.freedesktop.NetworkManager /org/freedesktop/NetworkManager \
		org.freedesktop.NetworkManager GetDeviceByIpIface s wg0 2>/dev/null |
		awk '{print $2}' | tr -d '"')
	wgprop() {
		busctl --user --address="$address" get-property \
			org.freedesktop.NetworkManager "$wg_path" \
			org.freedesktop.NetworkManager.Device.WireGuard "$1" 2>/dev/null
	}
	check "the tunnel is served as a wireguard device" \
		"$(printf '%s' "$wg_path" | grep -c '^/org/freedesktop/NetworkManager/Devices/' || true)" "1"
	check "and answers for the listen port the document chose" \
		"$(wgprop ListenPort)" "q 51822"
	check "and carries the public key the kernel derived" \
		"$(wgprop PublicKey | awk '{print $1, $2}')" "ay 32"
	check "and a firewall mark of none, rather than nothing at all" \
		"$(wgprop FwMark)" "u 0"
	# And the type number, read from the property rather than from a column
	# that renders two things the same way. 29 is NM's WireGuard.
	check "and says it is one in the property clients switch on" \
		"$(busctl --user --address="$address" get-property \
			org.freedesktop.NetworkManager "$wg_path" \
			org.freedesktop.NetworkManager.Device DeviceType 2>/dev/null)" "u 29"
fi

# --------------------------------------------------------------------- vlan
#
# The same lesson the wireguard block above spells out, applied to the second
# kind that has left `Generic`: read the properties, never the TYPE column,
# because a generic device whose description is the word `vlan` renders
# identically to a real one.

if ! command -v busctl >/dev/null 2>&1; then
	echo "nm.sh: skipping the vlan checks: no busctl to read the properties"
else
	vlan_path=$(busctl --user --address="$address" call \
		org.freedesktop.NetworkManager /org/freedesktop/NetworkManager \
		org.freedesktop.NetworkManager GetDeviceByIpIface s tagged0 2>/dev/null |
		awk '{print $2}' | tr -d '"')
	vlanprop() {
		busctl --user --address="$address" get-property \
			org.freedesktop.NetworkManager "$vlan_path" \
			org.freedesktop.NetworkManager.Device.Vlan "$1" 2>/dev/null
	}
	check "the vlan is served as a device" \
		"$(printf '%s' "$vlan_path" | grep -c '^/org/freedesktop/NetworkManager/Devices/' || true)" "1"
	# The id the document chose, which cannot arrive by accident and is in no
	# other property -- the same reasoning the listen port carries above.
	check "and answers for the tag the document chose" "$(vlanprop VlanId)" "u 42"
	# The parent as an object path, which is the property that needed 0060: a
	# parent netcfgd never sent to the kernel could not be read back from it.
	parent_path=$(busctl --user --address="$address" call \
		org.freedesktop.NetworkManager /org/freedesktop/NetworkManager \
		org.freedesktop.NetworkManager GetDeviceByIpIface s probe0 2>/dev/null |
		awk '{print $2}' | tr -d '"')
	check "and points at its parent device, not at a name" \
		"$(vlanprop Parent)" "o \"$parent_path\""
	check "and says it is a vlan in the property clients switch on" \
		"$(busctl --user --address="$address" get-property \
			org.freedesktop.NetworkManager "$vlan_path" \
			org.freedesktop.NetworkManager.Device DeviceType 2>/dev/null)" "u 11"
fi

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

	# ------------------------------------------- connections and activation

	connections() { nmcli --terse --fields NAME,TYPE,DEVICE connection show 2>/dev/null; }

	# One profile per block, and specifically none for the radio's `interface`
	# block: what you activate on a radio is a network, and an 802-3-ethernet
	# profile named `radio0` would be a thing in every client's list that
	# cannot be activated and is not an ethernet.
	# Including the bridge and its port, which is *not* the same call as the
	# tunnel below. What keeps a WireGuard interface out is that NM's profile
	# for one carries the peers and the private key; a bridge's carries neither,
	# and an 802-3-ethernet profile for a device that is not an ethernet is
	# already what a dummy gets here and has been since the first version.
	# `tagged0` is in this list, and its *device* is a VLAN while its *profile*
	# is the ordinary `802-3-ethernet` one every non-radio block gets. Those are
	# two different questions: NM's `vlan` connection type carries an id and a
	# parent in the connection, which is the same information from the other
	# side and is a separate piece of work (0077).
	check "every interface block is a profile" \
		"$(connections | awk -F: '{print $1}' | LC_ALL=C sort | tr '\n' ' ')" \
		"HomeFiber Prompted br0 port0 probe0 quiet0 tagged0 "
	# Nor a tunnel's, for the same reason and one more: NM's WireGuard profile
	# carries the peers and the private key, and this shim projects neither.
	check "a wireguard interface block is not a profile either" \
		"$(connections | awk -F: '$1 == "wg0" { print $1 }')" ""
	check "and a radio's interface block is not one" \
		"$(connections | grep -c '^radio0:' || true)" "0"
	check "the wifi profile is wireless" \
		"$(connections | awk -F: '$1 == "HomeFiber" { print $2 }')" "802-11-wireless"
	check "the interface profile is wired" \
		"$(connections | awk -F: '$1 == "probe0" { print $2 }')" "802-3-ethernet"

	# Derived, not stored: the same configuration produces this on any machine,
	# and the value is cross-checked against a second implementation in the
	# unit tests.
	check "the uuid is derived from the configuration" \
		"$(nmcli --terse --fields NAME,UUID connection show 2>/dev/null |
			awk -F: '$1 == "HomeFiber" { print $2 }')" \
		"7b9da559-bfbe-5bf1-82b1-bc18e6e2e81a"

	# The activation, end to end: a D-Bus call has to come out of the other
	# side as a supplicant command. Asserting only that the call returned would
	# pass for a shim that did nothing.
	# Measured as a delta, because the daemon already populated the supplicant
	# at apply time -- counting ADD_NETWORK over the whole log would count that
	# too and pass for a shim that did nothing here.
	before=$(wc -l < "$work/fake.log")
	nmcli connection up HomeFiber ifname radio0 > "$work/up.log" 2>&1 || true
	since_up=$(tail -n +$((before + 1)) "$work/fake.log")
	check "activating a profile reaches the supplicant" \
		"$(printf '%s' "$since_up" | grep -c 'SELECT_NETWORK' || true)" "1"
	# Through netcfgd's own join rather than a path of the shim's own: the
	# network is added the way `ncfg wifi connect` adds it, which is what keeps
	# decision 0013's boundary in one place.
	check "and it went through netcfgd's join" \
		"$(printf '%s' "$since_up" | grep -c 'ADD_NETWORK' || true)" "1"

	before=$(wc -l < "$work/fake.log")
	nmcli connection down HomeFiber > "$work/down.log" 2>&1 || true
	check "deactivating reaches it too" \
		"$(tail -n +$((before + 1)) "$work/fake.log" | grep -c '^DISCONNECT' || true)" "1"

	# The device's own view. This is nmcli's CONNECTION column and an applet's
	# "you are connected to" line, and it was empty until active connections
	# existed.
	check "the device names what is active on it" \
		"$(devices_full | awk -F: '$1 == "radio0" { print $4 }')" "HomeFiber"
	check "and a radio with an activation is connected, not disconnected" \
		"$(devices_full | awk -F: '$1 == "radio0" { print $3 }')" "connected"
	check "the wired device names its own profile" \
		"$(devices_full | awk -F: '$1 == "probe0" { print $4 }')" "probe0"

	# Writes are refused, with netcfgd's explanation rather than the bus's
	# "Unknown method". nmcli calls the newer spellings, so those exist purely
	# to be able to say no in netcfgd's words.
	# Creating a wifi network works and is checked below; creating anything
	# else is refused by name. An interface is configured by an `interface`
	# block, which is a file to edit rather than a profile to create -- and a
	# client that got a generic failure here would have no way to learn that.
	check "creating a wired profile is refused, and says why" \
		"$(timeout 15 nmcli connection add type ethernet ifname probe0 con-name x 2>&1 |
			grep -c 'wifi networks and nothing else' || true)" "1"
	check "modifying one is refused" \
		"$(nmcli connection modify HomeFiber connection.id x 2>&1 |
			grep -c 'read-only here' || true)" "1"
	check "deleting one is refused" \
		"$(nmcli connection delete HomeFiber 2>&1 |
			grep -c 'read-only here' || true)" "1"

	# And the secret never leaves. This is the one refusal that is a security
	# property rather than a missing feature.
	if command -v busctl >/dev/null 2>&1; then
		conn_path=$(busctl --user --address="$address" call \
			org.freedesktop.NetworkManager /org/freedesktop/NetworkManager/Settings \
			org.freedesktop.NetworkManager.Settings GetConnectionByUuid \
			s 7b9da559-bfbe-5bf1-82b1-bc18e6e2e81a 2>/dev/null |
			awk '{print $2}' | tr -d '"')
		check "a profile can be found by its uuid" \
			"$([ -n "$conn_path" ] && echo found || echo missing)" "found"
		check "and asking it for the passphrase is refused" \
			"$(busctl --user --address="$address" call org.freedesktop.NetworkManager \
				"$conn_path" org.freedesktop.NetworkManager.Settings.Connection \
				GetSecrets s 802-11-wireless-security 2>&1 |
				grep -c 'does not hand out secrets' || true)" "1"
		check "and the passphrase is nowhere in what it does hand out" \
			"$(busctl --user --address="$address" call org.freedesktop.NetworkManager \
				"$conn_path" org.freedesktop.NetworkManager.Settings.Connection \
				GetSettings 2>&1 | grep -c 'hunter2hunter2' || true)" "0"
	fi

	# ------------------------------------------------- what a panel shows

	# The Details tab of a settings panel, which was empty until the address
	# configuration objects existed: `Device.Ip4Config` was "/", NM's spelling
	# for "no object", so a panel opened on a working connection showed
	# nothing at all.
	details() { nmcli device show probe0 2>/dev/null; }
	detail() { details | awk -v want="$1" '$1 == want":" { print $2 }'; }

	check "the address a panel shows is the one netcfgd applied" \
		"$(detail 'IP4.ADDRESS[1]')" "10.7.7.1/24"
	check "and the gateway is the next hop of the default route" \
		"$(detail IP4.GATEWAY)" "10.7.7.254"
	# Establish that netcfgd has actually delivered the DNS, rather than
	# assuming the daemon's own pass got that far. It often has not.
	#
	# Execution stops at the first failed action (section 4), and this fixture
	# *guarantees* one: the `Prompted` network references a secret that does
	# not exist, so `backend.start radio0` fails on every apply -- deliberately,
	# because the secret-agent tests below are about exactly that. Every action
	# ordered after it is skipped, and `dns.apply` is one of them. So a panel
	# shows no nameservers because there are none: netcfgd never wrote them.
	#
	# Section 4 also says what to do about it -- "the remainder is re-runnable:
	# `ncfg apply` recomputes from current observed state and resumes cleanly"
	# -- and that is measured here rather than hoped for. One further apply
	# delivered the DNS in every occurrence seen; waiting does not, and ten
	# seconds of polling never saw it arrive on its own.
	#
	# Intermittent because it depends on how far the daemon's own applies had
	# got by the time these checks run, which is why it presented as three
	# unrelated panel checks failing together about two runs in ten.
	waited=0
	while [ ! -f "$work/resolv.conf" ] && [ "$waited" -lt 8 ]; do
		waited=$((waited + 1))
		"$repo/target/debug/ncfg" apply > /dev/null 2>&1 || true
	done
	if [ ! -f "$work/resolv.conf" ]; then
		echo "FAIL netcfgd delivered the DNS these panel checks read"
		echo "       no $work/resolv.conf after $waited applies, so the three"
		echo "       checks below would be asking about nothing"
		failures=$((failures + 1))
	fi
	# And the shim reads netcfgd's state over its monitor subscription, so give
	# that the moment it takes to arrive -- 200ms when measured. A bounded wait
	# on the value rather than a sleep, so a shim that never catches up fails
	# the check below rather than being papered over.
	waited=0
	while [ "$(detail 'IP4.DNS[1]')" != "10.0.0.1" ] && [ "$waited" -lt 50 ]; do
		waited=$((waited + 1))
		sleep 0.1
	done

	check "the nameservers come from what was applied, not from the config" \
		"$(detail 'IP4.DNS[1]')" "10.0.0.1"
	check "and the search domains with them" \
		"$(detail 'IP4.SEARCHES[1]')" "vibes.se"

	# A route with a next hop and a metric, which is the entry that exercises
	# every optional field at once.
	check "a route keeps its next hop and metric" \
		"$(details | grep -c 'dst = 10.9.0.0/16, nh = 10.7.7.9, mt = 600' || true)" "1"

	# Both families, from one device, through two objects with different
	# signatures for the same idea.
	check "the ipv6 address is there too" \
		"$(details | grep -c '2001:db8:7::1/64' || true)" "1"
	check "and the ipv6 nameserver" \
		"$(details | grep -c '2001:db8::1' || true)" "1"

	# The deprecated packed form against the modern one. NM still serves both,
	# and the packed integers are the half that is easy to get subtly wrong --
	# 10.7.7.1 is 0x0107070a read as a little-endian word.
	if command -v busctl >/dev/null 2>&1; then
		probe_dev=$(busctl --user --address="$address" call \
			org.freedesktop.NetworkManager /org/freedesktop/NetworkManager \
			org.freedesktop.NetworkManager GetDeviceByIpIface s probe0 2>/dev/null |
			awk '{print $2}' | tr -d '"')
		ip4_path=$(busctl --user --address="$address" get-property \
			org.freedesktop.NetworkManager "$probe_dev" \
			org.freedesktop.NetworkManager.Device Ip4Config 2>/dev/null |
			awk '{print $2}' | tr -d '"')
		check "the device points at a real address object" \
			"$(printf '%s' "$ip4_path" | grep -c '^/org/freedesktop/NetworkManager/IP4Config/' || true)" "1"
		check "and its deprecated packed form agrees with the address" \
			"$(busctl --user --address="$address" get-property \
				org.freedesktop.NetworkManager "$ip4_path" \
				org.freedesktop.NetworkManager.IP4Config Addresses 2>/dev/null |
				grep -c '17237770 24' || true)" "1"
	fi

	# ------------------------------------------ static addressing, both ways

	# What a panel reads when it opens a profile for editing. The method alone
	# was enough while nothing read the rest; a panel reporting `manual` with
	# an empty address table is one where pressing save deletes the address.
	if command -v busctl >/dev/null 2>&1 && command -v python3 >/dev/null 2>&1; then
		probe_profile=$(busctl --user --address="$address" call \
			org.freedesktop.NetworkManager /org/freedesktop/NetworkManager/Settings \
			org.freedesktop.NetworkManager.Settings GetConnectionByUuid \
			s 495c0b54-eb91-5818-92fe-63725172fd96 2>/dev/null | awk '{print $2}' | tr -d '"')

		# Through JSON rather than by grepping busctl's prose. The first
		# version matched on `"method" "s" "manual"` and found nothing --
		# busctl prints the type without quotes, and wraps -- so five checks
		# passed a value they had never seen.
		ip4() {
			busctl --user --address="$address" --json=short call \
				org.freedesktop.NetworkManager "$probe_profile" \
				org.freedesktop.NetworkManager.Settings.Connection GetSettings 2>/dev/null |
				python3 "$repo/tests/live/nm_setting.py" ipv4 "$1"
		}

		check "a static profile reports its method" "$(ip4 method)" "manual"
		check "and the address a panel would draw, with its prefix" \
			"$(ip4 address)" "10.7.7.1/24"
		check "the gateway is the default route's next hop" \
			"$(ip4 gateway)" "10.7.7.254"
		# And not also in the route table: NM keeps the default route's next hop
		# in `gateway` and everything else in `route-data`, so reporting it in
		# both would draw a duplicate row in every panel.
		check "a non-default route is in the route table, and the default is not" \
			"$(ip4 routes)" "10.9.0.0/16"
	fi

	# And back the other way: a client creating a network with a static address
	# has to produce a config line an operator would have written.
	nmcli connection add type wifi ifname '*' con-name Office ssid Office \
		ipv4.method manual ipv4.addresses 192.0.2.5/24 ipv4.gateway 192.0.2.1 \
		ipv4.routes "10.0.0.0/8 192.0.2.9 600" \
		> "$work/static.log" 2>&1 || true
	office="$work/etc/conf.d/nm-Office.conf"

	# The address is in the config list. Not the whole line: nmcli defaults
	# ipv6.method to auto, so `slaac` is in there beside it -- which is nmcli
	# asking for something real rather than noise to assert away.
	check "a static address written from a client becomes a config line" \
		"$(grep -c 'config = \["192.0.2.5/24"' "$office" 2>/dev/null || true)" "1"
	check "and the ipv6 method nmcli defaulted to came with it" \
		"$(grep -c '"slaac"' "$office" 2>/dev/null || true)" "1"
	check "the gateway comes back as a default route" \
		"$(grep -c 'default via 192.0.2.1' "$office" 2>/dev/null || true)" "1"
	check "and the other route keeps its next hop and metric" \
		"$(grep -c '10.0.0.0/8 via 192.0.2.9 metric 600' "$office" 2>/dev/null || true)" "1"
	check "netcfgd accepts what was written" \
		"$("$repo/target/debug/ncfg" show 2>/dev/null | grep -c '"id": "Office"' || true)" "1"

	timeout 15 nmcli connection delete Office > /dev/null 2>&1 || true

	# --------------------------------------------- per-connection options

	# What a settings panel offers beside the address. Round-tripped: the
	# fixture's HomeFiber carries them, and a client writes them back.
	if command -v busctl >/dev/null 2>&1 && command -v python3 >/dev/null 2>&1; then
		home_profile=$(busctl --user --address="$address" call \
			org.freedesktop.NetworkManager /org/freedesktop/NetworkManager/Settings \
			org.freedesktop.NetworkManager.Settings GetConnectionByUuid \
			s 7b9da559-bfbe-5bf1-82b1-bc18e6e2e81a 2>/dev/null | awk '{print $2}' | tr -d '"')
		option() {
			busctl --user --address="$address" --json=short call \
				org.freedesktop.NetworkManager "$home_profile" \
				org.freedesktop.NetworkManager.Settings.Connection GetSettings 2>/dev/null |
				python3 "$repo/tests/live/nm_setting.py" connection "$1"
		}
		check "a network reports the priority it was given" "$(option priority)" "30"
		# 1 is NM_METERED_YES. netcfgd's flag is a boolean, so `false` becomes
		# an explicit "no" rather than "unknown" -- an operator who wrote it
		# said something, and reporting unknown would have a desktop guess.
		check "and whether it is metered, as a statement rather than a guess" \
			"$(option metered)" "1"
		check "and whether it joins by itself" "$(option autoconnect)" "True"

		dns_of() {
			busctl --user --address="$address" --json=short call \
				org.freedesktop.NetworkManager "$home_profile" \
				org.freedesktop.NetworkManager.Settings.Connection GetSettings 2>/dev/null |
				python3 "$repo/tests/live/nm_setting.py" ipv4 "$1"
		}
		check "a network's own nameservers reach a panel" "$(dns_of dns)" "9.9.9.9"
		# And in the packed form an older client reads, which has to be the
		# same address: 9.9.9.9 is 0x09090909, which is 151587081 either way
		# round -- so the fixture uses it deliberately as the one address that
		# cannot tell a byte-order mistake apart, and the unit tests cover the
		# asymmetric case.
		check "and in the packed form beside it" "$(dns_of dns-packed)" "151587081"
		check "and its search domains" "$(dns_of dns-search)" "quad9.example"
	fi

	# And back: a client setting them has to produce the keys netcfgd reads.
	nmcli connection add type wifi ifname '*' con-name Opts ssid Opts \
		connection.metered yes connection.autoconnect-priority 42 \
		ipv4.dns 1.1.1.1 ipv4.dns-search example.com \
		> "$work/opts.log" 2>&1 || true
	opts="$work/etc/conf.d/nm-Opts.conf"

	check "metered comes back as a network key" \
		"$(grep -c 'metered = true' "$opts" 2>/dev/null || true)" "1"
	# Priority goes inside the wifi block, which is where netcfgd keeps the
	# keys a station uses to choose between networks.
	check "priority goes inside the wifi block" \
		"$(grep -c 'wifi { open = true; priority = 42 }' "$opts" 2>/dev/null || true)" "1"
	check "and the nameservers become a dns block" \
		"$(grep -c 'dns { servers = \["1.1.1.1"\]; search = \["example.com"\] }' "$opts" 2>/dev/null || true)" "1"
	check "which netcfgd accepts" \
		"$("$repo/target/debug/ncfg" show 2>/dev/null | grep -c '"id": "Opts"' || true)" "1"

	# An MTU is the one option that has nowhere to go: an interface has one and
	# an SSID does not. It is named in the file rather than silently ignored.
	timeout 15 nmcli connection delete Opts > /dev/null 2>&1 || true
	nmcli connection add type wifi ifname '*' con-name Mtu ssid Mtu \
		802-11-wireless.mtu 1400 > "$work/mtu.log" 2>&1 || true
	check "an option netcfgd cannot express is named in the file" \
		"$(grep -c '802-11-wireless.mtu' "$work/etc/conf.d/nm-Mtu.conf" 2>/dev/null || true)" "1"
	timeout 15 nmcli connection delete Mtu > /dev/null 2>&1 || true

	# ------------------------------------------------------- the write path

	# Design section 9.4: a GUI is just another editor of config files. What
	# comes out the other end of `nmcli connection add` has to be a netcfgd
	# block an operator could have typed.
	nmcli connection add type wifi ifname '*' con-name Roaming ssid Roaming \
		wifi-sec.key-mgmt wpa-psk wifi-sec.psk correcthorsebattery \
		> "$work/add.log" 2>&1 || true
	created="$work/etc/conf.d/nm-Roaming.conf"

	check "creating a network writes a netcfgd block" \
		"$([ -f "$created" ] && echo yes || echo no)" "yes"
	check "and netcfgd reads it" \
		"$("$repo/target/debug/ncfg" show 2>/dev/null |
			grep -c '"id": "Roaming"' || true)" "1"
	check "the block is what a person would have written" \
		"$(grep -c 'network "Roaming" {' "$created" || true)" "1"

	# The credential goes to the provider, and the block gets a reference. This
	# is constraint 5 applied to a file a GUI created.
	check "the passphrase is a reference, not a value" \
		"$(grep -c '@secret:Roaming' "$created" || true)" "1"
	check "and the value is nowhere in the block" \
		"$(grep -c 'correcthorsebattery' "$created" || true)" "0"
	check "the value is in the secrets directory" \
		"$(cat "$work/etc/secrets/Roaming" 2>/dev/null)" "correcthorsebattery"
	check "readable by nobody else" \
		"$(stat -c '%a' "$work/etc/secrets/Roaming" 2>/dev/null)" "600"

	# A lossy translation that says nothing is how somebody finds out months
	# later that a setting never took effect.
	check "what could not be translated is written into the file" \
		"$(grep -c '^#   ' "$created" || true)" "1"

	# An update from a client carries back what GetSettings gave it, which
	# never includes the passphrase. Requiring one would refuse every edit that
	# is not a password change.
	timeout 15 nmcli connection modify Roaming 802-11-wireless.hidden yes \
		> "$work/modify.log" 2>&1 || true
	check "editing a generated profile does not need the passphrase again" \
		"$(grep -c 'hidden = true' "$created" || true)" "1"
	check "and the secret it never sent is still there" \
		"$(cat "$work/etc/secrets/Roaming" 2>/dev/null)" "correcthorsebattery"

	# A hand-written block is not ours to edit, whatever a client asks. This is
	# the rule that stops a stray click rewriting a tuned interface.
	check "a hand-written block is still read-only" \
		"$(timeout 15 nmcli connection modify HomeFiber 802-11-wireless.hidden yes 2>&1 |
			grep -c 'read-only here' || true)" "1"
	check "and it is still in the configuration afterwards" \
		"$(grep -c 'HomeFiber' "$work/etc/netcfgd.conf" || true)" "1"

	timeout 15 nmcli connection delete Roaming > "$work/delete.log" 2>&1 || true
	waited=0
	while [ -f "$created" ] && [ "$waited" -lt 50 ]; do
		waited=$((waited + 1))
		sleep 0.1
	done
	check "deleting takes the file with it" \
		"$([ -f "$created" ] && echo yes || echo no)" "no"
	check "and the credential too, rather than leaving it for nothing" \
		"$([ -f "$work/etc/secrets/Roaming" ] && echo yes || echo no)" "no"
	check "and netcfgd no longer has the network" \
		"$("$repo/target/debug/ncfg" show 2>/dev/null |
			grep -c '"id": "Roaming"' || true)" "0"

	# --------------------------------------------------- the secret agent

	# Every object's introspection has to be XML. That sounds like it could not
	# fail, and it did: zbus copies doc comments into the introspection data,
	# and `--` is illegal inside an XML comment -- which is exactly what this
	# project's own style rule says to write instead of an em dash. Every
	# interface here was malformed, and only a client that introspects (which
	# dbus-python does by default, and GDBus does not) ever noticed.
	if command -v python3 >/dev/null 2>&1; then
		malformed=$(DBUS_SYSTEM_BUS_ADDRESS="$address" python3 - <<'PYEOF'
import sys
import xml.parsers.expat

import dbus

# Every kind of object the shim serves, one of each.
PATHS = [
    "/org/freedesktop/NetworkManager",
    "/org/freedesktop/NetworkManager/Settings",
    "/org/freedesktop/NetworkManager/AgentManager",
    "/org/freedesktop/NetworkManager/Devices/1",
]

bus = dbus.SystemBus()
bad = []
for path in PATHS:
    obj = bus.get_object("org.freedesktop.NetworkManager", path, introspect=False)
    data = obj.Introspect(dbus_interface="org.freedesktop.DBus.Introspectable")
    parser = xml.parsers.expat.ParserCreate()
    try:
        parser.Parse(data, True)
    except xml.parsers.expat.ExpatError as error:
        bad.append(f"{path}: {error}")

print(len(bad))
for line in bad:
    print(line, file=sys.stderr)
PYEOF
)
		check "every object's introspection is well-formed xml" "$malformed" "0"
	fi

	# A network whose credential does not exist, and nobody to ask. netcfgd's
	# own message is the useful one here; a shim that invented a complaint
	# about missing agents would send the operator looking for a desktop
	# problem on a machine with no desktop.
	#
	# Through busctl rather than nmcli, and that is the point rather than a
	# convenience: `nmcli connection up` registers a secret agent of its own
	# before it activates anything, so "no agent is registered" is a state
	# nmcli cannot be used to observe. It was written with nmcli first and hung
	# for twenty seconds -- the shim asking nmcli's agent, and nmcli, not being
	# in interactive mode, never answering.
	if command -v busctl >/dev/null 2>&1; then
		# The UUID is derived from the configuration, so a test can compute it
		# rather than hunt for it -- which is the property decision 0029 built
		# the derivation for.
		prompted_path=$(busctl --user --address="$address" call \
			org.freedesktop.NetworkManager /org/freedesktop/NetworkManager/Settings \
			org.freedesktop.NetworkManager.Settings GetConnectionByUuid \
			s 01db0f38-75b0-589c-8a47-a7e125a1b0e5 2>/dev/null |
			awk '{print $2}' | tr -d '"')
		radio_dev=$(busctl --user --address="$address" call \
			org.freedesktop.NetworkManager /org/freedesktop/NetworkManager \
			org.freedesktop.NetworkManager GetDeviceByIpIface s radio0 2>/dev/null |
			awk '{print $2}' | tr -d '"')
		check "with no agent, the missing secret is netcfgd's own message" \
			"$(timeout 20 busctl --user --address="$address" call \
				org.freedesktop.NetworkManager /org/freedesktop/NetworkManager \
				org.freedesktop.NetworkManager ActivateConnection ooo \
				"$prompted_path" "$radio_dev" / 2>&1 |
				grep -c 'secret `Prompted` was not found' || true)" "1"
	fi

	if command -v python3 >/dev/null 2>&1 && python3 -c 'import dbus' 2>/dev/null; then
		# An agent that refuses, the way a user pressing Escape does. The
		# activation must fail *and* leave nothing behind: a half-written
		# credential for a network nobody joined is worse than no credential.
		python3 "$repo/tests/live/fake_agent.py" --cancel refused \
			> "$work/agent-cancel.log" 2>&1 &
		cancel_agent=$!
		# `Register` is a synchronous D-Bus call, so the agent prints this only
		# after the shim has taken it -- the signal is sound and there is no
		# window between the two. What was not sound is giving up on it
		# silently: this loop used to `break` after ten seconds and run the
		# activation anyway, which turns "the agent never started" into
		# "netcfgd did not report a cancelled prompt". Say which one it is.
		waited=0
		until grep -q registered "$work/agent-cancel.log" 2>/dev/null; do
			waited=$((waited + 1))
			if [ "$waited" -gt 100 ]; then
				echo "FAIL the cancelling agent registered"
				echo "       it never printed \`registered\`; it said:"
				sed 's/^/       /' "$work/agent-cancel.log" 2>/dev/null
				failures=$((failures + 1))
				break
			fi
			sleep 0.1
		done
		# The timeout is a guard against hanging, not a deadline under test --
		# but when it fires the output is empty and the check below reports
		# `expected 1, actual 0`, which reads as netcfgd saying the wrong thing
		# rather than as nmcli having been killed. 124 is what `timeout` exits
		# with, and it gets its own sentence.
		# `|| cancel_status=$?`, never a bare assignment: `set -e` is on and
		# this activation is *expected* to fail -- the agent cancels. A bare
		# assignment therefore aborts the script at this line, which is how the
		# first version of this change ended the run mid-way with no summary and
		# every later check unrun. The same shape caught `ppp.sh` earlier in the
		# same session; "0 failed" and "all checks passed" are not the same
		# sentence.
		cancel_status=0
		# 60 rather than 25, because 25 is the number GDBus uses for its own
		# default method timeout -- so the old guard and nmcli's reply timeout
		# were the same value, racing. Whichever fired first decided what the
		# failure looked like, and the guard firing first hid nmcli's own
		# output, which is the thing worth reading.
		cancel_out=$(timeout 60 nmcli connection up Prompted ifname radio0 2>&1) ||
			cancel_status=$?
		if [ "$cancel_status" -eq 124 ]; then
			echo "FAIL a cancelled prompt is reported as such"
			echo "       nmcli did not return within 60s and was killed, so this"
			echo "       says nothing about what netcfgd reported"
			failures=$((failures + 1))
		elif ! printf '%s' "$cancel_out" | grep -q 'did not supply a passphrase'; then
			# Known intermittent, roughly one run in five, and **the shim's**
			# rather than this script's: `ActivateConnection` occasionally
			# returns nothing for GDBus's full 25-second default timeout, the
			# agent is never asked for a secret at all -- its log stops at
			# `registered` -- and nmcli exits having printed only its version
			# warning. Raising the timeout does not help, because the reply
			# never comes; it is a stall, not slowness.
			echo "FAIL a cancelled prompt is reported as such"
			echo "       nmcli returned without the expected message. It said:"
			printf '%s\n' "$cancel_out" | sed 's/^/       /'
			echo "       agent log: $(tr '\n' ' ' < "$work/agent-cancel.log" 2>/dev/null)"
			echo "       $(grep 'last agent asked' "$work/nm.log" 2>/dev/null | tail -1)"
			# The shim's own account, which is where the answer is. `nm.log` is
			# the file it writes to; naming any other one prints nothing at
			# exactly the moment it is wanted.
			echo "       --- the shim said (last 20 lines) ---"
			tail -20 "$work/nm.log" 2>/dev/null | sed 's/^/       /'
			echo "       --- end ---"
			echo "       NCFG_NM_TRACE=1 adds a checkpoint ring inside the shim,"
			echo "       dumped by its watchdog when a handler stalls (0107)"
			echo "       if the agent log stops at \`registered\`, the shim never"
			echo "       asked it -- see docs/decisions/0106"
			failures=$((failures + 1))
		else
			echo "ok   a cancelled prompt is reported as such"
		fi
		check "and writes no credential" \
			"$([ -f "$work/etc/secrets/Prompted" ] && echo yes || echo no)" "no"
		kill "$cancel_agent" 2>/dev/null
		wait "$cancel_agent" 2>/dev/null || true

		# And one that answers.
		python3 "$repo/tests/live/fake_agent.py" supersecretpass \
			> "$work/agent.log" 2>&1 &
		agent=$!
		waited=0
		until grep -q registered "$work/agent.log" 2>/dev/null; do
			waited=$((waited + 1))
			[ "$waited" -gt 100 ] && break
			sleep 0.1
		done

		before=$(wc -l < "$work/fake.log")
		timeout 25 nmcli connection up Prompted ifname radio0 > "$work/prompted.log" 2>&1 || true

		check "the agent was asked for the right setting" \
			"$(grep -c 'setting=802-11-wireless-security' "$work/agent.log" || true)" "1"
		# Flags 5 is ALLOW_INTERACTION|USER_REQUESTED: a person is waiting, so
		# an agent may put a dialog on the screen. Without them a real applet
		# would refuse silently rather than prompt.
		check "and told that a person is waiting" \
			"$(grep -c 'flags=5' "$work/agent.log" || true)" "1"

		check "the passphrase reached netcfgd's provider" \
			"$(cat "$work/etc/secrets/Prompted" 2>/dev/null)" "supersecretpass"
		check "readable by nobody else" \
			"$(stat -c '%a' "$work/etc/secrets/Prompted" 2>/dev/null)" "600"
		# The whole point of the bridge: the value goes to the provider and the
		# configuration keeps the reference it already had.
		check "and the configuration still holds only a reference" \
			"$(grep -c 'supersecretpass' "$work/etc/netcfgd.conf" || true)" "0"

		check "and the activation then reached the supplicant" \
			"$(tail -n +$((before + 1)) "$work/fake.log" | grep -c 'SELECT_NETWORK' || true)" "1"

		kill "$agent" 2>/dev/null
		wait "$agent" 2>/dev/null || true
	fi
fi

echo
if [ "$failures" -eq 0 ]; then
	echo "nm.sh: all checks passed"
else
	echo "nm.sh: $failures check(s) failed"
	exit 1
fi
