#!/bin/sh
# What a device the C port creates actually carries, against a real kernel.
#
#     unshare -rn sh tests/live/c_link_settings.sh
#
# Most link kinds are configured by the `RTM_NEWLINK` that creates them: the
# settings ride along in `IFLA_INFO_DATA` and the device exists configured.
# **Two are not**, and a create that stops at the link leaves those two on the
# kernel's defaults with the apply reporting `ok`:
#
#   * a WireGuard device cannot be -- its key, port, mark and peers go over
#     generic netlink. `c_wireguard.sh` is that half, and it needs the module;
#   * a bridge deliberately is not. The kernel would take `IFLA_INFO_DATA`
#     there and decision 0057 says not to: correcting an existing bridge has to
#     be a separate `RTM_NEWLINK` anyway, and one path rather than two is what
#     stops the two cases drifting apart.
#
# The port took the first half of 0057 and not the second, so every bridge it
# made came up with forward delay 15s, hello time 2s, priority 32768 and STP
# off, whatever the document said. There is no `link.set_bridge` in a plan that
# creates a bridge -- in either implementation, and correctly, because a create
# carries its whole configuration -- so nothing else was going to reach it.
#
# **The reader is `ip -d`, and the comparison is against the Rust.** Reading
# the state back through `ncfg status` would prove only that netcfgd agrees
# with itself, which is what section 9 warns about; `ip` is a third program
# with its own netlink code. The two implementations are given the same
# document in the same namespace, one after the other, and what the kernel
# holds afterwards has to be the same both times.
#
# Agreeing is not enough on its own -- two programs can be wrong alike -- so
# the bridge's four settings are also asserted against the numbers the
# document asked for. The kinds that ride along are here to keep it that way:
# bond, vxlan, vlan and macvlan were all identical when the bridge was not, and
# a future change that moves one of them off the create path would show here.

set -eu

repo=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)

skip() {
	if [ -n "${NCFG_LIVE:-}" ]; then
		echo "c_link_settings.sh: NCFG_LIVE is set but this cannot run: $1" >&2
		exit 1
	fi
	echo "c_link_settings.sh: skipping: $1"
	exit 0
}

command -v ip >/dev/null 2>&1 || skip "no ip(8)"
[ -x "$repo/c/ncfg" ] || skip "the C ncfg is not built (make -C c)"
[ -x "$repo/target/debug/ncfg" ] || skip "the Rust ncfg is not built, and it is the comparison"

work=$(mktemp -d "${TMPDIR:-/tmp}/ncfg-c-link-settings.XXXXXX")
cleanup() { rm -rf "$work"; }
trap cleanup EXIT INT TERM

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

# The kind line `ip -d` prints for a device, with what changes between runs
# taken out: the MAC is generated per link and the queue and offload numbers
# are the kernel's, not netcfgd's.
#
# **And a bridge's line carries clocks.** `hello_timer`, `gc_timer`,
# `tcn_timer` and `topology_change_timer` are the running state of a bridge
# that is up, and they tick -- so comparing the whole line compares when the
# two applies happened. This script did, and failed about twice in sixty-five
# runs with `hello_timer 0.99` against `1.00`: rare enough to look like a
# defect somewhere else, and reproducible in fifteen runs once the machine was
# made busy enough to put a hundredth of a second between them.
#
# Dropped by name rather than by rounding. What is left is the kind and its
# settings, which is what netcfgd put there.
kind_line() {
	ip -d link show "$1" 2>/dev/null | sed -n '3p' |
		sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//' \
		    -e 's/ addrgenmode.*//' \
		    -e 's/ [a-z_]*_timer  *[0-9.]*//g'
}

# Wait for a device to be gone, bounded, and say so if it is not.
#
# The two programs are given the same document one after the other in one
# namespace, so the second one's create happens where the first one's device
# was. `ip link del` returns when the request is accepted rather than when the
# link is torn down, and a create that lands in that window fails `EEXIST` --
# which is the script reporting a defect that is its own. Fifty tenths of a
# second is far past what a link teardown takes and far short of hanging.
gone() {
	waited=0
	while [ "$waited" -lt 50 ]; do
		ip link show "$1" >/dev/null 2>&1 || return 0
		sleep 0.1
		waited=$((waited + 1))
	done
	echo "FAIL $1 was still there five seconds after it was deleted"
	failures=$((failures + 1))
	return 1
}

# One program, one document, in this namespace. Each gets its own directories
# so that neither reads what the other recorded as owned.
apply_with() {
	tree="$work/$2"
	mkdir -p "$tree/etc" "$tree/run"
	cat > "$tree/etc/netcfgd.conf"
	NCFG_CONFIG_DIR="$tree/etc" NCFG_RUN_DIR="$tree/run" \
		timeout 60 "$1" apply > "$tree/out" 2>&1 && return 0
	echo "FAIL the apply itself ($2)"
	tail -3 "$tree/out"
	failures=$((failures + 1))
	return 1
}

# Both programs, the same document, and what the kernel holds after each.
# Written twice into the same namespace with the devices removed in between,
# which is what makes the two answers comparable rather than two machines'.
compare() {
	what="$1"
	devices="$2"
	document="$3"

	printf '%s\n' "$document" | apply_with "$repo/target/debug/ncfg" "rust" || return 0
	rust_says=""
	for device in $devices; do
		rust_says="$rust_says|$(kind_line "$device")"
	done
	for device in $devices; do
		ip link del "$device" 2>/dev/null || true
	done
	for device in $devices; do
		gone "$device" || return 0
	done

	printf '%s\n' "$document" | apply_with "$repo/c/ncfg" "c" || return 0
	c_says=""
	for device in $devices; do
		c_says="$c_says|$(kind_line "$device")"
	done

	check "$what" "$c_says" "$rust_says"
}

# ------------------------------------------------- the kind that was wrong

# Four settings, none of them the kernel's default, so every one of them is a
# statement. The timers are seconds in the document and hundredths in the
# kernel -- `ops.h` owns that conversion, and a bridge that differs from
# itself by a factor of a hundred is what the comment there is about.
BRIDGE='device br0 {
	bridge {
		stp           = true
		forward_delay = 4
		hello_time    = 1
		priority      = 4096
	}
}
interface br0 {
	config = "10.9.0.1/24"
}'

compare "a bridge comes up carrying what the document says" "br0" "$BRIDGE"

# And against the numbers themselves, because two programs agreeing is one
# witness when the same hand wrote both. These are the kernel's units.
bridge_value() {
	ip -d link show br0 2>/dev/null | tr -s ' \n' '\n' | grep -A1 "^$1\$" | tail -1
}
check "  with STP on, which it is not by default" "$(bridge_value stp_state)" "1"
check "  a forward delay of 4s and not 15" "$(bridge_value forward_delay)" "400"
check "  a hello time of 1s and not 2" "$(bridge_value hello_time)" "100"
check "  and the priority it was given, not 32768" "$(bridge_value priority)" "4096"
ip link del br0 2>/dev/null || true

# ------------------------------------------- the kinds that ride along

# Not decoration: these are the ones whose settings the create message carries,
# and they were identical while the bridge was not. A change that moved any of
# them onto a second message would land here rather than in somebody's bridge.

compare "a bond carries its mode and its link monitoring" "bond0" 'device bond0 {
	bond {
		mode   = "802.3ad"
		miimon = 250
	}
}
interface bond0 {
	config = "10.9.1.1/24"
}'
ip link del bond0 2>/dev/null || true

compare "a vxlan carries its id, its endpoints and its port" "vx0" 'device vx0 {
	vxlan {
		vni    = 42
		local  = "10.9.2.1"
		remote = "10.9.2.2"
		port   = 4789
	}
}
interface vx0 {
	config = "10.9.2.1/24"
}'
ip link del vx0 2>/dev/null || true

# Both over one parent, which is also the only case here where a device the
# document creates is another device's parent -- so the order the plan puts
# them in is part of what is being compared.
compare "a vlan and a macvlan carry theirs, over a parent made in the same plan" \
	"vl0 mv0" 'device base0 { kind = "dummy" }
device vl0 {
	vlan {
		parent = "base0"
		id     = 101
	}
}
device mv0 {
	macvlan {
		parent = "base0"
		mode   = "bridge"
	}
}
interface base0 {
	config = "10.9.3.1/24"
}
interface vl0 {
	config = "10.9.4.1/24"
}
interface mv0 {
	config = "10.9.5.1/24"
}'
for device in mv0 vl0 base0; do
	ip link del "$device" 2>/dev/null || true
done

if [ "$failures" -eq 0 ]; then
	echo "c_link_settings.sh: all checks passed"
else
	echo "c_link_settings.sh: $failures check(s) failed"
	exit 1
fi
