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
# **The reader is `ip -d`.** Reading the state back through `ncfg status`
# would prove only that netcfgd agrees with itself, which is what section 9
# warns about; `ip` is a third program with its own netlink code. Every
# setting is asserted against the number the document asked for, in the
# kernel's units.
#
# Until 0317 each device was also compared whole against what the Rust made
# from the same document. That comparison found the bridge; the assertions
# here are what it found it with, and they need nothing but the C. The kinds
# that ride along stay for the reason they were added: bond, vxlan, vlan and
# macvlan were right when the bridge was not, and a change that moved one of
# them off the create path would show here.

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
# **Runnable, not merely present.** `[ -x ]` answers "is there an executable
# file", which is not "can this machine run it" -- and the two differ wherever
# the libc the binary was linked against is not the one installed. Measured on
# Alpine 2026-10-23: this tree's glibc `ncfg` is `-x` there, and running it gets
# `not found` from the shell, because the ELF interpreter it names is absent.
# So the skip never fired, and a comparison binary that could not run reported
# as a missing file several checks later.
"$repo/c/ncfg" --version >/dev/null 2>&1 || skip "the C ncfg will not run here (a glibc build on musl)"

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

# One setting of a device as `ip -d` prints it: the word after KEY on the
# kind line. `ip -d` prints `key value` pairs, so splitting on space and
# taking what follows the key reads one without depending on the order or
# on what else this iproute2 prints beside it.
value_of() {
	ip -d link show "$1" 2>/dev/null | sed -n '3p' | tr -s ' \t' '\n' |
		grep -A1 -x -- "$2" | sed -n '2p'
}

# The C, one document, in this namespace, with directories of its own.
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

# Apply a document and check each named device exists afterwards.
apply_c() {
	what="$1"
	devices="$2"
	printf '%s\n' "$3" | apply_with "$repo/c/ncfg" "$4" || return 1
	for device in $devices; do
		if ! ip link show "$device" >/dev/null 2>&1; then
			echo "FAIL $what: $device was not created"
			failures=$((failures + 1))
			return 1
		fi
	done
	echo "ok   $what"
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

apply_c "a bridge comes up" "br0" "$BRIDGE" bridge
check "  with STP on, which it is not by default" "$(value_of br0 stp_state)" "1"
check "  a forward delay of 4s and not 15" "$(value_of br0 forward_delay)" "400"
check "  a hello time of 1s and not 2" "$(value_of br0 hello_time)" "100"
check "  and the priority it was given, not 32768" "$(value_of br0 priority)" "4096"
ip link del br0 2>/dev/null || true

# ------------------------------------------- the kinds that ride along

# Not decoration: these are the ones whose settings the create message carries,
# and they were identical while the bridge was not. A change that moved any of
# them onto a second message would land here rather than in somebody's bridge.

apply_c "a bond comes up" "bond0" 'device bond0 {
	bond {
		mode   = "802.3ad"
		miimon = 250
	}
}
interface bond0 {
	config = "10.9.1.1/24"
}' bond
check "  in 802.3ad" "$(value_of bond0 mode)" "802.3ad"
check "  monitoring its links every 250ms" "$(value_of bond0 miimon)" "250"
ip link del bond0 2>/dev/null || true

apply_c "a vxlan comes up" "vx0" 'device vx0 {
	vxlan {
		vni    = 42
		local  = "10.9.2.1"
		remote = "10.9.2.2"
		port   = 4789
	}
}
interface vx0 {
	config = "10.9.2.1/24"
}' vxlan
check "  with its id" "$(value_of vx0 id)" "42"
check "  its local end" "$(value_of vx0 local)" "10.9.2.1"
check "  its remote end" "$(value_of vx0 remote)" "10.9.2.2"
check "  and its port" "$(value_of vx0 dstport)" "4789"
ip link del vx0 2>/dev/null || true

# Both over one parent, which is also the only case here where a device the
# document creates is another device's parent -- so the order the plan puts
# them in is part of what is being checked.
apply_c "a vlan and a macvlan come up over a parent made in the same plan" \
	"base0 vl0 mv0" 'device base0 { kind = "dummy" }
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
}' stacked
check "  the vlan with its id" "$(value_of vl0 id)" "101"
check "  the macvlan in bridge mode" "$(value_of mv0 mode)" "bridge"
check "  the vlan over base0" "$(ip -o link show vl0 2>/dev/null | sed -n 's/.*: vl0@\([^:]*\):.*/\1/p')" "base0"
for device in mv0 vl0 base0; do
	ip link del "$device" 2>/dev/null || true
done

if [ "$failures" -eq 0 ]; then
	echo "c_link_settings.sh: all checks passed"
else
	echo "c_link_settings.sh: $failures check(s) failed"
	exit 1
fi
