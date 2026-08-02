#!/bin/sh
# Association, against simulated radios.
#
# The one thing wifi.sh cannot cover. It drives a real wpa_supplicant but has
# no radio, so everything up to "and then it joins the network" is verified and
# the joining is not. This loads mac80211_hwsim, stands up an access point on
# one virtual radio, and has netcfgd associate with it from the other.
#
#     sudo sh tests/live/hwsim.sh
#
# Needs real root: loading a module, creating a network namespace, and moving a
# wireless phy between namespaces are all things a user namespace cannot do.
#
# ## What it does to the machine, and what it undoes
#
# It loads `mac80211_hwsim`, which creates virtual radios. It does not touch
# any real wireless device: `mac80211` and `cfg80211` are already loaded by
# whatever driver your card uses, so nothing that card depends on is reloaded.
#
# Both virtual radios are moved into a private network namespace immediately,
# before anything else can notice them. That is not tidiness -- NetworkManager
# will happily adopt a new wireless device, start scanning on it, and point its
# own supplicant at the interface this test is trying to use. In a namespace it
# cannot see them.
#
# On exit -- including on failure or interrupt -- the namespace is deleted and
# the module is unloaded, but *only* if this script loaded it. A machine that
# already had `mac80211_hwsim` loaded is one where somebody else is using it,
# and this refuses to run rather than removing it out from under them.

set -eu

repo=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
ns=ncfg-hwsim
loaded_here=
created_ns=

find_in_sbin() {
	for dir in /usr/sbin /sbin /usr/local/sbin /usr/bin /bin; do
		if [ -x "$dir/$1" ]; then
			echo "$dir/$1"
			return 0
		fi
	done
	return 1
}

die() {
	echo "hwsim.sh: $1" >&2
	exit 1
}

skip() {
	if [ -n "${NCFG_LIVE:-}" ]; then
		echo "hwsim.sh: NCFG_LIVE is set but this cannot run: $1" >&2
		exit 1
	fi
	echo "hwsim.sh: skipping: $1"
	exit 0
}

# ---------------------------------------------------------------- preflight

[ "$(id -u)" = 0 ] || skip "needs real root (module loading and phy netns moves)"

supplicant=$(find_in_sbin wpa_supplicant) || skip "wpa_supplicant is not installed"
iw=$(find_in_sbin iw) || skip "iw is not installed (apt install iw)"
ip=$(find_in_sbin ip) || die "no ip(8), which is not something this can work around"
[ -x "$repo/target/debug/ncfg" ] || skip "netcfgd is not built (cargo build --workspace)"

# The AP side is wpa_supplicant in AP mode rather than hostapd, so this needs
# no package the station side did not already need. That requires the binary to
# have been built with CONFIG_AP=y, which Debian's is.
#
# There is deliberately no preflight check for it. The first version of this
# script grepped the binary for `AP-ENABLED`, anchored -- and the string in the
# binary is `AP-ENABLED ` with a trailing space, so the check reported "no AP
# mode" on a build that has it and skipped the entire test. A check that can
# only produce a false negative, on the one machine it was written for, is
# worse than no check: it turns a test that would have run into a test that
# reports "skipped" and looks fine.
#
# If AP mode really is missing, the access point below fails to start and the
# diagnostic there says so, having read what wpa_supplicant actually printed
# rather than guessing from the binary.

# A radio that cannot exist here is a missing tool, and the Makefile says so in
# as many words: a machine that cannot run this should get a skip rather than a
# failure. It did not get one. `make live` as root inside a container aborted
# the whole suite at `modprobe: not found` -- which is the one way this suite is
# meant to be run in full, since three of its scripts need real root.
#
# The line is drawn where the answer stops being about this machine: no kmod and
# no module in this kernel are both "not here", while a module that exists and
# will not load is worth going red over, and the `die` below still does that.
command -v modprobe >/dev/null 2>&1 || skip "no modprobe (apt install kmod)"
modinfo mac80211_hwsim >/dev/null 2>&1 ||
	skip "this kernel has no mac80211_hwsim module"

if grep -q '^mac80211_hwsim ' /proc/modules; then
	die "mac80211_hwsim is already loaded, so something else is using it.
       This will not unload a module it did not load. Run
       \`rmmod mac80211_hwsim\` yourself first if it is safe to."
fi

# ------------------------------------------------------------------ cleanup

cleanup() {
	status=$?
	set +e
	[ -n "$created_ns" ] && "$ip" netns pids "$ns" 2>/dev/null | xargs -r kill 2>/dev/null
	[ -n "$created_ns" ] && "$ip" netns delete "$ns" 2>/dev/null
	# The phys go back to the initial namespace when the namespace is deleted,
	# and then away entirely with the module. Unloading is what keeps this from
	# leaving two wireless devices for the desktop to find.
	if [ -n "$loaded_here" ]; then
		# The module can take a moment to become removable after its
		# interfaces go away.
		for _ in 1 2 3 4 5; do
			rmmod mac80211_hwsim 2>/dev/null && break
			sleep 0.4
		done
		if grep -q '^mac80211_hwsim ' /proc/modules; then
			echo "hwsim.sh: could not unload mac80211_hwsim; \`rmmod mac80211_hwsim\`" >&2
		fi
	fi
	[ -n "${work:-}" ] && rm -rf "$work"
	exit "$status"
}
trap cleanup EXIT INT TERM

# -------------------------------------------------------------- the radios

before=$(ls /sys/class/ieee80211 2>/dev/null | sort)
modprobe mac80211_hwsim radios=2 || die "could not load mac80211_hwsim"
loaded_here=yes
# udev renames interfaces asynchronously; give it a moment before reading them.
sleep 1
after=$(ls /sys/class/ieee80211 | sort)

phys=$(echo "$before
$after" | sort | uniq -u)
[ "$(echo "$phys" | wc -l)" = 2 ] || die "expected 2 new phys, got: $(echo "$phys" | tr '\n' ' ')"

ap_phy=$(echo "$phys" | head -1)
sta_phy=$(echo "$phys" | tail -1)

netdev_of() {
	ls "/sys/class/ieee80211/$1/device/net" 2>/dev/null | head -1
}
ap_dev=$(netdev_of "$ap_phy")
sta_dev=$(netdev_of "$sta_phy")
[ -n "$ap_dev" ] && [ -n "$sta_dev" ] || die "the new phys have no interfaces"

echo "hwsim.sh: ap $ap_phy/$ap_dev, station $sta_phy/$sta_dev"

"$ip" netns add "$ns" || die "could not create the network namespace"
created_ns=yes
# Into the namespace before anything else can adopt them.
"$iw" phy "$ap_phy" set netns name "$ns" || die "could not move $ap_phy"
"$iw" phy "$sta_phy" set netns name "$ns" || die "could not move $sta_phy"
"$ip" -n "$ns" link set lo up

inns() { "$ip" netns exec "$ns" "$@"; }

# ------------------------------------------------------------------ fixtures

# Short, because a unix socket path has to fit in SUN_LEN.
work=$(mktemp -d /tmp/ncfg-hwsim.XXXXXX)
mkdir -p "$work/etc/secrets" "$work/run" "$work/ctrl" "$work/ap"

passphrase=hunter2hunter2

# The access point. wpa_supplicant in AP mode: `mode=2` with an explicit
# frequency, since there is no scan to learn one from.
#
# Channel 1 (2412 MHz) because AP mode needs permission to transmit, and the
# world-roaming regulatory domain a fresh hwsim radio inherits allows it there:
# the 2402-2472 range carries no NO-IR flag. Pick a channel that does and the
# radio comes up and never beacons, which looks like an association failure
# several steps later.
#
# Nothing here changes the regulatory domain, and it would not matter to a real
# card if it did -- modern wifi hardware registers as self-managed and ignores
# the global setting.
cat > "$work/ap/ap.conf" <<CONF
ctrl_interface=$work/ap/ctrl
update_config=0

network={
	ssid="netcfgd-test"
	mode=2
	frequency=2412
	key_mgmt=SAE WPA-PSK
	proto=RSN
	ieee80211w=1
	psk="$passphrase"
}
CONF

cat > "$work/etc/netcfgd.conf" <<CONF
device $sta_dev {
	wifi { backend = "wpa_supplicant"; autoconnect = true }
}

network "netcfgd-test" {
	wifi   { psk = "@secret:test"; proto = "wpa2+wpa3" }
	config = "null"
}

interface $sta_dev { config = "null" }
CONF
printf '%s' "$passphrase" > "$work/etc/secrets/test"
chmod 600 "$work/etc/secrets/test"

ncfg="$repo/target/debug/ncfg"
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

# ------------------------------------------------------------- the access point

inns "$supplicant" -B -Dnl80211 -i "$ap_dev" -c "$work/ap/ap.conf" \
	> "$work/ap/log" 2>&1 || die "could not start the access point"

# Polled through the control socket rather than by watching the log: with `-B`
# the interesting output happens after the fork, where the redirect no longer
# reaches. In AP mode `wpa_state` reaches COMPLETED once the BSS is up.
waited=0
ap_state=
until [ "$ap_state" = COMPLETED ]; do
	ap_state=$(inns "$cli" -p "$work/ap/ctrl" -i "$ap_dev" status 2>/dev/null |
		sed -n 's/^wpa_state=//p')
	waited=$((waited + 1))
	if [ "$waited" -gt 150 ]; then
		echo "hwsim.sh: the access point never came up (last state: ${ap_state:-none})" >&2
		if grep -q 'not included in the build' "$work/ap/log"; then
			echo "hwsim.sh: this wpa_supplicant was built without CONFIG_AP." >&2
			echo "hwsim.sh:   install hostapd and use it as the AP instead." >&2
		fi
		cat "$work/ap/log" >&2
		exit 1
	fi
	sleep 0.1
done
echo "ok   the access point is beaconing"

# ------------------------------------------------------------------- netcfgd

# `ncfg wifi *` goes over the control socket, so the daemon has to be running
# inside the namespace -- exporting these here would only affect this shell.
innc() {
	inns env NCFG_CONFIG_DIR="$work/etc" NCFG_RUN_DIR="$work/run" \
		NCFG_WPA_CTRL_DIR="$work/ctrl" "$@"
}

innc "$repo/target/debug/netcfgd" --no-apply-on-start > "$work/daemon.log" 2>&1 &
waited=0
while [ ! -e "$work/run/netcfgd.sock" ]; do
	waited=$((waited + 1))
	if [ "$waited" -gt 100 ]; then
		cat "$work/daemon.log" >&2
		die "the daemon never bound its socket"
	fi
	sleep 0.1
done

plan=$(innc "$ncfg" plan)
contains "the plan starts a supplicant for the radio" "$plan" "backend.start $sta_dev"

innc "$ncfg" apply > "$work/apply.log" 2>&1 || {
	echo "FAIL apply did not succeed"
	cat "$work/apply.log"
	exit 1
}
echo "ok   netcfgd started a supplicant and gave it the network"

# ---------------------------------------------------------------- association
#
# The whole point of the file. Everything above this line was already covered
# without a radio.

waited=0
state=
until [ "$state" = COMPLETED ]; do
	state=$(inns "$cli" -p "$work/ctrl" -i "$sta_dev" status 2>/dev/null |
		sed -n 's/^wpa_state=//p')
	waited=$((waited + 1))
	if [ "$waited" -gt 200 ]; then
		echo "FAIL never associated (last state: ${state:-none})"
		inns "$cli" -p "$work/ctrl" -i "$sta_dev" status 2>&1 | head -20
		failures=$((failures + 1))
		break
	fi
	sleep 0.1
done
[ "$state" = COMPLETED ] && echo "ok   associated"

if [ "$state" = COMPLETED ]; then
	status=$(inns "$cli" -p "$work/ctrl" -i "$sta_dev" status)
	ssid=$(printf '%s\n' "$status" | sed -n 's/^ssid=//p')
	check "on the network the document named" "$ssid" "netcfgd-test"

	# Transitional mode has to actually negotiate one of the two, and which
	# one is the thing no fixture could ever tell us.
	keymgmt=$(printf '%s\n' "$status" | sed -n 's/^key_mgmt=//p')
	case "$keymgmt" in
	SAE | WPA2-PSK* | WPA-PSK*)
		echo "ok   negotiated $keymgmt from the transitional offer"
		;;
	*)
		echo "FAIL unexpected key management: $keymgmt"
		failures=$((failures + 1))
		;;
	esac

	# And netcfgd's own view agrees with the supplicant's, resolved back to
	# the `network` block it came from. A status that cannot name the block
	# means decision 0015 does not hold.
	own=$(innc "$ncfg" wifi status 2>&1 || true)
	contains "ncfg agrees it is associated" "$own" "COMPLETED"
	contains "and names the network block" "$own" "netcfgd-test"

	scan=$(innc "$ncfg" wifi scan 2>&1 || true)
	contains "a scan finds the access point" "$scan" "netcfgd-test"
fi

echo
if [ "$failures" -eq 0 ]; then
	echo "hwsim.sh: all checks passed"
else
	echo "hwsim.sh: $failures failed"
	exit 1
fi
