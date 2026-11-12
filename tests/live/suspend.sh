#!/bin/sh
# A laptop's lid, measured: netcfgd across a real suspend and resume.
#
# WHY THIS FILE EXISTS
#   project.md's register, under "Suspend and resume have never been designed
#   for or run", lists what to measure in the order it will bite: whether a
#   lease that expired during the sleep is renewed or silently stale; whether
#   the supplicant is still associated and, if not, how long netcfgd takes to
#   notice; whether the rfkill watcher's blocking read survives; and what the
#   confirm window does across the lid. `tests/live/` cannot suspend the
#   machine it runs on, so none of it had been measured (10.773).
#
# WHERE IT RUNS
#   Only in a machine of its own that can suspend and be woken: `make
#   hull-suspend`, on hull's (sleep true), which hull built at netcfgd's asking
#   (f741a47; project.md 10.809). As root, with mac80211_hwsim, dnsmasq,
#   wpa_supplicant and dhcpcd -- the hwsim image has all four.
#
# HOW IT IS WOKEN
#   By the guest's own RTC alarm, which is what `rtcwake` does on a laptop:
#   `/sys/class/rtc/rtc0/wakealarm`, then `mem` (or $NCFG_SUSPEND_STATE) into
#   `/sys/power/state`. Nothing here is hull's syntax. A guest whose alarm does
#   not wake it never returns from the write, and the run ends at the
#   Makefile's timeout -- which is the answer "this hull cannot do it yet".
#
# THE NUMBERS
#   The lease is two minutes, dnsmasq's floor, and the sleep is 150 s, so the
#   lease runs out while the machine is asleep. The confirm window is 120 s,
#   so its wall-clock deadline also passes while asleep: 10.665 decided a
#   window pauses across a sleep, and this asks that it did.
#
# POSIX sh, not bash: this runs wherever the project does.

set -u

repo=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
build="${NCFG_LIVE_BUILD:-$repo/c}"
sleep_for="${NCFG_SUSPEND_SECONDS:-150}"
state="${NCFG_SUSPEND_STATE:-mem}"
ns=ncfg-suspend-ap
ssid=netcfgd-lid
passphrase=hunter2hunter2

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
note() { echo "     $*"; }
die() { echo "suspend.sh: $*" >&2; exit 1; }
skip() {
	echo "suspend.sh: skipping: $1"
	[ -n "${NCFG_LIVE:-}" ] && exit 1
	exit 0
}

[ "$(id -u)" = 0 ] || skip "needs real root (a module, a phy moved, the machine suspended)"
for tool in modprobe iw ip wpa_supplicant wpa_cli dnsmasq dhcpcd cc; do
	command -v "$tool" >/dev/null 2>&1 || skip "$tool is not installed"
done
[ -x "$build/netcfgd" ] && [ -x "$build/ncfg" ] || skip "netcfgd is not built"
[ -w /sys/class/rtc/rtc0/wakealarm ] || skip "no RTC alarm to be woken by"
grep -qw "$state" /sys/power/state || skip "this kernel cannot enter $state"

# The time spent suspended since boot: CLOCK_BOOTTIME counts it and
# CLOCK_MONOTONIC does not, which is how confirm.c measures it too.
asleep() {
	"$work/asleep"
}

work=$(mktemp -d /tmp/ncfg-suspend.XXXXXX)
cleanup() {
	status=$?
	[ -n "${daemon_job:-}" ] && kill "$daemon_job" 2>/dev/null
	[ -n "${control_job:-}" ] && kill "$control_job" 2>/dev/null
	[ -n "${timeline_job:-}" ] && kill "$timeline_job" 2>/dev/null
	ip netns pids "$ns" 2>/dev/null | xargs -r kill 2>/dev/null
	sleep 0.5
	# **Every step bounded** (10.809): the first runs that slept ended here
	# with no verdict, the log stopping after the summary -- a step that
	# waits on a radio the resume left odd is a step that never returns.
	[ -n "${daemon_job:-}" ] && { kill -9 "$daemon_job" 2>/dev/null; wait "$daemon_job" 2>/dev/null; }
	timeout 10 ip link del sus0 2>/dev/null
	# **Not waited for.** After a resume the namespace's delete and the
	# module's removal have each sat in the kernel past any timeout -- a
	# process in D state ignores the signal -- and the machine is discarded
	# after this anyway. Started and left, so the test can end.
	( ip netns delete "$ns"; modprobe -r mac80211_hwsim ) > /dev/null 2>&1 &
	case "$work" in /tmp/ncfg-suspend.*) rm -rf "$work" ;; esac
	exit "$status"
}
trap cleanup EXIT INT TERM

cat > "$work/asleep.c" <<'C'
#include <stdio.h>
#include <time.h>
int main(void)
{
	struct timespec boot, mono;
	clock_gettime(CLOCK_BOOTTIME, &boot);
	clock_gettime(CLOCK_MONOTONIC, &mono);
	printf("%ld\n", (long)(boot.tv_sec - mono.tv_sec));
	return 0;
}
C
cc -o "$work/asleep" "$work/asleep.c" 2>/dev/null || die "no compiler for the clock reader"

# ----------------------------------------------------------- two radios
modprobe mac80211_hwsim radios=2 || die "could not load mac80211_hwsim"
sleep 1
phys=$(ls /sys/class/ieee80211 | sort)
ap_phy=$(echo "$phys" | sed -n 1p)
sta_phy=$(echo "$phys" | sed -n 2p)
ap_dev=$(ls "/sys/class/ieee80211/$ap_phy/device/net" | head -1)
sta_dev=$(ls "/sys/class/ieee80211/$sta_phy/device/net" | head -1)
[ -n "$ap_dev" ] && [ -n "$sta_dev" ] || die "the radios have no interfaces"
ip netns add "$ns" || die "no network namespace"
iw phy "$ap_phy" set netns name "$ns" || die "could not move $ap_phy"
inns() { ip netns exec "$ns" "$@"; }
inns ip link set lo up

# ------------------------------------------- the access point and its DHCP
mkdir -p "$work/ap" "$work/etc/secrets" "$work/etc/conf.d" "$work/run" "$work/ctrl"
cat > "$work/ap/ap.conf" <<CONF
ctrl_interface=$work/ap/ctrl
network={
	ssid="$ssid"
	mode=2
	frequency=2412
	key_mgmt=WPA-PSK
	proto=RSN
	psk="$passphrase"
}
CONF
inns wpa_supplicant -B -Dnl80211 -i "$ap_dev" -c "$work/ap/ap.conf" > "$work/ap/log" 2>&1 ||
	die "could not start the access point"
inns ip addr add 10.77.0.1/24 dev "$ap_dev"
inns ip link set "$ap_dev" up
inns dnsmasq --no-daemon --port=0 --interface="$ap_dev" --bind-interfaces \
	--dhcp-range=10.77.0.50,10.77.0.99,2m --dhcp-leasefile="$work/ap/leases" \
	--pid-file="$work/ap/dnsmasq.pid" > "$work/ap/dnsmasq.log" 2>&1 &

# ----------------------------------------------- a dock: a wired link (10.810)
# **The case the radio cannot ask.** A station's resume drops the association,
# and the supplicant's reconnect makes the DHCP client ask again. A wire keeps
# its carrier across a suspend -- a veth here, a dock or a cable on a laptop --
# so nothing tells the client that the lease it holds ran out while its
# monotonic clock stood still. Same namespace, same two-minute lease.
ip link add sus-eth type veth peer name sus-dock netns "$ns" || die "no veth for the dock"
inns ip addr add 10.78.0.1/24 dev sus-dock
inns ip link set sus-dock up
inns dnsmasq --no-daemon --port=0 --interface=sus-dock --bind-interfaces \
	--dhcp-range=10.78.0.50,10.78.0.99,2m --dhcp-leasefile="$work/ap/wired.leases" \
	${NCFG_SUSPEND_AUTHORITATIVE:+--dhcp-authoritative} --log-dhcp \
	--pid-file="$work/ap/wired.pid" > "$work/ap/wired.log" 2>&1 &

# ------------------------------------------------- netcfgd as the station
printf '%s' "$passphrase" > "$work/etc/secrets/lid"
chmod 600 "$work/etc/secrets/lid"
cat > "$work/etc/netcfgd.conf" <<CONF
device $sta_dev {
	wifi { backend = "wpa_supplicant"; autoconnect = true }
}
interface $sta_dev {
	config = "dhcp"
}
interface sus-eth {
	config = "dhcp"
}
network "$ssid" {
	wifi { psk = "@secret:lid" }
}
CONF
export NCFG_CONFIG_DIR="$work/etc" NCFG_RUN_DIR="$work/run" NCFG_WPA_CTRL_DIR="$work/ctrl"
export NCFG_DHCPCD_HOOK="$repo/packaging/hooks/dhcpcd-hook"
# **The control** (10.809), `NCFG_SUSPEND_CONTROL=1`: the same radios and the
# same sleep with a plain wpa_supplicant as the station and no netcfgd, asking
# only whether it is associated again. It decides whose a station that does
# not come back is: netcfgd's, or the simulated radio's across a resume.
control="${NCFG_SUSPEND_CONTROL:-}"
if [ -n "$control" ]; then
	cat > "$work/sta.conf" <<CONF
ctrl_interface=$work/ctrl
network={
	ssid="$ssid"
	key_mgmt=WPA-PSK
	psk="$passphrase"
}
CONF
	ip link set "$sta_dev" up
	wpa_supplicant -Dnl80211 -i "$sta_dev" -c "$work/sta.conf" > "$work/daemon.log" 2>&1 &
	control_job=$!
else
	"$build/netcfgd" > "$work/daemon.log" 2>&1 &
	daemon_job=$!
fi

station_address() {
	ip -4 -o addr show dev "$sta_dev" 2>/dev/null | awk '/10\.77\.0\./ {print $4; exit}'
}
associated() {
	wpa_cli -p "$work/ctrl" -i "$sta_dev" status 2>/dev/null | sed -n 's/^wpa_state=//p'
}
# Whole seconds until `test` holds, up to `limit`; the limit plus one if never.
seconds_until() {
	limit=$1
	shift
	waited=0
	while [ "$waited" -le "$limit" ]; do
		"$@" && { echo "$waited"; return 0; }
		sleep 1
		waited=$((waited + 1))
	done
	echo $((limit + 1))
	return 1
}
has_address() { [ -n "$(station_address)" ]; }
wired_address() {
	ip -4 -o addr show dev sus-eth 2>/dev/null | awk '{print $4; exit}'
}
has_wired_address() { [ -n "$(wired_address)" ]; }
# The expiry dnsmasq granted last, from its lease file: what says whether the
# client asked again after a time.
granted() {
	inns cat "$1" 2>/dev/null | awk 'NR==1 {print $1}'
}
is_associated() { [ "$(associated)" = COMPLETED ]; }

took=$(seconds_until 60 is_associated)
[ "$took" -le 60 ] || { tail -20 "$work/daemon.log"; die "the station never associated"; }
if [ -z "$control" ]; then
	took=$(seconds_until 60 has_address)
	[ "$took" -le 60 ] || { tail -20 "$work/daemon.log"; die "the station never got a lease"; }
	echo "ok   the station is associated and leased: $(station_address)"
	took=$(seconds_until 60 has_wired_address)
	[ "$took" -le 60 ] || { tail -20 "$work/daemon.log"; die "the dock never got a lease"; }
	echo "ok   the dock is leased: $(wired_address)"
else
	echo "ok   CONTROL: a plain wpa_supplicant is associated, with no netcfgd"
fi

# ------------------------------------------------- a confirm window, armed
if [ -z "$control" ]; then
ip link add sus0 type dummy
cat > "$work/etc/conf.d/lid.conf" <<CONF
interface sus0 {
	config = "192.0.2.77/24"
}
CONF
"$build/ncfg" apply --confirm-within 120 > "$work/apply.log" 2>&1 ||
	{ cat "$work/apply.log"; die "could not arm a confirm window"; }
sleep 2
check "a confirm window is armed over a change" \
	"$(ip -4 -o addr show dev sus0 | grep -c 192.0.2.77)" 1
fi

# ------------------------------------------------------------- the lid
before_asleep=$(asleep)
# **A rig check, not a lid**, where $NCFG_SUSPEND_TEST names a pm_test level:
# the kernel suspends that far and comes straight back, so the rig's own
# mechanics are exercised on a machine that cannot yet be woken -- but nothing
# expires, and what it says about the lease and the window is about a pause of
# a few seconds, not a sleep.
if [ -n "${NCFG_SUSPEND_TEST:-}" ]; then
	echo "$NCFG_SUSPEND_TEST" > /sys/power/pm_test || die "no pm_test level $NCFG_SUSPEND_TEST"
	echo "     RIG CHECK ONLY: pm_test=$NCFG_SUSPEND_TEST, so nothing here is a real sleep"
fi
echo 0 > /sys/class/rtc/rtc0/wakealarm
echo "+$sleep_for" > /sys/class/rtc/rtc0/wakealarm
echo "     suspending to $state for ${sleep_for}s"
sync
started=$(date +%s)
echo "$state" > /sys/power/state
rc=$?
[ -n "${NCFG_SUSPEND_TEST:-}" ] && echo none > /sys/power/pm_test
woke=$(date +%s)
slept=$(( $(asleep) - before_asleep ))
# The dock, second by second from the wake (10.810): whether it holds an
# address, and the expiry dnsmasq granted last. A renewal that arrives is not
# enough; a laptop with no address for a minute after the lid opens is the
# fault the first dock run showed and its check did not.
if [ -z "$control" ]; then
	(
		n=0
		while [ "$n" -lt 150 ]; do
			echo "$n $(wired_address) $(granted "$work/ap/wired.leases")"
			sleep 1
			n=$((n + 1))
		done
	) > "$work/dock.timeline" 2>&1 &
	timeline_job=$!
fi
# **The access point did not sleep; this one did** (10.809). A laptop's access
# point is another machine, beaconing all the while. Here it shares the kernel
# and mac80211_hwsim stops its beacons across the resume -- the control,
# NCFG_SUSPEND_CONTROL=1, found a plain wpa_supplicant scanning an empty air
# exactly as netcfgd's did, the access point's radio sending 2 frames after the
# wake. So it is started again, as a power-on would, before the station is
# asked anything: what is measured is the station's recovery.
inns wpa_cli -p "$work/ap/ctrl" -i "$ap_dev" disable_network 0 > /dev/null 2>&1
inns wpa_cli -p "$work/ap/ctrl" -i "$ap_dev" enable_network 0 > /dev/null 2>&1
check "the machine came back from $state" "$rc" 0
note "wall clock moved $((woke - started))s; asleep by the clocks ${slept}s"
[ "$slept" -ge $((sleep_for - 10)) ] ||
	note "the kernel counted less sleep than asked for -- a test level, or a wake before the alarm"

# --------------------------------------------------------- what came back
# **The window first, at once** (10.809). It has its 120 s less the two spent
# before the sleep, so asked after the waits below -- up to six minutes awake
# -- it has rightly closed, and the first run here read that as a window that
# did not pause. Asked now, a window that did not pause has already reverted,
# its deadline having passed while asleep; one that paused still stands.
#
# **After ten seconds, not at once.** The daemon looks at the window on its
# next pass, five seconds apart at most, and asked within a second of the wake
# a window that did not pause had not been looked at yet: a netcfgd whose
# window ignored the sleep passed this check (10.809's sabotage). Ten seconds
# is two passes, and leaves the paused window over a hundred.
if [ -z "$control" ]; then
sleep 10
check "the confirm window paused while asleep: the change still stands" \
	"$(ip -4 -o addr show dev sus0 | grep -c 192.0.2.77)" 1
"$build/ncfg" confirm > "$work/confirm.log" 2>&1
check "and it can still be confirmed" "$?" 0
fi

took=$(seconds_until 120 is_associated)
note "associated again ${took}s after resume"
check "the supplicant is associated again within two minutes" \
	"$([ "$took" -le 120 ] && echo yes || echo no)" yes
if [ "$took" -gt 120 ]; then
	# Both ends, since either can be what did not come back.
	note "station: $(wpa_cli -p "$work/ctrl" -i "$sta_dev" status 2>&1 | tr '\n' ' ')"
	note "station link: $(iw dev "$sta_dev" link 2>&1 | tr '\n' ' ')"
	note "access point: $(inns wpa_cli -p "$work/ap/ctrl" -i "$ap_dev" status 2>&1 | tr '\n' ' ')"
	note "access point radio: $(inns iw dev "$ap_dev" info 2>&1 | tr '\n' ' ')"
	note "scan: $(wpa_cli -p "$work/ctrl" -i "$sta_dev" scan_results 2>&1 | tr '\n' ' ')"
	note "kernel: $(dmesg 2>/dev/null | tail -12 | tr '\n' '|')"
fi
if [ -n "$control" ]; then
	echo
	echo "suspend.sh: CONTROL ended, $failures failed: association only, no netcfgd"
	[ "$failures" -eq 0 ] || exit 1
	exit 0
fi

took=$(seconds_until 120 has_address)
note "addressed ${took}s after resume: $(station_address)"
# A lease that expired asleep, renewed: dnsmasq's file carries the expiry it
# granted, and one more than 100 s past the wake on a 120 s lease was granted
# within twenty seconds of it -- a lease the client asked for after waking,
# where the one from before the sleep ran out while asleep.
renewed=no
waited=0
while [ "$waited" -le 120 ]; do
	expiry=$(inns cat "$work/ap/leases" 2>/dev/null | awk 'NR==1 {print $1}')
	if [ -n "$expiry" ] && [ "$expiry" -gt $((woke + 100)) ]; then
		renewed=yes
		break
	fi
	sleep 1
	waited=$((waited + 1))
done
check "the lease that ran out while asleep is renewed, not held stale" "$renewed" yes

if [ -z "$control" ]; then
	# The dock's lease ran out asleep too. Renewed means a grant from dnsmasq
	# after the wake: an expiry more than 100 s past it on a 120 s lease.
	wired_renewed=no
	waited=0
	while [ "$waited" -le 120 ]; do
		expiry=$(granted "$work/ap/wired.leases")
		if [ -n "$expiry" ] && [ "$expiry" -gt $((woke + 100)) ]; then
			wired_renewed=yes
			break
		fi
		sleep 1
		waited=$((waited + 1))
	done
	note "dock: renewed after ${waited}s; it holds $(wired_address)"
	check "a wired lease that ran out while asleep is renewed, not held stale" \
		"$wired_renewed" yes
	[ -n "${timeline_job:-}" ] && wait "$timeline_job" 2>/dev/null
	# Seconds after the wake with no address, and the first second a lease
	# granted after the wake was seen.
	gap=$(awk 'NF < 2 || $2 !~ /\// { n++ } END { print n + 0 }' "$work/dock.timeline")
	first=$(awk -v w="$woke" 'NF >= 3 && $3 > w + 100 { print $1; exit }' "$work/dock.timeline")
	note "dock: ${gap}s of the first 150 with no address; renewed at ${first:-never}s"
	note "dock timeline: $(awk '{ printf "%s:%s ", $1, (NF >= 2 && $2 ~ /\//) ? "a" : "-" }' "$work/dock.timeline")"
	note "dock's dhcp server: $(grep -E 'DHCP(DISCOVER|OFFER|REQUEST|ACK|NAK|RELEASE|DECLINE|INFORM)|ignor|lease not found' "$work/ap/wired.log" 2>/dev/null | tail -20 | tr '\n' '|')"
	note "daemon after the wake: $(awk -v w="$woke" 'BEGIN{p=0} /suspending|resum|dhcp|lease|sus-eth/ {print}' "$work/daemon.log" | tail -15 | tr '\n' '|')"
	check "the dock keeps an address, or has one again within 15 s of the wake" \
		"$([ "$gap" -le 15 ] && echo yes || echo no)" yes
	# **Asked again soon, not when its own clock runs out** (10.810). Before
	# netcfgd asked its clients to renew after a sleep, the dock held the lease
	# that ran out asleep for 103 s, its timers on a clock that had stood
	# still, and asked again at 112 s.
	check "the dock asks for its lease again within 30 s of the wake" \
		"$([ -n "$first" ] && [ "$first" -le 30 ] && echo yes || echo no)" yes
fi

# The rfkill watcher: does it still hear a block after the resume? Through
# the kernel's own switch in sysfs, which needs no tool -- the hwsim image has
# no `rfkill`, and a check that skipped for want of one asked nothing.
switch=$(ls -d /sys/class/ieee80211/"$sta_phy"/rfkill* 2>/dev/null | head -1)
if [ -n "$switch" ] && [ -w "$switch/soft" ]; then
	# Asked of the daemon rather than read from its log: a block plans
	# nothing to log (10.791 stopped the `link.up` that used to fail, loudly,
	# on every pass), so what shows the watcher heard is the status saying
	# the radio is off, and the link coming back up once it is on again.
	says_off() {
		"$build/ncfg" wifi status "$sta_dev" 2>/dev/null | grep -qi 'switched off'
	}
	link_up() {
		ip -o link show "$sta_dev" 2>/dev/null | grep -q '[<,]UP[,>]'
	}
	echo 1 > "$switch/soft"
	heard=$(seconds_until 15 says_off)
	check "the rfkill watcher still hears a block after the resume" \
		"$([ "$heard" -le 15 ] && echo yes || echo no)" yes
	echo 0 > "$switch/soft"
	back=$(seconds_until 30 link_up)
	check "  and brings the radio up again when the switch comes back" \
		"$([ "$back" -le 30 ] && echo yes || echo no)" yes
else
	note "no rfkill switch under $sta_phy; the watcher was not asked"
fi

echo
if [ "$failures" -ne 0 ]; then
	echo "suspend.sh: $failures failed; the daemon said:"
	tail -30 "$work/daemon.log"
	exit 1
fi
echo "suspend.sh: all checks passed"
