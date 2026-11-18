#!/bin/sh
# Handing a router's network from netifd to netcfgd and back, with the
# switcher the package ships (project.md 10.874).
#
# A router has no console, so the switch is held: netifd stopped and still
# enabled, netcfgd started and not yet enabled, until `netcfgd_select.sh
# confirm`; without it, a watcher switches back. Checked, in order:
#
#   - stock netifd runs and is enabled, as on any OpenWrt;
#   - selecting netcfgd stops netifd without disabling it, starts netcfgd
#     without enabling it, and records the switch as pending;
#   - a second switch while one is pending is refused;
#   - left unconfirmed, the window ends with netifd back and netcfgd gone;
#   - selected again and confirmed, netifd is disabled and netcfgd enabled,
#     and that holds past the window;
#   - selecting netifd with no window puts the router back as it came.
#
# Always exits 0 and reports through /verdict/openwrt-select.
#
# HOW IT STOPS: every wait is bounded (ubus at 40 s, each change at 20 s, the
# windows at 15 and 30 s), the steps are a fixed list, and the vm takes procd,
# netifd and netcfgd with it.
out=/verdict/openwrt-select
: > "$out"
say() { echo "$*" >> "$out"; echo "openwrt-select: $*"; }
failed=0
check() { # $1 what, $2 got, $3 wanted
	if [ "$2" = "$3" ]; then
		say "ok   $1"
	else
		say "FAIL $1: got '$2', wanted '$3'"
		failed=1
	fi
}
bad() {
	say "VERDICT bad: $*"
	exit 0
}
running() { pidof "$1" > /dev/null 2>&1 && echo running || echo stopped; }
enabled() { "/etc/init.d/$1" enabled 2>/dev/null && echo enabled || echo disabled; }
# Seconds until `$1` succeeds, or "never" after `$2` (default 20).
within() {
	n=0
	limit=${2:-20}
	until eval "$1" > /dev/null 2>&1 || [ $n -gt "$limit" ]; do
		sleep 1
		n=$((n + 1))
	done
	[ $n -gt "$limit" ] && echo never || echo $n
}
switch_to() { netcfgd_select.sh "$@" > /tmp/select.log 2>&1; }

say "pid 1 is $(cat /proc/1/comm); $(grep DISTRIB_RELEASE /etc/openwrt_release)"
n=0
until ubus call service list > /dev/null 2>&1 || [ $n -gt 40 ]; do sleep 1; n=$((n + 1)); done
ubus call service list > /dev/null 2>&1 || bad "procd's ubus never answered"
[ "$(within '[ "$(running netifd)" = running ]')" != never ] || bad "netifd never ran"

apk add --allow-untrusted --no-network /payload/netcfgd.apk > /tmp/apk.log 2>&1 ||
	bad "apk would not add netcfgd: $(tail -2 /tmp/apk.log)"
[ -x /usr/sbin/netcfgd_select.sh ] || bad "the package carries no switcher"
mkdir -p /etc/netcfgd
: > /etc/netcfgd/netcfgd.conf

check "stock: netifd runs" "$(running netifd)" running
check "  and is enabled" "$(enabled network)" enabled

switch_to netcfgd --confirm=15 --no-wait
check "a switch to netcfgd is made" "$?" 0
check "  netcfgd runs" "$([ "$(within '[ "$(running netcfgd)" = running ]')" != never ] && echo running || echo stopped)" running
check "  netifd is stopped" "$(running netifd)" stopped
check "  and still enabled, so a reboot comes back on it" "$(enabled network)" enabled
check "  netcfgd is not yet enabled" "$(enabled netcfgd)" disabled
check "  the switch waits to be confirmed" "$([ -f /var/run/netcfgd-select.pending ] && echo pending || echo none)" pending

switch_to netifd --no-wait
check "a second switch while one waits is refused" "$?" 1

took=$(within '[ "$(running netifd)" = running ] && [ "$(running netcfgd)" = stopped ]' 30)
check "unconfirmed, the window ends with netifd back and netcfgd gone" \
	"$([ "$took" != never ] && echo back || echo "not back")" back
check "  netifd still enabled" "$(enabled network)" enabled
check "  netcfgd not enabled" "$(enabled netcfgd)" disabled
check "  nothing pending" "$([ -f /var/run/netcfgd-select.pending ] && echo pending || echo none)" none

switch_to netcfgd --confirm=15 --no-wait
switch_to confirm
check "a confirmed switch is answered" "$?" 0
check "  netifd is disabled" "$(enabled network)" disabled
check "  netcfgd is enabled" "$(enabled netcfgd)" enabled
sleep 20
check "  and past the window netcfgd still runs" "$(running netcfgd)" running
check "  and netifd does not" "$(running netifd)" stopped

switch_to netifd --confirm=0 --no-wait
check "selecting netifd with no window" "$?" 0
check "  puts netifd back, enabled" "$(enabled network)/$([ "$(within '[ "$(running netifd)" = running ]')" != never ] && echo running || echo stopped)" enabled/running
check "  and netcfgd away, disabled" "$(enabled netcfgd)/$([ "$(within '[ "$(running netcfgd)" = stopped ]')" != never ] && echo stopped || echo running)" disabled/stopped

if [ "$failed" -ne 0 ]; then
	sed 's/^/  select: /' /tmp/select.log >> "$out"
	logread 2>/dev/null | grep -E 'netcfgd|netifd|netcfgd_select' | tail -15 |
		sed 's/^/  log: /' >> "$out"
	say "VERDICT bad"
else
	say "VERDICT ok"
fi
exit 0
