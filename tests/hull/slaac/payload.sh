#!/bin/sh
# SLAAC on an interface that forwards, against hull's advertiser (0073,
# project.md 10.624). The twin of tests/live/slaac.sh, which needs dnsmasq to
# advertise and so skips on a machine without it; here hull answers the
# kernel's router solicitation with the segment's /64 for SLAAC.
#
# **hull advertises only when asked**, and a kernel asks only when it would
# act on the answer: at `accept_ra` 2, or on an interface that does not
# forward. So the wire is proved first, at 2, before anything is concluded
# from an address that does not arrive -- the same ordering slaac.sh uses, for
# its reason: the surest way to see no address is for nobody to be
# advertising.
#
# Asserted:
#   - the interface forwards and its accept_ra is the kernel's default;
#   - at accept_ra 2 the kernel solicits and configures an address from the
#     advertised prefix (the wire works);
#   - at accept_ra 1, forwarding, no address comes;
#   - netcfgd's plan for `config = "slaac"` sets accept_ra, names the
#     forwarding as the reason, and does so before the link comes up;
#   - the apply writes 2 and the kernel configures an address from the prefix;
#   - a second plan has nothing to do; dropping slaac hands back 1; and a value
#     netcfgd never wrote is left alone.
#
# Always exits 0 and reports through /verdict/slaac.
#
# HOW IT STOPS: every wait is a bounded loop (60 s at most each), the steps
# are a fixed list, and the machine takes everything in it when it ends.
set -u
PATH=/usr/sbin:/sbin:/usr/local/sbin:/usr/local/bin:/usr/bin:/bin
export PATH
out=/verdict/slaac
: > "$out"
say() { echo "$*" >> "$out"; echo "slaac: $*"; }
failed=0
check() { # $1 what, $2 actual, $3 expected
	if [ "$2" = "$3" ]; then
		say "ok   $1"
	else
		say "FAIL $1 -- expected '$3', got '$2'"
		failed=1
	fi
}
mount -t tmpfs -o size=16m tmpfs /tmp 2>/dev/null
work=/tmp/slaac
mkdir -p "$work/etc" "$work/run"
export NCFG_CONFIG_DIR="$work/etc" NCFG_RUN_DIR="$work/run"
ncfg=/repo/c/ncfg
if [ ! -x "$ncfg" ]; then
	say "VERDICT bad: $ncfg is not built on the host"
	exit 0
fi
dev=eth0
prefix=fd42:84:
slaac_address() { ip -6 addr show dev "$dev" | grep -q "inet6 $prefix.*proto kernel_ra"; }
wait_for() { # $1 a command, $2 quarter-seconds
	waited=0
	while ! eval "$1" >/dev/null 2>&1; do
		waited=$((waited + 1))
		[ "$waited" -gt "$2" ] && return 1
		sleep 0.25
	done
	return 0
}
flap() { ip link set "$dev" down; ip link set "$dev" up; }

echo 1 > "/proc/sys/net/ipv6/conf/$dev/forwarding"
check "the interface under test forwards" "$(cat /proc/sys/net/ipv6/conf/$dev/forwarding)" "1"
check "and its accept_ra is the kernel's default" "$(cat /proc/sys/net/ipv6/conf/$dev/accept_ra)" "1"

# The wire first: at 2 the kernel solicits on coming up and acts on the answer.
echo 2 > "/proc/sys/net/ipv6/conf/$dev/accept_ra"
ip -6 addr flush dev "$dev" scope global
flap
if wait_for slaac_address 240; then
	say "ok   at accept_ra 2 the kernel solicits and configures from hull's advertisement"
else
	say "VERDICT bad: no advertisement was acted on even at accept_ra 2, so nothing below would measure anything; $dev has: $(ip -6 -br addr show dev "$dev")"
	exit 0
fi
arrived_in=$waited

# The counter-proof: forwarding, the kernel's default, and the address gone.
echo 1 > "/proc/sys/net/ipv6/conf/$dev/accept_ra"
ip -6 addr flush dev "$dev" scope global
flap
waited=0
while [ "$waited" -lt $(( (arrived_in * 2) + 8 )) ]; do
	waited=$((waited + 1))
	sleep 0.25
done
if slaac_address; then
	say "FAIL an interface that forwards at accept_ra 1 configured itself: $(ip -6 -br addr show dev "$dev")"
	failed=1
else
	say "ok   an interface that forwards gets nothing at accept_ra 1"
fi

# netcfgd brings the interface up, as it ordinarily does.
ip link set "$dev" down
cat > "$work/etc/netcfgd.conf" <<CONF
interface $dev {
	config     = "slaac"
	forwarding = true
}
CONF
plan=$("$ncfg" plan 2>&1 || true)
check "the plan sets accept_ra" "$(printf '%s\n' "$plan" | grep -c 'sysctl.set_accept_ra')" "1"
check "and its reason names the forwarding" \
	"$(printf '%s\n' "$plan" | grep 'sysctl.set_accept_ra' | grep -c forwards)" "1"
# Before link.up: the kernel decides whether to solicit as the link comes up,
# and with hull answering only when asked, a sysctl written afterwards would
# leave this interface with no advertisement at all rather than a late one.
sysctl_line=$(printf '%s\n' "$plan" | grep -n 'sysctl.set_accept_ra' | head -1 | cut -d: -f1)
up_line=$(printf '%s\n' "$plan" | grep -n "link.up $dev" | head -1 | cut -d: -f1)
if [ -n "$sysctl_line" ] && [ -n "$up_line" ] && [ "$sysctl_line" -lt "$up_line" ]; then
	say "ok   and it is written before the interface comes up"
else
	say "FAIL the sysctl is not before link.up (sysctl ${sysctl_line:-none}, up ${up_line:-none})"
	failed=1
fi
"$ncfg" apply > "$work/apply.log" 2>&1
say "ncfg apply rc=$?"
check "netcfgd wrote the value that survives forwarding" \
	"$(cat /proc/sys/net/ipv6/conf/$dev/accept_ra)" "2"
if wait_for slaac_address 240; then
	say "ok   and the kernel configured an address from the advertised prefix"
else
	say "FAIL no address from the prefix after the apply: $(ip -6 -br addr show dev "$dev")"
	failed=1
fi
"$ncfg" apply > "$work/apply2.log" 2>&1
check "a second plan has nothing to do" "$("$ncfg" plan 2>&1 | head -1)" "nothing to do"

cat > "$work/etc/netcfgd.conf" <<CONF
interface $dev {
	forwarding = true
}
CONF
"$ncfg" apply > "$work/apply3.log" 2>&1
check "dropping slaac hands accept_ra back to the kernel's default" \
	"$(cat /proc/sys/net/ipv6/conf/$dev/accept_ra)" "1"
echo 0 > "/proc/sys/net/ipv6/conf/$dev/accept_ra"
"$ncfg" apply > "$work/apply4.log" 2>&1
check "a value netcfgd never wrote is left alone" \
	"$(cat /proc/sys/net/ipv6/conf/$dev/accept_ra)" "0"

if [ "$failed" -ne 0 ]; then
	sed 's/^/  apply: /' "$work/apply.log" | tail -8 >> "$out"
	say "VERDICT bad"
else
	say "VERDICT ok"
fi
exit 0
