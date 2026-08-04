#!/bin/sh
# SLAAC against a real router advertisement, on an interface that forwards.
#
# `privacy.sh` says why it will not wait for an address: what netcfgd owns there
# is one sysctl and the address is the kernel's to build. This is the other half,
# and here the address is the whole point -- because the defect is that it never
# arrives.
#
# **`accept_ra` defaults to 1, which means "accept unless this interface
# forwards".** So `config = "slaac"` on a router's WAN, or on any machine whose
# sysctl.conf or container runtime turned IPv6 forwarding on, obtains no address
# at all: the document asked, the apply succeeded, and `ip addr` shows a
# link-local and nothing else. Nothing in netcfgd said a word about it until
# decision 0073, and finding out took an hour the first time -- there is a comment
# in `delegation.sh` that says so.
#
# The advertiser is dnsmasq, which is one package and needs no configuration file:
# `--enable-ra` with an `ra-only` range sends advertisements a kernel will
# autoconfigure from. radvd would do as well and is what netcfgd itself drives
# (0009), but this is the *receiving* side and using the same daemon on both would
# say less.
#
# **It makes its own namespaces**, for the reason `dhcpcd.sh` does and with the
# same two ways in. dnsmasq drops privileges at startup, and `unshare -rn` writes
# `deny` to `/proc/self/setgroups` -- which is what an unprivileged gid mapping
# costs -- so the drop fails and it exits before it advertises anything:
#
#     dnsmasq: failed to change group-id to root: Operation not permitted
#
# Real root works, and so does `unshare --map-root-user --map-auto`, where
# newgidmap does the mapping and setgroups is left alone. Everything inside is a
# private network namespace: /proc/sys/net is per namespace, and so is the damage.

set -eu

# Is that pid a process that is still running?
#
# Not `kill -0`, which calls a **zombie** alive. A process that has been killed
# but not yet reaped keeps its /proc entry and its pid, and that is what any
# daemon this script stops becomes whenever pid 1 does not reap -- a container
# whose pid 1 is a shell, say -- and equally what a child of *this script*
# becomes between being killed and being waited for. So `kill -0` is wrong in
# both directions: it reports a stopped daemon as still running, and it reports
# a process that something wrongly killed as still alive.
#
# A zombie has no command line at all, which is the same question netcfgd's own
# ownership check asks of a pid file. Found on Alpine, where the whole suite
# runs in a container (0100); `delegation.sh` had reasoned it out first.
still_running() {
	[ "${1:-0}" -gt 0 ] 2>/dev/null || return 1
	# `cat ... 2>/dev/null | tr`, not a redirection: with `< /proc/<pid>/...`
	# it is the *shell* that reports a missing file, and its complaint does not
	# go through the redirection attached to the command.
	[ -n "$(cat "/proc/$1/cmdline" 2>/dev/null | tr -d '\0')" ]
}

repo=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)

skip() {
	if [ -n "${NCFG_LIVE:-}" ]; then
		echo "slaac.sh: NCFG_LIVE is set but this cannot run: $1" >&2
		exit 1
	fi
	echo "slaac.sh: skipping: $1"
	exit 0
}

# dnsmasq installs into sbin, which an ordinary user's PATH does not have.
find_in_sbin() {
	for dir in /usr/sbin /sbin /usr/local/sbin /usr/bin /bin; do
		if [ -x "$dir/$1" ]; then
			echo "$dir/$1"
			return 0
		fi
	done
	return 1
}

command -v ip >/dev/null 2>&1 || skip "no ip(8)"
[ -x "$repo/target/debug/ncfg" ] || skip "ncfg is not built"
[ -d /proc/sys/net/ipv6 ] || skip "this kernel has no IPv6 (ipv6.disable=1)"
dnsmasq=$(find_in_sbin dnsmasq) ||
	skip "no dnsmasq, which is the router here (apt install dnsmasq-base | apk add dnsmasq)"

# ------------------------------------------------------------- the namespace

if [ -z "${NCFG_SLAAC_NS:-}" ]; then
	NCFG_SLAAC_NS=1
	export NCFG_SLAAC_NS
	if [ "$(id -u)" = 0 ]; then
		exec unshare --net -- sh "$0" "$@"
	fi
	command -v newuidmap >/dev/null 2>&1 ||
		skip "dnsmasq drops privileges and an unprivileged namespace needs newuidmap (apt install uidmap | apk add shadow-uidmap)"
	unshare --map-root-user --map-auto --net true 2>/dev/null ||
		skip "no subordinate uid range in /etc/subuid, so dnsmasq has no group to drop to"
	exec unshare --map-root-user --map-auto --net -- sh "$0" "$@"
fi

work=$(mktemp -d /tmp/ncfg-slaac.XXXXXX)
router=
cleanup() {
	if [ -n "$router" ]; then kill "$router" 2>/dev/null || true; fi
	rm -rf "$work"
}
trap cleanup EXIT INT TERM
mkdir -p "$work/etc" "$work/run"

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

# An advertisement is unsolicited every few seconds and solicited on request, so
# a wait of a few seconds is generous -- but the interesting case is the one where
# it never arrives, and that has to be bounded rather than hung.
wait_for() {
	waited=0
	while ! eval "$1" >/dev/null 2>&1; do
		waited=$((waited + 1))
		if [ "$waited" -gt 60 ]; then
			return 1
		fi
		sleep 0.25
	done
	return 0
}

# ------------------------------------------------------------------ the wire

ip link add wan type veth peer name isp
ip link set isp up
ip addr add 2001:db8:77::1/64 dev isp nodad
# The advertising side has to forward, or it is not a router. Written straight
# into /proc rather than through sysctl(8), which is procps and is not on a
# machine that has only busybox -- `privacy.sh` reads the same files the same way.
echo 1 > /proc/sys/net/ipv6/conf/isp/forwarding 2>/dev/null ||
	skip "cannot write /proc/sys/net/ipv6 (run under unshare -rn)"

# And this is the machine under test: an interface that forwards, which is what a
# router's WAN looks like and what a container hands you whether you asked or not.
ip link set wan up
echo 1 > /proc/sys/net/ipv6/conf/wan/forwarding
check "the interface under test forwards" \
	"$(cat /proc/sys/net/ipv6/conf/wan/forwarding)" "1"
check "and its accept_ra is the kernel's default" \
	"$(cat /proc/sys/net/ipv6/conf/wan/accept_ra)" "1"

if ! wait_for '[ "$(ip -6 -o addr show dev isp scope link | grep -c tentative)" = 0 ]'; then
	echo "slaac.sh: the router's link-local never left duplicate address detection" >&2
fi
# `--group` as well as `--user`: dnsmasq drops to the `dip` group on Debian, and
# a namespace with one mapped gid has no such group -- it exits with "failed to
# change group-id" and the log is the only place it says so.
"$dnsmasq" --keep-in-foreground --log-facility="$work/dnsmasq.log" \
	--pid-file="$work/dnsmasq.pid" --dhcp-leasefile="$work/dnsmasq.leases" \
	--user=root --group=root --interface=isp --bind-interfaces --no-resolv --port=0 \
	--dhcp-range=2001:db8:77::,ra-only,64,300 \
	--enable-ra --ra-param=isp,5,300 > "$work/dnsmasq.out" 2>&1 &
router=$!
sleep 1
if ! still_running "$router"; then
	echo "slaac.sh: the router did not start:" >&2
	sed 's/^/  /' "$work/dnsmasq.log" 2>/dev/null >&2
	sed 's/^/  /' "$work/dnsmasq.out" 2>/dev/null >&2
	exit 1
fi

# --------------------------------------------------- first: prove the wire works

# The check below is that an address does *not* arrive, and the surest way to pass
# that is for nothing to be advertising at all -- which is exactly what happened
# on the first run of this script, with a dnsmasq that had exited before it sent
# anything. So the wire is established first, by hand, with the one sysctl this is
# all about: `2` accepts advertisements whatever the interface forwards.
echo 2 > /proc/sys/net/ipv6/conf/wan/accept_ra
if ! wait_for 'ip -6 addr show wan | grep -q "proto kernel_ra"'; then
	echo "slaac.sh: no advertisement arrived even at accept_ra 2, so this whole" >&2
	echo "slaac.sh: script would be measuring a router that is not advertising" >&2
	sed 's/^/  /' "$work/dnsmasq.log" 2>/dev/null >&2
	exit 1
fi
echo "ok   the router advertises, and at accept_ra 2 the kernel acts on it"
# How long that took, so the negative check below can wait longer than it -- the
# same self-calibrating bound `dhcpcd.sh` needed, for the same reason: there is no
# event to wait for when the answer is "nothing happens".
arrived_in=$waited

# ------------------------------------------- the counter-proof: nothing arrives

# Back to the kernel's default, with the address taken away, and the interface
# still forwarding. This is the state an operator is in: being advertised at, and
# quietly ignoring it.
echo 1 > /proc/sys/net/ipv6/conf/wan/accept_ra
ip -6 addr flush dev wan scope global
ip link set wan down
ip link set wan up
waited=0
while [ "$waited" -lt $(( (arrived_in * 2) + 8 )) ]; do
	waited=$((waited + 1))
	sleep 0.25
done
if ip -6 -br addr show wan | grep -q 2001:db8:77:; then
	echo "FAIL an interface that forwards ignores advertisements at accept_ra 1"
	echo "       it configured itself anyway: $(ip -6 -br addr show wan)"
	failures=$((failures + 1))
else
	echo "ok   an interface that forwards ignores advertisements at accept_ra 1"
fi

# ------------------------------------------------------------------- netcfgd

# Down first, so netcfgd is the one that brings it up. That is the ordinary path
# -- an interface comes up under netcfgd -- and it is the one where the ordering
# below matters.
ip link set wan down

cat > "$work/etc/netcfgd.conf" <<'CONF'
interface wan {
	config     = "slaac"
	forwarding = true
}
CONF

plan=$("$ncfg" plan 2>&1 || true)
contains "the plan says the sysctl is what is missing" "$plan" "sysctl.set_accept_ra"
# The reason has to name the second half. "accept_ra 1" on its own is the state
# every working laptop is in, so a reason that stopped there would read as noise.
contains "and the reason names the forwarding, not just the value" "$plan" "forwards"

# **Before `link.up`, and this is the assertion that says so.** The kernel decides
# whether to solicit a router when the interface comes up, and it does not solicit
# on one whose advertisements it would ignore -- so a sysctl written afterwards
# leaves the interface waiting for the router's own unsolicited timer. Measured at
# 14.2 seconds against a dnsmasq set to five, and minutes on a real network.
sysctl_line=$(printf '%s\n' "$plan" | grep -n 'sysctl.set_accept_ra' | head -1 | cut -d: -f1)
up_line=$(printf '%s\n' "$plan" | grep -n 'link.up wan' | head -1 | cut -d: -f1)
if [ -n "$sysctl_line" ] && [ -n "$up_line" ] && [ "$sysctl_line" -lt "$up_line" ]; then
	echo "ok   and it is written before the interface comes up, not after"
else
	echo "FAIL and it is written before the interface comes up, not after"
	echo "       sysctl at line ${sysctl_line:-none}, link.up at line ${up_line:-none}"
	printf '%s\n' "$plan" | sed 's/^/       /'
	failures=$((failures + 1))
fi

if ! "$ncfg" apply > "$work/apply.log" 2>&1; then
	if grep -q 'Operation not permitted' "$work/apply.log"; then
		skip "no CAP_NET_ADMIN (run under unshare -rn)"
	fi
	echo "slaac.sh: apply failed" >&2
	cat "$work/apply.log" >&2
	exit 1
fi
check "netcfgd wrote the value that survives forwarding" \
	"$(cat /proc/sys/net/ipv6/conf/wan/accept_ra)" "2"

# And now the thing the document asked for happens. `proto kernel_ra` is the
# kernel saying where the address came from, which is what makes this an
# assertion about SLAAC rather than about any address turning up.
if wait_for 'ip -6 addr show wan | grep -q "proto kernel_ra"'; then
	echo "ok   and the kernel configured itself from the advertisement"
else
	echo "FAIL and the kernel configured itself from the advertisement"
	echo "       wan has: $(ip -6 addr show wan)"
	echo "       dnsmasq said:"
	sed 's/^/       /' "$work/dnsmasq.log" 2>/dev/null | tail -5
	failures=$((failures + 1))
fi
contains "with an address out of the advertised prefix" \
	"$(ip -6 -br addr show wan)" "2001:db8:77:"

# Twice is the same as once, which is section 4's rule and the thing a sysctl pass
# gets wrong most easily: a value written on every reconcile is a plan that never
# converges.
"$ncfg" apply > "$work/apply2.log" 2>&1 || true
contains "and a second apply has nothing to do" \
	"$("$ncfg" plan 2>&1 | head -1)" "nothing to do"

# ---------------------------------------------------------- handing it back

# An interface that stops asking gets the kernel's default back -- not `0`, which
# netcfgd never writes, and not `2` left behind on a machine that no longer wants
# advertisements acted on.
cat > "$work/etc/netcfgd.conf" <<'CONF'
interface wan {
	forwarding = true
}
CONF
"$ncfg" apply > "$work/apply3.log" 2>&1 || {
	cat "$work/apply3.log" >&2
	exit 1
}
check "dropping slaac hands the sysctl back to the kernel's default" \
	"$(cat /proc/sys/net/ipv6/conf/wan/accept_ra)" "1"
contains "and that too converges" \
	"$("$ncfg" plan 2>&1 | head -1)" "nothing to do"

# What netcfgd did not write, it does not touch. This is the same ownership rule
# that governs a route or an address, applied to a sysctl -- and the only reason
# the reset above is safe.
echo 0 > /proc/sys/net/ipv6/conf/wan/accept_ra
cat > "$work/etc/netcfgd.conf" <<'CONF'
interface wan {
	forwarding = true
}
CONF
"$ncfg" apply > "$work/apply4.log" 2>&1 || true
check "a value netcfgd never wrote is left alone" \
	"$(cat /proc/sys/net/ipv6/conf/wan/accept_ra)" "0"

echo
if [ "$failures" -eq 0 ]; then
	echo "slaac.sh: all checks passed"
else
	echo "slaac.sh: $failures failed"
	exit 1
fi
