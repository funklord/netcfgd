#!/bin/sh
# A real delegated prefix, from a real server, turned into a real address.
#
#     sudo sh tests/live/delegation.sh
#
# Or in a privileged container, which is how it is usually run here and needs
# nothing of the machine's own network:
#
#     docker run --rm --privileged -v $PWD:/repo -w /repo debian:trixie \
#         sh -c '<the packages below>; sh tests/live/delegation.sh'
#
# One thing to know about a container: its pid 1 is whatever the image was told
# to run, and `sleep infinity` never reaps. A daemon this script stops is then a
# zombie rather than gone, and `kill -0` calls a zombie alive -- which is why the
# teardown below reads /proc/<pid>/cmdline instead.
#
# This is decision 0009's whole loop, which nothing had ever run end to end: the
# document asks for a prefix, `odhcp6c` solicits one, the ISP delegates one, the
# hook netcfgd generated reports it, netcfgd derives an address on the LAN from
# the `@pd:` reference, and `radvd` advertises that prefix to a host which
# configures itself from it without being asked. Every one of those steps was tested separately and
# the joins between them were not -- which is how three separate defects in the
# dhcpcd half survived for as long as they did (decision 0050).
#
# `kea-dhcp6` is the ISP. A veth pair is the line. There is no hardware here.
#
# **Needs real root**: odhcp6c binds port 546 and opens a packet socket, and kea
# binds 547. The same bucket as `hwsim.sh` and `pppoe-session.sh`, and it makes
# its own namespaces for the same reason. `make live` invokes it either way and
# an unprivileged run skips -- so an unprivileged suite says nothing about any of
# this, and the way to hear from it is to run the suite as root.
#
# It also needs **odhcp6c**, which Debian does not package -- decision 0050 is
# why netcfgd will not pretend dhcpcd can do this instead. It builds from source
# in a couple of minutes, and the dependencies are named here because the recipe
# that omitted them stopped at `None of the required 'json-c' found` on a clean
# trixie:
#
#     apt-get install -y kea-dhcp6-server radvd \
#         git cmake build-essential pkg-config libjson-c-dev
#     git clone https://github.com/openwrt/libubox && cd libubox
#     cmake -B build -DBUILD_LUA=OFF -DBUILD_EXAMPLES=OFF && cmake --build build
#     sudo cmake --install build && sudo ldconfig
#     git clone https://github.com/openwrt/odhcp6c && cd odhcp6c
#     cmake -B build && cmake --build build
#     sudo install -m 0755 build/odhcp6c /usr/local/bin/odhcp6c
#
# On OpenWrt, where prefix delegation is the ordinary case, it is already there.

set -eu

repo=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)

if [ "$(id -u)" != "0" ]; then
	echo "delegation.sh: needs real root: odhcp6c binds port 546 and kea binds 547."
	echo "delegation.sh:   sudo sh tests/live/delegation.sh"
	exit 0
fi

if [ -z "${NCFG_PD_NS:-}" ]; then
	NCFG_PD_NS=1
	export NCFG_PD_NS
	exec unshare -mn sh "$0" "$@"
fi

for tool in odhcp6c kea-dhcp6 radvd ip; do
	command -v "$tool" >/dev/null 2>&1 || {
		echo "delegation.sh: skipping: no $tool (see the header for odhcp6c)"
		exit 0
	}
done
[ -x "$repo/target/debug/ncfg" ] || {
	echo "delegation.sh: skipping: ncfg is not built"
	exit 0
}

work=$(mktemp -d /tmp/ncfg-pd.XXXXXX)
cleanup() {
	pkill -f 'kea-dhcp6 -c' 2>/dev/null || true
	pkill -f 'odhcp6c' 2>/dev/null || true
	# Scoped to this run's directory: netcfgd starts radvd, and a run that
	# failed before the teardown would otherwise leave one advertising on a
	# namespace that no longer exists. Killing every radvd on the machine is
	# not this script's business.
	pkill -f "radvd --config $work" 2>/dev/null || true
	rm -rf "$work"
}
trap cleanup EXIT INT TERM
mkdir -p "$work/etc" "$work/run" /run/kea /var/lib/kea

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

ip link set lo up
ip link add isp0 type veth peer name wan0
# The LAN is a veth pair too, so there is something on it to be advertised
# *at*: `host0` is an ordinary host with no netcfgd on it, which is the only
# way to check that what radvd sends is something a kernel acts on.
ip link add lan0 type veth peer name host0
ip link set isp0 up
ip link set wan0 up
ip link set lan0 up
ip link set host0 up
# Before anything advertises. A host that has accept_ra switched on *after* the
# first advertisement waits for the next unsolicited one, which radvd sends
# sixteen seconds later -- long enough to look like a failure and short enough
# to pass on a good day, which is the worst combination a test can have.
sysctl -qw net.ipv6.conf.host0.accept_ra=1 >/dev/null 2>&1 || true
# And it has to be a host. `accept_ra=1` means "accept unless this interface
# forwards", so an environment that starts with forwarding on -- a container
# usually does -- makes the kernel ignore every advertisement while `ip addr`
# shows nothing to explain it. That cost an hour; `accept_ra=2` is the other
# way to say it and says less about what this end is.
sysctl -qw net.ipv6.conf.host0.forwarding=0 >/dev/null 2>&1 || true

# Duplicate address detection has to finish before anything binds a link-local
# address, or the bind fails with "Cannot assign requested address" on an
# address `ip addr` will happily show. kea does exactly that if it starts too
# early, and the error names the address rather than the reason.
waited=0
while [ "$(ip -6 -o addr show scope link | grep -c tentative)" != "0" ] ||
	[ "$(ip -6 -o addr show scope link | wc -l)" -lt 2 ]; do
	waited=$((waited + 1))
	[ "$waited" -gt 100 ] && break
	sleep 0.1
done

cat > "$work/kea.json" <<'JSON'
{ "Dhcp6": {
  "interfaces-config": { "interfaces": [ "isp0" ] },
  "lease-database": { "type": "memfile", "persist": false },
  "valid-lifetime": 600,
  "subnet6": [ {
      "id": 1,
      "subnet": "2001:db8:aaaa::/48",
      "pools": [ { "pool": "2001:db8:aaaa::100 - 2001:db8:aaaa::200" } ],
      "pd-pools": [ { "prefix": "2001:db8:1234::", "prefix-len": 48, "delegated-len": 56 } ],
      "interface": "isp0"
  } ]
} }
JSON
kea-dhcp6 -c "$work/kea.json" > "$work/kea.log" 2>&1 &
sleep 2

# The router shape from decision 0009: the WAN asks for a prefix, and the LAN
# takes an address out of it. Nothing in the document is the prefix itself --
# `@pd:wan0` is a reference, and what it refers to does not exist until an ISP
# says so.
cat > "$work/etc/netcfgd.conf" <<'CONF'
interface wan0 {
	config = "dhcp6 pd_length 56"
}

interface lan0 {
	config     = "@pd:wan0=::1/64"
	forwarding = true
	advertise { prefixes = ["@pd:wan0"] }
}
CONF

"$ncfg" plan > "$work/plan.txt" 2>&1 || true
# Before the lease, *two* things are waiting on it and both say so rather than
# failing or inventing a prefix: the address that would be derived from it, and
# the advertisement that would carry it. The second one matters more than it
# looks -- planning it early puts an action that must fail ahead of the DHCPv6
# client whose lease it is waiting for, which stops the apply and means the
# router never comes up at all. A tunnel taught that once already.
check "the address waits for the delegation rather than failing" \
	"$(grep -c 'waiting on a delegated prefix from wan0; nothing planned' "$work/plan.txt" \
		|| true)" "1"
check "and so does the advertisement, rather than being planned to fail" \
	"$(grep -c 'before advertising' "$work/plan.txt" || true)" "1"
check "so nothing is planned for the LAN at all yet" \
	"$(grep -c 'backend.start lan0' "$work/plan.txt" || true)" "0"

"$ncfg" apply > "$work/apply.txt" 2>&1 || true

prefixes="$work/run/prefixes/wan0"
waited=0
while [ ! -s "$prefixes" ]; do
	waited=$((waited + 1))
	[ "$waited" -gt 200 ] && break
	sleep 0.1
done

check "odhcp6c solicited and the ISP delegated" \
	"$(grep -c '^2001:db8:1234::/56$' "$prefixes" 2>/dev/null || true)" "1"
if [ ! -s "$prefixes" ]; then
	echo "--- odhcp6c said:"; tail -10 "$work/apply.txt" || true
	echo "--- kea said:"; tail -10 "$work/kea.log" || true
fi
# The lifetimes odhcp6c appends are not part of the prefix. It reports
# `2001:db8:1234::/56,365,590,178,290` and the hook keeps what is before the
# first comma.
check "and the hook kept the prefix without the lifetimes" \
	"$(grep -c ',' "$prefixes" 2>/dev/null || true)" "0"

# The second apply is the one that derives the address, because the reference
# had nothing behind it until now. `@pd:wan0=::1/64` is the first address of
# the first /64 of what the ISP gave.
"$ncfg" apply > "$work/apply2.txt" 2>&1 || true
check "netcfgd derived the LAN address from it" \
	"$(ip -6 addr show lan0 | grep -c '2001:db8:1234::1/64' || true)" "1"
# `0x6e` is 110: iproute2 prints an address protocol in hex and a route
# protocol in decimal, for the same tag. Worth knowing before writing the
# obvious assertion and watching it fail on a correct address.
check "and tagged it as its own, so it can be withdrawn again" \
	"$(ip -6 addr show lan0 | grep -c 'proto 0x6e' || true)" "1"

"$ncfg" plan > "$work/replan.txt" 2>&1 || true
check "and the next plan has nothing to do" \
	"$(grep -cE 'addr\.|route\.' "$work/replan.txt" || true)" "0"

# ------------------------------------------------------------ advertising

# The host end of the LAN, which is not netcfgd's and never hears from it. What
# reaches it is a router advertisement, and what it does with one is the
# kernel's business -- so this is the check that netcfgd asked radvd for
# something a host acts on, rather than that a file has the right words in it.
# A router solicitation, so the answer does not wait on radvd's own schedule:
# the kernel sends one when an interface with accept_ra comes up, and radvd
# answers a solicitation at once. Without this the test waits up to sixteen
# seconds for the second unsolicited advertisement.
ip link set host0 down
ip link set host0 up
waited=0
while [ "$(ip -6 addr show host0 | grep -c '2001:db8:1234:' || true)" = "0" ]; do
	waited=$((waited + 1))
	[ "$waited" -gt 200 ] && break
	sleep 0.1
done
check "a host on the LAN configured itself from the delegated prefix" \
	"$(ip -6 addr show host0 | grep -c '2001:db8:1234:' || true)" "1"
# SLAAC, which is what `AdvAutonomous on` buys: `proto kernel_ra` is the kernel
# saying an advertisement is where this came from. Without `AdvAutonomous` the
# host would treat the prefix as on-link and never take an address from it.
#
# The address is `2001:db8:1234:0:...` rather than `2001:db8:1234::...` -- the
# host fills the bottom 64 bits in itself, which is the whole idea, and a grep
# for the prefix with `::` in it matches nothing. That cost a wrong assertion
# on a working feature.
check "by autoconfiguration, which is what the prefix flags are for" \
	"$(ip -6 addr show host0 | grep -c 'proto kernel_ra' || true)" "1"
# And the router is its default gateway, which is the other half of an RA.
check "and took netcfgd's router as its default route" \
	"$(ip -6 route show default | grep -c 'dev host0' || true)" "1"

if [ "$(ip -6 addr show host0 | grep -c '2001:db8:1234:' || true)" = "0" ]; then
	echo "--- radvd said:"; cat "$work/run/radvd/lan0.log" 2>/dev/null || true
	echo "--- netcfgd said:"; tail -10 "$work/apply2.txt" || true
	echo "--- host0:"; ip -6 addr show host0
	echo "--- lan0:"; ip -6 addr show lan0
	echo "--- sysctl:"; sysctl net.ipv6.conf.host0.accept_ra net.ipv6.conf.host0.forwarding net.ipv6.conf.all.forwarding 2>&1
	echo "--- config:"; cat "$work/run/radvd/lan0.conf" 2>/dev/null
	echo "--- radvd running:"; ps ax | grep '[r]advd' | head -3
fi

# What netcfgd wrote, checked by the tool that reads it. `--configtest` is
# radvd's own parser and needs no privileges, which is the same lever `ap.sh`
# uses on hostapd.
radvd --config "$work/run/radvd/lan0.conf" --configtest > "$work/configtest.txt" 2>&1 \
	&& parsed=yes || parsed=no
check "and radvd's own parser accepts what netcfgd wrote" "$parsed" "yes"

# ------------------------------------------------------------- renumbering

# What a real line does at three in the morning: the ISP hands out a different
# block. Everything derived from the old one has to move -- the LAN's address
# and what is being advertised on it -- and nothing but a real renewal exercises
# that, because the prefix is the one value in this whole path that no config
# file contains.
#
# kea is restarted with a different pool and an empty lease database, and
# odhcp6c is told to rebind: SIGUSR2 is its "ask anybody", which is what a
# client does when the server it knew is gone.
pkill -f 'kea-dhcp6 -c' 2>/dev/null || true
sed -i 's/2001:db8:1234::/2001:db8:5678::/' "$work/kea.json"
kea-dhcp6 -c "$work/kea.json" > "$work/kea2.log" 2>&1 &
sleep 2
pkill -USR2 -f odhcp6c 2>/dev/null || true

waited=0
while ! grep -q '^2001:db8:5678:' "$prefixes" 2>/dev/null; do
	waited=$((waited + 1))
	[ "$waited" -gt 300 ] && break
	sleep 0.1
done
check "the ISP renumbered and the client reported the new prefix" \
	"$(grep -c '^2001:db8:5678::/56$' "$prefixes" 2>/dev/null || true)" "1"

"$ncfg" apply > "$work/renumber.txt" 2>&1 || true
check "netcfgd moved the LAN onto the new prefix" \
	"$(ip -6 addr show lan0 | grep -c '2001:db8:5678::1/64' || true)" "1"
check "and took the old address away rather than keeping both" \
	"$(ip -6 addr show lan0 | grep -c '2001:db8:1234::1/64' || true)" "0"
# The advertisement has to move with it. A router still announcing a prefix the
# ISP has taken back is telling every host on the LAN to use an address the
# upstream will not route.
check "and the advertisement followed the address" \
	"$(grep -c 'prefix 2001:db8:5678::/64' "$work/run/radvd/lan0.conf" || true)" "1"
check "rather than still announcing the prefix that was taken back" \
	"$(grep -c 'prefix 2001:db8:1234::/64' "$work/run/radvd/lan0.conf" || true)" "0"

# ------------------------------------------------------- stopping the client

# The lease going away takes the address with it. This used to be written as
# `pkill -f odhcp6c` followed by truncating the prefix file by hand -- the test
# doing what netcfgd could not, which is exactly how the defect stayed hidden:
# `stop_backend` answered `Dhcp6` with "not implemented in this build", so an
# apply that dropped `config = "dhcp6"` failed outright and nothing stopped the
# client. Decision 0071. So the document is edited instead, which is what an
# operator does.
pid=$(cat "$work/run/odhcp6c/wan0.pid" 2>/dev/null || echo 0)
check "the client wrote its pid where netcfgd told it to" \
	"$([ "$pid" -gt 0 ] && echo yes || echo no)" "yes"

cat > "$work/etc/netcfgd.conf" <<'CONF'
interface wan0 {
}

interface lan0 {
	forwarding = true
}
CONF
if "$ncfg" apply > "$work/gone.txt" 2>&1; then
	echo "ok   dropping dhcp6 from the document is an apply that succeeds"
else
	echo "FAIL dropping dhcp6 from the document is an apply that succeeds"
	sed 's/^/       /' "$work/gone.txt"
	failures=$((failures + 1))
fi

# Read through /proc rather than `kill -0`, because a daemonised client is
# reparented to init and a pid 1 that does not reap -- a container's `sleep
# infinity`, say -- leaves a zombie that `kill -0` reports as alive. A zombie has
# no command line at all, so this is the same question netcfgd's own ownership
# check asks: does that pid still name this client?
still_running() { cat "/proc/$1/cmdline" 2>/dev/null | tr '\0' ' ' | grep -q odhcp6c; }

# The guard is not decoration. With no pid, `/proc/0/cmdline` does not exist,
# "is it still running?" answers no, and all three checks below go green because
# the feature is broken -- which is what happened when `-p` was taken off the
# client's arguments to see whether these could fail. Section 9's first
# corollary, in the run that was meant to prove the opposite.
if [ "$pid" -le 0 ]; then
	echo "FAIL and the client is gone"
	echo "       there is no pid to look for, so nothing below could be checked"
	failures=$((failures + 1))
else
	waited=0
	while still_running "$pid"; do
		waited=$((waited + 1))
		[ "$waited" -gt 100 ] && break
		sleep 0.1
	done
	check "and the client is gone" "$(still_running "$pid" && echo yes || echo no)" "no"
	# odhcp6c calls its script one last time on the way out, and PREFIXES is
	# unset once it is no longer bound -- so the hook writes an empty file and
	# the reference has nothing behind it again. Nothing here truncated that
	# file, which the old teardown did by hand.
	check "and emptied the prefix file itself on the way out" \
		"$(grep -c '^2001:db8:5678::/56$' "$prefixes" 2>/dev/null || true)" "0"
	check "and removed the pid file with it" \
		"$([ -e "$work/run/odhcp6c/wan0.pid" ] && echo yes || echo no)" "no"
fi

"$ncfg" apply > "$work/gone2.txt" 2>&1 || true
check "a prefix that goes takes the address derived from it" \
	"$(ip -6 addr show lan0 | grep -c '2001:db8:5678::1/64' || true)" "0"
# And the advertiser goes with the advertisement. netcfgd started this radvd and
# stops it by the pid file it told it to write, which is the same shape the
# client above has -- and the reason the old teardown left one running on every
# run of this script.
check "and the advertiser netcfgd started is stopped too" \
	"$(pgrep -f "radvd --config $work" >/dev/null 2>&1 && echo yes || echo no)" "no"

echo
if [ "$failures" -eq 0 ]; then
	echo "delegation.sh: all checks passed"
else
	echo "delegation.sh: $failures check(s) failed"
	exit 1
fi
