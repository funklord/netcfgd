#!/bin/sh
# The customer end: netcfgd asking for a prefix and configuring from it.
#
# The document is `tests/live/delegation.sh`'s router shape from decision 0009
# -- the WAN asks for a prefix and the LAN takes an address out of it -- with
# the interface names this segment gives: eth1 is the wire and a dummy stands
# in for the LAN, since one guest has one segment NIC.
set -u
out=/verdict/cpe
say() { printf '%s\n' "$*" >> "$out"; }
: > "$out"

build=${NCFG_BUILD:-/repo/c}
say "netcfgd from $build"
for program in netcfgd ncfg; do
	if [ ! -x "$build/$program" ]; then
		say "VERDICT bad: $build/$program is not built on the host"
		exit 0
	fi
done
command -v odhcp6c >/dev/null || { say "VERDICT bad: no odhcp6c in the image"; exit 0; }

# **Wait for the ISP before soliciting, which is not politeness.** A client
# that solicits before kea is listening gets no answer -- and odhcp6c gives up
# rather than retrying for ever, which presents as "no prefix was delegated"
# with a healthy server beside it. This rig failed twice that way and passed
# once with nothing relevant changed, which is what an unsynchronised start
# looks like from outside.
#
# hull.conf orders it with hull's start order -- `(after isp)`, the ISP ready
# at its `VERDICT ok` -- so there this finds the ISP up at once. lossy.conf
# starts both together, for the reason it gives, so the loop stays for it.
waited=0
while [ "$waited" -lt 300 ]; do
	if grep -q '^VERDICT ok' /verdict/isp 2>/dev/null; then
		break
	fi
	waited=$((waited + 1))
	sleep 0.2
done
if ! grep -q '^VERDICT ok' /verdict/isp 2>/dev/null; then
	say "VERDICT bad: the ISP never reported itself up, so nothing was asked of it"
	exit 0
fi
say "the ISP reported up after $((waited / 5))s, so a solicit has somewhere to go"

mount -t tmpfs tmpfs /tmp 2>/dev/null || say "note: no tmpfs on /tmp"
work=$(mktemp -d /tmp/cpe.XXXXXX)
export NCFG_CONFIG_DIR="$work/etc" NCFG_RUN_DIR="$work/run"
mkdir -p "$work/etc" "$work/run"

# **DAD off on the segment, deliberately.** A solicit needs a usable
# link-local source; a tentative address is not one, and a switch that does
# not carry DAD's multicast leaves it tentative for ever. Two machines whose
# addresses this rig assigns cannot collide, so duplicate detection buys
# nothing here and can cost the whole exchange.
sysctl -q -w net.ipv6.conf.eth1.accept_dad=0 2>/dev/null || true
ip link set eth1 up
# **Not `|| true`.** The first run hid this: `ip link add` failed for want of
# `modprobe`, lan0 never existed, and what the run reported was netcfgd unable
# to open /proc/sys/net/ipv4/conf/lan0/forwarding -- the symptom two steps from
# the cause. A fixture that cannot make its own preconditions says so.
if ! ip link add lan0 type dummy 2>>"$out"; then
	say "VERDICT bad: this guest cannot make a dummy device for the LAN side"
	exit 0
fi
ip link set lan0 up
cat > "$work/etc/netcfgd.conf" <<CONF
interface eth1 {
	config = "dhcp6 pd_length 56"
}

interface lan0 {
	config     = "@pd:eth1=::1/64"
	forwarding = true
}
CONF

"$build/netcfgd" --no-apply-on-start > "$work/daemon.log" 2>&1 &
pid=$!
waited=0
while [ ! -e "$work/run/netcfgd.sock" ] && [ "$waited" -lt 100 ]; do
	waited=$((waited + 1))
	sleep 0.1
done
if [ ! -e "$work/run/netcfgd.sock" ]; then
	say "VERDICT bad: the daemon never started"
	sed 's/^/  daemon: /' "$work/daemon.log" >> "$out"
	exit 0
fi

"$build/ncfg" apply > "$work/apply.log" 2>&1
say "ncfg apply rc=$?"
sed 's/^/  apply: /' "$work/apply.log" >> "$out"

# **The prefix arrives asynchronously and a SECOND apply derives from it.**
# `tests/live/delegation.sh` has the sequence and says why: the first apply
# starts odhcp6c, the hook writes what the ISP delegated, and only then does
# `@pd:eth1=::1/64` refer to anything -- so the address is derived by the apply
# that follows. A rig that applied once waited for an address nothing had been
# asked to compute, which is what this one did on its first run.
prefixes="$work/run/prefixes/eth1"
waited=0
# **600, not 200.** The same payload serves the lossy rig, where a solicit
# may be dropped several times and odhcp6c backs off between tries. A wait that
# suited a clean wire would make loss look like a failure to delegate.
while [ ! -s "$prefixes" ] && [ "$waited" -lt 600 ]; do
	waited=$((waited + 1))
	sleep 0.1
done
if [ ! -s "$prefixes" ]; then
	say "VERDICT bad: odhcp6c solicited and no prefix was delegated"
	# **What the failure needs to say, since DHCPv6 depends on things this rig
	# does not control.** A solicit goes from a link-local source to a
	# multicast group, so a link-local still tentative under DAD, or a switch
	# that does not carry ff02::1:2, both look exactly like an ISP that did not
	# answer. Report the state rather than theorise about it.
	# **Does the wire carry multicast?** A DHCPv6 solicit goes to ff02::1:2
	# from a link-local source, so a segment that carries unicast and not
	# multicast looks exactly like a server that is not answering. All-nodes
	# ping separates the two: if the ISP replies to ff02::1 the wire carries
	# multicast, and the fault is above it.
	say "  all-nodes multicast on eth1 (does the segment carry it?):"
	ping -6 -c 2 -W 2 -I eth1 ff02::1 2>&1 | sed 's/^/    /' >> "$out"
	say "  eth1 addresses:"
	ip -o -6 addr show dev eth1 2>/dev/null | sed 's/^/    /' >> "$out"
	# **Read /proc, because this image has no procps.** The first version used
	# `ps -eo pid=,args=`, which does not exist here -- and its output went
	# through a pipe, so the missing tool left the line blank and the pipeline
	# still succeeded. That read as "odhcp6c is not running" and was evidence
	# of nothing at all. `/proc` is always there.
	say "  processes whose command line names odhcp6c:"
	found=0
	for p in /proc/[0-9]*; do
		[ -r "$p/cmdline" ] || continue
		if tr '\0' ' ' < "$p/cmdline" 2>/dev/null | grep -q odhcp6c; then
			say "    ${p#/proc/}: $(tr '\0' ' ' < "$p/cmdline")"
			found=$((found + 1))
		fi
	done
	[ "$found" -eq 0 ] && say "    none"
	say "  what netcfgd left under its run directory:"
	find "$work/run" -type f 2>/dev/null | sed 's|^|    |' >> "$out"
	# **Found rather than guessed at.** The first version of this listed two
	# globs and netcfgd keeps the client's log at `run/dhcp/<iface>-<family>.log`,
	# which matched neither -- so the one file that said why odhcp6c died was
	# the one the failure path did not print.
	find "$work/run" -name '*.log' 2>/dev/null | while read -r log; do
		say "  $log:"
		tail -20 "$log" | sed 's/^/    /' >> "$out"
	done
	sed 's/^/  daemon: /' "$work/daemon.log" >> "$out"
	kill "$pid" 2>/dev/null
	exit 0
fi
delegated=$(head -1 "$prefixes")
say "the ISP delegated: $delegated"

"$build/ncfg" apply > "$work/apply2.log" 2>&1
say "second ncfg apply rc=$?"
sed 's/^/  apply2: /' "$work/apply2.log" >> "$out"

# **The assertion is relational: derived from what arrived, not hardcoded.**
# `@pd:eth1=::1/64` is the first address of the first /64 of whatever the ISP
# gave, so the network part of lan0's address has to be the network part of the
# delegated prefix. Taking it from the file rather than from this script's
# memory is what makes the check about the round trip instead of about kea's
# configuration, which this guest never sees.
network=${delegated%%::*}
waited=0
got=
while [ "$waited" -lt 200 ]; do
	got=$(ip -o -6 addr show dev lan0 2>/dev/null | awk '{print $4}' | grep -v '^fe80' | head -1)
	[ -n "$got" ] && break
	waited=$((waited + 1))
	sleep 0.1
done
say "lan0 carries: ${got:-<nothing>}"
kill "$pid" 2>/dev/null
if [ -z "$got" ]; then
	say "VERDICT bad: the prefix arrived and no address was derived from it"
	sed 's/^/  daemon: /' "$work/daemon.log" >> "$out"
	exit 0
fi
case "$got" in
"$network":*)
	say "VERDICT ok: lan0 carries $got, whose network is the delegated $delegated"
	;;
*)
	say "VERDICT bad: $got does not come from $delegated"
	;;
esac
