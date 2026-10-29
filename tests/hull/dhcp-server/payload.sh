#!/bin/sh
# A DHCP server netcfgd configures (decision 0297, project.md 10.601).
#
# netcfgd is given `lan0`, one end of a veth pair, with a static address and a
# `dhcp_server` block; a dhcpcd client takes the other end in a namespace.
# Asserted:
#
#   - the first plan starts the server after the address;
#   - the client is given an address in the default range, the router, the
#     DNS server named and the lease, read from dhcpcd's own hook;
#   - the lease is in netcfgd's lease file under /run, by the client's MAC,
#     with the name the client sent as its fourth column (10.602);
#   - a second plan has nothing to do;
#   - a changed lease is planned as a restart, the apply runs a new dnsmasq,
#     and the lease file is kept across it.
#
# Always exits 0 and reports through /verdict/dhcp-server.
#
# HOW IT STOPS: every wait is bounded (each client run at 20 s), the steps
# are a fixed list, and the vm takes dnsmasq and dhcpcd with it.
set -u
PATH=/usr/sbin:/sbin:/usr/local/sbin:/usr/local/bin:/usr/bin:/bin
export PATH
out=/verdict/dhcp-server
: > "$out"
say() { echo "$*" >> "$out"; echo "dhcp-server: $*"; }
mount -t tmpfs -o size=64m tmpfs /tmp 2>/dev/null
work=/tmp/dhcp-server
mkdir -p "$work/etc" "$work/run"

build=/repo/c
for program in netcfgd ncfg; do
	if [ ! -x "$build/$program" ]; then
		say "VERDICT bad: $build/$program is not built on the host"
		exit 0
	fi
done

ip netns add client
ip link add lan0 type veth peer name eth0 netns client
ip -n client link set lo up
ip -n client link set eth0 up
mac=$(ip -n client link show eth0 | awk '/link\/ether/ {print $2}')

conf() {
	cat > "$work/etc/netcfgd.conf" <<CONF
interface lan0 {
	config = "192.168.7.1/24"
	dhcp_server {
		dns = ["192.168.7.53"]
		$1
	}
}
CONF
}
conf ""
export NCFG_CONFIG_DIR="$work/etc" NCFG_RUN_DIR="$work/run"
"$build/ncfg" plan > "$work/plan-first.log" 2>&1
starts=$(grep -cE '^ +[0-9]+ +backend\.start lan0 +dhcp_server' "$work/plan-first.log")
say "the first plan: $(grep -E 'backend\.start|addr\.add' "$work/plan-first.log" | tr -s ' ' | tr '\n' ';')"
"$build/ncfg" apply > "$work/apply.log" 2>&1
say "ncfg apply rc=$?"
say "  lan0.conf: $(grep -vE '^#' "$work/run/dhcp-server/lan0.conf" 2>/dev/null | tr '\n' ' ')"
pid1=$(cat "$work/run/dhcp-server/lan0.pid" 2>/dev/null)

client() {
	: > "$work/given"
	ip netns exec client timeout 20 dhcpcd -1 -4 -t 15 -h laptop --script /payload/hook.sh eth0 \
		> "$work/client.log" 2>&1
	cat "$work/given"
}
given=$(client)
say "the client is given: $given"
leases=$(cat "$work/run/dhcp-server/lan0.leases" 2>/dev/null)
say "  lan0.leases: $leases"
"$build/ncfg" plan > "$work/plan-again.log" 2>&1
again=$(grep -c '^nothing to do' "$work/plan-again.log")
say "a second plan: $(head -1 "$work/plan-again.log")"

conf "lease = 3600"
"$build/ncfg" plan > "$work/plan-lease.log" 2>&1
restart=$(grep -cE '^ +[0-9]+ +backend\.(stop|start) lan0 +dhcp_server' "$work/plan-lease.log")
say "after the lease changed: $(grep -E 'backend\.' "$work/plan-lease.log" | head -1 | tr -s ' ')"
"$build/ncfg" apply > "$work/apply2.log" 2>&1
say "ncfg apply rc=$?"
pid2=$(cat "$work/run/dhcp-server/lan0.pid" 2>/dev/null)
kept=$(cat "$work/run/dhcp-server/lan0.leases" 2>/dev/null)
say "  dnsmasq pid $pid1 -> $pid2; lease file kept: $(printf '%s' "$kept" | grep -c "$mac")"

failed=0
[ "$starts" -eq 1 ] || { say "  the first plan did not start one DHCP server on lan0"; failed=1; }
case "$given" in
	*"address=192.168.7."*" routers=192.168.7.1 dns=192.168.7.53 lease=43200"*) ;;
	*) say "  the client was not given the range, router, DNS server and lease asked for"; failed=1 ;;
esac
addr=$(printf '%s' "$given" | sed -n 's/.*address=192\.168\.7\.\([0-9]*\) .*/\1/p')
[ -n "$addr" ] && [ "$addr" -ge 100 ] && [ "$addr" -le 249 ] ||
	{ say "  the address is not in the default range, .100 to .249"; failed=1; }
case "$leases" in *" $mac 192.168.7."*) ;; *) say "  the lease is not in netcfgd's lease file"; failed=1 ;; esac
# 10.602: the name the client sent, in the fourth column, which is where
# `ncfg_dhcp_server_lease_of` reads it -- the layout only dnsmasq can say.
printf '%s\n' "$leases" | awk -v m="$mac" '$2 == m && $4 == "laptop" {found=1} END {exit !found}' ||
	{ say "  the client's name is not the lease's fourth column"; failed=1; }
[ "$again" -ge 1 ] || { say "  the second plan was not empty"; failed=1; }
[ "$restart" -eq 2 ] || { say "  a changed lease was not planned as a stop and a start"; failed=1; }
[ -n "$pid2" ] && [ "$pid2" != "$pid1" ] || { say "  the apply did not run a new dnsmasq"; failed=1; }
grep -q '^dhcp-range=lan0,192.168.7.100,192.168.7.249,3600$' "$work/run/dhcp-server/lan0.conf" ||
	{ say "  the new lease is not in the file"; failed=1; }
printf '%s' "$kept" | grep -q "$mac" || { say "  the lease file was not kept across the restart"; failed=1; }
if [ "$failed" -ne 0 ]; then
	sed 's/^/  apply: /' "$work/apply.log" | tail -6 >> "$out"
	sed 's/^/  client: /' "$work/client.log" | tail -6 >> "$out"
	sed 's/^/  dnsmasq: /' "$work/run/dhcp-server/lan0.log" 2>/dev/null | tail -6 >> "$out"
	say "VERDICT bad"
else
	say "VERDICT ok"
fi
exit 0
