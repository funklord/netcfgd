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
#     and the lease file is kept across it;
#   - a reservation for the client's MAC (10.605) is planned as a restart
#     counting one host, and the client asking again is given the reserved
#     address, outside the range, where it held one inside it;
#   - the LAN's DNS forwarder (0301): turning it on is a restart, dnsmasq
#     binds port 53 on lan0's address and not on loopback -- where a resolver
#     is already listening, the collision measured against 2.91 -- the client
#     is offered the router, and through it resolves a name the upstream
#     answers and the reservation's own name.
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

conf() { # $1 the server's other lines; $2 its dns line, the default when absent
	# Set before the here-document: inside one, `\"` keeps its backslash.
	dns_line=${2-'dns = ["192.168.7.53"]'}
	cat > "$work/etc/netcfgd.conf" <<CONF
interface lan0 {
	config = "192.168.7.1/24"
	dhcp_server {
		$dns_line
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

# A reservation, outside the range, for the client that already holds a lease
# inside it: dnsmasq must move it rather than renew what it has.
conf "lease = 3600
		host \"desk\" { mac = \"$mac\"; address = \"192.168.7.50\" }"
"$build/ncfg" plan > "$work/plan-host.log" 2>&1
reserved_plan=$(grep -cE 'backend\.(stop|start) lan0 +dhcp_server.*1 host ' "$work/plan-host.log")
say "after a reservation: $(grep -E 'backend\.' "$work/plan-host.log" | head -1 | tr -s ' ')"
"$build/ncfg" apply > "$work/apply3.log" 2>&1
say "ncfg apply rc=$?"
say "  lan0.conf: $(grep '^dhcp-host=' "$work/run/dhcp-server/lan0.conf" 2>/dev/null)"
reserved=$(client)
say "the client is given: $reserved"

# The forwarder (0301). An upstream resolver on loopback first, which is both
# what the router resolves through and the socket a forwarder binding
# loopback would collide with; the router's resolv.conf names it.
timeout -k 2 120 dnsmasq -k --conf-file=/dev/null --port=53 --listen-address=127.0.0.2 \
	--bind-interfaces --no-resolv --address=/example.test/10.9.9.9 --pid-file= --user=root \
	> "$work/upstream.log" 2>&1 &
upstream=$!
echo "nameserver 127.0.0.2" > /etc/resolv.conf
conf "lease = 3600
		host \"desk\" { mac = \"$mac\"; address = \"192.168.7.50\" }
		dns_forward = true" ""
"$build/ncfg" plan > "$work/plan-dns.log" 2>&1
forward_plan=$(grep -cE 'backend\.(stop|start) lan0 +dhcp_server.*forwarding dns' "$work/plan-dns.log")
say "after the forwarder: $(grep -E 'backend\.' "$work/plan-dns.log" | head -1 | tr -s ' ')"
"$build/ncfg" apply > "$work/apply4.log" 2>&1
say "ncfg apply rc=$?"
sleep 1
listening=$(ss -lnu | awk 'NR>1 {print $4}' | grep ':53$' | sort -u | tr '\n' ' ')
say "  port 53 bound on: $listening"
forwarded=$(client)
say "the client is given: $forwarded"
mkdir -p /etc/netns/client
echo "nameserver 192.168.7.1" > /etc/netns/client/resolv.conf
upstream_name=$(ip netns exec client timeout 10 getent hosts example.test | awk '{print $1}')
lease_name=$(ip netns exec client timeout 10 getent hosts desk | awk '{print $1}')
say "  the client resolves example.test to '$upstream_name' and desk to '$lease_name'"
kill "$upstream" 2>/dev/null

failed=0
[ "$forward_plan" -ge 1 ] || { say "  turning the forwarder on was not planned as a restart"; failed=1; }
case " $listening" in *" 192.168.7.1:53 "*) ;; *) say "  the forwarder is not on lan0's address"; failed=1 ;; esac
case " $listening" in *" 127.0.0.1:53 "*) say "  the forwarder bound loopback too"; failed=1 ;; esac
case "$forwarded" in *" dns=192.168.7.1 "*) ;; *) say "  the client was not offered the router as its DNS server"; failed=1 ;; esac
[ "$upstream_name" = "10.9.9.9" ] || { say "  a name the upstream answers did not resolve through the forwarder"; failed=1; }
[ "$lease_name" = "192.168.7.50" ] || { say "  the reservation's name did not resolve"; failed=1; }
case "$reserved" in
	*"address=192.168.7.50 "*) ;;
	*) say "  the client was not given its reserved address"; failed=1 ;;
esac
[ "$reserved_plan" -ge 1 ] || { say "  the reservation was not planned as a restart naming it"; failed=1; }
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
	sed 's/^/  apply4: /' "$work/apply4.log" | tail -6 >> "$out"
	sed 's/^/  upstream: /' "$work/upstream.log" | tail -4 >> "$out"
	say "VERDICT bad"
else
	say "VERDICT ok"
fi
exit 0
