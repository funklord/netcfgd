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

client() { # $@ more dhcpcd options, such as the options to ask for
	: > "$work/given"
	ip netns exec client timeout 20 dhcpcd -1 -4 -t 15 -h laptop "$@" --script /payload/hook.sh eth0 \
		> "$work/client.log" 2>&1
	cat "$work/given"
}
given=$(client)
say "the client is given: $given"
leases=$(cat "$work/run/dhcp-server/lan0.leases" 2>/dev/null)
say "  lan0.leases: $leases"
# The same lease as `ncfg status` shows it (0303): the client's address, its
# MAC and the name it sent.
"$build/ncfg" status > "$work/status.log" 2>&1
shown=$(sed -n '/^DHCP leases/,$p' "$work/status.log" | grep -i "$mac" | tr -s ' ')
say "  ncfg status shows: $shown"
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
# Read now: the stages after this one rewrite the file.
lease_line=$(grep -c '^dhcp-range=lan0,192.168.7.100,192.168.7.249,3600$' "$work/run/dhcp-server/lan0.conf")
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

# The standard options (0303): asked for by the client, since dnsmasq sends
# an option only to a client that asks, and the domain answering a lease's
# name under it through the forwarder.
conf "lease = 3600
		host \"desk\" { mac = \"$mac\"; address = \"192.168.7.50\" }
		dns_forward = true
		gateway = \"192.168.7.254\"
		domain = \"home.lan\"
		ntp = [\"192.168.7.1\", \"192.168.7.2\"]
		boot_file = \"pxelinux.0\"
		boot_server = \"192.168.7.5\"
		tftp_server = \"tftp.home.lan\"
		wpad = \"http://wpad.home.lan/wpad.dat\"" ""
"$build/ncfg" plan > "$work/plan-options.log" 2>&1
options_plan=$(grep -cE 'backend\.(stop|start) lan0 +dhcp_server.*options ' "$work/plan-options.log")
say "after the options: $(grep -E 'backend\.' "$work/plan-options.log" | head -1 | tr -s ' ')"
"$build/ncfg" apply > "$work/apply5.log" 2>&1
say "ncfg apply rc=$?"
sleep 1
optioned=$(client -o ntp_servers -o tftp_server_name -o wpad_url -o bootfile_name)
say "the client is given: $optioned"
# A client that asks for option 67 is given the file there and an empty
# header field, measured against 2.91; one that does not -- a PXE ROM reading
# the BOOTP header -- has to find it in the header.
headered=$(client)
say "a client not asking for option 67 is given: $headered"
domain_name=$(ip netns exec client timeout 10 getent hosts desk.home.lan | awk '{print $1}')

# DNS records (0303), answered by the forwarder. The router's own upstream
# (127.0.0.2) knows nothing of corp.example; a second one (127.0.0.3) does, and
# the `forward` record is what sends the name there.
timeout -k 2 120 dnsmasq -k --conf-file=/dev/null --port=53 --listen-address=127.0.0.3 \
	--bind-interfaces --no-resolv --address=/corp.example/10.7.7.7 --pid-file= --user=root \
	> "$work/corp.log" 2>&1 &
corp=$!
timeout -k 2 120 dnsmasq -k --conf-file=/dev/null --port=53 --listen-address=127.0.0.2 \
	--bind-interfaces --no-resolv --address=/example.test/10.9.9.9 --pid-file= --user=root \
	> "$work/upstream2.log" 2>&1 &
upstream=$!
cat >> "$work/etc/netcfgd.conf" <<'RECORDS'
dns_record "nas.home.lan" { address = ["192.168.7.10", "fd00::10"] }
dns_record "files.home.lan" { cname = "nas.home.lan" }
dns_record "home.lan" { mx = "mail.home.lan"; preference = 5; txt = "v=spf1 -all" }
dns_record "_sip._udp.home.lan" { srv = "pbx.home.lan"; port = 5060; priority = 1; weight = 2 }
dns_record "corp.example" { forward = ["127.0.0.3"] }
RECORDS
"$build/ncfg" plan > "$work/plan-records.log" 2>&1
records_plan=$(grep -cE 'backend\.(stop|start) lan0 +dhcp_server.*5 records ' "$work/plan-records.log")
say "after the records: $(grep -E 'backend\.' "$work/plan-records.log" | head -1 | tr -s ' ')"
"$build/ncfg" apply > "$work/apply7.log" 2>&1
say "ncfg apply rc=$?"
sleep 1
lookup() { ip netns exec client timeout 10 getent ahosts "$1" | awk 'NR==1 {print $1}'; }
nas=$(lookup nas.home.lan)
nas6=$(ip netns exec client timeout 10 getent ahostsv6 nas.home.lan | awk 'NR==1 {print $1}')
alias=$(lookup files.home.lan)
corp_name=$(lookup www.corp.example)
say "  nas.home.lan is '$nas' and '$nas6', files.home.lan '$alias', www.corp.example '$corp_name'"
if command -v dig > /dev/null 2>&1; then
	asked() { ip netns exec client timeout 10 dig +short @192.168.7.1 "$2" "$1" | tr '\n' ' '; }
	mx=$(asked home.lan MX)
	txt=$(asked home.lan TXT)
	srv=$(asked _sip._udp.home.lan SRV)
	say "  home.lan MX '$mx' TXT '$txt', _sip._udp SRV '$srv'"
else
	mx=skipped
	say "  no dig in the image: MX, TXT and SRV are checked by dhcp_server_test's lines only"
fi

# Block lists (0305), on the forwarder above, whose upstream answers every
# name under example.test with 10.9.9.9. A name in the configuration first,
# with the list's file not fetched yet, which the plan has to say; then the
# file, carrying a line that is not a name, whose arrival is a restart.
mkdir -p "$work/block"
cat >> "$work/etc/netcfgd.conf" <<BLOCK
block_list "ads" {
	domain = ["ads.example.test"]
	file   = ["$work/block/ads.txt"]
	allow  = ["ok.ads.example.test"]
}
BLOCK
sed -i 's/^\t\tdns_forward = true$/&\n\t\tblock = ["ads"]/' "$work/etc/netcfgd.conf"
"$build/ncfg" plan > "$work/plan-block.log" 2>&1
block_warned=$(grep -c 'block list `ads` names .*ads.txt, which is not there' "$work/plan-block.log")
block_plan=$(grep -cE 'backend\.(stop|start) lan0 +dhcp_server.*blocking 1 list ' "$work/plan-block.log")
say "after a block list: $(grep -E 'backend\.' "$work/plan-block.log" | head -1 | tr -s ' ')"
"$build/ncfg" apply > "$work/apply-block.log" 2>&1
say "ncfg apply rc=$?"
sleep 1
blocked=$(lookup ads.example.test)$(lookup deep.ads.example.test)
allowed=$(lookup ok.ads.example.test)
unblocked=$(lookup www.example.test)
say "  blocked '$blocked', allowed '$allowed', not listed '$unblocked'"
printf '%s\n' "0.0.0.0 tracker.example.test" "dhcp-script=/bin/false" "||adblock.example.test^" \
	> "$work/block/ads.txt"
"$build/ncfg" plan > "$work/plan-fetched.log" 2>&1
fetched_plan=$(grep -cE 'backend\.(stop|start) lan0 +dhcp_server.*blocking 1 list ' "$work/plan-fetched.log")
say "after the file arrives: $(grep -E 'backend\.' "$work/plan-fetched.log" | head -1 | tr -s ' ')"
"$build/ncfg" apply > "$work/apply-fetched.log" 2>&1
say "ncfg apply rc=$?"
sleep 1
from_file=$(lookup tracker.example.test)$(lookup adblock.example.test)
hostile=$(grep -c 'dhcp-script' "$work/run/dhcp-server/lan0.block" 2>/dev/null)
canary=$(grep -c '^address=/use-application-dns.net/$' "$work/run/dhcp-server/lan0.block" 2>/dev/null)
say "  from the file '$from_file'; $(tail -1 "$work/run/dhcp-server/lan0.block" 2>/dev/null)"

# DNS interception (0305). The client is set to ask a server that is not
# there, as a device with one built in does; asked through the router's
# default route it gets no answer until `dns_intercept` sends port 53 to
# the forwarder, which then answers it -- block list included.
ip -n client route replace default via 192.168.7.1 2>/dev/null
echo "nameserver 192.0.2.53" > /etc/netns/client/resolv.conf
uncaught=$(lookup www.example.test)
sed -i 's/^\t\tdns_forward = true$/&\n\t\tdns_intercept = true/' "$work/etc/netcfgd.conf"
"$build/ncfg" plan > "$work/plan-intercept.log" 2>&1
intercept_plan=$(grep -c 'dns+udp' "$work/plan-intercept.log")
"$build/ncfg" apply > "$work/apply-intercept.log" 2>&1
say "ncfg apply rc=$?"
sleep 1
caught=$(lookup www.example.test)
caught_blocked=$(lookup ads.example.test)
say "  asking 192.0.2.53: before '$uncaught', after '$caught', a blocked name '$caught_blocked'"
"$build/ncfg" plan > "$work/plan-intercept2.log" 2>&1
intercept_again=$(grep -c 'nothing to do' "$work/plan-intercept2.log")
echo "nameserver 192.168.7.1" > /etc/netns/client/resolv.conf
kill "$corp" "$upstream" 2>/dev/null

# Custom options (0303), each typed, read by a client that knows each code's
# width: a u16 of 5 sent as one byte, which dnsmasq does with a bare 5, is
# refused by it and arrives empty.
conf "lease = 3600
		option \"voip\" { code = 150; ip = [\"192.168.7.9\", \"192.168.7.10\"] }
		option \"motd\" { code = 224; text = \"hello world\" }
		option \"mtu2\" { code = 225; u16 = 5 }
		option \"big\" { code = 226; u32 = 70000 }
		option \"flag\" { code = 227; bool = true }
		option \"raw\" { code = 228; hex = \"01:A2:03\" }
		option \"one\" { code = 229; hex = \"ff\" }
		option \"small\" { code = 230; u8 = 7 }"
"$build/ncfg" apply > "$work/apply6.log" 2>&1
say "ncfg apply rc=$?"
say "  lan0.conf: $(grep '^dhcp-option=' "$work/run/dhcp-server/lan0.conf" 2>/dev/null | tr '\n' ' ')"
sleep 1
: > "$work/custom"
client -f /payload/dhcpcd-options.conf > /dev/null
custom=$(cat "$work/custom")
say "the client is given custom options: $custom"
say "  the client resolves desk.home.lan to '$domain_name'"

# DHCPv6 (0303): a range of suffixes in lan0's own prefix, the forwarder on
# so the router is offered as the DNS server over v6 too.
cat > "$work/etc/netcfgd.conf" <<CONF
interface lan0 {
	config = ["192.168.7.1/24", "fd00:7::1/64"]
	dhcp_server {
		dns_forward = true
		range6 = "::100-::1ff"
	}
}
CONF
"$build/ncfg" plan > "$work/plan-v6.log" 2>&1
v6_plan=$(grep -cE 'backend\.(stop|start) lan0 +dhcp_server.*dhcpv6 ::100-::1ff' "$work/plan-v6.log")
v6_warned=$(grep -c 'tells the hosts to ask' "$work/plan-v6.log")
say "after DHCPv6: $(grep -E 'backend\.' "$work/plan-v6.log" | head -1 | tr -s ' ')"
"$build/ncfg" apply > "$work/apply8.log" 2>&1
say "ncfg apply rc=$?"
say "  lan0.conf: $(grep '^dhcp-range=' "$work/run/dhcp-server/lan0.conf" 2>/dev/null | tr '\n' ' ')"
sleep 2
: > "$work/given6"
ip netns exec client timeout 25 dhcpcd -1 -6 -t 20 -f /payload/dhcpcd-v6.conf \
	--script /payload/hook.sh eth0 > "$work/client6.log" 2>&1
given6=$(cat "$work/given6")
say "the client is given over DHCPv6: $given6"

# Relay (0303): lan0 passes requests to a server netcfgd does not run, in a
# namespace of its own behind wan0, which leases from a range of its own for
# lan0's network -- so an address from that range is the relay's proof.
ip netns add upstream
ip link add wan0 type veth peer name eth0 netns upstream
ip -n upstream link set lo up
ip -n upstream link set eth0 up
ip -n upstream addr add 10.9.0.2/24 dev eth0
ip -n upstream route add 192.168.7.0/24 via 10.9.0.1
ip netns exec upstream timeout -k 2 120 dnsmasq -k --conf-file=/dev/null --port=0 \
	--interface=eth0 --bind-interfaces --dhcp-range=192.168.7.150,192.168.7.160,255.255.255.0,600 \
	--dhcp-leasefile="$work/upstream.leases" --pid-file= --user=root --log-dhcp \
	--log-facility="$work/upstream-dhcp.log" > /dev/null 2>&1 &
upstream_dhcp=$!
# And a second LAN served by netcfgd at the same time: the relay listens on
# two interfaces, so its DHCP socket is not bound to one device, and it has
# to leave lan1's server room to start and answer.
ip link add lan1 type veth peer name eth1 netns client
ip -n client link set eth1 up
cat > "$work/etc/netcfgd.conf" <<CONF
interface wan0 {
	config = "10.9.0.1/24"
}
interface lan0 {
	config = "192.168.7.1/24"
	dhcp_server {
		relay = ["10.9.0.2"]
	}
}
interface lan1 {
	config = "192.168.8.1/24"
	dhcp_server {
		dns = ["192.168.8.1"]
	}
}
CONF
"$build/ncfg" plan > "$work/plan-relay.log" 2>&1
relay_plan=$(grep -cE 'backend\.(stop|start) lan0 +dhcp_server: relay to 10.9.0.2' "$work/plan-relay.log")
"$build/ncfg" apply > "$work/apply10.log" 2>&1
say "ncfg apply rc=$?"
say "  lan0.conf: $(grep -vE '^#' "$work/run/dhcp-server/lan0.conf" 2>/dev/null | tr '\n' ' ')"
sleep 1
# Longer than `client`'s 15 s, and with no link-local fallback: a relayed
# lease is slower by the server's ping of the address before offering it and
# the client's ARP probe after, and dhcpcd configures a link-local address
# after ten seconds without a lease -- which `-1` takes as done, exiting with
# the real lease still in hand.
: > "$work/given"
ip netns exec client timeout 50 dhcpcd -1 -4 -L -t 45 -h laptop --script /payload/hook.sh eth0 \
	> "$work/client.log" 2>&1
relayed=$(cat "$work/given")
say "the client is given through the relay: $relayed"
say "  upstream heard: $(grep -cE 'DHCPDISCOVER|DHCPREQUEST' "$work/upstream-dhcp.log") requests, offered $(grep -c DHCPOFFER "$work/upstream-dhcp.log")"
: > "$work/given"
ip netns exec client timeout 20 dhcpcd -1 -4 -t 15 --script /payload/hook.sh eth1 \
	> "$work/client1.log" 2>&1
beside=$(cat "$work/given")
say "and a client on lan1, beside it: $beside"
for i in lan0 lan1; do
	pid=$(cat "$work/run/dhcp-server/$i.pid" 2>/dev/null)
	alive=no
	[ -n "$pid" ] && [ -d "/proc/$pid" ] && alive=yes
	say "  $i dnsmasq alive=$alive log: $(tail -3 "$work/run/dhcp-server/$i.log" 2>/dev/null | tr '\n' ' ')"
done
kill "$upstream_dhcp" 2>/dev/null

# A static prefix advertised with the managed flag (0304): an ordinary client,
# waiting for the advertisement as a host does, takes an address from the
# prefix by itself and asks the server for one more.
cat > "$work/etc/netcfgd.conf" <<CONF
interface lan0 {
	config     = ["192.168.7.1/24", "fd00:7::1/64"]
	forwarding = true
	advertise { prefixes = ["fd00:7::/64"]; managed = true }
	dhcp_server {
		dns_forward = true
		range6 = "::100-::1ff"
	}
}
CONF
"$build/ncfg" plan > "$work/plan-ra.log" 2>&1
ra_started=$(grep -cE 'backend\.start lan0 +advertise' "$work/plan-ra.log")
"$build/ncfg" apply > "$work/apply9.log" 2>&1
say "ncfg apply rc=$?"
say "  radvd.conf: $(tr '\n' ' ' < "$work/run/radvd/lan0.conf" 2>/dev/null)"
sleep 2
ip -n client addr flush dev eth0 scope global 2>/dev/null
: > "$work/given6"
ip netns exec client timeout 30 dhcpcd -1 -6 -t 25 -f /payload/dhcpcd-ra.conf \
	--script /payload/hook.sh eth0 > "$work/client-ra.log" 2>&1
sleep 1
ra_addresses=$(ip -n client -6 addr show dev eth0 scope global | awk '/inet6/ {print $2}' | tr '\n' ' ')
say "the client, told by the advertisement, holds: $ra_addresses"

# DNS interception over IPv6 (0305): the client asks 2001:db8::53, where
# nothing listens, through the router -- unanswered until `dns_intercept`
# sends port 53 to lan0's fd00:7::1, where the forwarder listens.
timeout -k 2 60 dnsmasq -k --conf-file=/dev/null --port=53 --listen-address=127.0.0.2 \
	--bind-interfaces --no-resolv --address=/example.test/10.9.9.9 --pid-file= --user=root \
	> "$work/upstream6.log" 2>&1 &
upstream6=$!
router_ll=$(ip -6 addr show dev lan0 scope link | awk '/inet6/ {sub("/.*", "", $2); print $2; exit}')
ip -n client -6 route replace default via "$router_ll" dev eth0 2>/dev/null
echo "nameserver 2001:db8::53" > /etc/netns/client/resolv.conf
uncaught6=$(lookup www.example.test)
sed -i 's/^\t\tdns_forward = true$/&\n\t\tdns_intercept = true/' "$work/etc/netcfgd.conf"
"$build/ncfg" plan > "$work/plan-intercept6.log" 2>&1
intercept6_plan=$(grep -c 'dns6+udp' "$work/plan-intercept6.log")
"$build/ncfg" apply > "$work/apply-intercept6.log" 2>&1
say "ncfg apply rc=$?"
sleep 1
caught6=$(lookup www.example.test)
say "  asking 2001:db8::53 through $router_ll: before '$uncaught6', after '$caught6'"
"$build/ncfg" plan > "$work/plan-intercept6b.log" 2>&1
intercept6_again=$(grep -c 'nothing to do' "$work/plan-intercept6b.log")
kill "$upstream6" 2>/dev/null
echo "nameserver 192.168.7.1" > /etc/netns/client/resolv.conf

failed=0
[ "$relay_plan" -ge 1 ] || { say "  the relay was not planned as a restart naming where it relays"; failed=1; }
case "$beside" in
	*"address=192.168.8."*) ;;
	*) say "  lan1's server did not answer beside the relay"; failed=1 ;;
esac
case "$relayed" in
	*"address=192.168.7.15"[0-9]" "*|*"address=192.168.7.160 "*) ;;
	*) say "  the client was not given an address from the server behind the relay"; failed=1 ;;
esac
case "$shown" in
	*"192.168.7."*" laptop"*) ;;
	*) say "  ncfg status did not show the lease with the client's name"; failed=1 ;;
esac
[ -z "$uncaught6" ] || { say "  a server that is not there answered over IPv6 before interception"; failed=1; }
[ "$intercept6_plan" -ge 1 ] || { say "  IPv6 interception was not planned as the dns6+udp forward"; failed=1; }
[ "$caught6" = "10.9.9.9" ] || { say "  DNS sent to an IPv6 server was not answered by the router"; failed=1; }
[ "$intercept6_again" -ge 1 ] || { say "  the plan after IPv6 interception was not empty"; failed=1; }
[ "$ra_started" -ge 1 ] || { say "  a static prefix did not start the advertiser"; failed=1; }
case " $ra_addresses" in
	*" fd00:7::1"[0-9a-f][0-9a-f]"/128 "*) ;;
	*) say "  the client did not ask the DHCPv6 server when the advertisement said to"; failed=1 ;;
esac
case " $ra_addresses" in
	*" fd00:7::"*"/64 "*) ;;
	*) say "  the client did not take an address from the advertised prefix"; failed=1 ;;
esac
[ "$v6_plan" -ge 1 ] || { say "  DHCPv6 was not planned as a restart naming its range"; failed=1; }
[ "$v6_warned" -ge 1 ] || { say "  a range6 with no managed advertisement was not warned about"; failed=1; }
case "$given6" in
	*"address6=fd00:7::1"[0-9a-f][0-9a-f]" "*) ;;
	*) say "  the client was not given an address from fd00:7::100 to ::1ff"; failed=1 ;;
esac
[ "$block_warned" -ge 1 ] || { say "  a list file not fetched yet was not warned about"; failed=1; }
[ "$block_plan" -ge 1 ] || { say "  blocking was not planned as a restart naming it"; failed=1; }
[ -z "$blocked" ] || { say "  a blocked name, or one under it, resolved: '$blocked'"; failed=1; }
[ "$allowed" = "10.9.9.9" ] || { say "  an allowed name under a blocked one did not resolve"; failed=1; }
[ "$unblocked" = "10.9.9.9" ] || { say "  a name on no list did not resolve"; failed=1; }
[ "$fetched_plan" -ge 1 ] || { say "  a list file arriving was not planned as a restart"; failed=1; }
[ -z "$from_file" ] || { say "  a name from the list's file resolved: '$from_file'"; failed=1; }
[ "$hostile" -eq 0 ] || { say "  a line that is not a name reached dnsmasq"; failed=1; }
[ "$canary" -eq 1 ] || { say "  Firefox's DNS-over-HTTPS switch was not answered"; failed=1; }
[ -z "$uncaught" ] || { say "  a server that is not there answered before interception: '$uncaught'"; failed=1; }
[ "$intercept_plan" -ge 1 ] || { say "  interception was not planned as the dns+udp forward"; failed=1; }
[ "$caught" = "10.9.9.9" ] || { say "  DNS sent elsewhere was not answered by the router"; failed=1; }
[ -z "$caught_blocked" ] || { say "  a blocked name resolved through interception"; failed=1; }
[ "$intercept_again" -ge 1 ] || { say "  the plan after interception was not empty"; failed=1; }
[ "$records_plan" -ge 1 ] || { say "  the records were not planned as a restart counting them"; failed=1; }
[ "$nas" = "192.168.7.10" ] || { say "  an address record did not resolve"; failed=1; }
[ "$nas6" = "fd00::10" ] || { say "  its IPv6 address did not resolve"; failed=1; }
[ "$alias" = "192.168.7.10" ] || { say "  an alias did not resolve to its target's address"; failed=1; }
[ "$corp_name" = "10.7.7.7" ] || { say "  a forwarded domain was not asked of the server named"; failed=1; }
if [ "$mx" != skipped ]; then
	case "$mx" in *"5 mail.home.lan."*) ;; *) say "  the MX record was not answered"; failed=1 ;; esac
	case "$txt" in *'"v=spf1 -all"'*) ;; *) say "  the TXT record was not answered"; failed=1 ;; esac
	case "$srv" in *"1 2 5060 pbx.home.lan."*) ;; *) say "  the SRV record was not answered"; failed=1 ;; esac
fi
case "$custom" in
	*"voip=192.168.7.9 192.168.7.10 motd=hello world mtu2=5 big=70000 flag=1 raw=01a203 one=ff small=7"*) ;;
	*) say "  the custom options did not arrive at the widths their types say"; failed=1 ;;
esac
[ "$options_plan" -ge 1 ] || { say "  the options were not planned as a restart naming them"; failed=1; }
case "$optioned" in
	*" routers=192.168.7.254 "*) ;;
	*) say "  the client was not offered the gateway named"; failed=1 ;;
esac
case "$optioned" in
	*" domain=home.lan ntp=192.168.7.1 192.168.7.2 file= tftp=tftp.home.lan wpad=http://wpad.home.lan/wpad.dat bootfile=pxelinux.0"*) ;;
	*) say "  the client was not given the domain, NTP, boot file, TFTP server and WPAD URL"; failed=1 ;;
esac
case "$headered" in
	*" file=pxelinux.0 "*) ;;
	*) say "  a client not asking for option 67 did not find the boot file in the header"; failed=1 ;;
esac
[ "$domain_name" = "192.168.7.50" ] || { say "  a lease's name did not resolve under the domain"; failed=1; }
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
[ "$lease_line" -ge 1 ] || { say "  the new lease is not in the file"; failed=1; }
printf '%s' "$kept" | grep -q "$mac" || { say "  the lease file was not kept across the restart"; failed=1; }
if [ "$failed" -ne 0 ]; then
	sed 's/^/  apply: /' "$work/apply.log" | tail -6 >> "$out"
	sed 's/^/  client: /' "$work/client.log" | tail -6 >> "$out"
	sed 's/^/  dnsmasq: /' "$work/run/dhcp-server/lan0.log" 2>/dev/null | tail -6 >> "$out"
	sed 's/^/  apply4: /' "$work/apply4.log" | tail -6 >> "$out"
	sed 's/^/  upstream: /' "$work/upstream.log" | tail -4 >> "$out"
	sed 's/^/  apply5: /' "$work/apply5.log" | tail -6 >> "$out"
	sed 's/^/  apply6: /' "$work/apply6.log" | tail -6 >> "$out"
	sed 's/^/  apply7: /' "$work/apply7.log" | tail -6 >> "$out"
	sed 's/^/  apply-block: /' "$work/apply-block.log" | tail -6 >> "$out"
	sed 's/^/  apply-fetched: /' "$work/apply-fetched.log" | tail -6 >> "$out"
	sed 's/^/  apply-intercept: /' "$work/apply-intercept.log" | tail -6 >> "$out"
	sed 's/^/  plan-intercept2: /' "$work/plan-intercept2.log" | tail -6 >> "$out"
	sed 's/^/  apply-intercept6: /' "$work/apply-intercept6.log" | tail -6 >> "$out"
	sed 's/^/  plan-intercept6b: /' "$work/plan-intercept6b.log" | tail -6 >> "$out"
	sed 's/^/  client6: /' "$work/client6.log" | tail -8 >> "$out"
	sed 's/^/  apply9: /' "$work/apply9.log" | tail -6 >> "$out"
	sed 's/^/  apply10: /' "$work/apply10.log" | tail -6 >> "$out"
	sed 's/^/  upstream-dhcp: /' "$work/upstream-dhcp.log" | tail -6 >> "$out"
	sed 's/^/  client-ra: /' "$work/client-ra.log" | tail -10 >> "$out"
	say "VERDICT bad"
else
	say "VERDICT ok"
fi
exit 0
