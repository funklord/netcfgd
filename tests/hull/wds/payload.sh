#!/bin/sh
# A repeater through four-address (WDS) mode, both ends netcfgd's in turn
# (project.md 10.587 item 4).
#
# Four hwsim radios in one vm, two halves, each against a reference end so
# that what is under test is whether netcfgd's end works with a standard one:
#
#   A  netcfgd's access point: wlan0, `wds = true`, in br0 with a veth to a
#      host in namespace `lan` (10.30.0.10). The reference repeater is a bare
#      four-address wpa_supplicant on wlan1 in namespace `rep`, bridged with a
#      veth to a host in `far` (10.30.0.20).
#   B  netcfgd's repeater: wlan3, `device { wifi { wds = true } }`, in brS with
#      a veth to a host in `far2` (10.40.0.20). The reference access point is
#      a bare hostapd with `wds_sta` on wlan2 in namespace `apns`, bridged
#      with a host in `lan2` (10.40.0.10).
#
# Each half passes when a UDP echo crosses from the far host to the LAN host,
# which only bridged four-address frames can carry. The control is the same
# echo before the apply, which must fail. And a second `ncfg plan` has nothing
# to do.
#
# Always exits 0 and reports through /verdict/wds.
#
# HOW IT STOPS: every wait is bounded (the radios at 5 s, each association
# at 15 s, each echo at 4 s), the steps are a fixed list, and the vm takes the
# daemons with it.
set -u
PATH=/usr/sbin:/sbin:/usr/local/sbin:/usr/local/bin:/usr/bin:/bin
export PATH
out=/verdict/wds
: > "$out"
say() { echo "$*" >> "$out"; echo "wds: $*"; }
mount -t tmpfs -o size=64m tmpfs /tmp 2>/dev/null
work=/tmp/wds
mkdir -p "$work/etc/secrets" "$work/run" "$work/rep" "$work/apns"
# The setup's complaints, for the failure report rather than the console.
exec 2>> "$work/setup.log"

build=/repo/c
for program in netcfgd ncfg; do
	if [ ! -x "$build/$program" ]; then
		say "VERDICT bad: $build/$program is not built on the host"
		exit 0
	fi
done

modprobe mac80211_hwsim radios=4
n=0
while [ ! -e /sys/class/net/wlan3 ] && [ "$n" -lt 50 ]; do
	sleep 0.1
	n=$((n + 1))
done
[ -e /sys/class/net/wlan3 ] || { say "VERDICT bad: hwsim gave fewer than four radios"; exit 0; }
for ns in lan rep far apns lan2 far2; do ip netns add "$ns"; done
phy_of() { cat "/sys/class/net/$1/phy80211/name"; }
iw phy "$(phy_of wlan1)" set netns name rep
iw phy "$(phy_of wlan2)" set netns name apns

# A veth between this namespace and another, with an address on the far end.
# The far end is `peer`, not `h`: `ip link set h up` reads `h` as `help`,
# prints the usage, and leaves the link down -- which is how both halves of
# this rig first failed with everything else correct.
host() { # $1 near name, $2 namespace, $3 address
	ip link add "$1" type veth peer name peer netns "$2"
	ip netns exec "$2" ip addr add "$3/24" dev peer
	ip netns exec "$2" ip link set peer up
	ip link set "$1" up
}
host vlan0 lan 10.30.0.10
host vrep2 far2 10.40.0.20

# The reference repeater for half A: 4addr on, bridged with a host in `far`.
R() { ip netns exec rep "$@"; }
R ip link add brR type bridge
R ip link set brR up
R ip link add vrep type veth peer name peer netns far
ip netns exec far ip addr add 10.30.0.20/24 dev peer
ip netns exec far ip link set peer up
R ip link set vrep master brR
R ip link set vrep up

# The reference access point for half B: wds_sta, bridged with a host in
# `lan2`.
A() { ip netns exec apns "$@"; }
A ip link add brA type bridge
A ip link set brA up
A ip link add vlan2 type veth peer name peer netns lan2
ip netns exec lan2 ip addr add 10.40.0.10/24 dev peer
ip netns exec lan2 ip link set peer up
A ip link set vlan2 master brA
A ip link set vlan2 up
cat > "$work/apns/ap.conf" <<CONF
interface=wlan2
bridge=brA
driver=nl80211
ctrl_interface=$work/apns/ctrl
ssid=rep2
hw_mode=g
channel=6
wpa=2
wpa_key_mgmt=WPA-PSK
rsn_pairwise=CCMP
wpa_passphrase=correcthorse
wds_sta=1
wds_bridge=brA
CONF
A hostapd -B -f "$work/apns/ap.log" "$work/apns/ap.conf" >/dev/null 2>&1

# A UDP echo: a server in a namespace, a client in another, each bounded.
cat > "$work/echo.py" <<'PY'
import socket, sys
if sys.argv[1] == "serve":
	s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	s.bind((sys.argv[2], 5000))
	s.settimeout(120)
	try:
		while True:
			data, peer = s.recvfrom(64)
			s.sendto(data, peer)
	except socket.timeout:
		pass
else:
	s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	s.settimeout(1)
	for _ in range(4):
		try:
			s.sendto(b"wds", (sys.argv[2], 5000))
			if s.recvfrom(64)[0] == b"wds":
				print("echoed")
				sys.exit(0)
		except OSError:
			pass
	print("silent")
PY
ip netns exec lan python3 "$work/echo.py" serve 10.30.0.10 &
server_a=$!
ip netns exec lan2 python3 "$work/echo.py" serve 10.40.0.10 &
server_b=$!
echo_a() { ip netns exec far python3 "$work/echo.py" send 10.30.0.10 2>/dev/null; }
echo_b() { ip netns exec far2 python3 "$work/echo.py" send 10.40.0.10 2>/dev/null; }

say "before the apply, half A's echo: $(echo_a); half B's: $(echo_b)"

printf 'correcthorse' > "$work/etc/secrets/rep"
chmod 600 "$work/etc/secrets/rep"
cat > "$work/etc/netcfgd.conf" <<CONF
device br0 {
	bridge { members = ["wlan0", "vlan0"] }
}
interface br0 { config = "10.30.0.1/24" }
interface wlan0 { }
interface vlan0 { }
access_point "rep" {
	device  = "wlan0"
	channel = 1
	wds     = true
	wifi { psk = "@secret:rep"; proto = "wpa2" }
}

device brS {
	bridge { members = ["wlan3", "vrep2"] }
}
device wlan3 {
	wifi { wds = true }
}
interface brS { config = "10.40.0.1/24" }
interface wlan3 { }
interface vrep2 { }
network "rep2" {
	wifi { psk = "@secret:rep"; proto = "wpa2" }
}
CONF
export NCFG_CONFIG_DIR="$work/etc" NCFG_RUN_DIR="$work/run"
"$build/ncfg" apply > "$work/apply.log" 2>&1
applied=$?
say "ncfg apply rc=$applied"

# Half A's reference repeater joins netcfgd's access point.
cat > "$work/rep/sta.conf" <<CONF
ctrl_interface=$work/rep/ctrl
network={
	ssid="rep"
	psk="correcthorse"
	key_mgmt=WPA-PSK
}
CONF
R iw dev wlan1 set 4addr on
R ip link set wlan1 master brR
R ip link set wlan1 up
R wpa_supplicant -B -i wlan1 -b brR -c "$work/rep/sta.conf" -f "$work/rep/sta.log" \
	>/dev/null 2>&1

state_of() { # $1 = a namespace prefix command or nothing, $2 ctrl dir, $3 iface
	$1 wpa_cli -p "$2" -i "$3" status 2>/dev/null | sed -n 's/^wpa_state=//p'
}
n=0
until [ "$(state_of R "$work/rep/ctrl" wlan1)" = COMPLETED ] || [ "$n" -gt 150 ]; do
	sleep 0.1
	n=$((n + 1))
done
sleep 2
a_state=$(state_of R "$work/rep/ctrl" wlan1)
a_echo=$(echo_a)
say "half A, netcfgd's access point: repeater ${a_state:-?}; br0: $(ls /sys/class/net/br0/brif | tr '\n' ' ')echo: $a_echo"

# Half B: netcfgd's repeater, joined by the apply.
n=0
until iw dev wlan3 link 2>/dev/null | grep -q '^Connected' || [ "$n" -gt 150 ]; do
	sleep 0.1
	n=$((n + 1))
done
sleep 2
b_4addr=$(iw dev wlan3 info 2>/dev/null | sed -n 's/^[[:space:]]*4addr: //p')
b_echo=$(echo_b)
say "half B, netcfgd's repeater: wlan3 4addr ${b_4addr:-off}; brS: $(ls /sys/class/net/brS/brif 2>/dev/null | tr '\n' ' ')$(iw dev wlan3 link 2>/dev/null | head -1); echo: $b_echo"

"$build/ncfg" plan > "$work/plan.log" 2>&1
again=$(grep -c '^nothing to do' "$work/plan.log")
say "a second plan: $(head -1 "$work/plan.log")"

kill "$server_a" "$server_b" 2>/dev/null
wait "$server_a" "$server_b" 2>/dev/null
failed=0
[ "$applied" -eq 0 ] || { say "  the apply failed"; failed=1; }
[ "$a_echo" = echoed ] || { say "  half A: nothing crossed netcfgd's access point"; failed=1; }
[ "$b_echo" = echoed ] || { say "  half B: nothing crossed netcfgd's repeater"; failed=1; }
[ "$b_4addr" = on ] || { say "  half B: wlan3 is not in four-address mode"; failed=1; }
[ "$again" -ge 1 ] || { say "  the second plan was not empty"; failed=1; }
if [ "$failed" -ne 0 ]; then
	sed 's/^/  apply: /' "$work/apply.log" | tail -14 >> "$out"
	sed 's/^/  plan: /' "$work/plan.log" | head -8 >> "$out"
	sed 's/^/  setup: /' "$work/setup.log" 2>/dev/null | head -20 >> "$out"
	ip -br link 2>&1 | sed 's/^/  link: /' >> "$out"
	bridge link 2>&1 | sed 's/^/  port: /' >> "$out"
	R bridge link 2>&1 | sed 's/^/  rep port: /' >> "$out"
	A bridge link 2>&1 | sed 's/^/  apns port: /' >> "$out"
	ip -br addr 2>&1 | sed 's/^/  addr: /' >> "$out"
	for ns in lan far lan2 far2; do
		ip netns exec "$ns" ip -br addr 2>&1 | sed "s/^/  $ns: /" >> "$out"
	done
	tail -8 "$work/rep/sta.log" 2>/dev/null | sed 's/^/  rep sta: /' >> "$out"
	say "VERDICT bad"
else
	say "VERDICT ok"
fi
exit 0
