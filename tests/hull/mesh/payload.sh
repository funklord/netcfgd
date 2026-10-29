#!/bin/sh
# netcfgd joining an 802.11s mesh (project.md 10.588).
#
# Two hwsim radios in one vm. netcfgd's node is wlan0, configured by a `mesh`
# block and an `interface` block and joined by `ncfg apply`. The other node is
# wlan1, moved into a network namespace and run by a bare wpa_supplicant from
# a file -- the reference implementation, so what is under test is whether
# netcfgd's node is one a standard mesh node peers with.
#
# What is asserted, and the control that makes each mean something:
#
#   - the peer link is established (`mesh plink: ESTAB`), and wlan0 is a mesh
#     point -- which only netcfgd's apply could have made it;
#   - traffic crosses: a UDP echo from 10.20.0.1 to 10.20.0.2 comes back. The
#     same echo is tried before the apply and must fail, which is what shows
#     the probe can tell a mesh from no mesh;
#   - a second `ncfg plan` has nothing to do, which is the apply's record and
#     the observation's digest agreeing -- the two sides of 10.588's one
#     fingerprint question.
#
# Always exits 0 and reports through /verdict/mesh.
#
# HOW IT STOPS: every wait is bounded (the radios at 5 s, the peer link at 20
# s, each echo at 3 s), the steps are a fixed list, and the vm takes both
# supplicants with it.
set -u
PATH=/usr/sbin:/sbin:/usr/local/sbin:/usr/local/bin:/usr/bin:/bin
export PATH
out=/verdict/mesh
: > "$out"
say() { echo "$*" >> "$out"; echo "mesh: $*"; }
mount -t tmpfs -o size=64m tmpfs /tmp 2>/dev/null
work=/tmp/mesh
mkdir -p "$work/etc/secrets" "$work/run" "$work/peer"

build=/repo/c
for program in netcfgd ncfg; do
	if [ ! -x "$build/$program" ]; then
		say "VERDICT bad: $build/$program is not built on the host"
		exit 0
	fi
done

modprobe mac80211_hwsim radios=2
n=0
while [ ! -e /sys/class/net/wlan1 ] && [ "$n" -lt 50 ]; do
	sleep 0.1
	n=$((n + 1))
done
[ -e /sys/class/net/wlan1 ] || { say "VERDICT bad: hwsim gave no second radio"; exit 0; }
peer_mac=$(cat /sys/class/net/wlan1/address)
ip netns add peer
iw phy "$(cat /sys/class/net/wlan1/phy80211/name)" set netns name peer

# The reference node: the same mesh, from a file.
cat > "$work/peer.conf" <<CONF
ctrl_interface=$work/peer
update_config=0
network={
	ssid="backhaul"
	mode=5
	frequency=2412
	key_mgmt=SAE
	sae_password="correcthorse"
	ieee80211w=2
}
CONF
ip netns exec peer wpa_supplicant -B -i wlan1 -c "$work/peer.conf" -f "$work/peer.log" \
	>/dev/null 2>&1
ip netns exec peer ip addr add 10.20.0.2/24 dev wlan1
ip netns exec peer ip link set wlan1 up

# A UDP echo across the mesh: a server in the peer's namespace, a client here,
# each bounded. Prints `echoed` or `silent`.
cat > "$work/echo.py" <<'PY'
import socket, sys
if sys.argv[1] == "serve":
	s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	s.bind(("10.20.0.2", 5000))
	s.settimeout(60)
	try:
		while True:
			data, peer = s.recvfrom(64)
			s.sendto(data, peer)
	except socket.timeout:
		pass
else:
	s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	s.settimeout(1)
	for _ in range(3):
		try:
			s.sendto(b"mesh", ("10.20.0.2", 5000))
			if s.recvfrom(64)[0] == b"mesh":
				print("echoed")
				sys.exit(0)
		except OSError:
			pass
	print("silent")
PY
ip netns exec peer python3 "$work/echo.py" serve &
server=$!

# The control: no mesh yet, so nothing may come back.
before=$(python3 "$work/echo.py" send 2>/dev/null)
say "before the apply, the echo: ${before:-nothing}"

printf 'correcthorse' > "$work/etc/secrets/mesh"
chmod 600 "$work/etc/secrets/mesh"
cat > "$work/etc/netcfgd.conf" <<CONF
mesh "backhaul" {
	device  = "wlan0"
	channel = 1
	wifi { psk = "@secret:mesh" }
}

interface wlan0 {
	config = "10.20.0.1/24"
}
CONF
export NCFG_CONFIG_DIR="$work/etc" NCFG_RUN_DIR="$work/run"
"$build/ncfg" apply > "$work/apply.log" 2>&1
applied=$?
say "ncfg apply rc=$applied"

n=0
until iw dev wlan0 station dump 2>/dev/null | grep -q 'mesh plink:.*ESTAB' || [ "$n" -gt 200 ]; do
	sleep 0.1
	n=$((n + 1))
done
iftype=$(iw dev wlan0 info 2>/dev/null | sed -n 's/^[[:space:]]*type //p')
link=$(iw dev wlan0 station dump 2>/dev/null | grep -A20 "^Station $peer_mac" |
	sed -n 's/^[[:space:]]*mesh plink:[[:space:]]*//p' | head -1)
say "wlan0: type ${iftype:-?}; peer link to $peer_mac: ${link:-none}"
after=$(python3 "$work/echo.py" send 2>/dev/null)
say "after the apply, the echo: ${after:-nothing}"

"$build/ncfg" plan > "$work/plan.log" 2>&1
again=$(grep -c '^nothing to do' "$work/plan.log")
say "a second plan: $(head -1 "$work/plan.log")"

kill "$server" 2>/dev/null
wait "$server" 2>/dev/null
failed=0
[ "$applied" -eq 0 ] || { say "  the apply failed"; failed=1; }
[ "$before" = silent ] || { say "  the control failed: an echo came back with no mesh"; failed=1; }
[ "$iftype" = "mesh point" ] || { say "  wlan0 is not a mesh point"; failed=1; }
[ "$link" = ESTAB ] || { say "  no established peer link to $peer_mac"; failed=1; }
[ "$after" = echoed ] || { say "  no traffic crossed the mesh"; failed=1; }
[ "$again" -ge 1 ] || { say "  the second plan was not empty: the record and the observation disagree"; failed=1; }
if [ "$failed" -ne 0 ]; then
	sed 's/^/  apply: /' "$work/apply.log" | tail -12 >> "$out"
	sed 's/^/  plan: /' "$work/plan.log" | head -8 >> "$out"
	say "VERDICT bad"
else
	say "VERDICT ok"
fi
exit 0
