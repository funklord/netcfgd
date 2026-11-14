#!/bin/sh
# An IPsec tunnel's virtual IP and routes, reaching its XFRM interface through
# the report netcfgd's updown command writes (decision 0324).
#
# WHAT IS REAL AND WHAT IS NOT
#   strongSwan is not here: this host's has neither swanctl nor vici, and
#   tests/ipsec/probe.sh measured in a container what charon hands the updown
#   command. This drives `packaging/hooks/ipsec-updown` with exactly that
#   environment, and everything after it is real -- the XFRM interface netcfgd
#   makes, the fragment the command writes, and what `ncfg apply` does with it
#   against the kernel.
#
# Run as root, or under `unshare -rn` (which is how `make live` runs it).
#
# HOW IT STOPS: two applies and four reads; nothing is started that outlives
# the script, and the work directory goes with it.
#
# POSIX sh.
set -eu

repo=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
build="${NCFG_LIVE_BUILD:-$repo/c}"
updown="$repo/packaging/hooks/ipsec-updown"

skip() {
	if [ -n "${NCFG_LIVE:-}" ]; then
		echo "ipsec_report.sh: NCFG_LIVE is set but this cannot run: $1" >&2
		exit 1
	fi
	echo "ipsec_report.sh: skipping: $1"
	exit 0
}

command -v ip >/dev/null 2>&1 || skip "no ip(8) to check the result with"
[ -x "$build/ncfg" ] || skip "ncfg is not built"
[ "$(id -u)" = 0 ] || skip "needs root, or unshare -rn"
ip link add ncfg-xfrm-probe type xfrm if_id 99 2>/dev/null || skip "this kernel makes no XFRM interface"
ip link del ncfg-xfrm-probe

work=$(mktemp -d "${TMPDIR:-/tmp}/ncfg-ipsec.XXXXXX")
trap 'rm -rf "$work"; ip link del ipsec0 2>/dev/null || true; ip link del up0 2>/dev/null || true' EXIT INT TERM
mkdir -p "$work/etc" "$work/run"
cat > "$work/etc/netcfgd.conf" <<'CONF'
device ipsec0 {
	xfrm { if_id = 7 }
}
interface ipsec0 {
	config = "reported"
}
CONF

failures=0
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
apply() {
	"$build/ncfg" apply --oneshot --config-dir "$work/etc" --factory-dir "$work/none" \
		--run-dir "$work/run" > "$work/apply.txt" 2>&1 || {
		cat "$work/apply.txt" >&2
		exit 1
	}
}
# What charon handed the command in tests/ipsec/probe.sh, with a second child
# for the fragment that has to stay its own.
up() {
	env NCFG_RUN_DIR="$work/run" PLUTO_VERB=up-client PLUTO_MY_SOURCEIP=10.98.0.1 \
		PLUTO_IF_ID_IN=7 PLUTO_IF_ID_OUT=7 PLUTO_PEER=192.0.2.1 \
		PLUTO_PEER_CLIENT="$2" PLUTO_CONNECTION="$1" PLUTO_DNS4_1=10.99.0.53 \
		sh "$updown" ipsec0
}
down() {
	env NCFG_RUN_DIR="$work/run" PLUTO_VERB=down-client PLUTO_CONNECTION="$1" \
		sh "$updown" ipsec0
}

ip link set lo up
up net 10.99.0.0/24
up mgmt 10.97.0.0/24
contains "the updown command writes the child's fragment" \
	"$(cat "$work/run/reported.d/ipsec0/net" 2>/dev/null)" "address=10.98.0.1/32"
contains "  with the far side's subnet as a route" \
	"$(cat "$work/run/reported.d/ipsec0/net" 2>/dev/null)" "route=10.99.0.0/24"
contains "and a second child keeps its own" \
	"$(cat "$work/run/reported.d/ipsec0/mgmt" 2>/dev/null)" "route=10.97.0.0/24"

apply
contains "netcfgd makes the XFRM interface" "$(ip -d link show ipsec0 2>&1)" "xfrm if_id 0x7"
contains "and puts the virtual IP on it" "$(ip -o -4 addr show dev ipsec0)" "10.98.0.1/32"
routes=$(ip route show dev ipsec0)
contains "and routes the first child's subnet into it" "$routes" "10.99.0.0/24"
contains "and the second's" "$routes" "10.97.0.0/24"

down net
apply
routes=$(ip route show dev ipsec0)
case "$routes" in
*10.99.0.0/24*)
	echo "FAIL a child going down takes its route away"
	failures=$((failures + 1))
	;;
*) echo "ok   a child going down takes its route away" ;;
esac
contains "and leaves the other child's" "$routes" "10.97.0.0/24"
down mgmt
apply
contains "and with both down the address goes too" \
	"$(ip -o -4 addr show dev ipsec0 | wc -l | tr -d ' ')" "0"

# A full tunnel (project.md 10.859): all of IPv4 into ipsec0, and the peer
# reached only by the uplink's default route, as a DHCP client installs it.
# Its own packets to the peer must still leave by the uplink, so netcfgd pins
# a host route to the peer there -- and takes it away with the tunnel.
cat >> "$work/etc/netcfgd.conf" <<'CONF'
device up0 { kind = "dummy" }
interface up0 {
	config = "192.0.2.2/24"
}
CONF
apply
ip route add default via 192.0.2.1 dev up0 metric 100
env NCFG_RUN_DIR="$work/run" PLUTO_VERB=up-client PLUTO_MY_SOURCEIP=10.98.0.1 \
	PLUTO_PEER=198.51.100.1 PLUTO_PEER_CLIENT=0.0.0.0/0 PLUTO_CONNECTION=all \
	sh "$updown" ipsec0
contains "the report names the peer" "$(cat "$work/run/reported.d/ipsec0/all")" \
	"peer=198.51.100.1"
apply
contains "the tunnel takes the default route" "$(ip route get 203.0.113.9)" "dev ipsec0"
contains "and the peer is pinned to the uplink" "$(ip route get 198.51.100.1)" \
	"via 192.0.2.1 dev up0"
contains "and the next plan has nothing to do" \
	"$("$build/ncfg" plan --config-dir "$work/etc" --factory-dir "$work/none" \
		--run-dir "$work/run" 2>&1 | head -1)" "nothing to do"
env NCFG_RUN_DIR="$work/run" PLUTO_VERB=down-client PLUTO_CONNECTION=all \
	sh "$updown" ipsec0
apply
contains "with the tunnel down the pin is gone" "$(ip route show dev up0)" "default via 192.0.2.1"
case "$(ip route show dev up0)" in
*198.51.100.1*)
	echo "FAIL   and only the pin"
	failures=$((failures + 1))
	;;
*) echo "ok     and only the pin" ;;
esac

# A `report_writer` named for a tunnel that already exists takes effect at
# the next apply rather than at the device's next remake (10.868). `root` is
# the one account a user namespace can hand a directory to.
rm -rf "$work/run/reported.d/ipsec0"
sed -i 's/xfrm { if_id = 7 }/xfrm { if_id = 7; report_writer = "root" }/' "$work/etc/netcfgd.conf"
apply
contains "a writer named for an existing tunnel gets its directory at the next apply" \
	"$([ -d "$work/run/reported.d/ipsec0" ] && echo present || echo absent)" "present"
sed -i 's/; report_writer = "root"//' "$work/etc/netcfgd.conf"

# `ncfg tunnel up|down` (10.864): the daemon asks strongSwan, through a
# swanctl that records what it was asked -- `NCFG_SWANCTL` names it, as
# `NCFG_OPENVPN` names openvpn. Started detached, so the record is waited for.
sed -i 's/xfrm { if_id = 7 }/xfrm { if_id = 7; connection = "home"; child = "all" }/' \
	"$work/etc/netcfgd.conf"
cat > "$work/swanctl" <<SWAN
#!/bin/sh
echo "\$*" >> "$work/swanctl.log"
SWAN
chmod 755 "$work/swanctl"
env NCFG_CONFIG_DIR="$work/etc" NCFG_RUN_DIR="$work/run" NCFG_SWANCTL="$work/swanctl" \
	"$build/netcfgd" --no-apply-on-start > "$work/daemon.log" 2>&1 &
daemon=$!
trap 'kill "$daemon" 2>/dev/null || true; rm -rf "$work"; ip link del ipsec0 2>/dev/null || true; ip link del up0 2>/dev/null || true' EXIT INT TERM
waited=0
until [ -e "$work/run/fuzznet.sock" ] || [ "$waited" -gt 100 ]; do
	sleep 0.1
	waited=$((waited + 1))
done
asked() {
	waited=0
	until grep -q -- "$1" "$work/swanctl.log" 2>/dev/null || [ "$waited" -gt 50 ]; do
		sleep 0.1
		waited=$((waited + 1))
	done
	grep -c -- "$1" "$work/swanctl.log" 2>/dev/null || echo 0
}
said=$(NCFG_RUN_DIR="$work/run" "$build/ncfg" tunnel up ipsec0 2>&1)
contains "ncfg tunnel up is answered" "$said" "asked strongSwan to bring ipsec0 up"
contains "and strongSwan is asked for the child of the connection" \
	"$(asked '--initiate --child all --ike home')" "1"
NCFG_RUN_DIR="$work/run" "$build/ncfg" tunnel down ipsec0 > /dev/null 2>&1
contains "ncfg tunnel down takes the connection down" \
	"$(asked '--terminate --ike home')" "1"
contains "a device that is not a tunnel is refused by name" \
	"$(NCFG_RUN_DIR="$work/run" "$build/ncfg" tunnel up up0 2>&1)" "up0 is not an IPsec tunnel"
kill "$daemon" 2>/dev/null
wait "$daemon" 2>/dev/null || true

echo
if [ "$failures" -eq 0 ]; then
	echo "ipsec_report.sh: all checks passed"
else
	echo "ipsec_report.sh: $failures check(s) failed"
	exit 1
fi
