#!/bin/sh
# Layer one's firewall, written to a real kernel and read back by nft.
#
#     unshare -rn sh tests/live/firewall.sh
#
# project.md 10.592 slice 2. `ncfg_nft_build_replace` writes the three filter
# chains and every rule expression layer one has, and the only honest proof of
# those bytes is a kernel taking them and a reader that is not netcfgd listing
# them back. A user and network namespace can hold an nftables table -- measured
# -- so this needs no root, and `nft` is the reader.
#
# HOW IT STOPS: a fixed list of steps, each a bounded command; the namespace is
# the process's, so the table goes with it.

set -eu

repo=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
build="${NCFG_LIVE_BUILD:-$repo/c}"
PATH="$PATH:/usr/sbin:/sbin"

skip() {
	if [ -n "${NCFG_LIVE:-}" ]; then
		echo "firewall.sh: NCFG_LIVE is set but this cannot run: $1" >&2
		exit 1
	fi
	echo "firewall.sh: skipping: $1"
	exit 0
}

probe="$build/examples/live_firewall"
[ -x "$probe" ] || skip "examples/live_firewall is not built (make -C c examples)"
command -v nft >/dev/null 2>&1 || skip "no nft(8) to read the ruleset back with"
nft list tables >/dev/null 2>&1 || skip "this namespace cannot use nftables"

work=$(mktemp -d "${TMPDIR:-/tmp}/ncfg-firewall.XXXXXX")
trap 'rm -rf "$work"' EXIT INT TERM

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
has() { # $1 what, $2 fixed text the listing must hold
	check "$1" "$(grep -cF -- "$2" "$work/listed" || true)" "1"
}

cat > "$work/netcfgd.conf" <<'CONF'
firewall {
	input {
		policy = "drop"
		accept "established" { state = ["established", "related"] }
		accept "ssh" { protocol = "tcp"; port = 22; from = ["192.168.7.9/16"] }
		accept "v6ping" { protocol = "icmpv6" }
		drop "strangers" { mac = ["de:ad:be:*"] }
		drop "one-station" { mac = ["02:00:00:00:01:00"] }
		reject "one" { from = ["2001:DB8::1"]; interface = "eth0" }
	}
	forward { policy = "drop" }
	output {
		policy = "accept"
		drop "smtp-out" { protocol = "tcp"; port = 25; to = ["198.51.100.0/24"]; interface = "wan0" }
	}
}
CONF

"$probe" "$work" > "$work/sent" 2>&1 || true
check "the kernel takes the transaction" "$(cat "$work/sent")" ""
nft list ruleset > "$work/listed" 2>&1 || true

has "the input chain is a filter chain at its hook, with the document's policy" \
	"type filter hook input priority filter; policy drop;"
has "and so is forward" "type filter hook forward priority filter; policy drop;"
has "and output" "type filter hook output priority filter; policy accept;"
has "a state set reads back as nft writes one" \
	'ct state established,related accept comment "name=established sha256='
has "a protocol, a port and a CIDR read back as written" \
	'tcp dport 22 ip saddr 192.168.0.0/16 accept comment "name=ssh sha256='
has "icmpv6 is the protocol nft calls ipv6-icmp" \
	'meta l4proto ipv6-icmp accept comment "name=v6ping sha256='
has "a station prefix is a mask nftables applies itself" \
	'ether saddr & ff:ff:ff:00:00:00 == de:ad:be:00:00:00 drop comment "name=strangers'
has "an exact station is an exact comparison" \
	'ether saddr 02:00:00:00:01:00 drop comment "name=one-station'
has "an IPv6 address, an arriving interface and a reject" \
	'ip6 saddr 2001:db8::1 iifname "eth0" reject comment "name=one sha256='
has "in output, the interface is the leaving one and the address the destination" \
	'tcp dport 25 ip daddr 198.51.100.0/24 oifname "wan0" drop comment "name=smtp-out'
check "nothing is written outside netcfgd's table" \
	"$(grep -c '^table ' "$work/listed" || true)" "1"

# The decoder (0295 A, 10.592 slice 2c): each kernel rule read back, and the
# digest recomputed from what was read. For a rule written with one value per
# match, agreeing digests say the reader and the writer agree.
"$probe" --read > "$work/read" 2>&1 || true
read_has() { # $1 what, $2 fixed text a decoded line must hold
	check "$1" "$(grep -cF -- "$2" "$work/read" || true)" "1"
}
read_has "a state set is read back" \
	"input established accept protocol=0 state=established state=related digest=recomputed"
read_has "a protocol, a port and a CIDR are read back" \
	"input ssh accept protocol=1 port=22 from=192.168.0.0/16 digest=recomputed"
read_has "a station prefix is read back as a prefix" \
	"input strangers drop protocol=0 mac=de:ad:be:* digest=recomputed"
read_has "an exact station as an address" \
	"input one-station drop protocol=0 mac=02:00:00:00:01:00 digest=recomputed"
read_has "an IPv6 source, an interface and a reject" \
	"input one reject protocol=0 from=2001:db8::1 interface=eth0 digest=recomputed"
read_has "and in output, the destination and the leaving interface" \
	"output smtp-out drop protocol=1 port=25 to=198.51.100.0/24 interface=wan0 digest=recomputed"
check "every rule the probe wrote is read, and none is refused" \
	"$(grep -c 'digest=recomputed' "$work/read" || true) $(grep -c '^refused' "$work/read" || true)" \
	"7 0"

# A rule somebody added inside netcfgd's table by hand is not netcfgd's as
# written, and the reader says so rather than describing it.
nft add rule inet netcfgd input tcp dport 8080 accept
nft add rule inet netcfgd input limit rate 10/second accept comment '"name=sneaky sha256=0000000000000000"'
"$probe" --read > "$work/read" 2>&1 || true
check "a hand-added rule with no identity is refused, naming why" \
	"$(grep -c '^refused .*no .name=... sha256=.... comment' "$work/read" || true)" "1"
check "and one wearing an identity with an expression netcfgd never writes" \
	"$(grep -c '^refused rule .sneaky. has a .limit. expression' "$work/read" || true)" "1"

# A replacement: the table is there, and a smaller ruleset takes its place.
cat > "$work/netcfgd.conf" <<'CONF'
firewall {
	input { policy = "accept" }
	forward { policy = "accept" }
	output { policy = "accept" }
}
CONF
"$probe" "$work" --replace > "$work/sent" 2>&1 || true
check "a replacement is taken too" "$(cat "$work/sent")" ""
nft list ruleset > "$work/listed" 2>&1 || true
check "and leaves none of the old rules behind" \
	"$(grep -c 'comment "name=' "$work/listed" || true)" "0"
has "with the new policy in place" "type filter hook input priority filter; policy accept;"

# Several values, and both families, in one rule: one kernel rule per
# combination, each carrying the written rule's name (10.592 slice 2b).
cat > "$work/netcfgd.conf" <<'CONF'
firewall {
	input {
		policy = "accept"
		drop "netbios" { protocol = "udp"; port = [137, 138]; from = ["10.0.0.0/8", "fd00::/8"] }
		drop "pair" { mac = ["02:00:00:00:00:01", "aa:bb:cc:*"] }
	}
	forward { policy = "accept" }
	output { policy = "accept" }
}
CONF
"$probe" "$work" --replace > "$work/sent" 2>&1 || true
check "a rule with several values is taken" "$(cat "$work/sent")" ""
nft list ruleset > "$work/listed" 2>&1 || true
check "as one kernel rule per port and address" \
	"$(grep -c 'comment "name=netbios sha256=' "$work/listed" || true)" "4"
has "the IPv6 one among them" \
	'udp dport 138 ip6 saddr fd00::/8 drop comment "name=netbios'
check "all four with one digest, the written rule's" \
	"$(grep -o 'name=netbios sha256=[0-9a-f]*' "$work/listed" | sort -u | wc -l | tr -d ' ')" "1"
check "and the stations as two" \
	"$(grep -c 'comment "name=pair sha256=' "$work/listed" || true)" "2"

# The refusals, which must refuse before anything is sent.
cat > "$work/netcfgd.conf" <<'CONF'
firewall {
	input {
		policy = "accept"
		drop "both" { from = ["10.0.0.1"]; to = ["2001:db8::1"] }
	}
	forward { policy = "accept" }
	output { policy = "accept" }
}
CONF
"$probe" "$work" --replace > "$work/sent" 2>&1 || true
check "a rule matching both address families is refused, not sent" \
	"$(grep -c 'no packet carries' "$work/sent" || true)" "1"
nft list ruleset > "$work/listed" 2>&1 || true
check "and the table it would have replaced is still there" \
	"$(grep -c 'policy accept;' "$work/listed" || true)" "3"

# ------------------------------------------- planned and applied by ncfg

# Slice 3 (10.592): the firewall through the program rather than the probe.
# The table above is cleared first, so this starts from a machine with none.
nft delete table inet netcfgd 2>/dev/null || true
ncfg="$build/ncfg"
[ -x "$ncfg" ] || skip "ncfg is not built"
mkdir -p "$work/etc" "$work/run"
export NCFG_CONFIG_DIR="$work/etc" NCFG_RUN_DIR="$work/run"
write_etc() {
	cat > "$work/etc/netcfgd.conf"
}
write_etc <<'CONF'
host_list "banned" { mac = ["de:ad:be:*", "02:00:00:00:00:09"] }
firewall {
	input {
		policy = "drop"
		accept "established" { state = ["established", "related"] }
		accept "ssh" { protocol = "tcp"; port = 22 }
		drop "strangers" { mac = ["@host_list:banned"] }
	}
	forward { policy = "drop" }
	output { policy = "accept" }
}
CONF
"$ncfg" plan > "$work/plan" 2>&1 || true
check "a firewall the machine lacks is planned as one table replacement" \
	"$(grep -c 'nftables.replace' "$work/plan" || true)" "1"
"$ncfg" apply > "$work/apply" 2>&1 || true
check "and applied" "$(grep -c '^ok   nftables.replace' "$work/apply" || true)" "1"
nft list ruleset > "$work/listed" 2>&1 || true
has "the host list's prefix is enforced in the kernel, as a mask" \
	'ether saddr & ff:ff:ff:00:00:00 == de:ad:be:00:00:00 drop comment "name=strangers'
has "and its exact station as an address" \
	'ether saddr 02:00:00:00:00:09 drop comment "name=strangers'
"$ncfg" plan > "$work/plan" 2>&1 || true
check "a second plan has nothing to do" "$(cat "$work/plan")" "nothing to do"
"$ncfg" status > "$work/status" 2>&1 || true
check "ncfg status shows the installed firewall as rules" \
	"$(grep -cE '^    (accept established state established,related|accept ssh protocol tcp port 22|drop strangers mac (de:ad:be:\*|02:00:00:00:00:09))$' "$work/status" || true)" "4"

# A hand edit inside netcfgd's table is a difference, and is replaced.
nft add rule inet netcfgd input tcp dport 8080 accept
"$ncfg" status > "$work/status" 2>&1 || true
check "ncfg status names a rule that is not netcfgd's as written" \
	"$(grep -c 'not netcfgd.s as written' "$work/status" || true)" "1"
"$ncfg" plan > "$work/plan" 2>&1 || true
check "and the plan replaces the table to take it out" \
	"$(grep -c 'nftables.replace' "$work/plan" || true)" "1"
"$ncfg" apply > /dev/null 2>&1 || true
check "after which the hand-added rule is gone" \
	"$(nft list ruleset | grep -c 'dport 8080' || true)" "0"

# Editing only the host list moves the firewall.
write_etc <<'CONF'
host_list "banned" { mac = ["de:ad:be:*"] }
firewall {
	input {
		policy = "drop"
		accept "established" { state = ["established", "related"] }
		accept "ssh" { protocol = "tcp"; port = 22 }
		drop "strangers" { mac = ["@host_list:banned"] }
	}
	forward { policy = "drop" }
	output { policy = "accept" }
}
CONF
"$ncfg" plan > "$work/plan" 2>&1 || true
check "a host list edit alone is planned" "$(grep -c 'nftables.replace' "$work/plan" || true)" "1"
"$ncfg" apply > /dev/null 2>&1 || true
check "and leaves the station it lost unmatched" \
	"$(nft list ruleset | grep -c '02:00:00:00:00:09' || true)" "0"

# Another table filtering at the same hook is reported before the apply, and
# left alone (0294): nftables is additive and the strictest verdict wins.
nft add table inet neighbour
nft add chain inet neighbour in '{ type filter hook input priority 0; policy accept; }'
"$ncfg" plan > "$work/plan" 2>&1 || true
check "a neighbour's filter chain at the input hook is named in the plan" \
	"$(grep -c 'neighbour/in (input)' "$work/plan" || true)" "1"
"$ncfg" apply > /dev/null 2>&1 || true
check "and is not touched" "$(nft list tables | grep -c 'inet neighbour' || true)" "1"
nft delete table inet neighbour

# Taking the firewall out of the document takes it out of the kernel.
: > "$work/etc/netcfgd.conf"
"$ncfg" apply > "$work/apply" 2>&1 || true
check "a document with no firewall removes the table" \
	"$(nft list tables | grep -c 'inet netcfgd' || true)" "0"

echo
if [ "$failures" -eq 0 ]; then
	echo "firewall.sh: all checks passed"
else
	echo "firewall.sh: $failures check(s) failed"
	exit 1
fi
