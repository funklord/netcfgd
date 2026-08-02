#!/bin/sh
# What netcfgd hands pppd, checked against a real pppd.
#
#     unshare -rn sh tests/live/ppp.sh
#
# A DSL line is the part nobody here has, and `/dev/ppp` needs real root, so a
# session cannot be dialled. What *can* be done is hand the options file netcfgd
# generated to a real pppd and see whether it takes it -- the same technique
# `ap.sh` uses to validate a hostapd configuration on a machine with no radio.
#
# With one wrinkle that took a negative control to notice. The rp-pppoe plugin
# opens `/dev/ppp` **when it is loaded**, part-way through option parsing, so
# pppd never reaches the options after the `plugin` line on a machine like this
# one. "No unrecognized option" on the whole file is therefore a check that
# passes because nothing was parsed, and it passed exactly that way until a
# deliberately misspelled option failed to make it fail. The options netcfgd
# chooses for itself are checked without the plugin line, and the plugin's own
# options are named as the part this cannot reach.
#
# The other half is the scripts. pppd runs one when a session comes up and one
# when it goes down, and it hands the *same* environment to both -- `DNS1` and
# `DNS2` stay set on the way down. That is why there are two scripts rather than
# one branching on its environment, and running them is the only way to see it.
#
# Not run under NCFG_LIVE, for the reason ap.sh is not: ppp is a package a
# machine with no DSL line has no reason to have.

set -eu

repo=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)

skip() {
	if [ -n "${NCFG_LIVE:-}" ]; then
		echo "ppp.sh: NCFG_LIVE is set but this cannot run: $1" >&2
		exit 1
	fi
	echo "ppp.sh: skipping: $1"
	exit 0
}

# The same search order netcfgd uses, so a test that found pppd somewhere
# netcfgd does not look cannot pass while netcfgd reports it missing.
find_pppd() {
	for path in /usr/sbin/pppd /sbin/pppd /usr/bin/pppd; do
		if [ -x "$path" ]; then
			echo "$path"
			return 0
		fi
	done
	return 1
}

[ -x "$repo/target/debug/ncfg" ] || skip "ncfg is not built"
pppd=$(find_pppd) || skip "pppd is not installed (apt install ppp)"

work=$(mktemp -d /tmp/ncfg-ppp.XXXXXX)
trap 'rm -rf "$work"' EXIT INT TERM
mkdir -p "$work/etc/secrets" "$work/run"

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

printf '%s' 'dsl-password' > "$work/etc/secrets/dsl"
chmod 600 "$work/etc/secrets/dsl"
ip link add eth-wan type dummy
ip link set eth-wan up

cat > "$work/etc/netcfgd.conf" <<'CONF'
interface ppp0 {
	routes = "default"
	pppoe {
		parent   = "eth-wan"
		username = "alice@isp.example"
		password = "@secret:dsl"
	}
	dns { }
}
CONF

# The apply dials, pppd fails somewhere after parsing -- there is no DSL line --
# and the options file is written before any of that.
"$ncfg" apply > "$work/apply.txt" 2>&1 || true
options="$work/run/ppp/ppp0"
check "netcfgd wrote the options file" \
	"$([ -f "$options" ] && echo yes || echo no)" "yes"
# The password is in it, which is why it is 0600 and under /run.
check "at mode 0600, because the password is in it" \
	"$(stat -c '%a' "$options" 2>/dev/null)" "600"

# ---------------------------------------------------- the reference tool

# A real pppd, on the real file -- and the first thing it says is the one thing
# this can check about the plugin: that it loaded. The rp-pppoe plugin opens
# /dev/ppp when it is loaded, which needs real root, so pppd never reaches the
# options *after* the plugin line here. That makes "no unrecognized option" on
# the whole file a check that passes because nothing was parsed, which is how
# the first version of this test passed.
"$pppd" file "$options" > "$work/parse.txt" 2>&1 || true
check "a real pppd loads the plugin netcfgd named" \
	"$(grep -c 'Plugin pppoe.so loaded' "$work/parse.txt" || true)" "1"
check "and stops where an unprivileged machine has to" \
	"$(grep -c '/dev/ppp' "$work/parse.txt" || true)" "1"

# So the options netcfgd chose are parsed without it. `nic-` and `rp_pppoe_*`
# are the plugin's own and go with it; what is left is netcfgd's own list, and
# that is the half that has been wrong before -- `usepeerdns` was left out for
# years on a belief nobody checked.
grep -v '^plugin \|^nic-\|^rp_pppoe_' "$options" > "$work/core.opts"
check "the plugin's options are the only ones this cannot check" \
	"$(grep -c '^nic-eth-wan$' "$options" || true)" "1"
"$pppd" file "$work/core.opts" > "$work/core.txt" 2>&1 || true
check "and a real pppd takes every option netcfgd chose itself" \
	"$(grep -c 'unrecognized option' "$work/core.txt" || true)" "0"
check "having got as far as looking for a device" \
	"$(grep -c 'no device specified' "$work/core.txt" || true)" "1"

# The check above is only worth something if pppd would have said so. Proved
# rather than assumed, because "no complaint" is the reading a broken check
# gives too -- and it is the reading the whole-file version gave.
sed 's/^usepeerdns$/usepeerdns-but-spelled-wrong/' "$work/core.opts" > "$work/broken.opts"
"$pppd" file "$work/broken.opts" > "$work/broken.txt" 2>&1 || true
check "and would have said so, given one it does not know" \
	"$(grep -c "unrecognized option 'usepeerdns-but-spelled-wrong'" "$work/broken.txt" \
		|| true)" "1"

# ------------------------------------------------------------ the scripts

check "netcfgd wrote both scripts, executable" \
	"$([ -x "$work/run/ppp/ppp0.up" ] && [ -x "$work/run/ppp/ppp0.down" ] \
		&& echo yes || echo no)" "yes"
check "and pointed pppd at each of them" \
	"$(grep -c "^ip-up-script $work/run/ppp/ppp0.up$" "$options" || true)" "1"

# pppd's own argv and environment, from ipcp.c: interface, tty, speed, local,
# remote, ipparam -- and DNS1/DNS2, which `usepeerdns` is what asks for.
run_script() {
	IPLOCAL=10.0.0.2 IPREMOTE=10.0.0.1 USEPEERDNS=1 \
	DNS1=195.190.228.10 DNS2=195.190.228.20 \
		sh "$1" ppp0 /dev/pts/3 0 10.0.0.2 10.0.0.1 ''
}

run_script "$work/run/ppp/ppp0.up"
report="$work/run/reported/ppp0"
check "the up script reported what pppd learned" \
	"$(grep -c '^dns=195.190.228.10$' "$report" 2>/dev/null || true)" "1"
check "both of them" \
	"$(grep -c '^dns=195.190.228.20$' "$report" 2>/dev/null || true)" "1"
# The address stays with pppd (decision 0047) and the only route a ppp link has
# is the one the document writes, so neither belongs in the report.
check "and nothing else, because the rest is not pppd's to report" \
	"$(grep -cE '^(address|route|gateway)=' "$report" 2>/dev/null || true)" "0"

# What netcfgd then does with them is not checked here and cannot be: the apply
# stops at the dial, because there is no DSL line, and every action after a
# failed one is skipped by design. The gate that decides whether a `dns` block
# is needed is a fixture test, and the delivery itself is report.sh's.

# The session drops. The down script empties the report -- and this is the
# check the whole two-script arrangement exists for, because pppd hands the
# ip-down call the very same DNS1 and DNS2.
#
# It is also the one check here that the unit tests cannot make. They call the
# script generator directly and would go on passing if both files were written
# from the same side of it, which is the mistake this catches: made on purpose,
# and this line went red while every unit test stayed green.
run_script "$work/run/ppp/ppp0.down"
check "the down script reports nothing, with DNS1 still in its environment" \
	"$(grep -c '^dns=' "$report" 2>/dev/null || true)" "0"

echo
if [ "$failures" -eq 0 ]; then
	echo "ppp.sh: all checks passed"
else
	echo "ppp.sh: $failures check(s) failed"
	exit 1
fi
