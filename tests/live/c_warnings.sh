#!/bin/sh
# What netcfgd warns about a document, line for line.
#
#     unshare -rn sh tests/live/c_warnings.sh
#
# `ncfg show --json` is the pure path, a configuration directory in and a
# canonical document out. A plan is not pure -- it observes the machine -- and
# the planner is where every warning is decided, so a warning is only reached
# by planning.
#
# **Every document here is a configuration that is legal, compiles, plans
# actions and does something other than what it looks like**: a `device` block
# with no `interface` block, a fixed `mac` under a `mac_policy` that replaces
# it, EAP that pins no issuer, a `phase2` that pins no inner method, an access
# point on a DFS channel, the second access point on a radio this build will
# not start. That is the only kind of mistake a warning can catch.
#
# **A namespace is what makes a plan repeatable.** In a fresh network namespace
# the machine is empty and does not change, so the observation half is the
# same every run and what is left is what netcfgd says about the document.
#
# WHAT IS EXPECTED, AND WHERE IT CAME FROM
#   Until 0317 this compared the C against the Rust, with the lines the C says
#   differently declared one by one. The expected lines below are the C's on
#   the day the Rust was retired, when that comparison passed -- so each one is
#   a line two implementations written apart agreed on, or a declared
#   difference with its reason beside it in the C. They are **exact whole
#   lines** for the reason the declarations were: a pattern quietly covers the
#   next change too, and a whole line fails the moment its text moves, which is
#   when somebody should read it again.
#
#   A document with no expected warnings would compare nothing -- five of the
#   first eight written for this were refused by the compiler and reported
#   "same" -- so every case names at least one, and one that does not compile
#   fails rather than passing.
set -eu
repo=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
skip() {
	if [ -n "${NCFG_LIVE:-}" ]; then
		echo "c_warnings.sh: NCFG_LIVE is set but this cannot run: $1" >&2
		exit 1
	fi
	echo "c_warnings.sh: skipping: $1"
	exit 0
}
[ -x "$repo/c/ncfg" ] || skip "the C ncfg is not built (make -C c)"
# **Runnable, not merely present.** `[ -x ]` answers "is there an executable
# file", which is not "can this machine run it" -- and the two differ wherever
# the libc the binary was linked against is not the one installed. Measured on
# Alpine 2026-10-23: this tree's glibc `ncfg` is `-x` there, and running it gets
# `not found` from the shell, because the ELF interpreter it names is absent.
# So the skip never fired, and a comparison binary that could not run reported
# as a missing file several checks later.
"$repo/c/ncfg" --version >/dev/null 2>&1 || skip "the C ncfg will not run here (a glibc build on musl)"
work=$(mktemp -d "${TMPDIR:-/tmp}/ncfg-c-warnings.XXXXXX")
cleanup() { rm -rf "$work"; }
trap cleanup EXIT INT TERM
mkdir -p "$work/etc" "$work/run"

export NCFG_CONFIG_DIR="$work/etc"
export NCFG_RUN_DIR="$work/run"

failures=0

# One document, and the warnings it must produce, exactly.
#
#   $1  what this document is about
#   $2  the document
#
# The expected lines are read from `$work/wanted`, which the caller writes
# immediately before, and removed here so one case cannot inherit the last.
expect() {
	what="$1"
	printf '%s\n' "$2" > "$work/etc/netcfgd.conf"
	if ! [ -s "$work/wanted" ]; then
		echo "FAIL $what: no warnings are expected, so nothing would be compared"
		failures=$((failures + 1))
		return
	fi
	if timeout 60 "$repo/c/ncfg" plan 2>&1 | grep -q '^ncfg:'; then
		echo "FAIL $what: the document does not compile, so nothing was compared"
		timeout 60 "$repo/c/ncfg" plan 2>&1 | head -2 | sed 's/^/       /'
		failures=$((failures + 1))
		rm -f "$work/wanted"
		return
	fi
	timeout 60 "$repo/c/ncfg" plan 2>&1 | grep '^warning:' | sort > "$work/said" || true
	sort "$work/wanted" -o "$work/wanted"
	if diff -q "$work/wanted" "$work/said" >/dev/null 2>&1; then
		echo "ok   $what: $(wc -l < "$work/said") warning(s), as expected"
	else
		echo "FAIL $what: the warnings changed"
		diff "$work/wanted" "$work/said" | sed 's/^/       /'
		failures=$((failures + 1))
	fi
	rm -f "$work/wanted"
}

# ---------------------------------------------------------------- the wifi four

cat > "$work/wanted" <<'WANTED'
warning: `phase2 = "auth"` on network `office` pins no inner method: wpa_supplicant reads this as `key=value` and ignores anything else, so the server proposes the inner method and the supplicant accepts it -- including one that sends the password in clear inside the tunnel. Write `auth=MSCHAPV2`, or `autheap=` where the inner method is itself EAP
warning: inert0: inert0 has a `device` block and no `interface` block, so nothing is planned for it: netcfgd plans by interface, and a `device` block on its own is policy about hardware nobody has asked it to configure. `interface inert0 { config = "dhcp" }` is what makes it netcfgd's
warning: network `office` pins a `ca_cert` and no `domain_suffix_match`, so it accepts any server certificate that issuer signed. Where the issuer is a public CA that is anybody who can buy one: they raise an access point with this name, are believed, and take what the inner method sends. Set `domain_suffix_match` to the server's name, such as `radius.example.com`
warning: network `plain` authenticates with EAP and pins no `ca_cert`, so it will trust any server that answers -- which is how the credential is taken. Set `ca_cert` to the issuer's certificate, or `ncfg wifi add ... --ca-cert PATH`, and `domain_suffix_match` to the server's name
warning: radio0: radio0 is configured but no such device is present; nothing planned for it
warning: radio0: radio0 sets `mac` to 02:00:00:00:00:01 and a `mac_policy` of `per_network`, which replaces it: the supplicant applies a randomised address when it associates, over whatever the link is carrying. netcfgd does both, so the configured address holds until the radio joins a network and not after. If the fixed address is for MAC-based admission, `mac_policy = "permanent"` is what keeps it
WANTED
expect "a radio whose fixed mac is replaced, and EAP that trusts anything" '
device radio0 {
	mac = "02:00:00:00:00:01"
	wifi {
		backend     = "wpa_supplicant"
		autoconnect = true
		mac_policy  = "per_network"
	}
}
device inert0 { kind = "dummy" }
interface radio0 {
	config = "dhcp"
}
network "office" {
	wifi {
		eap      = "peap"
		identity = "someone@corp.example"
		password = "@secret:office"
		ca_cert  = "@secret:corp-ca"
		phase2   = "auth"
	}
}
network "plain" {
	wifi {
		eap      = "peap"
		identity = "someone@corp.example"
		password = "@secret:office"
	}
}'

# ------------------------------------------------------------- access points

cat > "$work/wanted" <<'WANTED'
warning: ap0: `ap0` has more than one access point and this build runs one BSS per radio, so `one` is started and `two` is not
warning: ap0: access point `one` is on channel 52, which is shared with radar in most regulatory domains: the radio has to listen on it before it may beacon, so the access point will be silent for a minute or so after this apply returns -- longer on some channels. Channels 36 to 48 and 149 upwards need no such wait
warning: ap0: ap0 is configured but no such device is present; nothing planned for it
WANTED
expect "an access point on a radar channel, and a second one that will not run" '
device ap0 {
	wifi { backend = "wpa_supplicant" }
}
interface ap0 { config = "dhcp" }
access_point "one" {
	device  = "ap0"
	channel = 52
	wifi    { open = true }
}
access_point "two" {
	device  = "ap0"
	channel = 6
	wifi    { open = true }
}'

# ------------------------------------------- what nothing in netcfgd acts on

# A network block's own addressing is applied by nothing: it round-trips
# through `ncfg profile save` and nothing else reads it. `plan/wifi.c` has the
# reasoning, and `plan/build.c` the sentence it shares with the next one.
cat > "$work/wanted" <<'WANTED'
warning: the `network` block `n1` states addressing, and nothing applies it: netcfgd plans addressing, routes and `dns` from an `interface` block, and a network's own only round-trip via `ncfg profile save`. Nothing in netcfgd acts on it, so there is nothing to wait for. The block is kept so a configuration written now still means this when the code arrives
WANTED
expect "a network block carrying addressing nothing will apply" '
device h0 { kind = "dummy" }
interface h0 {
	config = "10.9.52.1/24"
}
network "n1" {
	wifi   { open = true }
	config = "dhcp"
}'

# The same gap, for an ethtool setting. `plan/offload.c` budgets the length of
# this one to the character.
cat > "$work/wanted" <<'WANTED'
warning: eth0: `speed` in the `ethtool` block is recognised and applied by nothing: it can only be exercised against a physical NIC, and an encoder nobody has run against one is how the last three netlink bugs here got in. The offloads are applied. Nothing in netcfgd acts on it, so there is nothing to wait for. The block is kept so a configuration written now still means this when the code arrives
WANTED
expect "an ethtool setting that needs hardware nothing here has" '
device eth0 {
	kind = "dummy"
	ethtool { rx_checksum = "on"; gro = "off"; speed = 1000 }
}
interface eth0 {
	config = "10.9.50.1/24"
}'

# ---------------------------------------------------------- and the rest

cat > "$work/wanted" <<'WANTED'
warning: un0: `un0` is `managed = false` with `on_unmanage = "clear"`: netcfgd removes everything it owns on it -- addresses and routes carrying its tag, backends it started, and the credentials those hold -- and then leaves it alone. Anything it did not put there is left exactly as it is. The plan above is what is left to remove; an empty one means it is done
WANTED
expect "a device taken out of the daemon's hands, told what it loses" '
device un0 {
	kind        = "dummy"
	managed     = false
	on_unmanage = "clear"
}
interface un0 {
	config = "10.9.51.1/24"
}'

cat > "$work/wanted" <<'WANTED'
warning: `nat` is set but no interface has `forwarding = true`, so nothing will reach the translation. Set it on the interface the traffic arrives on -- the LAN side, not the uplink.
WANTED
expect "an interface asking for NAT" '
device n0 { kind = "dummy" }
interface n0 {
	config = "10.9.53.1/24"
	nat    = true
}'

cat > "$work/wanted" <<'WANTED'
warning: dns.apply cannot be undone; commit-confirm will not revert it
WANTED
expect "a resolver mode nothing on this machine provides" '
global {
	dns_mode = "resolved"
	dns      = ["10.9.0.53"]
}
device d0 { kind = "dummy" }
interface d0 { config = "10.9.54.1/24" }'

if [ "$failures" -eq 0 ]; then
	echo "c_warnings.sh: all checks passed"
else
	echo "c_warnings.sh: $failures check(s) failed"
	exit 1
fi
