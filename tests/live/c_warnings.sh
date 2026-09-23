#!/bin/sh
# What the two implementations say about a document, compared.
#
#     unshare -rn sh tests/live/c_warnings.sh
#
# `agree_gate.py` compares `ncfg show --json` because that is the whole pure
# path: a configuration directory in, a canonical document out. A plan is not
# pure -- it observes the machine -- so the gate cannot reach the planner, and
# the planner is where every warning is decided.
#
# **That gap had four warnings in it**, found by hand: a `device` block with no
# `interface` block, a fixed `mac` under a `mac_policy` that replaces it, EAP
# that pins no issuer, and a `phase2` that pins no inner method. Two more
# followed: an access point on a DFS channel, and the second access point on a
# radio that this build will not start. Every one is about a configuration that
# is legal, compiles, plans actions and does something other than what it looks
# like -- which is the only kind of mistake a warning can catch, and the only
# kind nothing else here was looking for.
#
# **A namespace is what makes a plan comparable.** Both programs observe the
# same machine a moment apart, and in a fresh network namespace that machine is
# empty and does not change between the two runs, so the observation half is
# the same for both and what is left is what they say about the document.
#
# WHAT A DIFFERENCE IS ALLOWED TO BE
#   This port says some things the Rust does not, deliberately and with its own
#   reasons written down beside them. Those are declared here as **exact whole
#   lines**, per document, in the shape `agree_gate.py` uses and for its
#   reason: an exception that is a pattern quietly covers the next divergence
#   too, and an exception that is a whole line expires by failing when the line
#   it names stops being emitted. There is no allow-list and no "ignore
#   anything matching".
#
# Adding a document here is the cheap half of this. If it produces no warnings
# from either program it is not comparing anything -- five of the first eight
# written for this were refused by both compilers and reported "same" -- so
# each one declares how many warnings it expects, and a document that stops
# producing them fails rather than passing quietly.

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
[ -x "$repo/target/debug/ncfg" ] || skip "the Rust ncfg is not built, and it is the comparison"

work=$(mktemp -d "${TMPDIR:-/tmp}/ncfg-c-warnings.XXXXXX")
cleanup() { rm -rf "$work"; }
trap cleanup EXIT INT TERM
mkdir -p "$work/etc" "$work/run"

export NCFG_CONFIG_DIR="$work/etc"
export NCFG_RUN_DIR="$work/run"

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

warnings_from() {
	timeout 60 "$1" plan 2>&1 | grep '^warning:' | sort || true
}

# One document through both programs.
#
#   $1  what this document is about
#   $2  how many warnings the Rust must produce -- a document that stops
#       producing them is a case that stopped testing anything
#   $3  the document
#
# Lines this port adds are read from `$extra`, and a Rust line this port
# rewords from `$reword_from` / `$reword_to`; both are set by the caller and
# cleared here, so a declaration cannot leak into the next document.
compare() {
	what="$1"
	expected="$2"
	printf '%s\n' "$3" > "$work/etc/netcfgd.conf"

	if timeout 60 "$repo/target/debug/ncfg" plan 2>&1 | grep -q '^ncfg:'; then
		echo "FAIL $what: the document does not compile, so nothing was compared"
		timeout 60 "$repo/target/debug/ncfg" plan 2>&1 | head -2 | sed 's/^/       /'
		failures=$((failures + 1))
		extra=""; reword_from=""; reword_to=""
		return
	fi

	warnings_from "$repo/target/debug/ncfg" > "$work/rust"
	warnings_from "$repo/c/ncfg" > "$work/c"
	check "$what: the document still produces the warnings it was written for" \
		"$(grep -c '^warning:' "$work/rust" || true)" "$expected"

	# The Rust's output, with this port's declared differences applied. An
	# exception that no longer describes anything leaves a line that does not
	# match, so it fails rather than lingering.
	cp "$work/rust" "$work/wanted"
	if [ -n "$reword_from" ]; then
		if ! grep -qxF "$reword_from" "$work/wanted"; then
			echo "FAIL $what: a declared rewording names a line the Rust no longer says"
			echo "       $reword_from"
			failures=$((failures + 1))
		fi
		grep -vxF "$reword_from" "$work/wanted" > "$work/wanted.next" || true
		printf '%s\n' "$reword_to" >> "$work/wanted.next"
		mv "$work/wanted.next" "$work/wanted"
	fi
	if [ -n "$extra" ]; then
		printf '%s\n' "$extra" >> "$work/wanted"
	fi
	sort "$work/wanted" -o "$work/wanted"

	if diff -q "$work/wanted" "$work/c" >/dev/null 2>&1; then
		echo "ok   $what: both say the same thing"
	else
		echo "FAIL $what: the two disagree"
		diff "$work/wanted" "$work/c" | sed 's/^/       /'
		failures=$((failures + 1))
	fi
	extra=""; reword_from=""; reword_to=""
}

extra=""; reword_from=""; reword_to=""

# ---------------------------------------------------------------- the wifi four

compare "a radio whose fixed mac is replaced, and EAP that trusts anything" 6 '
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

compare "an access point on a radar channel, and a second one that will not run" 3 '
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

# --------------------------------------------- where this port says more

# A network block's own addressing is applied by neither implementation and
# only this one says so: they round-trip through `ncfg profile save` and
# nothing else reads them. `plan/wifi.c` has the reasoning.
extra='warning: the `network` block `n1` states addressing, and nothing applies it: netcfgd plans addressing, routes, `dns` and hooks from an `interface` block, and a network'"'"'s own only round-trip through `ncfg profile save`. That is not this port catching up: nothing acts on it in the Rust either, so there is nothing to wait for. The block is kept so a configuration written now still means this when the code arrives'
compare "a network block carrying addressing nothing will apply" 0 '
device h0 { kind = "dummy" }
interface h0 {
	config = "10.9.52.1/24"
}
network "n1" {
	wifi   { open = true }
	config = "dhcp"
}'

# The same gap, said in agreeing number. `plan/offload.c` budgets the length of
# this one to the character, which is why it is a rewording rather than a
# second sentence.
reword_from='warning: eth0: `speed` in the ethtool block are recognised but not applied by this build. They can only be exercised against a physical NIC, and an encoder nobody has run against one is how the last three netlink bugs here got in. The offloads are applied.'
reword_to='warning: eth0: `speed` in the `ethtool` block is recognised and applied by nothing: it can only be exercised against a physical NIC, and an encoder nobody has run against one is how the last three netlink bugs here got in. The offloads are applied. That is not this port catching up: nothing acts on it in the Rust either, so there is nothing to wait for. The block is kept so a configuration written now still means this when the code arrives'
compare "an ethtool setting that needs hardware nothing here has" 1 '
device eth0 {
	kind = "dummy"
	ethtool { rx_checksum = "on"; gro = "off"; speed = 1000 }
}
interface eth0 {
	config = "10.9.50.1/24"
}'

# ------------------------------------------------- and where they agree already

compare "a device taken out of the daemon's hands, told what it loses" 1 '
device un0 {
	kind        = "dummy"
	managed     = false
	on_unmanage = "clear"
}
interface un0 {
	config = "10.9.51.1/24"
}'

compare "an interface asking for NAT" 1 '
device n0 { kind = "dummy" }
interface n0 {
	config = "10.9.53.1/24"
	nat    = true
}'

compare "a resolver mode nothing on this machine provides" 1 '
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
