#!/bin/sh
# The wifi association, as the observation sees it, against a real radio.
#
# Decision 0153 lets a `network` carry a `metric` that outranks its interface's
# `preference` while the machine is on that network. The planner can only apply
# it if the observation knows which network a radio joined -- so this asserts
# the one link in that chain that no fixture can reach: a real wpa_supplicant,
# associated to a real access point, resolved back to a real document.
#
#     sudo sh tests/live/association.sh
#
# ## What it does to the machine, and what it undoes
#
# **Nothing, and nothing.** It reads. `netcfgd_observe::current` reads netlink,
# sysfs and the supplicant's control socket; persisting an observation is the
# caller's job and this is not that caller. Run beside a live daemon it adds
# one reader and no writer, which is the same thing `ncfg status` already does.
#
# It does not reconfigure, associate, disconnect, or write under /run. That is
# deliberate rather than incidental: this is meant to be runnable on the
# machine somebody is using, over the very wifi it is asking about.
#
# ## Why it needs root
#
# The supplicant's control socket is `root:root` with no write bit for others,
# and connecting to a unix socket needs write. Without it the association read
# returns nothing -- which is exactly what an unassociated radio returns, so a
# non-root run would report a clean pass having proved nothing. The probe
# refuses rather than allowing that, and this checks the refusal happens.

set -eu

repo=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
probe="$repo/target/debug/examples/live_association"

skip() {
	if [ -n "${NCFG_LIVE:-}" ]; then
		echo "association.sh: NCFG_LIVE is set but this cannot run: $1" >&2
		exit 1
	fi
	echo "association.sh: skipping: $1"
	exit 0
}

fail() {
	echo "association.sh: FAIL: $1" >&2
	exit 1
}

[ -x "$probe" ] || skip "the probe is not built (cargo build -p netcfgd-host --example live_association)"
command -v ncfg >/dev/null 2>&1 || skip "no ncfg to take an independent reading with"
[ -S /run/netcfgd/netcfgd.sock ] || skip "no netcfgd is running to compare against"

# A radio that is not associated cannot answer the question this asks. Skipping
# is the honest outcome: "no association found" would otherwise read as a pass
# on a machine whose wifi is simply off.
status=$(ncfg wifi status 2>/dev/null) || skip "ncfg wifi status did not answer"
interface=$(printf '%s\n' "$status" | awk 'NR == 1 { print $1 }')
state=$(printf '%s\n' "$status" | awk 'NR == 1 { print $2 }')
[ -n "$interface" ] || skip "no wireless interface is managed"
[ "$state" = "COMPLETED" ] || skip "$interface is $state rather than associated"

# **The independent reading.** This comes out of the daemon's `wifi status`,
# which resolves the association through the socket path, while the probe
# resolves it through the observation path. Two paths that share only
# `network_for` -- so agreement is evidence the wiring is right, and a
# disagreement names which side is wrong rather than just that something is.
expected=$(printf '%s\n' "$status" | sed -n 's/^[[:space:]]*from the `\(.*\)` network block$/\1/p')
[ -n "$expected" ] || skip "$interface is on a network the document does not describe"

echo "association.sh: $interface is associated, and ncfg calls it \`$expected\`"

# The probe refuses without root, and that refusal is what keeps a powerless
# run from reporting a clean pass. Checked rather than assumed: a probe that
# stopped refusing would make every later assertion vacuous.
if [ "$(id -u)" -ne 0 ]; then
	if "$probe" >/dev/null 2>&1; then
		fail "the probe ran without root; it cannot see the supplicant socket from there"
	fi
	skip "not root, and the supplicant socket is root-only"
fi

observed=$("$probe" 2>/dev/null) || fail "the probe could not observe"
got=$(printf '%s\n' "$observed" | awk -v want="$interface" '$1 == want { print $3 }')

[ -n "$got" ] || fail "the observation reported no row for $interface"
if [ "$got" = "-" ]; then
	fail "the observation says $interface is on no configured network, but ncfg says \`$expected\`"
fi
[ "$got" = "$expected" ] || fail "the observation says \`$got\`, ncfg says \`$expected\`"

echo "association.sh: the observation agrees: $interface -> \`$got\`"

# And the radio is the only kind of link that gets one. A wired link reporting
# a network would mean the field was being filled from something other than an
# association -- the failure that a test asserting only the radio cannot see.
wired=$(printf '%s\n' "$observed" | awk '$2 == "wired" && $3 != "-" { print $1 }')
[ -z "$wired" ] || fail "wired link(s) claim a network: $wired"

echo "association.sh: and no wired link claims one"
echo "association.sh: all checks passed"
