#!/bin/sh
# The natcap measurement on a kernel built without the construct netcfgd asks
# for, in a hull machine.
#
# WHAT THIS IS FOR
#   `tests/hull/natcap/` measures the same states on the host's kernel by
#   blocking module autoload, which makes a construct unreachable by the same
#   lookup that fails when it was never compiled. That is an argument; this is
#   the experiment it predicts. These kernels have `CONFIG_MODULES` off
#   entirely, so there is no loader at all and "absent" cannot be confused
#   with "blocked".
#
# **WHICH STATE THIS IS COMES FROM THE KERNEL'S OWN CONFIG**, not from an
# argument. `/proc/config.gz` is the instrument's account of itself, and a run
# against the wrong bzImage would otherwise look exactly like a run against
# the right one -- which is not hypothetical: hull's `(kernel "path:...")` was
# silently ignored by a stale core for a day, and the only thing that showed
# it was a guest whose release differed from the host's.
#
# It ran as PID 1 in hand-driven qemu until 2026-10-25, mounting /proc and
# powering the machine off itself. hull's machine does both, so this is a
# workload now: `run.sh` has the tier's whole argument.
set -u
build=${NCFG_BUILD:-/repo/c}
echo "=== $(uname -sr), config:"
zcat /proc/config.gz 2>/dev/null |
	grep -E '^(CONFIG_MODULES|CONFIG_NF_TABLES|CONFIG_NFT_NAT|CONFIG_NFT_MASQ|CONFIG_NF_NAT)=' |
	sed 's/^/     /'
if ! zcat /proc/config.gz >/dev/null 2>&1; then
	echo "     /proc/config.gz is absent, so this kernel cannot say what it is" >&2
	echo "VERDICT bad: no config to derive the state from"
	exit 1
fi
if zcat /proc/config.gz | grep -qx CONFIG_MODULES=y; then
	echo "     !! this kernel has module support, so it is not one of this tier's"
fi

# **The bridge state comes first, being told apart by a different symbol.**
# k0, k1 and k2 have no bridge at all (`CONFIG_BRIDGE` is a module in
# `x86_64_defconfig` and modules are off), so `BRIDGE=y` with filtering unset
# is k3 and nothing else.
if zcat /proc/config.gz | grep -qx CONFIG_BRIDGE=y &&
    ! zcat /proc/config.gz | grep -qx CONFIG_BRIDGE_VLAN_FILTERING=y; then
	echo "=== a bridge that cannot filter: what netcfgd tells an operator"
	mount -t tmpfs tmpfs /tmp 2>/dev/null || true
	work=$(mktemp -d /tmp/kstate.XXXXXX)
	export NCFG_CONFIG_DIR="$work/etc" NCFG_RUN_DIR="$work/run"
	mkdir -p "$work/etc" "$work/run"
	cat > "$work/etc/netcfgd.conf" <<'CONF'
device br0 {
	bridge {
		vlan_filtering = true
	}
	vlans = "10"
}
interface br0 {
	config = "10.9.8.1/24"
}
CONF
	"$build/netcfgd" --no-apply-on-start > "$work/daemon.log" 2>&1 &
	pid=$!
	waited=0
	while [ ! -e "$work/run/netcfgd.sock" ] && [ "$waited" -lt 100 ]; do
		waited=$((waited + 1))
		sleep 0.1
	done
	if [ ! -e "$work/run/netcfgd.sock" ]; then
		echo "the daemon never started:"
		sed 's/^/     /' "$work/daemon.log"
		echo "VERDICT bad: no daemon"
		exit 1
	fi
	"$build/ncfg" apply > "$work/apply.log" 2>&1
	rc=$?
	kill "$pid" 2>/dev/null
	wait "$pid" 2>/dev/null
	echo "=== ncfg apply rc=$rc"
	sed 's/^/     /' "$work/apply.log"
	# **What this state found, now asserted.** It was added to see whether
	# netcfgd's per-port vlan sentence -- which names `vlan_filtering = true`,
	# a configuration cause -- would misname things on a kernel that cannot
	# filter at all. It does not: the vlans are skipped behind an earlier
	# refusal, and that refusal had no sentence of its own. So what is checked
	# is the sentence that was missing: the settings step names the kernel
	# option, where the generic errno text said "a module may not be loaded"
	# about a module that was loaded.
	if ! grep -q 'EOPNOTSUPP' "$work/apply.log"; then
		echo "VERDICT bad: expected the settings to be refused EOPNOTSUPP"
		exit 1
	fi
	if ! grep -q 'CONFIG_BRIDGE_VLAN_FILTERING' "$work/apply.log"; then
		echo "VERDICT bad: the refusal does not name the option that is missing"
		exit 1
	fi
	if grep -q 'vlan_filtering = true' "$work/apply.log"; then
		echo "VERDICT bad: it blames the config key, which cannot be the remedy"
		exit 1
	fi
	echo "VERDICT ok: the settings refusal names the kernel option, not the key"
	exit 0
fi

# The three NAT states, in the order a reader meets them in `config-kernel.sh`.
if zcat /proc/config.gz | grep -qx CONFIG_NFT_MASQ=y; then
	expect=applied
	state="everything NAT needs, which is the control"
elif zcat /proc/config.gz | grep -qx CONFIG_NFT_NAT=y; then
	expect=NFT_MSG_NEWRULE
	state="the nat chain type, with no masquerade"
else
	expect=NFT_MSG_NEWCHAIN
	state="no nat chain type at all"
fi
echo "=== $state, so the kernel should answer with $expect"

# **A tmpfs for what this writes**, for the reason `tests/hull/hwsim` carries
# at length: a stored source's root is 9p, writes cross to the host, and a
# daemon whose socket and logs are on that path is slow enough for netcfgd to
# read its own backend as wedged.
mount -t tmpfs tmpfs /tmp 2>/dev/null ||
	echo "note: no tmpfs on /tmp, so this writes through the machine's root"

work=$(mktemp -d /tmp/kstate.XXXXXX)
export NCFG_CONFIG_DIR="$work/etc" NCFG_RUN_DIR="$work/run"
mkdir -p "$work/etc" "$work/run"
cat > "$work/etc/netcfgd.conf" <<'CONF'
device wan0 {
	kind   = "dummy"
}
interface wan0 {
	config = "10.9.9.2/24"
	nat    = true
}
CONF

"$build/netcfgd" --no-apply-on-start > "$work/daemon.log" 2>&1 &
pid=$!
waited=0
while [ ! -e "$work/run/netcfgd.sock" ] && [ "$waited" -lt 100 ]; do
	waited=$((waited + 1))
	sleep 0.1
done
if [ ! -e "$work/run/netcfgd.sock" ]; then
	echo "the daemon never started:"
	sed 's/^/     /' "$work/daemon.log"
	echo "VERDICT bad: no daemon"
	exit 1
fi
"$build/ncfg" apply > "$work/apply.log" 2>&1
rc=$?
kill "$pid" 2>/dev/null
wait "$pid" 2>/dev/null
echo "=== ncfg apply rc=$rc"
sed 's/^/     /' "$work/apply.log"

# **The vacuity guard this is most exposed to**: a converged machine plans no
# `nftables.replace` and the apply then says nothing about the kernel while looking
# like a result.
if ! grep -q 'nftables.replace' "$work/apply.log"; then
	echo "VERDICT bad: no nftables.replace in that plan, so this measured nothing"
	exit 1
fi
if [ "$expect" = applied ]; then
	# The control, and the only state here that must succeed: without it a
	# refusal could be a property of a small kernel rather than of the
	# construct that was left out.
	if [ "$rc" -eq 0 ] && grep -q 'ok   nftables.replace' "$work/apply.log"; then
		echo "VERDICT ok: a kernel with both constructs applies NAT"
	else
		echo "VERDICT bad: the control kernel did not apply NAT"
		exit 1
	fi
elif grep -q "$expect" "$work/apply.log" && grep -q ENOENT "$work/apply.log" &&
    ! grep -q EOPNOTSUPP "$work/apply.log"; then
	echo "VERDICT ok: $expect refused with ENOENT, and not EOPNOTSUPP"
else
	echo "VERDICT bad: wanted $expect refused with ENOENT"
	exit 1
fi
