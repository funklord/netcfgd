#!/bin/sh
# PID 1 in a machine whose kernel genuinely cannot do nftables NAT.
#
# Run by `tests/kernel/run.sh`, which has the tier's whole argument; it is
# packed into an initramfs as /init and is the only thing the machine runs.
#
# The companion to `tests/hull/natcap/payload.sh`, which measures the same
# states on the host's kernel by blocking module autoload. Here there is no
# module support at all -- CONFIG_MODULES is off -- so "absent" means compiled
# out, with no loader that could be said to have been blocked instead.
#
# **Which state this is comes from the kernel's own config, not from an
# argument.** `/proc/config.gz` is the instrument's account of itself, and a
# run against the wrong bzImage would otherwise look exactly like a run
# against the right one.
#
# Termination: mounts, one daemon killed by pid, then a sysrq power-off. The
# kernel is booted with `panic=5` and qemu with `-no-reboot`, so an exit from
# here ends the machine too.
set -u
mount -t proc proc /proc 2>/dev/null
mount -t sysfs sys /sys 2>/dev/null
mount -t devtmpfs dev /dev 2>/dev/null
echo
echo "=== $(uname -srm), config says:"
if [ -r /proc/config.gz ]; then
	zcat /proc/config.gz | grep -E "^(CONFIG_MODULES|CONFIG_NF_TABLES|CONFIG_NFT_NAT|CONFIG_NFT_MASQ|CONFIG_NF_NAT)=" |
		sed 's/^/      /'
	zcat /proc/config.gz | grep -E "^# (CONFIG_MODULES|CONFIG_NFT_NAT|CONFIG_NFT_MASQ|CONFIG_NF_NAT) is not set" |
		sed 's/^/      /'
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
	if zcat /proc/config.gz | grep -qx CONFIG_MODULES=y; then
		echo "      !! this kernel has module support, so it is not the one built for this"
	fi
else
	echo "      /proc/config.gz is absent, so this kernel cannot say what it is" >&2
	expect=NFT_MSG_NEWCHAIN
	state="unknown, assumed to lack the chain type"
fi
echo "=== state: $state, so the refused message should be $expect"

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

build=/opt/ncfg
work=/run/natcap
mkdir -p "$work/etc" "$work/run"
export NCFG_CONFIG_DIR="$work/etc" NCFG_RUN_DIR="$work/run"
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
	sed 's/^/    /' "$work/daemon.log"
	failures=$((failures + 1))
else
	"$build/ncfg" apply > "$work/apply.log" 2>&1
	rc=$?
	kill "$pid" 2>/dev/null
	wait "$pid" 2>/dev/null
	echo "--- ncfg apply rc=$rc"
	sed 's/^/    /' "$work/apply.log"
	said() { grep -q -- "$1" "$work/apply.log" && echo yes || echo no; }

	check "  the plan held the nat.replace, so this measured something" \
		"$(said 'nat.replace')" yes
	if [ "$expect" = applied ]; then
		# **The control, and the only state here that must succeed.** It is
		# what separates "this construct is missing" from "this stripped
		# kernel cannot do NAT for some other reason" -- without it every
		# refusal above is consistent with a kernel that was simply too
		# small, and the measurement would prove nothing about the two
		# options that were left out.
		check "a kernel with both constructs built in applies NAT" \
			"$([ "$rc" -eq 0 ] && echo applied || echo refused)" applied
		check "  with the op reported ok" "$(said 'ok   nat.replace')" yes
	else
		check "a kernel built without it refuses the apply" \
			"$([ "$rc" -ne 0 ] && echo refused || echo applied)" refused
		check "  the kernel's answer is ENOENT, as the blocked-autoload rig measured" \
			"$(said 'ENOENT')" yes
		check "  and not EOPNOTSUPP" "$(said 'EOPNOTSUPP')" no
		check "  the refused message is the one this config predicts" \
			"$(said "$expect")" yes
	fi
fi

echo
if [ "$failures" -gt 0 ]; then
	echo "natcap-kernel: $failures check(s) failed"
else
	echo "natcap-kernel: every check passed"
fi
echo 1 > /proc/sys/kernel/sysrq 2>/dev/null
sync
echo o > /proc/sysrq-trigger 2>/dev/null
# If sysrq did not take, fall off the end: panic=5 and qemu's -no-reboot end it.
sleep 5
