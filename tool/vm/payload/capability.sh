# What this tier exists for, asserted inside a guest: its own kernel, its own
# modules, its own init. Run by tool/vm/run.sh; see 0265.
#
# **This asserts rather than reports, and the first version did not.** It ended
# with an `echo`, so its exit status was that echo's and `make vm` would have
# passed with not one module loaded -- a gate over a capability it never
# checked, which is the shape this tree keeps finding and which went into its
# own harness anyway.
#
# The module names are the kernel's, not the config symbols': `BT_HCIVHCI`
# builds `hci_vhci`, and asking for `vhci` reports "not found in modules.dep",
# which reads exactly like the capability being absent when it is the name that
# is wrong.
set -u
failures=0
note() { echo "  $1"; }
fail() {
	echo "  FAIL: $1"
	failures=$((failures + 1))
}

note "kernel: $(uname -r)"
note "init:   $(cat /proc/1/comm)"
if rc-status --version >/dev/null 2>&1; then
	note "openrc: $(rc-status --version | head -1)"
else
	fail "no OpenRC, which is one of the three init systems netcfgd ships"
fi

# The three modules the eight skipping live scripts need. A namespace on the
# host cannot load any of them; that is the whole of why this tier exists, so
# each one failing is this tier not delivering what it was built for.
for mod in mac80211_hwsim hci_vhci pppoe; do
	if modprobe "$mod" 2>/dev/null; then
		note "module: $mod loaded"
	else
		fail "$mod did not load, so this guest is not what the tier promises"
	fi
done

# mac80211_hwsim makes radios, and the radios are what hwsim.sh wants. Two by
# default: the module's own default is a pair, and a count of zero means the
# module loaded and did nothing, which a modprobe status cannot see.
phys=$(ls /sys/class/ieee80211/ 2>/dev/null | tr '\n' ' ')
case "$phys" in
*phy0*) note "phys:   $phys" ;;
*) fail "mac80211_hwsim loaded and made no radio (phys: ${phys:-none})" ;;
esac

if [ -c /dev/vhci ]; then
	note "vhci:   present"
else
	fail "/dev/vhci is absent though hci_vhci loaded"
fi

echo "  capability: $failures failure(s)"
[ "$failures" -eq 0 ]
