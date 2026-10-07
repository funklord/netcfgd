# What this tier exists for, asserted inside a guest: its own kernel, its own
# modules, its own init. Run by tool/vm/run.sh; see 0265.
#
# The module names are the kernel's, not the config symbols': `BT_HCIVHCI`
# builds `hci_vhci`, and asking for `vhci` reports "not found in modules.dep"
# -- which reads exactly like the capability being absent when it is the name
# that is wrong.
echo "kernel: $(uname -r)"
echo "init:   $(cat /proc/1/comm)"
rc-status --version >/dev/null 2>&1 && echo "openrc: $(rc-status --version | head -1)"
for mod in mac80211_hwsim hci_vhci pppoe; do
	if modprobe "$mod" 2>/dev/null; then
		echo "module: $mod loaded"
	else
		echo "module: $mod FAILED"
	fi
done
# The radios mac80211_hwsim creates, which is what hwsim.sh wants and cannot
# have on a host that will not load a module.
echo "phys:   $(ls /sys/class/ieee80211/ 2>/dev/null | tr '\n' ' ')"
echo "vhci:   $([ -c /dev/vhci ] && echo present || echo absent)"
