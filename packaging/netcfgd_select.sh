#!/bin/sh
# Choose which daemon configures this machine's network, and make it stick.
#
#     netcfgd_select.sh [netcfgd|networkmanager|networkd|none]
#
# Run with no argument it selects netcfgd, which is what `postinst` does: a
# machine that installed netcfgd gets netcfgd, not a program sitting next to
# whatever was already fighting for the interfaces.
#
# WHY THIS IS A SCRIPT AND NOT A LINE IN postinst
#   Because it has to run in the other direction too. `postrm` calls it with
#   `none` to unmask everything on the way out -- without that, removing
#   netcfgd would leave a machine whose every network daemon is masked and no
#   way back onto the network. And an operator who wants NetworkManager back
#   for an afternoon runs `netcfgd_select.sh networkmanager` rather than
#   reconstructing six systemctl invocations from memory.
#
# WHAT IT DOES BEYOND stop AND disable
#   Stopping a network daemon does not undo what it left behind, and the
#   leftovers are what make the next daemon fail in ways nobody can read:
#
#     * **Its runtime claim.** NetworkManager writes
#       /run/NetworkManager/devices/<ifindex> and systemd-networkd writes
#       /run/systemd/netif/links/<ifindex>. Neither is removed when the daemon
#       stops -- NM's unit has no RuntimeDirectory= and networkd sets
#       RuntimeDirectoryPreserve=yes. netcfgd reads those files to decide
#       whether somebody else holds an interface, so a stopped NM went on
#       holding every interface for ever and netcfgd declined them all. That
#       is decision 0145, and it cost the copyright holder days: the guard
#       against two daemons fighting produced a machine with no daemon on it.
#
#     * **Its children.** A supplicant or a DHCP client started by NM is not
#       stopped with NM -- `KillMode=process` leaves them -- so the radio is
#       still held by a process whose parent is gone. Those are the orphans.
#
# WHAT IT WILL NOT TOUCH
#   No package is removed and no binary renamed. netcfgd *runs* wpa_supplicant,
#   dhcpcd, hostapd, pppd, openvpn, udhcpc, odhcp6c and resolvconf -- they are
#   tools it delegates to, not rivals. And the NetworkManager package stays
#   whatever is selected, because desktop wireless applets depend on it and
#   they work against netcfgd through `netcfgd-nm`, which serves NM's own bus
#   name. What cannot run is the NM *daemon*: two processes cannot own one bus
#   name.
#
#   Anything whose command line mentions /run/netcfgd/ is netcfgd's own and is
#   never signalled, and neither is a process in another network namespace --
#   a container's daemons are visible in /proc and are somebody else's
#   business (0167).
#
# POSIX sh: this runs on Debian, Alpine and OpenWrt alike.
set -eu

me=${0##*/}

usage() {
	cat <<USAGE
usage: $me [netcfgd|networkmanager|networkd|none]

  netcfgd         stand the others down and run netcfgd  (the default)
  networkmanager  stand the others down and run NetworkManager
  networkd        stand the others down and run systemd-networkd
  none            unmask everything and start nothing -- what postrm uses

  --dry-run       say what would happen and change nothing
USAGE
}

dry=
target=
for argument in "$@"; do
	case "$argument" in
	--dry-run) dry=yes ;;
	-h | --help)
		usage
		exit 0
		;;
	netcfgd | networkmanager | networkd | none) target=$argument ;;
	*)
		echo "$me: unknown argument: $argument" >&2
		usage >&2
		exit 2
		;;
	esac
done
[ -n "$target" ] || target=netcfgd

# **`--dry-run` is exempt, and that is not a convenience.** It changes
# nothing, so refusing it without root would leave the one mode an operator
# can use to find out what this would do on their machine available only to
# the account that no longer needs to ask.
if [ -z "$dry" ] && [ "$(id -u)" != 0 ]; then
	echo "$me: this changes which daemon owns the network, so it needs root" >&2
	echo "$me: try '$me --dry-run $target' to see what it would do" >&2
	exit 1
fi

run() {
	if [ -n "$dry" ]; then
		echo "$me: would: $*"
	else
		"$@" >/dev/null 2>&1 || true
	fi
}

say() { echo "$me: $*"; }

# ---------------------------------------------------------------------------
# The managers, and what each leaves behind.
#
# One case arm rather than four parallel lists: three facts about one daemon
# belong together, and a list that has to be edited in three places is how the
# fourth entry ends up with two of them.
# ---------------------------------------------------------------------------
managers='netcfgd networkmanager networkd connman modemmanager resolved
supplicant iwd dhcpcd ifupdown wicd'

# **netplan is deliberately not in that list, and is warned about instead.**
# It is not a daemon and cannot be selected or stood down: it is a generator
# that renders /etc/netplan/*.yaml into systemd-networkd or NetworkManager
# configuration at boot. Masking those two is what stops them running, and
# this script does that -- but the yaml stays, so anybody who later unmasks
# them gets netplan's idea of the network back rather than a clean machine.
# Removing somebody's declarative configuration is not this script's business,
# so it says so and leaves it.

# More than one unit per manager where more than one can start it. **A masked
# service that a socket can still activate is not stood down** -- systemd
# starts the service when the socket is hit, and `systemctl mask` on the
# service alone leaves that door open. Same for the `-wait-online` units,
# which pull their daemon in as a dependency at boot.
unit_of() {
	case "$1" in
	netcfgd) echo netcfgd.service ;;
	networkmanager) echo 'NetworkManager.service NetworkManager-wait-online.service NetworkManager-dispatcher.service' ;;
	networkd) echo 'systemd-networkd.service systemd-networkd.socket systemd-networkd-wait-online.service' ;;
	connman) echo 'connman.service connman-wait-online.service' ;;
	modemmanager) echo ModemManager.service ;;
	resolved) echo systemd-resolved.service ;;
	supplicant) echo 'wpa_supplicant.service wpa_supplicant.socket' ;;
	iwd) echo 'iwd.service iwd.socket' ;;
	dhcpcd) echo 'dhcpcd.service dhcpcd5.service' ;;
	ifupdown) echo networking.service ;;
	wicd) echo wicd.service ;;
	esac
}

# The per-interface files a stopped daemon leaves claiming interfaces it no
# longer manages. Empty for the daemons that leave none.
claims_of() {
	case "$1" in
	networkmanager) echo /run/NetworkManager/devices ;;
	networkd) echo /run/systemd/netif/links ;;
	# **ifupdown's /run/network/ifstate is deliberately NOT here**, and the
	# first draft had it. It is not a stale claim, it is ifupdown's live
	# record of which interfaces it brought up -- and netcfgd never reads it,
	# so removing it buys netcfgd nothing and costs ifupdown the ability to
	# bring those interfaces down again. Caught by running `--dry-run` on the
	# development machine, where it proposed deleting the entries for eth0,
	# ib0 and lo.
	#
	# The two above are here for the opposite reason: netcfgd *does* read
	# them, and 0145 is what happens when it believes a stopped daemon still
	# holds every interface.
	*) echo '' ;;
	esac
}

# Programs a manager starts and does not stop. `comm` names, which the kernel
# truncates to 15 characters -- a name one character too long never matches
# and the sweep would report nothing while looking as though it had looked.
children_of() {
	case "$1" in
	networkmanager) echo 'wpa_supplicant dhclient dhcpcd iwd' ;;
	networkd) echo 'wpa_supplicant' ;;
	connman) echo 'wpa_supplicant dhclient' ;;
	modemmanager) echo 'mbim-proxy qmi-proxy' ;;
	ifupdown) echo 'dhclient dhcpcd wpa_supplicant udhcpc' ;;
	wicd) echo 'wpa_supplicant dhclient' ;;
	iwd) echo '' ;;
	dhcpcd) echo '' ;;
	*) echo '' ;;
	esac
}

# **Not stood down, deliberately, and this list is as load-bearing as the one
# above.** netcfgd delegates to these: standing them down would break netcfgd
# rather than its rivals. dnsmasq and unbound are DNS backends decision 0007
# offers as modes, so a machine on `dns_mode = "dnsmasq"` needs that daemon
# running; resolvconf and openresolv are the same one layer down. The rest are
# programs netcfgd starts itself, which is why they never appear in
# `unit_of` -- netcfgd runs the binary, not the service.
#
#     dnsmasq unbound resolvconf openresolv
#     hostapd pppd openvpn udhcpc odhcp6c
#
# wpa_supplicant and dhcpcd are the two that appear in both worlds: the
# *service* is a rival that another manager drives, and the *binary* is a tool
# netcfgd starts with its own marker. Standing the service down never costs
# netcfgd its own, which is what `is_netcfgds` below is for.

# ---------------------------------------------------------------------------
# Is this process ours, or somebody else's world?
# ---------------------------------------------------------------------------

# netcfgd names every backend it starts with a path under /run/netcfgd/, and
# the process carries it in its own argv for as long as it lives (0140). That
# is what tells netcfgd's wpa_supplicant from NetworkManager's, and it is the
# difference between standing a rival down and killing netcfgd's own radio.
is_netcfgds() {
	tr '\0' '\n' < "/proc/$1/cmdline" 2>/dev/null | grep -q '/run/netcfgd/'
}

# A process in another network namespace cannot be configuring this machine's
# interfaces (0167). Fails closed: an unreadable link means "not ours to
# signal", because the cost of guessing wrong is killing something outside the
# world this script is arranging.
in_our_netns() {
	ours=$(readlink /proc/self/ns/net 2>/dev/null) || return 1
	theirs=$(readlink "/proc/$1/ns/net" 2>/dev/null) || return 1
	[ "$ours" = "$theirs" ]
}

# ---------------------------------------------------------------------------

stand_down() {
	manager=$1

	if [ -d /run/systemd/system ]; then
		for unit in $(unit_of "$manager"); do
			run systemctl stop "$unit"
			run systemctl disable "$unit"
			# `mask` and not merely `disable`: disable stops it starting at
			# boot and does nothing about another package's dependency, an
			# upgrade, or `systemctl start` typed by hand. A mask is what
			# makes it stay down.
			run systemctl mask "$unit"
		done
	elif command -v rc-update >/dev/null 2>&1; then
		run rc-service "$manager" stop
		run rc-update del "$manager" default
	elif [ -x "/etc/init.d/$manager" ]; then
		run "/etc/init.d/$manager" stop
	fi

	# The orphans: what it started and did not stop.
	for program in $(children_of "$manager"); do
		for pid in $(pgrep -x "$program" 2>/dev/null || true); do
			if is_netcfgds "$pid"; then
				continue
			fi
			if ! in_our_netns "$pid"; then
				continue
			fi
			say "terminating $program (pid $pid) left behind by $manager"
			run kill "$pid"
		done
	done

	# The claim it left on interfaces it no longer manages. Removing the files
	# rather than the directory: the directory belongs to that package, and a
	# daemon that starts again should find its own home where it left it.
	for dir in $(claims_of "$manager"); do
		[ -d "$dir" ] || continue
		for claim in "$dir"/*; do
			[ -e "$claim" ] || continue
			say "removing the stale claim $claim"
			run rm -f "$claim"
		done
	done
}

bring_up() {
	manager=$1
	if [ -d /run/systemd/system ]; then
		# Unmask every unit, but enable and start only the first -- the rest
		# are sockets and `-wait-online` helpers that the daemon's own unit
		# pulls in. Starting `NetworkManager-wait-online` by hand would block
		# until the network is up, which is not what selecting a daemon means.
		for unit in $(unit_of "$manager"); do
			run systemctl unmask "$unit"
		done
		primary=$(unit_of "$manager" | cut -d' ' -f1)
		run systemctl enable "$primary"
		run systemctl start "$primary"
	elif command -v rc-update >/dev/null 2>&1; then
		run rc-update add "$manager" default
		run rc-service "$manager" start
	elif [ -x "/etc/init.d/$manager" ]; then
		run "/etc/init.d/$manager" start
	fi
}

unmask_all() {
	[ -d /run/systemd/system ] || return 0
	for manager in $managers; do
		for unit in $(unit_of "$manager"); do
			run systemctl unmask "$unit"
		done
	done
}

# netplan has no daemon to stand down and its configuration outlives this.
warn_about_netplan() {
	for yaml in /etc/netplan/*.yaml /etc/netplan/*.yml; do
		[ -e "$yaml" ] || continue
		say "note: $yaml is still there. netplan renders it into"
		say "  systemd-networkd or NetworkManager configuration, so if either"
		say "  is ever unmasked it comes back with netplan's idea of the"
		say "  network. Nothing here removes your configuration."
		return 0
	done
}

# ---------------------------------------------------------------------------

case "$target" in
none)
	# What `postrm` calls. Unmask everything and start nothing: the operator
	# chooses what runs next, and a machine that has just had its network
	# daemon removed must not be left unable to run any of them.
	say "unmasking every network daemon and starting none"
	unmask_all
	say "nothing is running the network now. Start one, for example:"
	say "  systemctl enable --now NetworkManager"
	;;
*)
	say "selecting $target"
	for manager in $managers; do
		[ "$manager" = "$target" ] && continue
		# wpa_supplicant is a special case in one direction only: the SERVICE
		# is a system-wide instance another manager drives, and netcfgd starts
		# its own binary directly. Standing the service down never costs
		# netcfgd a supplicant.
		stand_down "$manager"
	done
	# Unmask the one being selected before starting it -- it may have been
	# masked by an earlier run of this script choosing something else.
	bring_up "$target"
	warn_about_netplan
	say "$target is now this machine's network daemon"
	say "  no package was removed and no binary renamed"
	say "  run '$me none' to unmask everything again"
	;;
esac
