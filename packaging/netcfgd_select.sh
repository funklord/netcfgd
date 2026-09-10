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
# What the persistence pass renamed, so the summary can say so rather than
# claiming nothing was. Empty on every ordinary run.
renamed=
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
# **Managers compete for interfaces. Tools are what a manager drives.**
# Conflating the two is the defect this file shipped with, and it broke a
# machine: `wpa_supplicant.service` was in one list with the managers, so
# selecting *anything* masked it -- and NetworkManager does not talk to radios
# itself, it drives wpa_supplicant over D-Bus. NM came up, showed the device
# and found no networks. Selecting `networkmanager` broke NetworkManager.
#
# netcfgd was unaffected, which is exactly why the mistake was invisible from
# here: it spawns the wpa_supplicant *binary* directly with its own
# `-P /run/netcfgd/supplicant/<iface>.pid` and never wants the service. So the
# machine ended with no daemon able to use the radio, which is 0145's outcome
# reached by a new route.
#
# Only these compete for interfaces, and only these are ever masked.
managers='netcfgd networkmanager networkd connman ifupdown wicd'

# A radio is held exclusively by whoever has it, so at most one of these may
# run -- but which one is a property of the *selected manager*, not something
# to be stood down uniformly.
radios='supplicant iwd'

# Services a manager may need. Stopped when the selected manager does not want
# them. Masked only where `revived_over_dbus` says a stop cannot hold, because
# masking is what makes a machine unrecoverable without root and knowledge.
tools='dhcpcd modemmanager resolved'

# **Stopping and disabling these does not keep them down.** Each ships a
# `/usr/share/dbus-1/system-services/*.service` naming `SystemdService=`, so
# any client asking for the bus name starts the unit again -- `disable` governs
# boot, not activation, and there is no socket unit on Debian to disable
# either.
#
# That matters here and nowhere else because `netcfgd-exclusive.conf` conflicts
# with both, and **`Conflicts=` is symmetric**: systemd resolves it by stopping
# whichever unit was already up. Verified with two throwaway units -- starting
# the one that declares nothing stopped the one that declared the conflict. So
# on a machine running netcfgd, a desktop applet asking for
# `fi.w1.wpa_supplicant1` does not merely start a rival supplicant, it stops
# netcfgd. Measured: netcfgd started at 14:09:33 and was gone at 14:09:46, when
# NetworkManager came up and asked for the supplicant. The stop is clean, so
# `Restart=on-failure` does not bring it back.
#
# **This is not 10.56's mistake returning, and the difference is which
# selection masks.** That fault masked `wpa_supplicant.service` on *every*
# selection, including `networkmanager` -- which drives the supplicant over
# D-Bus and cannot scan without it. Masking happens only in `stand_aside`,
# which is reached only for a service the selected manager does **not** need;
# `needs_of networkmanager` names both of these, so both go through
# `ensure_service` instead and are unmasked, enabled and started. The invariant
# that broke that machine is asserted three ways in `tests/live/select.sh` and
# still holds.
#
# **systemd-resolved is deliberately absent though it is D-Bus activatable
# too.** It contends for no device -- it is a resolver, orthogonal to which
# daemon configures interfaces -- so netcfgd does not conflict with it, nothing
# revives it *at netcfgd's expense*, and masking it would break
# `dns_mode = "resolved"`, the arrangement 0007 recommends. Asserted by
# `tests/live/select.sh`: no selection masks it.
revived_over_dbus='supplicant modemmanager'

# What each manager needs running. netcfgd needs nothing here, and that is not
# an oversight -- it starts wpa_supplicant, dhcpcd and the rest as *binaries*
# with its own markers (0140), so a system service instance is a rival to it
# rather than a dependency.
#
# systemd-resolved is in nobody's list. It is a DNS resolver and orthogonal to
# which daemon configures interfaces; netcfgd only contends with it under
# `dns_mode = "write_resolv_conf"`, which is what `netcfgd-exclusive.conf`
# and 0165's sweep are for. Standing it down here would break a netcfgd
# configured with `dns_mode = "resolved"` -- the arrangement 0007 recommends.
needs_of() {
	case "$1" in
	networkmanager) echo 'supplicant modemmanager' ;;
	networkd) echo 'supplicant' ;;
	connman) echo 'supplicant' ;;
	ifupdown) echo 'supplicant dhcpcd' ;;
	wicd) echo 'supplicant' ;;
	netcfgd) echo '' ;;
	*) echo '' ;;
	esac
}

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
	# **`netcfgd-nm.service` belongs here and was missing**, which is the
	# whole of a bug that read as "wifi works occasionally". The shim serves
	# NetworkManager's own bus name, so it carries `Conflicts=NM.service` and
	# `Requires=netcfgd.service` -- and this function was the only thing that
	# could stand it down. It never did, so `netcfgd_select.sh networkmanager`
	# stopped and masked netcfgd and left its shim enabled: at the next boot
	# multi-user.target pulled the shim in, its `Conflicts=` stopped the
	# NetworkManager that had just been selected, and its `Requires=` asked
	# for the daemon this script had masked. The machine came up with no
	# manager at all, and which of the three won was a race.
	#
	# Second in the list on purpose. `bring_up` unmasks every unit and starts
	# only the first, so selecting netcfgd unmasks the shim without enabling
	# it -- which is what `debian/rules` already decided with
	# `dh_installsystemd --no-enable --no-start`. Standing it down is a bug
	# fix; starting it is a policy this script does not get to make.
	netcfgd) echo 'netcfgd.service netcfgd-wait-online.service netcfgd-nm.service' ;;
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
	# **netcfgd's own, and their absence here was a bug with three names.**
	# netcfgd starts every one of these as a *binary* with a `/run/netcfgd/`
	# marker (0140) and `KillMode=process` deliberately leaves them running
	# when the service stops (0134, 0142) -- so stopping netcfgd is precisely
	# the case where something else has to sweep them, and this arm was
	# missing, so `stand_down netcfgd` swept nothing at all. Reported after a
	# switch to `none`: "I STILL had to kill orphaned dhcpcd and
	# wpa_supplicant."
	#
	# `comm` names, so all of these must be 15 characters or fewer -- the
	# kernel truncates, and a name one character too long never matches while
	# the sweep looks as though it had looked. `wpa_supplicant` is 14.
	#
	# **`dhcpcd` is deliberately in none of these lists**, and it used to be in
	# three. This sweep decides ownership from the `/run/netcfgd/` marker in a
	# process's argv, and dhcpcd calls `setproctitle`: its command line reads
	# `dhcpcd: wlp0s20f3 [ip4]`, with the marker gone and, for the BOOTP proxy,
	# the interface gone too. So the test cannot answer for it, and a test that
	# cannot answer does not abstain -- it returns "not netcfgd's", which made
	# `netcfgd_select.sh netcfgd` propose killing the client netcfgd had just
	# started, five processes at a time, as NetworkManager's leftover. Caught by
	# `--dry-run` on a machine that was already running netcfgd.
	#
	# It is stopped by `stop_netcfgd_dhcpcd` instead, from netcfgd's own
	# bookkeeping and with dhcpcd's own verb. Another manager's dhcpcd goes down
	# with that manager's service, which is `unit_of dhcpcd` and `stand_aside`.
	netcfgd) echo 'wpa_supplicant dhclient udhcpc odhcp6c hostapd pppd openvpn' ;;
	networkmanager) echo 'wpa_supplicant dhclient iwd' ;;
	networkd) echo 'wpa_supplicant' ;;
	connman) echo 'wpa_supplicant dhclient' ;;
	modemmanager) echo 'mbim-proxy qmi-proxy' ;;
	ifupdown) echo 'dhclient wpa_supplicant udhcpc' ;;
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
# The last resort: renaming a binary that will not stay down.
#
# **Only reached when standing the service down and killing the process was
# not enough** -- masked, signalled, and still there. On a machine where that
# never happens, nothing here ever runs, which is the intent.
#
# **`dpkg-divert`, not `mv`.** A plain rename is undone by the next upgrade of
# the package that owns the file, and `dpkg --verify` reports it as damage; it
# would look like it worked and quietly stop. A diversion is a rename dpkg
# knows about, survives upgrades, and is removed by one command -- which is
# what makes `none` able to put the machine back.
#
# **The list is short because almost nothing may be renamed**, and that is a
# consequence of what netcfgd is rather than caution. netcfgd *runs*
# wpa_supplicant, dhcpcd, hostapd, pppd, openvpn, udhcpc, odhcp6c and
# resolvconf; dnsmasq and unbound are DNS backends 0007 offers as modes; and
# NetworkManager's package has to stay because desktop applets depend on it
# and reach netcfgd through netcfgd-nm. Diverting any of those breaks netcfgd
# or the desktop rather than a competitor.
#
# What is left is a daemon netcfgd never invokes and nothing here depends on:
#
#     connmand   connman's daemon
#     dhclient   isc-dhcp-client's, started by NetworkManager and ifupdown.
#                netcfgd uses dhcpcd or udhcpc and never this.
divertible_path() {
	case "$1" in
	connmand) echo /usr/sbin/connmand ;;
	dhclient) echo /usr/sbin/dhclient ;;
	*) echo '' ;;
	esac
}
divertible='connmand dhclient'

# Where a diverted binary goes. Named for netcfgd so that `dpkg-divert --list`
# says who did it and why, which is the only trace an operator has to follow.
diverted_name() { echo "$1.netcfgd-disabled"; }

divert() {
	program=$1
	path=$(divertible_path "$program")
	[ -n "$path" ] || return 0
	[ -e "$path" ] || return 0
	if ! command -v dpkg-divert >/dev/null 2>&1; then
		say "$program will not stay down and there is no dpkg-divert here"
		say "  a plain rename would be undone by the next package upgrade,"
		say "  so nothing was renamed. Remove or mask $program by hand."
		return 0
	fi
	if dpkg-divert --list "$path" 2>/dev/null | grep -q .; then
		say "$path is already diverted"
		return 0
	fi
	say "renaming $path -- it stayed up through a stop, a mask and a signal"
	run dpkg-divert --add --rename --divert "$(diverted_name "$path")" "$path"
	renamed="$renamed $path"
}

undivert() {
	command -v dpkg-divert >/dev/null 2>&1 || return 0
	for program in $divertible; do
		path=$(divertible_path "$program")
		[ -n "$path" ] || continue
		# Only netcfgd's own diversions. Another package's -- and this machine
		# has several, from synaptic to util-linux -- is not ours to undo.
		if dpkg-divert --list "$path" 2>/dev/null | grep -q "netcfgd-disabled"; then
			say "restoring $path"
			run dpkg-divert --remove --rename "$path"
		fi
	done
}

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

# The dhcpcd clients netcfgd started, named by its own bookkeeping.
#
# **dhcpcd is the one backend `sweep_children` structurally cannot find.** Every
# other one carries `/run/netcfgd/...` in its argv for as long as it lives
# (0140), which is what `is_netcfgds` reads. dhcpcd calls `setproctitle` and
# destroys argv outright -- it reads `dhcpcd: wlp0s20f3 [ip4]` -- so the marker
# is gone and the sweep skips it. That is why "I STILL had to kill orphaned
# dhcpcd" survived the sweep being fixed: the fix worked for the supplicant and
# could never work for this.
#
# netcfgd's own answer is the same one (0143): it does not look at argv either,
# it asks dhcpcd over its control socket which `-f` it recites. The shell
# equivalent is the file that `-f` names -- netcfgd creates
# `/run/netcfgd/dhcpcd/<iface>-<family>.conf` for every client it starts, so the
# directory listing *is* the list of clients, and a dhcpcd somebody else started
# has no entry there.
#
# **Read before anything is stopped.** `RuntimeDirectoryPreserve=restart` means
# a real stop of netcfgd.service deletes `/run/netcfgd` and takes these markers
# with it -- measured, the orphan then logs `read_config: ... No such file or
# directory` and re-solicits a *second* lease, which is where the machine got
# two addresses. So the caller captures this at the top and passes it down.
netcfgd_dhcpcd_clients() {
	for marker in /run/netcfgd/dhcpcd/*.conf; do
		[ -e "$marker" ] || continue
		base=${marker##*/}
		printf '%s ' "${base%.conf}"
	done
}

# Stop them with dhcpcd's own verb, not a signal.
#
# `dhcpcd -4 -k <iface>` takes the client and its privilege-separated children
# together; signalling the pid leaves the proxies behind, which is what left
# five processes after a kill that looked like it had worked. The family flag is
# not decoration: a client started with `-4` writes `<iface>-4.pid`, and a bare
# `dhcpcd -k <iface>` looks for `<iface>.pid`, finds nothing and exits 1 (0070).
stop_netcfgd_dhcpcd() {
	[ -n "$1" ] || return 0
	command -v dhcpcd >/dev/null 2>&1 || return 0
	for client in $1; do
		client_iface=${client%-*}
		client_family=${client##*-}
		case "$client_family" in
		4 | 6) ;;
		*) continue ;;
		esac
		say "stopping the dhcpcd netcfgd started on $client_iface (-$client_family)"
		run dhcpcd "-$client_family" -k "$client_iface"
	done
}

# The processes a manager started and did not stop.
#
# **Whose they are decides it, in both directions.** `is_netcfgds` reads the
# `/run/netcfgd/` marker the process carries in its own argv (0140), and the
# test is not "skip netcfgd's" -- it is "take the ones belonging to the manager
# being stood down". Standing down NetworkManager must not kill netcfgd's
# supplicant, and standing down *netcfgd* must kill exactly that one and leave
# NetworkManager's alone. The old form skipped netcfgd's unconditionally, which
# is correct for every manager except the one whose orphans anybody actually
# needed swept.
sweep_children() {
	manager=$1
	# dhcpcd first, by netcfgd's bookkeeping rather than by argv -- see
	# `stop_netcfgd_dhcpcd`. The argv sweep below still runs and still finds
	# nothing for it, which is correct and cheap: a dhcpcd this did somehow
	# match would be one that had not yet rewritten its own command line.
	if [ "$manager" = netcfgd ]; then
		stop_netcfgd_dhcpcd "${netcfgd_clients:-}"
	fi
	for program in $(children_of "$manager"); do
		for pid in $(pgrep -x "$program" 2>/dev/null || true); do
			# Written as one comparison rather than two `&&`/`||` guards.
			# Under `set -eu` a trailing `[ ... ] && continue` returns 1 when
			# the test is false, and if it ever becomes the last command in
			# this loop body it aborts the script -- which is how the mask
			# guard in `stand_aside` was caught. This form cannot acquire that
			# property by being reordered.
			# **`sweep_` prefixes, because POSIX sh has no locals and the
			# obvious names are taken.** The first version of this used
			# `target`, which is the script-wide variable holding the selected
			# manager -- so the managers loop clobbered it on its first
			# `stand_down`, `needs_of "$target"` was then `needs_of no`,
			# nothing was wanted, and `netcfgd_select.sh networkmanager` masked
			# the supplicant. That is 0169's machine-breaking fault restored by
			# a variable name. Caught by `tests/live/select.sh`, which asserts
			# that selection does not mask it.
			sweep_mine=no
			if is_netcfgds "$pid"; then
				sweep_mine=yes
			fi
			sweep_wanted=no
			if [ "$manager" = netcfgd ]; then
				sweep_wanted=yes
			fi
			# Sweep a process only when it belongs to the manager standing
			# down: netcfgd's own when that is netcfgd, somebody else's
			# otherwise.
			if [ "$sweep_mine" != "$sweep_wanted" ]; then
				continue
			fi
			if ! in_our_netns "$pid"; then
				continue
			fi
			say "terminating $program (pid $pid) left behind by $manager"
			run kill "$pid"
		done
	done
}

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

	sweep_children "$manager"

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
		# **The wait-online helper is enabled and not started**, and that is
		# the whole of what makes `network-online.target` mean anything.
		# Selecting a daemon masks the other daemons' helpers -- correctly,
		# they belong to what is being stood aside -- and until netcfgd had one
		# of its own that left the target ungated: measured after a switch,
		# `NetworkManager-wait-online`, `systemd-networkd-wait-online` and
		# `connman-wait-online` all masked, with docker, cups-browsed and
		# fwupd-refresh ordered after a target nothing held. Enabling puts it
		# in `network-online.target.wants` for the next boot, which is when it
		# is wanted; starting it now would block this script until the network
		# is up, which is not what selecting a daemon means. Decision 0190.
		for unit in $(unit_of "$manager"); do
			case "$unit" in
			*-wait-online.service) run systemctl enable "$unit" ;;
			esac
		done
	elif command -v rc-update >/dev/null 2>&1; then
		run rc-update add "$manager" default
		run rc-service "$manager" start
	elif [ -x "/etc/init.d/$manager" ]; then
		run "/etc/init.d/$manager" start
	fi
}

# Everything this script knows about, not only the managers. A machine masked
# by the version of this file that conflated the two lists still has
# `wpa_supplicant.service` masked, and `none` is what has to get it back --
# so this walks the radios and tools too, whether or not the current code
# would ever have masked them.
unmask_all() {
	[ -d /run/systemd/system ] || return 0
	# `$revived_over_dbus` is a subset of `$radios $tools` and is not walked
	# separately: an entry that was not already in one of those could be masked
	# and never unmasked. `select_gate.py` asserts the subset holds.
	for entry in $managers $radios $tools; do
		for unit in $(unit_of "$entry"); do
			run systemctl unmask "$unit"
		done
	done
}

# A service the selected manager does not want. **Stopped and disabled; masked
# only where a stop does not hold.** A mask turns "not running" into "cannot be
# started by anything that needs it", so it is reserved for the case where the
# alternative is a service that comes straight back and takes the selected
# manager down with it -- see `revived_over_dbus`, which is the whole of the
# exception and names why each entry is in it.
#
# The rule this replaces was "never masked", and it was right about the
# incident it came from and wrong as a general statement: 10.56's fault was
# masking the supplicant on *every* selection, not masking it at all. This
# function is only ever reached for a service the target does not need, so
# `netcfgd_select.sh networkmanager` cannot arrive here for the supplicant.
stand_aside() {
	[ -d /run/systemd/system ] || return 0
	mask_it=
	if echo " $revived_over_dbus " | grep -q " $1 "; then
		mask_it=yes
	fi
	for unit in $(unit_of "$1"); do
		run systemctl stop "$unit"
		run systemctl disable "$unit"
		# An `if` and not `[ -n "$mask_it" ] && run ...`. Under `set -eu` that
		# list returns 1 when the test is false, and as the last command of the
		# loop it becomes the function's status -- so the first service that is
		# *not* masked would abort the whole script and leave the machine
		# half-switched. Caught by running it.
		if [ -n "$mask_it" ]; then
			run systemctl mask "$unit"
		fi
	done
}

# A service the selected manager needs. Unmasked first, because an earlier run
# of this script -- or of the version that masked everything -- may have left
# it that way.
ensure_service() {
	[ -d /run/systemd/system ] || return 0
	for unit in $(unit_of "$1"); do
		run systemctl unmask "$unit"
	done
	primary=$(unit_of "$1" | cut -d' ' -f1)
	run systemctl enable "$primary"
	run systemctl start "$primary"
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

# **Captured here, before a single unit is stopped.** Stopping netcfgd.service
# deletes /run/netcfgd and takes the dhcpcd markers with it, so anything that
# reads them afterwards reads an empty directory and sweeps nothing. This is the
# one piece of state that has to outlive the stop.
netcfgd_clients=$(netcfgd_dhcpcd_clients)

case "$target" in
none)
	# What `postrm` calls. Unmask everything and start nothing: the operator
	# chooses what runs next, and a machine that has just had its network
	# daemon removed must not be left unable to run any of them.
	say "standing netcfgd down and unmasking every network daemon"
	# **netcfgd's own processes, which nothing else will ever stop.**
	# `KillMode=process` keeps the supplicant and the DHCP clients alive
	# across a stop on purpose (0134, 0142), so stopping the service leaves
	# them holding the radio and the lease. This is `prerm`'s call, which
	# means netcfgd is going away and there is no later run to collect them.
	#
	# The old version unmasked and did nothing else, then said "nothing is
	# running the network now" -- which was false in exactly the case it was
	# written for. Reported: "I STILL had to kill orphaned dhcpcd and
	# wpa_supplicant after running the script to switch to none."
	if [ -d /run/systemd/system ]; then
		for unit in $(unit_of netcfgd); do
			run systemctl stop "$unit"
		done
	fi
	sweep_children netcfgd
	# **Only netcfgd's, and deliberately not every manager's.** `none` means
	# netcfgd stops, not that the machine loses its network: an operator
	# removing the package while NetworkManager runs must keep the connection
	# they are removing it over. Nothing here touches another manager's
	# processes -- `sweep_children` takes only what carries netcfgd's marker.
	unmask_all
	# Diversions outlive the package that made them, so this is the one
	# chance to undo them. A machine left with connmand renamed and netcfgd
	# gone has a daemon that cannot start and nothing saying why.
	undivert
	say "netcfgd is stopped and every network daemon is unmasked."
	say "  anything else that was running still is. If nothing is, start one:"
	say "  systemctl enable --now NetworkManager"
	;;
*)
	say "selecting $target"

	# 1. The rival managers. Only these are masked, because only these
	#    compete for the interfaces.
	for manager in $managers; do
		[ "$manager" = "$target" ] && continue
		stand_down "$manager"
	done

	# 2. The radios and tools, decided by what the selected manager needs
	#    rather than by which of them is the target. This is the half that
	#    was wrong: standing every non-target entry down masked
	#    wpa_supplicant.service for *every* selection, including the one that
	#    selects NetworkManager -- which cannot scan without it.
	wanted=$(needs_of "$target")
	for service in $radios $tools; do
		if echo " $wanted " | grep -q " $service "; then
			say "$target needs $service"
			ensure_service "$service"
		else
			stand_aside "$service"
		fi
	done
	# **The persistence pass, and it runs after everything else.** Standing a
	# service down and signalling what it left is enough on any ordinary
	# machine; a program still running here has survived a stop, a disable, a
	# mask and a SIGTERM, which is the "if they still persist" case.
	#
	# Checked once, after all the managers, rather than inside stand_down:
	# one manager's child is another's, and killing dhclient while standing
	# NetworkManager down then finding it again under ifupdown is not
	# persistence, it is two owners.
	for program in $divertible; do
		for pid in $(pgrep -x "$program" 2>/dev/null || true); do
			is_netcfgds "$pid" && continue
			in_our_netns "$pid" || continue
			divert "$program"
			# Signal it again now the binary cannot come back. Without this
			# the running copy stays up until something restarts it, which is
			# exactly what will not happen any more.
			run kill "$pid"
			break
		done
	done

	bring_up "$target"
	warn_about_netplan
	say "$target is now this machine's network daemon"
	# **Said only when it is true.** The first version printed "no binary
	# renamed" unconditionally, which is the common case and becomes a lie
	# the moment the persistence pass above fires -- a summary that cannot
	# report the unusual outcome is worse than none, because it is read
	# instead of `dpkg-divert --list`.
	if [ -n "$renamed" ]; then
		say "  no package was removed; renamed:$renamed"
		say "  'dpkg-divert --list' shows them, and '$me none' puts them back"
	else
		say "  no package was removed and no binary renamed"
	fi
	say "  run '$me none' to unmask everything again"
	;;
esac
