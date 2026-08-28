#!/bin/sh
# Association, against simulated radios.
#
# The one thing wifi.sh cannot cover. It drives a real wpa_supplicant but has
# no radio, so everything up to "and then it joins the network" is verified and
# the joining is not. This loads mac80211_hwsim, stands up an access point on
# one virtual radio, and has netcfgd associate with it from the other.
#
#     sudo sh tests/live/hwsim.sh
#
# Needs real root: loading a module, creating a network namespace, and moving a
# wireless phy between namespaces are all things a user namespace cannot do.
#
# ## What it does to the machine, and what it undoes
#
# It loads `mac80211_hwsim`, which creates virtual radios. It does not touch
# any real wireless device: `mac80211` and `cfg80211` are already loaded by
# whatever driver your card uses, so nothing that card depends on is reloaded.
#
# Both virtual radios are moved into a private network namespace immediately,
# before anything else can notice them. That is not tidiness -- NetworkManager
# will happily adopt a new wireless device, start scanning on it, and point its
# own supplicant at the interface this test is trying to use. In a namespace it
# cannot see them.
#
# On exit -- including on failure or interrupt -- the namespace is deleted and
# the module is unloaded, but *only* if this script loaded it. A machine that
# already had `mac80211_hwsim` loaded is one where somebody else is using it,
# and this refuses to run rather than removing it out from under them.

set -eu

repo=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
ns=ncfg-hwsim
loaded_here=
created_ns=

find_in_sbin() {
	for dir in /usr/sbin /sbin /usr/local/sbin /usr/bin /bin; do
		if [ -x "$dir/$1" ]; then
			echo "$dir/$1"
			return 0
		fi
	done
	return 1
}

die() {
	echo "hwsim.sh: $1" >&2
	exit 1
}

skip() {
	if [ -n "${NCFG_LIVE:-}" ]; then
		echo "hwsim.sh: NCFG_LIVE is set but this cannot run: $1" >&2
		exit 1
	fi
	echo "hwsim.sh: skipping: $1"
	exit 0
}

# ---------------------------------------------------------------- preflight

[ "$(id -u)" = 0 ] || skip "needs real root (module loading and phy netns moves)"

supplicant=$(find_in_sbin wpa_supplicant) || skip "wpa_supplicant is not installed"
iw=$(find_in_sbin iw) || skip "iw is not installed (apt install iw | apk add iw)"
ip=$(find_in_sbin ip) || die "no ip(8), which is not something this can work around"
[ -x "$repo/target/debug/ncfg" ] || skip "netcfgd is not built (cargo build --workspace)"

# The AP side is wpa_supplicant in AP mode rather than hostapd, so this needs
# no package the station side did not already need. That requires the binary to
# have been built with CONFIG_AP=y, which Debian's is.
#
# There is deliberately no preflight check for it. The first version of this
# script grepped the binary for `AP-ENABLED`, anchored -- and the string in the
# binary is `AP-ENABLED ` with a trailing space, so the check reported "no AP
# mode" on a build that has it and skipped the entire test. A check that can
# only produce a false negative, on the one machine it was written for, is
# worse than no check: it turns a test that would have run into a test that
# reports "skipped" and looks fine.
#
# If AP mode really is missing, the access point below fails to start and the
# diagnostic there says so, having read what wpa_supplicant actually printed
# rather than guessing from the binary.

# A radio that cannot exist here is a missing tool, and the Makefile says so in
# as many words: a machine that cannot run this should get a skip rather than a
# failure. It did not get one. `make live` as root inside a container aborted
# the whole suite at `modprobe: not found` -- which is the one way this suite is
# meant to be run in full, since three of its scripts need real root.
#
# The line is drawn where the answer stops being about this machine: no kmod and
# no module in this kernel are both "not here", while a module that exists and
# will not load is worth going red over, and the `die` below still does that.
#
# Found through `find_in_sbin` like everything else, and that is not a detail.
# The first version asked `command -v`, which is a question about `$PATH` rather
# than about the machine: this repository's own desktop has no `/usr/sbin` in a
# user's `$PATH` and has the module, so `modinfo` reported "not here" about a
# kernel that has it. A preflight that can only produce a false negative turns a
# test that would have run into a skip that reads as a pass -- the mistake the
# `AP-ENABLED` grep above already made once, in this file.
modprobe=$(find_in_sbin modprobe) || skip "no modprobe (apt install kmod | apk add kmod)"
modinfo=$(find_in_sbin modinfo) || skip "no modinfo (apt install kmod | apk add kmod)"
rmmod=$(find_in_sbin rmmod) || skip "no rmmod (apt install kmod | apk add kmod)"
"$modinfo" mac80211_hwsim >/dev/null 2>&1 ||
	skip "this kernel has no mac80211_hwsim module"

if grep -q '^mac80211_hwsim ' /proc/modules; then
	die "mac80211_hwsim is already loaded, so something else is using it.
       This will not unload a module it did not load. Run
       \`rmmod mac80211_hwsim\` yourself first if it is safe to."
fi

# ------------------------------------------------------------------ cleanup

cleanup() {
	status=$?
	set +e
	# Two ways of naming what to kill, because one of them was not enough.
	#
	# `ip netns pids` finds what is *in* the namespace -- netcfgd and both
	# supplicants. What it cannot see is the subshell the background job
	# forked, which stays in the initial namespace and holds this script's
	# stdout; a run that leaves it behind leaves a reader of that pipe waiting
	# for an end-of-file that never comes, which is a suite that hangs rather
	# than fails. One run here did exactly that: the script itself had exited,
	# the namespace and the work directory were gone, and netcfgd, two
	# supplicants and that subshell were still up ten minutes later. The
	# enumeration is right when it works and is not something to rely on alone.
	#
	# And then wait, because a SIGTERM is not an exit. netcfgd writes its run
	# directory on the way out, so the `rm -rf` below was racing a daemon still
	# shutting down -- it emptied the directory, the daemon put something back,
	# and the rmdir failed with "Directory not empty".
	[ -n "${daemon_job:-}" ] && kill "$daemon_job" 2>/dev/null
	if [ -n "$created_ns" ]; then
		"$ip" netns pids "$ns" 2>/dev/null | xargs -r kill 2>/dev/null
		for _ in 1 2 3 4 5 6 7 8 9 10; do
			[ -z "$("$ip" netns pids "$ns" 2>/dev/null)" ] && break
			sleep 0.2
		done
		# Whatever is left has had two seconds to take a hint. A supplicant
		# whose radio is about to be removed from under it is the plausible
		# candidate, and there is nothing to be gained by waiting longer.
		"$ip" netns pids "$ns" 2>/dev/null | xargs -r kill -9 2>/dev/null
		"$ip" netns delete "$ns" 2>/dev/null
	fi
	# Reap the background job, so nothing of this script's outlives it.
	[ -n "${daemon_job:-}" ] && { kill -9 "$daemon_job" 2>/dev/null; wait "$daemon_job" 2>/dev/null; }
	# The phys go back to the initial namespace when the namespace is deleted,
	# and then away entirely with the module. Unloading is what keeps this from
	# leaving two wireless devices for the desktop to find.
	if [ -n "$loaded_here" ]; then
		# The module can take a moment to become removable after its
		# interfaces go away.
		for _ in 1 2 3 4 5; do
			"$rmmod" mac80211_hwsim 2>/dev/null && break
			sleep 0.4
		done
		if grep -q '^mac80211_hwsim ' /proc/modules; then
			echo "hwsim.sh: could not unload mac80211_hwsim; \`rmmod mac80211_hwsim\`" >&2
		fi
	fi
	# Retried, because the wait above is a claim about processes and this is a
	# claim about a directory. `rm -rf` walks, unlinks and then rmdirs, so
	# anything writing between the walk and the rmdir defeats it once; a
	# second attempt after the writer is certainly gone does not need to know
	# which writer it was. Seen twice, unreproduced afterwards -- the run that
	# left its work directory behind still exited 0, so it was litter on
	# whichever machine has root rather than a failing test.
	if [ -n "${work:-}" ]; then
		for _ in 1 2 3; do
			# Retry: a signalled daemon writes on its way out, so a single `rm -rf`
	# races the process the lines above have just asked to stop. A trap that
	# exits non-zero fails the whole run after every check has passed, which is
	# how this surfaced -- three times, in three different scripts.
	waited=0
	while [ -d "$work" ]; do
		rm -rf "$work" 2>/dev/null && break
		waited=$((waited + 1))
		[ "$waited" -gt 50 ] && break
		sleep 0.1
	done
	if [ -d "$work" ]; then
		echo "note: $work outlived five seconds of trying to remove it" >&2
	fi 2>/dev/null
			[ -d "$work" ] || break
			sleep 0.5
		done
		[ -d "$work" ] && echo "hwsim.sh: left $work behind" >&2
	fi
	exit "$status"
}
trap cleanup EXIT INT TERM

# -------------------------------------------------------------- the radios

before=$(ls /sys/class/ieee80211 2>/dev/null | sort)
# Three radios, not two: the third is a second access point, so that choosing
# between saved networks can be tested rather than reasoned about. It costs one
# more simulated phy and nothing else -- hwsim radios are free and hear each
# other by default, which is exactly the topology "two networks in range" needs.
"$modprobe" mac80211_hwsim radios=3 || die "could not load mac80211_hwsim"
loaded_here=yes
# udev renames interfaces asynchronously; give it a moment before reading them.
sleep 1
after=$(ls /sys/class/ieee80211 | sort)

phys=$(echo "$before
$after" | sort | uniq -u)
[ "$(echo "$phys" | wc -l)" = 3 ] || die "expected 3 new phys, got: $(echo "$phys" | tr '\n' ' ')"

ap_phy=$(echo "$phys" | sed -n 1p)
ap2_phy=$(echo "$phys" | sed -n 2p)
sta_phy=$(echo "$phys" | sed -n 3p)

netdev_of() {
	ls "/sys/class/ieee80211/$1/device/net" 2>/dev/null | head -1
}
ap_dev=$(netdev_of "$ap_phy")
ap2_dev=$(netdev_of "$ap2_phy")
sta_dev=$(netdev_of "$sta_phy")
[ -n "$ap_dev" ] && [ -n "$sta_dev" ] && [ -n "$ap2_dev" ] ||
	die "the new phys have no interfaces"

echo "hwsim.sh: ap $ap_phy/$ap_dev, ap2 $ap2_phy/$ap2_dev, station $sta_phy/$sta_dev"

"$ip" netns add "$ns" || die "could not create the network namespace"
created_ns=yes
# Into the namespace before anything else can adopt them.
"$iw" phy "$ap_phy" set netns name "$ns" || die "could not move $ap_phy"
"$iw" phy "$ap2_phy" set netns name "$ns" || die "could not move $ap2_phy"
"$iw" phy "$sta_phy" set netns name "$ns" || die "could not move $sta_phy"
"$ip" -n "$ns" link set lo up

inns() { "$ip" netns exec "$ns" "$@"; }

# ------------------------------------------------------------------ fixtures

# Short, because a unix socket path has to fit in SUN_LEN.
work=$(mktemp -d "${TMPDIR:-/tmp}/ncfg-hwsim.XXXXXX")
mkdir -p "$work/etc/secrets" "$work/run" "$work/ctrl" "$work/ap" "$work/ap2"

passphrase=hunter2hunter2

# The access point. wpa_supplicant in AP mode: `mode=2` with an explicit
# frequency, since there is no scan to learn one from.
#
# Channel 1 (2412 MHz) because AP mode needs permission to transmit, and the
# world-roaming regulatory domain a fresh hwsim radio inherits allows it there:
# the 2402-2472 range carries no NO-IR flag. Pick a channel that does and the
# radio comes up and never beacons, which looks like an association failure
# several steps later.
#
# Nothing here changes the regulatory domain, and it would not matter to a real
# card if it did -- modern wifi hardware registers as self-managed and ignores
# the global setting.
cat > "$work/ap/ap.conf" <<CONF
ctrl_interface=$work/ap/ctrl
update_config=0

network={
	ssid="netcfgd-test"
	mode=2
	frequency=2412
	key_mgmt=SAE WPA-PSK
	proto=RSN
	ieee80211w=1
	psk="$passphrase"
}
CONF

cat > "$work/etc/netcfgd.conf" <<CONF
device $sta_dev {
	wifi { backend = "wpa_supplicant"; autoconnect = true }
}

network "netcfgd-test" {
	wifi   { psk = "@secret:test"; proto = "wpa2+wpa3" }
	config = "null"
}

interface $sta_dev { config = "null" }
CONF
printf '%s' "$passphrase" > "$work/etc/secrets/test"
chmod 600 "$work/etc/secrets/test"

ncfg="$repo/target/debug/ncfg"
cli="${supplicant%wpa_supplicant}wpa_cli"

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
contains() {
	case "$2" in
	*"$3"*) echo "ok   $1" ;;
	*)
		echo "FAIL $1"
		echo "       expected to contain: $3"
		echo "       actual:              $2"
		failures=$((failures + 1))
		;;
	esac
}

# ------------------------------------------------------------- the access point

inns "$supplicant" -B -Dnl80211 -i "$ap_dev" -c "$work/ap/ap.conf" \
	> "$work/ap/log" 2>&1 || die "could not start the access point"

# Polled through the control socket rather than by watching the log: with `-B`
# the interesting output happens after the fork, where the redirect no longer
# reaches. In AP mode `wpa_state` reaches COMPLETED once the BSS is up.
waited=0
ap_state=
until [ "$ap_state" = COMPLETED ]; do
	ap_state=$(inns "$cli" -p "$work/ap/ctrl" -i "$ap_dev" status 2>/dev/null |
		sed -n 's/^wpa_state=//p')
	waited=$((waited + 1))
	if [ "$waited" -gt 150 ]; then
		echo "hwsim.sh: the access point never came up (last state: ${ap_state:-none})" >&2
		if grep -q 'not included in the build' "$work/ap/log"; then
			echo "hwsim.sh: this wpa_supplicant was built without CONFIG_AP." >&2
			echo "hwsim.sh:   install hostapd and use it as the AP instead." >&2
		fi
		cat "$work/ap/log" >&2
		exit 1
	fi
	sleep 0.1
done
echo "ok   the access point is beaconing"

# ------------------------------------------------------------------- netcfgd

# `ncfg wifi *` goes over the control socket, so the daemon has to be running
# inside the namespace -- exporting these here would only affect this shell.
# **Every invocation gets the tmpfs, not just the daemon's.**
#
# `ip netns exec` unshares a *fresh mount namespace per invocation*, and
# `ncfg apply` goes through the daemon only when `--confirm` is given -- without
# it the CLI applies in its own process, so dhcpcd is the CLI's child rather
# than the daemon's. Containing only the daemon therefore contained nothing:
# measured, the daemon sat in mnt:[4026536358] holding the tmpfs while dhcpcd
# ran in mnt:[4026536361] and wrote its lease to the operator's real
# /var/lib/dhcpcd.
#
# netcfgd cannot redirect it. dhcpcd 10.1.0 has no --dbdir and its state
# directory is compiled in, so the only lever is the mount namespace and this
# is the only place to pull it.
innc() {
	inns env NCFG_CONFIG_DIR="$work/etc" NCFG_RUN_DIR="$work/run" \
		NCFG_WPA_CTRL_DIR="$work/ctrl" sh -c '
		if [ -d /var/lib/dhcpcd ]; then
			mount -t tmpfs tmpfs /var/lib/dhcpcd || exit 90
			# A fresh tmpfs is empty. Anything visible is the host
			# showing through, and mount(8) returning 0 is not
			# evidence that the view changed.
			if [ -n "$(ls -A /var/lib/dhcpcd 2>/dev/null)" ]; then
				echo "the tmpfs over /var/lib/dhcpcd did not take" >&2
				exit 91
			fi
		fi
		exec "$@"
	' sh "$@"
}

# Taken before anything starts, so the containment above can be checked rather
# than asserted. A tmpfs that silently failed to mount looks exactly like one
# that worked, right up until the lease lands in the operator's directory.
host_leases_before=$(ls /var/lib/dhcpcd 2>/dev/null | sort)

# **A tmpfs over dhcpcd's lease directory, in the namespace netcfgd's children
# inherit.** netcfgd gives dhcpcd `-c`, `-f`, `-b`, `-m` and the interface and
# no lease-directory override, so dhcpcd uses its compiled-in /var/lib/dhcpcd
# -- which, without this, is the *host's*. `ip netns exec` unshares a mount
# namespace per invocation, so the mount has to happen in the same one that
# execs the daemon, and every dhcpcd netcfgd spawns then inherits it.
#
# This is the failure `dhcpcd_orphan.sh` was fixed for on the same day, in its
# quieter form: not killing the operator's processes, only writing into their
# state. A test that leaves a lease file named after a simulated radio in a
# real /var/lib/dhcpcd has reached outside its sandbox either way.
innc "$repo/target/debug/netcfgd" --no-apply-on-start > "$work/daemon.log" 2>&1 &
# Kept so cleanup can kill this by name rather than only by namespace. `$!` is
# the *subshell* the background function call forked, not netcfgd, and that is
# the point: it is the process holding this script's stdout open, and it sits
# in the initial namespace where `ip netns pids` never looks.
daemon_job=$!
waited=0
while [ ! -e "$work/run/netcfgd.sock" ]; do
	waited=$((waited + 1))
	if [ "$waited" -gt 100 ]; then
		cat "$work/daemon.log" >&2
		# Exit 90 is the wrapper above failing to mount a tmpfs over
		# dhcpcd's lease directory. It refuses rather than running
		# uncontained, so say which of the two happened.
		case "$(cat "$work/daemon.log" 2>/dev/null)" in
		*"did not take"* | *"Operation not permitted"*)
			die "could not contain /var/lib/dhcpcd, so the daemon was \
not started rather than have dhcpcd write to the host's"
			;;
		esac
		die "the daemon never bound its socket"
	fi
	sleep 0.1
done

plan=$(innc "$ncfg" plan)
contains "the plan starts a supplicant for the radio" "$plan" "backend.start $sta_dev"

innc "$ncfg" apply > "$work/apply.log" 2>&1 || {
	echo "FAIL apply did not succeed"
	cat "$work/apply.log"
	exit 1
}
echo "ok   netcfgd started a supplicant and gave it the network"

# ---------------------------------------------------------------- association
#
# The whole point of the file. Everything above this line was already covered
# without a radio.

waited=0
state=
until [ "$state" = COMPLETED ]; do
	state=$(inns "$cli" -p "$work/ctrl" -i "$sta_dev" status 2>/dev/null |
		sed -n 's/^wpa_state=//p')
	waited=$((waited + 1))
	if [ "$waited" -gt 200 ]; then
		echo "FAIL never associated (last state: ${state:-none})"
		inns "$cli" -p "$work/ctrl" -i "$sta_dev" status 2>&1 | head -20
		failures=$((failures + 1))
		break
	fi
	sleep 0.1
done
[ "$state" = COMPLETED ] && echo "ok   associated"

if [ "$state" = COMPLETED ]; then
	status=$(inns "$cli" -p "$work/ctrl" -i "$sta_dev" status)
	ssid=$(printf '%s\n' "$status" | sed -n 's/^ssid=//p')
	check "on the network the document named" "$ssid" "netcfgd-test"

	# Transitional mode has to actually negotiate one of the two, and which
	# one is the thing no fixture could ever tell us.
	keymgmt=$(printf '%s\n' "$status" | sed -n 's/^key_mgmt=//p')
	# `FT-*` is a success rather than a surprise: netcfgd offers fast
	# transition beside each base mode now, so an access point that does
	# 802.11r may select it, and that is the outcome the offer is for.
	case "$keymgmt" in
	SAE | WPA2-PSK* | WPA-PSK* | FT-SAE* | FT-PSK*)
		echo "ok   negotiated $keymgmt from the transitional offer"
		;;
	*)
		echo "FAIL unexpected key management: $keymgmt"
		failures=$((failures + 1))
		;;
	esac

	# And netcfgd's own view agrees with the supplicant's, resolved back to
	# the `network` block it came from. A status that cannot name the block
	# means decision 0015 does not hold.
	own=$(innc "$ncfg" wifi status 2>&1 || true)
	contains "ncfg agrees it is associated" "$own" "COMPLETED"
	contains "and names the network block" "$own" "netcfgd-test"

	scan=$(innc "$ncfg" wifi scan 2>&1 || true)
	contains "a scan finds the access point" "$scan" "netcfgd-test"
fi

# --------------------------------------------------------- and then an address
#
# **Associating is not having a network, and the gap between them is where the
# reported fault lived.** "When I start netcfgd, ping stops working" is about
# the step after joining: everything above proves the radio joins, and nothing
# above proves a packet can leave. The wireless tests had no radio and the DHCP
# tests had no radio either -- they run over veth -- so the join and the lease
# had never been exercised together.
#
# dnsmasq serves the access point side. It is optional: a missing one skips
# this phase and leaves the association result standing, which is the same
# bargain `ap.sh` makes for hostapd. Not run at all if the station never
# associated, because a lease that fails for want of an association would be
# reported as a DHCP fault.
if [ "$state" = COMPLETED ]; then
	dnsmasq=$(find_in_sbin dnsmasq || true)
	client=$(find_in_sbin dhcpcd || true)
	if [ -z "$dnsmasq" ]; then
		echo "note: no dnsmasq, so the address half is not run \
(apt install dnsmasq-base | apk add dnsmasq)"
	elif [ -z "$client" ]; then
		echo "note: no dhcpcd, so the address half is not run \
(apt install dhcpcd-base | apk add dhcpcd)"
	else
		inns "$ip" addr add 10.55.0.1/24 dev "$ap_dev"
		# Left to daemonise rather than backgrounded with `&`. A background
		# job forks a subshell this script would then have to kill by name,
		# which is the mistake the comment in cleanup() is about; a process
		# that puts itself in the namespace is found by `ip netns pids` and
		# reaped with everything else.
		inns "$dnsmasq" --log-facility="$work/dnsmasq.log" \
			--pid-file="$work/dnsmasq.pid" \
			--dhcp-leasefile="$work/dnsmasq.leases" \
			--user=root --interface="$ap_dev" --bind-interfaces \
			--no-resolv --port=0 \
			--dhcp-range=10.55.0.100,10.55.0.120,255.255.255.0,120 \
			>> "$work/dnsmasq.out" 2>&1 ||
			die "dnsmasq would not start: $(cat "$work/dnsmasq.out" 2>/dev/null)"

		# Ask for a lease on the interface that is already associated. The
		# document is rewritten rather than written this way from the start,
		# so that a DHCP failure cannot take the association checks with it.
		sed -i "s|^interface $sta_dev { config = \"null\" }|interface $sta_dev { config = \"dhcp\" }|" \
			"$work/etc/netcfgd.conf"
		grep -q "config = \"dhcp\"" "$work/etc/netcfgd.conf" ||
			die "the document was not rewritten, so this would test nothing"

		out=$(innc "$ncfg" apply 2>&1 || true)
		waited=0
		addr=
		until [ -n "$addr" ]; do
			addr=$(inns "$ip" -4 -o addr show dev "$sta_dev" 2>/dev/null |
				sed -n 's/.*inet \(10\.55\.0\.[0-9]*\)\/.*/\1/p')
			waited=$((waited + 1))
			if [ "$waited" -gt 300 ]; then
				echo "FAIL never got an address over the radio"
				echo "       ncfg apply said: $out"
				echo "       dnsmasq log:"
				sed 's/^/         /' "$work/dnsmasq.log" 2>/dev/null | tail -10
				failures=$((failures + 1))
				break
			fi
			sleep 0.1
		done

		if [ -n "$addr" ]; then
			echo "ok   took a DHCP lease over the radio ($addr)"
			# The server's own record has to agree. An address on the
			# interface with no lease behind it is what a link-local
			# autoconfiguration looks like, and it would pass the check above.
			if grep -q "$addr" "$work/dnsmasq.leases" 2>/dev/null; then
				echo "ok   and dnsmasq recorded the lease it handed out"
			else
				echo "FAIL the address is not in dnsmasq's lease file"
				failures=$((failures + 1))
			fi
			# **And the host's lease directory is untouched.** This is
			# the check the tmpfs above exists for, and without it the
			# mount could fail silently and nothing would say so.
			host_leases_after=$(ls /var/lib/dhcpcd 2>/dev/null | sort)
			if [ "$host_leases_before" = "$host_leases_after" ]; then
				echo "ok   and wrote no lease into the host's /var/lib/dhcpcd"
			else
				echo "FAIL this test wrote into the host's /var/lib/dhcpcd"
				echo "       before: $host_leases_before"
				echo "       after:  $host_leases_after"
				# **Which namespace did it escape from.** The daemon
				# verified its own tmpfs before exec'ing, so a lease on
				# the host means dhcpcd is not in the daemon's mount
				# namespace -- and the only ways out of one are setns
				# and unshare. Compare them rather than reason about it.
				for pid in $("$ip" netns pids "$ns" 2>/dev/null); do
					comm=$(cat "/proc/$pid/comm" 2>/dev/null)
					case "$comm" in
					netcfgd | dhcpcd)
						echo "       $comm[$pid] mnt=$(readlink "/proc/$pid/ns/mnt" 2>/dev/null)"
						;;
					esac
				done
				echo "       this shell mnt=$(readlink /proc/$$/ns/mnt)"
				echo "       daemon said:"
				sed 's/^/         /' "$work/daemon.log" 2>/dev/null | head -8
				failures=$((failures + 1))
			fi
			# And a packet actually crosses the simulated air.
			if inns ping -c 1 -W 2 10.55.0.1 >/dev/null 2>&1; then
				echo "ok   and reaches the access point over the air"
			else
				echo "FAIL cannot reach the access point at 10.55.0.1"
				failures=$((failures + 1))
			fi
		fi
	fi
fi

# ------------------------------------------------------ choosing between them
#
# **Two saved networks in range, and the document says which one to prefer.**
# `priority` is written into the supplicant's network block -- higher wins,
# which is wpa_supplicant's convention rather than netcfgd's -- and until now
# nothing exercised it with a radio. The code path was read and believed, which
# is the state every other wireless claim was in this morning.
#
# Deliberately after the checks above and on a rewritten document, so that a
# failure to prefer cannot take the association and lease results with it.
if [ "$state" = COMPLETED ]; then
	cat > "$work/ap2/ap.conf" <<CONF
ctrl_interface=$work/ap2/ctrl
update_config=0

network={
	ssid="netcfgd-better"
	mode=2
	frequency=2412
	key_mgmt=SAE WPA-PSK
	proto=RSN
	ieee80211w=1
	psk="$passphrase"
}
CONF
	inns "$supplicant" -B -Dnl80211 -i "$ap2_dev" -c "$work/ap2/ap.conf" \
		> "$work/ap2/log" 2>&1 || die "could not start the second access point"

	waited=0
	ap2_state=
	until [ "$ap2_state" = COMPLETED ]; do
		ap2_state=$(inns "$cli" -p "$work/ap2/ctrl" -i "$ap2_dev" status 2>/dev/null |
			sed -n 's/^wpa_state=//p')
		waited=$((waited + 1))
		if [ "$waited" -gt 150 ]; then
			echo "FAIL the second access point never came up (last: ${ap2_state:-none})"
			failures=$((failures + 1))
			break
		fi
		sleep 0.1
	done

	if [ "$ap2_state" = COMPLETED ]; then
		echo "ok   a second access point is beaconing"

		# Both networks, and the one the station is *not* on is preferred.
		# Written that way round on purpose: if the document is ignored
		# entirely the station stays where it is, which is the failure this
		# is looking for rather than a pass it could fall into.
		cat > "$work/etc/netcfgd.conf" <<CONF
device $sta_dev {
	wifi { backend = "wpa_supplicant"; autoconnect = true }
}

network "netcfgd-test" {
	wifi   { psk = "@secret:test"; proto = "wpa2+wpa3"; priority = 1 }
	config = "null"
}

network "netcfgd-better" {
	wifi   { psk = "@secret:test"; proto = "wpa2+wpa3"; priority = 100 }
	config = "null"
}

interface $sta_dev { config = "dhcp" }
CONF
		# **The supplicant is stopped first, and that is a finding rather
		# than a convenience.** `populate_supplicant` has one caller: the
		# `backend.start` handler. Networks reach the supplicant when it is
		# started and at no other time, so a `network` block added to the
		# document afterwards is never pushed and `ncfg apply` correctly
		# reports "nothing to do" -- measured, with the second network
		# absent from `list_networks` entirely.
		#
		# Decision 0015 says networks arrive "at apply time ... and are
		# removed by REMOVE_NETWORK when the document stops asking for
		# them", which describes a reconcile the planner has no operation
		# for. The document and the code disagree; that is the holder's to
		# settle, not this test's.
		#
		# So this stops the supplicant to get a fresh populate, which makes
		# the check below honest about what it proves: **that netcfgd
		# expresses the document's preference correctly**, not that it
		# notices a document changing under a running supplicant.
		# **Wait for the process, not for the socket.** The first version
		# polled the control socket and stopped as soon as it stopped
		# answering, which is earlier than the supplicant exiting -- so the
		# apply below found a pid that was still alive with no socket
		# behind it, classified it as running-and-silent, and refused to
		# kill a daemon that might only be busy. That refusal is correct
		# and is the guard working; the test was asking the wrong question.
		sta_pid=$(cat "$work/run/supplicant/$sta_dev.pid" 2>/dev/null)
		inns "$cli" -p "$work/ctrl" -i "$sta_dev" terminate > /dev/null 2>&1 || true
		waited=0
		while [ -n "$sta_pid" ] && kill -0 "$sta_pid" 2>/dev/null; do
			waited=$((waited + 1))
			if [ "$waited" -gt 150 ]; then
				echo "FAIL the supplicant did not exit after TERMINATE"
				failures=$((failures + 1))
				break
			fi
			sleep 0.1
		done
		# `--restart-wedged`, which netcfgd itself names in the refusal.
		#
		# **A supplicant that exits cleanly removes its own pid file, and
		# netcfgd reads a missing pid file as "cannot tell" rather than as
		# "gone".** So it stays `running`, the silent socket makes it
		# `running and silent`, and the restart is refused: the radio is
		# unconfigurable until somebody passes this flag.
		#
		# That is a real gap and not this test's to close. The obvious fix
		# is the one `read_backend_liveness` warns against, since reading
		# an absent pid file as "not running" would start a second dhcpcd
		# on every machine where netcfgd holds no file for one. Any fix has
		# to be per-backend -- `pid_by_marker` answers for a supplicant and
		# 0143 says it cannot for dhcpcd -- so it touches 0080, 0140 and
		# 0143 together.
		out=$(innc "$ncfg" apply --restart-wedged "$sta_dev" 2>&1 || true)

		waited=0
		chosen=
		until [ "$chosen" = netcfgd-better ]; do
			chosen=$(inns "$cli" -p "$work/ctrl" -i "$sta_dev" status 2>/dev/null |
				sed -n 's/^ssid=//p')
			waited=$((waited + 1))
			if [ "$waited" -gt 400 ]; then
				echo "FAIL did not move to the preferred network \
(on: ${chosen:-none})"
				echo "       ncfg apply said: $out"
				echo "       pid file: $work/run/supplicant/$sta_dev.pid"
				echo "       exists:   $([ -e "$work/run/supplicant/$sta_dev.pid" ] &&
					echo yes || echo NO)"
				echo "       contents: $(cat "$work/run/supplicant/$sta_dev.pid" 2>/dev/null |
					tr -d '\n')"
				echo "       captured: ${sta_pid:-<empty>}"
				echo "       supplicants alive in the namespace:"
				for q in $("$ip" netns pids "$ns" 2>/dev/null); do
					case "$(cat "/proc/$q/comm" 2>/dev/null)" in
					wpa_supplicant)
						echo "         $q $(tr '\0' ' ' < "/proc/$q/cmdline" |
							cut -c1-90)"
						;;
					esac
				done
				echo "       the supplicant knows:"
				inns "$cli" -p "$work/ctrl" -i "$sta_dev" list_networks 2>&1 |
					sed 's/^/         /'
				failures=$((failures + 1))
				break
			fi
			sleep 0.1
		done

		if [ "$chosen" = netcfgd-better ]; then
			echo "ok   preferred the higher-priority network of the two"
			echo "note: proved on a freshly started supplicant. A network"
			echo "note:   added to the document under a running one is not"
			echo "note:   pushed at all -- see the comment above."
			# And both are still configured: preferring one must not be
			# implemented by forgetting the other, which would look
			# identical from `status` alone and break the moment the
			# preferred network went away.
			known=$(inns "$cli" -p "$work/ctrl" -i "$sta_dev" list_networks 2>&1)
			case "$known" in
			*netcfgd-test*)
				echo "ok   and still knows the one it left"
				;;
			*)
				echo "FAIL the network it left is no longer configured"
				echo "$known" | sed 's/^/       /'
				failures=$((failures + 1))
				;;
			esac
		fi
	fi
fi

echo
if [ "$failures" -eq 0 ]; then
	echo "hwsim.sh: all checks passed"
else
	echo "hwsim.sh: $failures failed"
	exit 1
fi
