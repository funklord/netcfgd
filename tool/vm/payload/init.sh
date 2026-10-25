# The two init integrations that had never been executed.
#
# netcfgd ships four: systemd, sysvinit (LSB, which also serves OpenRC on
# Debian), `packaging/openrc` (an `openrc-run` script for Gentoo and Alpine)
# and procd. `sandbox_writes.sh` exercises the systemd unit; procd needs
# OpenWrt and is named in 0275 as deliberately out of reach. The other two --
# 124 lines of LSB script and 28 of `openrc-run` -- were shipped in the deb and
# read by nobody until this payload ran.
#
# **Where each half can run is measured, and the two guests differ.** This file
# first claimed a Debian guest could run both, on the grounds that Debian
# packages `openrc`. It does -- 0.56-1 in trixie, candidate confirmed in the
# guest -- and it still cannot be installed beside systemd, because `openrc`
# *depends on* `insserv` and `systemd-sysv` *conflicts with* it:
#
#     systemd-sysv : Conflicts: insserv but 1.26.0-1 is to be installed
#     openrc:amd64 Depends insserv
#
# So installing openrc on a systemd Debian means removing systemd as init, which
# apt will not do on the way to a dependency. That is structural and not
# transient. So:
#
#   * `make vm-init`, the tier's Debian systemd guest, runs the LSB half only,
#     and runs it through `systemd-sysv-generator` rather than under sysvinit.
#     The openrc half reports itself untested there and is not counted.
#   * `tests/hull/openrc/` runs **both**, in a guest whose pid 1 is
#     `/sbin/openrc-init` -- which is what the paragraph that stood here called
#     "a second image, the holder's call". On hull that image is a bake and a
#     spec rather than a qcow2, so the call cost an afternoon: 2026-10-23, 13
#     checks, and the first execution of the `openrc-run` script anywhere.
#   * `tests/hull/sandbox/` runs the sysvinit half under `/sbin/init`, which is
#     the init the LSB script is actually written for.
#
# Alpine is the other OpenRC world and is still out of reach as a guest here:
# it is musl, and its init is busybox rather than `openrc-init`, so it would be
# a third image proving the same 28 lines.
#
# ## What this proves and what it does not
#
# That each script starts the daemon, that the runtime directory its own
# comments promise is there, that status reports the truth, and that stop
# leaves nothing behind. **Not** that either integrates correctly with a real
# boot: ordering, `provide net`, and what waits on what are properties of a
# running init, and this starts the services by hand under the guest's systemd.
# Saying so because a green run here would otherwise read as "OpenRC works".
#
# **And the LSB half is weaker than it looks, measured rather than assumed.**
# The guest runs systemd, whose `systemd-sysv-generator` turns a script in
# /etc/init.d into a unit -- so `/etc/init.d/netcfgd start` printed *Starting
# netcfgd (via systemctl): netcfgd.service*, and `status` answered with
# `Loaded: loaded (/etc/init.d/netcfgd; generated)`. What that does prove is
# worth having: the generator parses the LSB header, which is the part most
# likely to be malformed, and the script's own `start`, `stop` and `status`
# shell ran. What it does not prove is the script under *sysvinit*, where
# nothing generates a unit and `start-stop-daemon --background` is unsupervised.
# A guest with `sysvinit-core` as pid 1 is what would close that, and this is
# not it.
#
# ## What stops it
#
# One daemon start and stop per script, each waited for with a bounded loop.
# The daemon is given an empty document so it has nothing to apply: this runs
# in the guest's real root namespace, and a document with interfaces in it
# would be a test reconfiguring the machine it is running on.
set -u
cd /mnt/repo || { echo "the repository is not mounted"; exit 1; }

fail=0
ok() { echo "    ok   $1"; }
bad() { echo "    FAIL $1"; fail=$((fail + 1)); }

check() {
	if [ "$2" = "$3" ]; then
		ok "$1"
	else
		bad "$1"
		echo "           expected: $3"
		echo "           actual:   $2"
	fi
}

echo "=== installing what the scripts need"
export DEBIAN_FRONTEND=noninteractive
timeout 300 apt-get -qq update 2>&1 | tail -2
# `lsb-base` only, because the LSB script sources `/lib/lsb/init-functions`
# when it is there and the guarded fallback it carries would otherwise be the
# only path ever taken. `openrc` was asked for here and cannot be installed --
# see the header, and the note where that section used to run.
for pkg in lsb-base; do
	# **Why it failed, not just that it did.** This printed `NOT AVAILABLE`
	# for every failure -- no candidate, a dependency conflict, a postinst
	# that refused, a network error -- with apt's output sent to /dev/null.
	# `openrc` came back NOT AVAILABLE here while Debian 13 carries it at
	# 0.56-1 and the host it was measured from has it installed, so the one
	# word was wrong about the one thing it was asked. A whole guest run was
	# spent learning nothing. `evidence.md`'s rule: a status word is the
	# tool's vocabulary, not a diagnosis.
	if timeout 600 apt-get -qq -y install "$pkg" > "/tmp/apt.$pkg" 2>&1; then
		echo "    $pkg: installed"
	else
		echo "    $pkg: NOT AVAILABLE, and apt said:"
		sed 's/^/      /' "/tmp/apt.$pkg" | tail -8
	fi
done
echo

# The daemon where both scripts look for it. Copied rather than symlinked from
# the read-only mount, because `start-stop-daemon --exec` resolves the path and
# compares it against `/proc/<pid>/exe`, which would be the mount path.
# **The C, because the C is what ships** (0266). This installed
# `target/debug/netcfgd` -- the Rust -- so the two init integrations were being
# exercised against the program that was retired, which is the one thing a
# packaging test must not do. `NCFG_LIVE_BUILD` is honoured for the same reason
# every script under `tests/live/` honours it.
build=${NCFG_LIVE_BUILD:-/mnt/repo/c}
install -m 0755 "$build/netcfgd" /usr/sbin/netcfgd ||
	{ echo "no netcfgd binary at $build/netcfgd"; exit 1; }
mkdir -p /etc/netcfgd
: > /etc/netcfgd/netcfgd.conf
echo "netcfgd: $(/usr/sbin/netcfgd --version 2>&1 | head -1)"
echo

# Both scripts name /run/netcfgd.pid and /usr/sbin/netcfgd, so they cannot be
# tested at once. Each is installed, exercised and removed in turn.
running() {
	[ -s /run/netcfgd.pid ] && [ -d "/proc/$(cat /run/netcfgd.pid)" ]
}

wait_for() {
	waited=0
	until "$1"; do
		waited=$((waited + 1))
		[ "$waited" -gt 100 ] && return 1
		sleep 0.1
	done
}

wait_gone() {
	waited=0
	while running; do
		waited=$((waited + 1))
		[ "$waited" -gt 100 ] && return 1
		sleep 0.1
	done
}

cleanup() {
	if [ -s /run/netcfgd.pid ]; then
		kill "$(cat /run/netcfgd.pid)" 2>/dev/null || true
	fi
	rm -f /run/netcfgd.pid /etc/init.d/netcfgd
}
trap cleanup EXIT INT TERM

# ----------------------------------------------------------------- sysvinit

echo "=== packaging/sysvinit/netcfgd"
cleanup
rm -rf /run/netcfgd
install -m 0755 packaging/sysvinit/netcfgd /etc/init.d/netcfgd

# Its own parser first, which costs nothing and separates "the script is
# broken" from "the daemon did not start".
sh -n /etc/init.d/netcfgd && ok "the script parses" || bad "the script parses"

/etc/init.d/netcfgd start > /tmp/sysv.start 2>&1
sed 's/^/      /' /tmp/sysv.start
if wait_for running; then
	ok "start brought the daemon up, with a pidfile pointing at it"
else
	bad "start brought the daemon up, with a pidfile pointing at it"
	echo "      pidfile: $(cat /run/netcfgd.pid 2>/dev/null || echo absent)"
fi
# The directory its own comment promises, and promises not to remove on stop.
check "and made the runtime directory" \
	"$([ -d /run/netcfgd ] && echo yes || echo no)" "yes"
/etc/init.d/netcfgd status > /tmp/sysv.status 2>&1
check "status agrees it is running" "$?" "0"
sed 's/^/      /' /tmp/sysv.status

/etc/init.d/netcfgd stop > /tmp/sysv.stop 2>&1
sed 's/^/      /' /tmp/sysv.stop
if wait_gone; then
	ok "stop took it down"
else
	bad "stop took it down"
fi
# 0135's choice, and the script says so in as many words: the record of what
# netcfgd installed has nowhere else to live, so a stop that removed it would
# leave the next daemon unable to put those things back.
check "and left the runtime directory, which is 0135's choice" \
	"$([ -d /run/netcfgd ] && echo yes || echo no)" "yes"
/etc/init.d/netcfgd status > /tmp/sysv.status2 2>&1
check "and status now reports it stopped" "$?" "3"
echo

# ------------------------------------------------------------------- openrc

echo "=== packaging/openrc/netcfgd"
# **Not tested, and not counted either way.** The reason is in the header and it
# is structural: openrc cannot be installed beside systemd-sysv. Reported here
# rather than skipped silently, and deliberately not as a failure -- a target
# that always goes red is one people learn to ignore, and this is a known gap
# with a named remedy rather than a regression.
#
# It is also not counted as a pass. `$fail` is over what was attempted, and the
# line below is what stops a green `vm-init` from reading as "both integrations
# work" -- which is the vacuous pass this tree keeps finding.
if [ -x /sbin/openrc-run ] || [ -x /usr/sbin/openrc-run ]; then
	# **Real checks since 2026-10-23**, which is what the note that stood here
	# asked its successor to do if openrc ever appeared. It appears in a guest
	# booted by `openrc-init`, which `tests/hull/openrc/` makes: on hull a
	# second image is a bake and a spec rather than a qcow2, so the "holder's
	# call" the header names cost an afternoon.
	#
	# **Two conditions, not one.** openrc installed is not openrc booted, and
	# the difference is not cosmetic: on a sysvinit-booted guest with openrc
	# merely installed, `start` answers " * WARNING: netcfgd is already
	# starting" and does nothing, `status` says "you are attempting to run an
	# openrc service on a system which openrc did not boot", and every check
	# below would fail for the environment rather than for the script.
	# Measured in that guest before this was written.
	if [ ! -f /run/openrc/softlevel ]; then
		echo "    not tested here: openrc is installed and did not boot this"
		echo "      system, so it refuses to manage services -- the script is"
		echo "      unexercised and this is not counted either way."
		echo "      \`tests/hull/openrc/\` boots a guest with openrc-init."
	else
	# **`need localmount` is a Gentoo and Alpine name, and a Debian guest has
	# nothing of it.** Measured here on the first run, which cost three checks:
	# openrc answered "Service 'netcfgd' needs non existent service
	# 'localmount'" and refused to start it, because Debian's openrc keeps
	# sysvinit's `mountall.sh` and nothing provides the name. The dependency is
	# correct for the two distributions the script names, so the image supplies
	# a stand-in -- `tests/hull/openrc/localmount` is an inert `localmount`
	# service, copied into that rig's image, and says why in its own header. Nothing here depends on it being
	# present: if it is absent, openrc refuses and the checks below fail
	# loudly, which is the honest outcome for a guest that cannot host the
	# script.
	cleanup
	rm -rf /run/netcfgd
	install -m 0755 packaging/openrc/netcfgd /etc/init.d/netcfgd
	sh -n /etc/init.d/netcfgd && ok "the script parses" || bad "the script parses"
	/etc/init.d/netcfgd start > /tmp/rc.start 2>&1
	sed 's/^/      /' /tmp/rc.start
	if wait_for running; then
		ok "start brought the daemon up, with a pidfile pointing at it"
	else
		bad "start brought the daemon up, with a pidfile pointing at it"
		echo "      pidfile: $(cat /run/netcfgd.pid 2>/dev/null || echo absent)"
	fi
	# `start_pre` calls `checkpath --directory`, which is the openrc idiom for
	# what the LSB script does with `mkdir`: the same promise by another route.
	check "and \`start_pre\` made the runtime directory" \
		"$([ -d /run/netcfgd ] && echo yes || echo no)" "yes"
	check "status agrees it is running" \
		"$(/etc/init.d/netcfgd status 2>&1 | grep -c 'status: started')" "1"
	/etc/init.d/netcfgd stop > /tmp/rc.stop 2>&1
	sed 's/^/      /' /tmp/rc.stop
	if wait_gone; then
		ok "stop took it down"
	else
		bad "stop took it down"
	fi
	check "and status now reports it stopped" \
		"$(/etc/init.d/netcfgd status 2>&1 | grep -c 'status: stopped')" "1"
	fi
else
	echo "    not tested here: openrc depends on insserv and systemd-sysv"
	echo "      conflicts with it, so a systemd guest cannot install it."
	echo "      Those 28 lines are exercised by \`tests/hull/openrc/\`, in a"
	echo "      guest booted by openrc-init; see the header."
fi
echo

echo "init: $fail failed, of what could be attempted here"
[ "$fail" -eq 0 ]
