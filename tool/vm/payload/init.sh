# The two init integrations nothing has ever executed.
#
# netcfgd ships four: systemd, sysvinit (LSB, which also serves OpenRC on
# Debian), `packaging/openrc` (an `openrc-run` script for Gentoo and Alpine)
# and procd. `sandbox_writes.sh` exercises the systemd unit; procd needs
# OpenWrt and is named in 0265 as deliberately out of reach. **The other two
# have never run anywhere** -- 124 lines of LSB script and 28 of `openrc-run`,
# shipped in the deb, read by nobody.
#
# **One of them is reachable here and the other is not, and that was measured
# rather than assumed.** This file first claimed a Debian guest could run both,
# on the grounds that Debian packages `openrc`. It does -- 0.56-1 in trixie,
# candidate confirmed in the guest -- and it still cannot be installed, because
# `openrc` *depends on* `insserv` and `systemd-sysv` *conflicts with* it:
#
#     systemd-sysv : Conflicts: insserv but 1.26.0-1 is to be installed
#     openrc:amd64 Depends insserv
#
# So installing openrc on a systemd Debian means removing systemd as init, which
# apt will not do on the way to a dependency. That is structural and not
# transient. Alpine is the other OpenRC guest in the tier and is musl, while the
# binary is glibc -- and the musl target was retired deliberately rather than
# pollute the host to serve a guest.
#
# What would close it: a Debian guest with `sysvinit-core` as pid 1 instead of
# `systemd-sysv`, where openrc installs and would also let the LSB script be
# tested under the init it is written for. That is a second image, which is the
# holder's call, so this says so rather than quietly testing one thing and
# naming two.
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
install -m 0755 target/debug/netcfgd /usr/sbin/netcfgd ||
	{ echo "no netcfgd binary at target/debug/netcfgd"; exit 1; }
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
	echo "    note: openrc-run is unexpectedly present -- the header's"
	echo "    note:   measurement has gone stale, and this section should"
	echo "    note:   become real checks again rather than this note"
else
	echo "    not tested here: openrc depends on insserv and systemd-sysv"
	echo "      conflicts with it, so a systemd guest cannot install it."
	echo "      28 lines of openrc-run script remain unexecuted anywhere."
	echo "      Closing it needs a sysvinit-core guest; see the header."
fi
echo

echo "init: $fail failed, of what could be attempted here"
[ "$fail" -eq 0 ]
