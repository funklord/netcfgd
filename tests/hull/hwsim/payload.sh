#!/bin/sh
# netcfgd's hwsim.sh in a hull vm: the one live script this workspace has never
# been able to run. The container tier cannot -- it shares the host's kernel,
# which has no mac80211_hwsim -- and the host cannot, wanting real root.
#
# **Nothing is compiled here.** `hwsim.sh` takes `NCFG_LIVE_BUILD`, so it runs
# the binaries the host already built, out of the read-only share: the host and
# this guest are one architecture and one libc, and what is under test is the
# radio rather than the build. Compiling in the guest was tried and is a
# finding of its own -- gcc's driver cannot find `cc1` on an overlay over the
# share, printing a bare name where it should print a path.
set -eu
echo "=== guest: uid $(id -u), kernel $(uname -r)"
printf '=== tools:'
for t in modprobe iw wpa_supplicant ip dnsmasq dhcpcd; do
	command -v "$t" >/dev/null && printf ' %s' "$t"
done
echo
# **A root-shaped PATH, and hull gives one as of `7b47668`.** This line is
# older than that fix: the agent used to run the command with no PATH at all,
# so libc's `/bin:/usr/bin` applied, a `dhcpcd` in `/usr/sbin` read as "not
# installed", and the address half of the test failed. hull exports the
# conventional root PATH now where the spec and image name none -- measured
# here, a machine printing
# `/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin` and finding
# `/usr/sbin/dhcpcd` -- and a PATH the spec names is kept as given, so this
# line is harmless and redundant against that hull.
#
# It stays until nothing here runs an older one, which is the only reason it
# is still here: the rig pins no hull version, and a rig that silently needs a
# newer one is a rig that fails on somebody's machine for a reason it does not
# say. netcfgd's own half of that finding is fixed too (90982d6c): a client in
# the sbins and not on PATH is now said to be exactly that, rather than
# reported as absent.
PATH=/usr/sbin:/sbin:/usr/local/sbin:$PATH
export PATH
echo "=== PATH: $PATH"
export NCFG_LIVE_BUILD=/repo/c
echo "=== netcfgd from the share: $(ls -l /repo/c/netcfgd | awk '{print $5}') bytes"
cd /repo
NCFG_LIVE=1 sh tests/live/hwsim.sh
