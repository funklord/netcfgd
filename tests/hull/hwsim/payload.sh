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
# **A root-shaped PATH, which the agent does not give.** netcfgd looks for a
# DHCP client on PATH alone and deliberately so -- `dhcp.c` says an operator's
# own client in front of the packaged one is a choice it honours -- and this
# guest's PATH has no `/usr/sbin`, so a `dhcpcd` that is installed read as
# "not installed" and the address half of the test failed. Any init gives root
# the sbins; the agent runs the command without them.
PATH=/usr/sbin:/sbin:/usr/local/sbin:$PATH
export PATH
echo "=== PATH: $PATH"
export NCFG_LIVE_BUILD=/repo/c
echo "=== netcfgd from the share: $(ls -l /repo/c/netcfgd | awk '{print $5}') bytes"
cd /repo
NCFG_LIVE=1 sh tests/live/hwsim.sh
