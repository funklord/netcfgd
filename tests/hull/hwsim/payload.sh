#!/bin/sh
# netcfgd's hwsim.sh in a hull vm: the one live script this workspace has never
# been able to run. The container tier cannot -- it shares the host's kernel,
# which has no mac80211_hwsim -- and the host cannot, wanting real root.
#
# **Built in the guest where the image has a compiler**, which is the shape
# `build-and-commit.md` argues for: a build in the runner's own image is what
# catches what a developer machine hides, and a test running the host's binary
# is a test of the host's toolchain. Measured 2026-10-22 on hull `7b47668`: the
# guest builds the C and `hwsim.sh` passes 27 checks against the guest's own
# binary, the two binaries being the same size.
#
# It falls back to the share, through `NCFG_LIVE_BUILD`, where the image has no
# compiler -- loudly, because a fallback nobody is told about is how a run
# covers less than it looks like it does. The build form in `hull.conf`
# installs one.
#
# **A guest could not build anything before `7b47668`.** hull gave the workload
# no PATH at all, so gcc could not resolve its own argv[0] and
# `cc -print-prog-name=cc1` printed a bare name; every compile failed with
# `cannot execute cc1`. That was one of the five findings this rig produced.
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
if command -v cc >/dev/null 2>&1 && command -v make >/dev/null 2>&1; then
	echo "=== building in the guest, with $(cc --version | head -1)"
	mkdir -p /work
	tar -C /repo -cf - --exclude=./target --exclude=./.git --exclude=./dist . |
		tar -C /work -xf -
	cd /work
	# **Objects AND binaries.** A share keeps the host's mtimes, so make finds
	# the host's objects current and compiles nothing; and a program left
	# behind lets a failed build run the host's binary and read as a pass.
	# Both mistakes were made here on the day this was written.
	find . -name '*.o' -delete 2>/dev/null || true
	find . -name '*.d' -delete 2>/dev/null || true
	rm -f c/netcfgd c/ncfg c/libncfg.a
	if ! make -C c 2>&1 | tail -6; then
		echo "the C did not build in the guest"
		exit 1
	fi
	[ -x c/netcfgd ] || { echo "no c/netcfgd after the build"; exit 1; }
	echo "=== built here: $(ls -l c/netcfgd | awk '{print $5}') bytes, against the \
share's $(ls -l /repo/c/netcfgd 2>/dev/null | awk '{print $5}')"
else
	echo "note: no compiler in this image, so the binaries come from the share \
and this run says nothing about building"
	export NCFG_LIVE_BUILD=/repo/c
	cd /repo
fi

NCFG_LIVE=1 sh tests/live/hwsim.sh
