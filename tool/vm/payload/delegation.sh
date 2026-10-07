# `delegation.sh` in a guest, with the client Debian does not package.
#
# This is the one live script that has never run anywhere. It needs real root,
# and it needs `odhcp6c`, which is not in Debian -- decision 0050 is why
# netcfgd refuses to pretend dhcpcd can report a prefix instead, and 0051
# lifted a deferred language addition on the grounds that odhcp6c "builds from
# source in a couple of minutes", which is what this does.
#
# So netcfgd's whole delegation chain has had no live coverage: the document
# asks for a prefix, odhcp6c solicits `IA_PD`, kea delegates, netcfgd resolves
# `@pd:wan0` into addresses and radvd advertises them to a host. Every link is
# covered by fixtures and none of them by a real exchange.
#
# **Its own payload rather than a step in `skipped.sh`.** The build pulls
# `build-essential` and `cmake` -- a few hundred megabytes and a few minutes --
# and charging that to every run of the other eight scripts is how a suite
# stops being run. `skipped.sh` goes on reporting delegation as "no odhcp6c",
# which is the truth there, and its header names this payload so a reader who
# meets that failure knows where the rest of it is.
#
# ## Pinned to a commit, and why not to a tarball
#
# Both sources are pinned by commit sha and fetched with git, which verifies
# them: a git object's name IS its content hash, so a wrong or tampered fetch
# cannot check out under the sha we asked for. A checksum over GitHub's
# generated tarballs would be weaker and more fragile -- those are produced on
# demand and their bytes have changed across compression changes before, so the
# checksum would eventually fail for a reason that is not a finding.
#
# The pin is still asserted after the checkout rather than assumed, because
# `git checkout` of a sha that is not there fails in ways a script can miss,
# and a build of whatever was at the tip of master would look identical.
#
# ## What stops it
#
# Every network step is wrapped in `timeout`, the two builds are bounded by
# having nothing to loop over, and the script runs one test and exits. Nothing
# is left running: `delegation.sh` does its own teardown, which is the subject
# of its own header.
set -u
cd /mnt/repo || { echo "the repository is not mounted"; exit 1; }

LIBUBOX_SHA=e7608b69283d919d031d13cc8e21692503f5dbea
ODHCP6C_SHA=10a52220aec9d45803518d8cc4d63e552484ed61

# **kea's AppArmor profile refuses it the capabilities root needs, and kea is
# the ISP here rather than anything under test.** Measured on the first run,
# from the guest's own audit log:
#
#     apparmor="DENIED" operation="capable" profile="kea-dhcp6" \
#         capname="dac_read_search"
#     apparmor="DENIED" operation="capable" profile="kea-dhcp6" \
#         capname="dac_override"
#
# Debian's package creates `/run/kea` owned by `_kea`, `delegation.sh` starts
# `kea-dhcp6` by hand as root, and the DAC bypass root would normally use is
# exactly what the profile denies -- so kea died with *Permission denied* on its
# logger lockfile and then fatally on its PID file. No ISP, no delegation, and
# five of the six failures that followed were cascade from the one.
#
# Unloaded rather than worked around, and the narrower fix was considered:
# `chown root:root /run/kea` removes the need for the capability without
# weakening anything. It is not taken because it is not known to be sufficient
# -- the profile confines paths too, and this script's kea config and log live
# in a work directory under `/tmp` that the profile has no reason to permit --
# so it would risk trading one denial for another and learning nothing.
#
# What makes the broad answer right here rather than merely easier: on a real
# machine kea is the operator's ISP, somewhere else entirely. It is scaffolding
# standing in for one, its confinement is not a property of netcfgd, and the
# guest is discarded when the run ends.
loaded() {
	grep -q "^$1 " /sys/kernel/security/apparmor/profiles 2>/dev/null
}

apparmor_off() {
	profile=$1
	# **The kernel's list is asked first, because that is the question.**
	# Whether a file exists under /etc/apparmor.d is a proxy for whether a
	# profile is enforcing, and the first version of this leant on the proxy:
	# it looked for the file, and returned success when it found none. A grep
	# pattern that did not match the package's spelling would then have
	# reported "nothing to unload" and passed, leaving the profile enforcing
	# and kea failing exactly as before -- a vacuous pass in the one step added
	# to stop a known failure.
	if ! loaded "$profile"; then
		echo "    $profile: not loaded, nothing to unload"
		return 0
	fi
	file=$(grep -rl "^profile $profile \|^$profile " /etc/apparmor.d \
		2>/dev/null | head -1)
	if [ -z "$file" ]; then
		echo "    $profile: enforcing, but no file under /etc/apparmor.d"
		echo "      declares it -- so it cannot be unloaded by name here"
		return 1
	fi
	apparmor_parser -R "$file" 2>/dev/null
	# Verified against the kernel rather than against the parser's exit status,
	# which is a fact about the parser.
	if loaded "$profile"; then
		echo "    $profile: STILL LOADED after unloading $file"
		return 1
	fi
	echo "    $profile: unloaded, and the kernel agrees"
}

build=/root/build
rm -rf "$build"
mkdir -p "$build" || { echo "cannot make a build directory"; exit 1; }

echo "=== installing what the build and the test need"
export DEBIAN_FRONTEND=noninteractive
timeout 300 apt-get -qq update 2>&1 | tail -2
for pkg in kea-dhcp6-server radvd git cmake build-essential pkg-config \
	libjson-c-dev; do
	if timeout 600 apt-get -qq -y install "$pkg" >/dev/null 2>&1; then
		echo "    $pkg: installed"
	else
		echo "    $pkg: NOT AVAILABLE"
	fi
done

echo "=== standing kea's AppArmor profile down"
apparmor_off kea-dhcp6 || exit 1
echo

# One function for both, because the only difference is the sha and what gets
# installed afterwards. The sha check is the whole point of it.
fetch_at() {
	name=$1
	sha=$2
	echo "=== $name at $sha"
	timeout 300 git clone -q "https://github.com/openwrt/$name" \
		"$build/$name" || { echo "    clone failed"; return 1; }
	timeout 120 git -C "$build/$name" checkout -q "$sha" ||
		{ echo "    no such commit in what was fetched"; return 1; }
	got=$(git -C "$build/$name" rev-parse HEAD)
	if [ "$got" != "$sha" ]; then
		echo "    checked out $got, which is not the pin"
		return 1
	fi
	echo "    at the pinned commit"
}

fetch_at libubox "$LIBUBOX_SHA" || exit 1
# BUILD_LUA off because lua is not installed and is not wanted; examples off
# because they are not what odhcp6c links against.
timeout 600 cmake -S "$build/libubox" -B "$build/libubox/build" \
	-DBUILD_LUA=OFF -DBUILD_EXAMPLES=OFF > "$build/libubox.log" 2>&1 &&
	timeout 600 cmake --build "$build/libubox/build" \
		>> "$build/libubox.log" 2>&1 &&
	timeout 120 cmake --install "$build/libubox/build" \
		>> "$build/libubox.log" 2>&1 && ldconfig ||
	{ echo "    libubox did not build:"; tail -15 "$build/libubox.log"; exit 1; }
echo "    libubox installed"

fetch_at odhcp6c "$ODHCP6C_SHA" || exit 1
timeout 600 cmake -S "$build/odhcp6c" -B "$build/odhcp6c/build" \
	> "$build/odhcp6c.log" 2>&1 &&
	timeout 600 cmake --build "$build/odhcp6c/build" \
		>> "$build/odhcp6c.log" 2>&1 ||
	{ echo "    odhcp6c did not build:"; tail -15 "$build/odhcp6c.log"; exit 1; }
install -m 0755 "$build/odhcp6c/build/odhcp6c" /usr/local/bin/odhcp6c ||
	{ echo "    could not install odhcp6c"; exit 1; }
echo "    odhcp6c installed"

# **The client answers before the test is asked to depend on it.** A binary that
# builds and will not run -- a missing shared library is the likely way, since
# libubox was just installed into /usr/local/lib -- would otherwise surface as
# a delegation failure rather than as a build problem.
if odhcp6c -h 2>&1 | grep -q 'Usage:'; then
	echo "    and runs: $(command -v odhcp6c)"
else
	echo "    but will not run:"
	odhcp6c -h 2>&1 | sed 's/^/      /' | head -5
	exit 1
fi
echo

# `NCFG_LIVE=1`, so a skip is a failure: with the client built, anything this
# still cannot do is something to hear about rather than to pass over. The
# status is the script's own, read from a file rather than through a pipe --
# `skipped.sh` reported nine of nine passing by reading `sed`'s status, and
# this is the same hazard with one script instead of nine.
echo "=== delegation.sh"
NCFG_LIVE=1 sh tests/live/delegation.sh > /tmp/out.delegation 2>&1
rc=$?
sed 's/^/    /' /tmp/out.delegation
echo
if [ "$rc" = 0 ]; then
	echo "delegation: passed"
else
	echo "delegation: FAILED rc=$rc"
fi
exit "$rc"
