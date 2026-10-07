# Can a payload reach the repository, and can it run what is in it?
#
# The share is how the tree gets into a guest without an image being rebuilt.
# Read-only on both sides, because a guest that could write to it would be a
# test editing the source it is testing.
set -u
echo "mount:  $(grep ' /mnt/repo ' /proc/mounts || echo NOT-MOUNTED)"
echo "files:  $(ls /mnt/repo 2>/dev/null | wc -l) entries at the root"
echo "marker: $([ -f /mnt/repo/project.md ] && echo project.md present || echo MISSING)"
# **And whether the host's binary can run here, which is the question that
# decides how this tier tests netcfgd.** The host builds against glibc and this
# guest is musl, so a dynamically linked binary from target/ is not expected to
# start -- this reports what actually happens rather than assuming it.
if [ -x /mnt/repo/target/debug/netcfgd ]; then
	out=$(/mnt/repo/target/debug/netcfgd --version 2>&1 | head -2)
	echo "netcfgd: ${out:-no output}"
else
	echo "netcfgd: not built on the host"
fi
