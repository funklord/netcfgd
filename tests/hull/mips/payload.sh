#!/bin/sh
# The C suite as big-endian 32-bit MIPS code, under qemu (project.md 10.742).
#
# Copies the tree's sources into the guest, builds them with Debian's MIPS
# compiler and runs `make -C c test`, with `binfmt_misc` handing every MIPS
# program to qemu so that a test starting `c/netcfgd` starts a MIPS one. The
# machine is asked first, so a run that quietly built for x86 cannot pass.
#
# Always exits 0 and reports through /verdict/mips.
#
# HOW IT STOPS: the build and the suite each run under `timeout`, the steps are
# a fixed list, and the vm takes everything with it.
out=/verdict/mips
: > "$out"
say() { echo "$*" >> "$out"; echo "mips: $*"; }

insmod /payload/binfmt_misc.ko 2>> "$out"
mount -t binfmt_misc binfmt_misc /proc/sys/fs/binfmt_misc 2>> "$out"
# Debian's own line for this machine: big-endian ELF32, machine 8. F, so qemu is
# opened now and works from any root.
printf '%s' ':qemu-mips:M::\x7fELF\x01\x02\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\x08:\xff\xff\xff\xff\xff\xff\xff\x00\xff\xff\xff\xff\xff\xff\xff\xff\xff\xfe\xff\xff:/usr/bin/qemu-mips-static:F' \
	> /proc/sys/fs/binfmt_misc/register 2>> "$out"
export QEMU_LD_PREFIX=/usr/mips-linux-gnu

# The tree's Makefiles call these by their plain names, and this host's cannot
# read a MIPS object.
mkdir -p /tools
for tool in ar nm ranlib size strip objdump; do
	ln -sf "/usr/bin/mips-linux-gnu-$tool" "/tools/$tool"
done
export PATH=/tools:$PATH

mkdir -p /work
(cd /repo && tar -cf - --exclude='*.o' --exclude='*.a' --exclude='*.d' \
	--exclude=fuzznet-build --exclude='fuzznet/build*' --exclude=.git \
	--exclude=fuzznet/qtty --exclude=target --exclude=.build-flags \
	c client fuzznet doc packaging tests crates helper VERSION) | tar -xf - -C /work
# Whatever this tree last built, by name, so that nothing x86 is linked.
(cd /work/c && make -s clean >/dev/null 2>&1)
rm -f /work/c/netcfgd /work/c/ncfg

cd /work/c || { say "VERDICT bad: the tree did not copy"; exit 0; }
timeout 2400 make -j4 CC=mips-linux-gnu-gcc netcfgd > /verdict/build.log 2>&1
built=$?
say "built: exit $built, $(file netcfgd 2>/dev/null | cut -d, -f1-2 | cut -d: -f2)"
[ "$built" -eq 0 ] || { tail -20 /verdict/build.log >> "$out"; say "VERDICT bad"; exit 0; }
file netcfgd | grep -q 'MSB.*MIPS' || { say "VERDICT bad: that is not a MIPS program"; exit 0; }
say "it runs: $(./netcfgd --version 2>&1 | head -1)"

timeout 3000 make -k -j2 CC=mips-linux-gnu-gcc test > /verdict/test.log 2>&1
say "ok lines: $(grep -c ' ok$' /verdict/test.log)"
# qemu-user answers EOPNOTSUPP for any rtnetlink message type it cannot translate,
# so what observes the machine cannot run here: these, by name, and nothing else.
# A failure in any other section fails the run. A section saying nothing of the
# emulator's limit is not excused either.
grep -q 'c: every check passed\|c: some checks failed' /verdict/test.log ||
	{ say "VERDICT bad: the suite never finished"; exit 0; }
awk '
	/^== / { section = $2; next }
	/FAILED/ { failed[section]++ }
	/EOPNOTSUPP|netlink request failed|the answer is not a page/ { limit[section]++ }
	END {
		split("tests/cli_apply_test tests/node_serve.sh tests/node_store_trouble.sh " \
		    "tests/node_ram_host.sh tests/node_fleet.sh tests/host_user.sh", names, " ")
		for (at in names) excused[names[at]] = 1
		for (s in failed) {
			kept = (s in excused && limit[s] > 0) ? "excused" : "NOT EXCUSED"
			printf "%s: %d failed, %s\n", s, failed[s], kept
		}
	}' /verdict/test.log | sort > /verdict/sections
cat /verdict/sections >> "$out"
if grep -q 'NOT EXCUSED' /verdict/sections; then
	grep -E '\bFAILED\b' /verdict/test.log | head -30 >> "$out"
	say "VERDICT bad"
else
	say "VERDICT ok"
fi
exit 0
