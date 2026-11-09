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

# The guest's own module first, and the host's copy only where it has none.
# hull boots its own kernel for a vm that names none since its 089facf, and a
# module built for the host's kernel will not load into that one; on the host's
# kernel the guest has the host's modules, so `modprobe` finds the same file.
# Built in is the third case, and the mount below is what each of them is for.
if ! modprobe binfmt_misc 2>/dev/null; then
	insmod /payload/binfmt_misc.ko 2>> "$out"
fi
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
	c client fuzznet doc packaging tests helper VERSION) | tar -xf - -C /work
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
bad=0
if grep -q 'NOT EXCUSED' /verdict/sections; then
	grep -E '\bFAILED\b' /verdict/test.log | head -30 >> "$out"
	bad=1
fi

# One estate of two byte orders, which no machine of either kind can test alone: a
# node built for this machine, which can observe, and a MIPS operator and client.
# All native first, so that a failure in the second pass is the second pass's.
mkdir -p /native
(cd /repo && tar -cf - --exclude='*.o' --exclude='*.a' --exclude='*.d' \
	--exclude=fuzznet-build --exclude='fuzznet/build*' --exclude=.git \
	--exclude=fuzznet/qtty --exclude=.build-flags --exclude=c/netcfgd --exclude=c/ncfg \
	c client fuzznet VERSION) | tar -xf - -C /native
(cd /native/c && PATH=${PATH#/tools:} timeout 900 make -j4 CC=gcc netcfgd ncfg) > /verdict/native.log 2>&1
say "native build: exit $?"
fleet() { # $1 the log, then the environment
	log=$1
	shift
	(cd /native/c && env "$@" timeout 420 sh tests/node_fleet.sh) > "$log" 2>&1
	echo "$?"
}
same=$(fleet /verdict/fleet-native.log PATH="${PATH#/tools:}")
say "fleet, one byte order: exit $same, $(grep -c ' ok$' /verdict/fleet-native.log) ok"
mixed=$(fleet /verdict/fleet-mixed.log PATH="${PATH#/tools:}" \
	NODE_FLEET_OPERATOR=/work/c/fuzznet-build/fuzznetd NODE_FLEET_CLIENT=/work/c/ncfg)
say "fleet, two byte orders: exit $mixed, $(grep -c ' ok$' /verdict/fleet-mixed.log) ok"
grep -E '\bFAILED\b' /verdict/fleet-mixed.log | head -20 | cut -c1-140 >> "$out"
[ "$same" -eq 0 ] && [ "$mixed" -eq 0 ] || bad=1

if [ "$bad" -ne 0 ]; then
	say "VERDICT bad"
else
	say "VERDICT ok"
fi
exit 0
