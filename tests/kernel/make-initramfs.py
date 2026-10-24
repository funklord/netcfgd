#!/usr/bin/env python3
"""A cpio spec for gen_init_cpio, from a rootfs directory plus the binaries.

Part of `tests/kernel/`, which boots netcfgd on kernels built without the
nftables NAT constructs; `run.sh` there says why that tier exists.

gen_init_cpio rather than `find | cpio`, for one reason that decides it: the
kernel opens /dev/console for PID 1, and an unprivileged user cannot mknod
one.  A spec file *declares* the node, so the archive carries it without
anybody being root.  Everything lands owned by root, which a user's tar
extract of a docker export could not do either.
"""
import os
import stat
import sys

rootfs, extra_init, binaries, out = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]
lines = []
counts = {"dir": 0, "file": 0, "slink": 0, "skipped": 0}

for base, dirs, files in os.walk(rootfs):
	rel = os.path.relpath(base, rootfs)
	guest = "/" if rel == "." else "/" + rel
	if guest != "/":
		lines.append("dir %s 0755 0 0" % guest)
		counts["dir"] += 1
	for name in sorted(files + [d for d in dirs if os.path.islink(os.path.join(base, d))]):
		host = os.path.join(base, name)
		there = (guest.rstrip("/") + "/" + name)
		try:
			info = os.lstat(host)
		except OSError:
			counts["skipped"] += 1
			continue
		mode = stat.S_IMODE(info.st_mode) or 0o644
		if stat.S_ISLNK(info.st_mode):
			lines.append("slink %s %s 0777 0 0" % (there, os.readlink(host)))
			counts["slink"] += 1
		elif stat.S_ISREG(info.st_mode):
			lines.append("file %s %s 0%o 0 0" % (there, os.path.abspath(host), mode))
			counts["file"] += 1
		else:
			# Sockets, fifos and device nodes: a docker export has none, and
			# the two the kernel needs are declared below.
			counts["skipped"] += 1
	dirs[:] = [d for d in dirs if not os.path.islink(os.path.join(base, d))]

# **The two the kernel needs before init can speak.** /dev/console is where
# PID 1's stdio goes; without it the boot is silent and looks like a hang.
lines.append("nod /dev/console 0600 0 0 c 5 1")
lines.append("nod /dev/null 0666 0 0 c 1 3")
lines.append("dir /opt 0755 0 0")
lines.append("dir /opt/ncfg 0755 0 0")
for program in binaries.split(","):
	lines.append("file /opt/ncfg/%s %s 0755 0 0" % (os.path.basename(program),
	    os.path.abspath(program)))
lines.append("file /init %s 0755 0 0" % os.path.abspath(extra_init))

with open(out, "w") as handle:
	handle.write("\n".join(lines) + "\n")
print("spec: %(dir)d dir(s), %(file)d file(s), %(slink)d symlink(s), "
      "%(skipped)d skipped, 2 device node(s)" % counts)
