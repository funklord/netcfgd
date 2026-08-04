#!/bin/sh
# Build netcfgd's apk with Alpine's own tools, inside Alpine.
#
# Run by `make apk-container`, which mounts the generated APKBUILD and source
# tarball at /dist. The point is that `abuild` does the work: what comes out is
# a package built by the distribution's tool rather than something this repo
# approximated.
#
# abuild refuses to run as root -- deliberately, and it is right -- so this
# makes a user, puts it in the `abuild` group, and gives it a throwaway signing
# key. The key is per-container and dies with it; a package for anyone else to
# install needs a real one.
set -eu

apk add --quiet --no-progress alpine-sdk

adduser -D -G abuild builder
mkdir -p /home/builder/build /home/builder/packages
cp /dist/APKBUILD /dist/*.tar.gz /home/builder/build/
chown -R builder /home/builder /dist

# `abuild-keygen -i` would install the public key itself, via `doas`, which a
# bare Alpine image does not have. Generating as the builder and installing as
# root is the same two files and one fewer package.
su builder -c 'abuild-keygen -a -n'
cp /home/builder/.abuild/*.rsa.pub /etc/apk/keys/

su builder -c '
	set -eu
	cd /home/builder/build
	abuild -F checksum
	REPODEST=/home/builder/packages abuild -F -r
'

find /home/builder/packages -name '*.apk' -exec cp {} /dist/ ';'
