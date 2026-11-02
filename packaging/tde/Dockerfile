# The TDE front end's toolchain, for `make tde-container`.
#
# TDE's development packages are not in Debian; they are in trinitydesktop.org's
# own repository, which this adds. The keyring comes from that project over
# https, so TLS to its domain is what vouches for it -- the same trust as
# following its install instructions by hand. The repository itself is http:
# its https name redirects to plain-http mirrors, which apt refuses as a
# downgrade, and apt checks every package against the keyring either way.
# Nothing is installed on the host.
FROM debian:trixie
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl \
 && curl -fsSL -o /tmp/trinity-keyring.deb \
      https://mirror.ppa.trinitydesktop.org/trinity/deb/trinity-keyring.deb \
 && apt-get install -y /tmp/trinity-keyring.deb && rm /tmp/trinity-keyring.deb \
 && echo "deb http://mirror.ppa.trinitydesktop.org/trinity/deb/trinity-r14.1.x trixie main deps" \
      > /etc/apt/sources.list.d/trinity.list \
 && apt-get update && apt-get install -y --no-install-recommends \
      tde-cmake tdelibs14-trinity-dev libtqt3-mt-dev cmake make gcc g++ pkg-config \
 && rm -rf /var/lib/apt/lists/*
