# gui/tests/dns_record_load.pro -- the DNS records tab must save what it loaded.
#
# Its own project rather than a case inside netcfgd-gui, for the reason
# access_frame.pro gives: a plain `make` in gui/ must not compile a test.

TEMPLATE = app
TARGET = dns_record_load
QT += widgets
CONFIG += c++17 console
CONFIG -= app_bundle

# Matching gui.pro, so the probe compiles the view the way it ships.
QMAKE_CXXFLAGS_RELEASE -= -O2
QMAKE_CXXFLAGS_RELEASE += -Os

CLIENT_DIR = $$PWD/../../client
INCLUDEPATH += $$CLIENT_DIR $$PWD/../src
LIBS += $$CLIENT_DIR/libncfg_client.a
# Relink when the client changes. Without it `make` here considers the probe up
# to date after the library is rebuilt, so the test runs against the old C
# client and passes or fails for reasons that are no longer in the tree -- which
# the live probes' projects already record, and which cost a debugging round
# here too.
PRE_TARGETDEPS += $$CLIENT_DIR/libncfg_client.a

SOURCES += dns_record_load.cpp ../src/dns_record_dialog.cpp ../src/ncfg_connection.cpp
HEADERS += ../src/dns_record_dialog.h ../src/ncfg_connection.h

# The daemon this drives, by absolute path: the test starts a real one, because
# the configuration has to come from somewhere and the socket round trip is the
# thing under test.
# **The C daemon, which is the one that ships** (0266). This named the Rust
# one under `target/debug`, which `make check`'s cargo step happened to
# build, so these probes tested the GUI against a daemon nothing installs --
# and one that has never heard of `dhcp_server` (project.md 10.606).
DEFINES += NETCFGD_BINARY=\\\"$$PWD/../../c/netcfgd\\\"
