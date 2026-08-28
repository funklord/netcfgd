# gui/tests/live/live_dns.pro -- the dns tab against a real daemon.
#
# In `gui/tests/live/` rather than beside the other probes, and the directory
# is the whole reason: `make -C gui test` globs `tests/*.pro` and runs whatever
# it finds, so a probe left there was picked up and run with no daemon -- which
# fails at "the view can reach netcfgd" and says nothing about the view. A
# subdirectory is the smallest thing that tells the glob apart from the live
# suite, which builds and runs this itself through `tests/live/gui_wifi.sh`.

TEMPLATE = app
TARGET = live_dns
QT += widgets
CONFIG += c++17 console
CONFIG -= app_bundle

QMAKE_CXXFLAGS_RELEASE -= -O2
QMAKE_CXXFLAGS_RELEASE += -Os

CLIENT_DIR = $$PWD/../../../client
INCLUDEPATH += $$CLIENT_DIR $$PWD/../../src
LIBS += $$CLIENT_DIR/libncfg_client.a
# Relink when the client changes. Without it `make` here considers the probe
# up to date after the library is rebuilt, so the test runs against the old C
# client and passes or fails for reasons that are no longer in the tree --
# which cost one debugging round on the day this was written.
PRE_TARGETDEPS += $$CLIENT_DIR/libncfg_client.a

SOURCES += live_dns.cpp ../../src/ncfg_connection.cpp \
	../../src/dns_view.cpp
HEADERS += ../../src/ncfg_connection.h ../../src/dns_view.h
