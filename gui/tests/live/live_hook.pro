# gui/tests/live/live_hook.pro -- hooks through the interface editor.
#
# In `gui/tests/live/` rather than beside the headless probes, for the reason
# live_network_dialog.pro gives: `make -C gui test` globs `tests/*.pro` and
# would run this with no daemon to talk to.

TEMPLATE = app
TARGET = live_hook
QT += widgets
CONFIG += c++17 console
CONFIG -= app_bundle

QMAKE_CXXFLAGS_RELEASE -= -O2
QMAKE_CXXFLAGS_RELEASE += -Os

CLIENT_DIR = $$PWD/../../../client
INCLUDEPATH += $$CLIENT_DIR $$PWD/../../src
LIBS += $$CLIENT_DIR/libncfg_client.a
# Relink when the client changes, for the reason the network dialog's project
# records: without it the probe runs against the old C client.
PRE_TARGETDEPS += $$CLIENT_DIR/libncfg_client.a

SOURCES += live_hook.cpp ../../src/ncfg_connection.cpp ../../src/hook_dialog.cpp \
	../../src/interface_dialog.cpp ../../src/probe_dialog.cpp
HEADERS += ../../src/ncfg_connection.h ../../src/hook_dialog.h \
	../../src/interface_dialog.h ../../src/probe_dialog.h
