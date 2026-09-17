# gui/tests/live/live_bluetooth.pro -- the device editor against a real daemon.
#
# In `gui/tests/live/` rather than beside the headless probes, for the reason
# live_network_dialog.pro gives: `make -C gui test` globs `tests/*.pro` and
# would run this with no daemon to talk to.

TEMPLATE = app
TARGET = live_bluetooth
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

SOURCES += live_bluetooth.cpp ../../src/ncfg_connection.cpp ../../src/bluetooth_dialog.cpp
HEADERS += ../../src/ncfg_connection.h ../../src/bluetooth_dialog.h
