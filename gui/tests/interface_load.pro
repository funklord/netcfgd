# gui/tests/interface_load.pro -- the interface dialog must load what it edits.
#
# Its own project rather than a case inside netcfgd-gui, for the reason
# access_frame.pro gives: a plain `make` in gui/ must not compile a test.

TEMPLATE = app
TARGET = interface_load
QT += widgets
CONFIG += c++17 console
CONFIG -= app_bundle

# Matching gui.pro, so the probe compiles the view the way it ships.
QMAKE_CXXFLAGS_RELEASE -= -O2
QMAKE_CXXFLAGS_RELEASE += -Os

CLIENT_DIR = $$PWD/../../client
INCLUDEPATH += $$CLIENT_DIR $$PWD/../src
LIBS += $$CLIENT_DIR/libncfg_client.a

# The probe dialog comes along because the interface dialog constructs one for
# its `edit`/`new` buttons; linking without it fails on the vtable.
SOURCES += interface_load.cpp ../src/interface_dialog.cpp ../src/probe_dialog.cpp \
	../src/ncfg_connection.cpp
HEADERS += ../src/interface_dialog.h ../src/probe_dialog.h ../src/ncfg_connection.h

# The daemon this drives, by absolute path: the test starts a real one, because
# the configuration has to come from somewhere and the socket round trip is the
# thing under test.
DEFINES += NETCFGD_BINARY=\\\"$$PWD/../../target/debug/netcfgd\\\"
