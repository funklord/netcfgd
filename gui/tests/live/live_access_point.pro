# gui/tests/live/live_access_point.pro -- the access point editor, live.
#
# In `gui/tests/live/` rather than beside the headless probes, for the reason
# live_network_dialog.pro gives: `make -C gui test` globs `tests/*.pro` and
# would run this with no daemon to talk to.

TEMPLATE = app
TARGET = live_access_point
QT += widgets
CONFIG += c++17 console
CONFIG -= app_bundle

QMAKE_CXXFLAGS_RELEASE -= -O2
QMAKE_CXXFLAGS_RELEASE += -Os

CLIENT_DIR = $$PWD/../../../client
INCLUDEPATH += $$CLIENT_DIR $$PWD/../../src
LIBS += $$CLIENT_DIR/libncfg_client.a
PRE_TARGETDEPS += $$CLIENT_DIR/libncfg_client.a

SOURCES += live_access_point.cpp ../../src/ncfg_connection.cpp \
	../../src/access_point_dialog.cpp
HEADERS += ../../src/ncfg_connection.h ../../src/access_point_dialog.h
