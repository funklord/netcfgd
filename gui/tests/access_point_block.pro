# gui/tests/access_point_block.pro -- the `access_point` block the editor writes.
#
# Its own project, as device_block.pro is, and for the same reason: a plain
# `make` in gui/ must not build a test.

TEMPLATE = app
TARGET = access_point_block
QT += widgets
CONFIG += c++17 console
CONFIG -= app_bundle

QMAKE_CXXFLAGS_RELEASE -= -O2
QMAKE_CXXFLAGS_RELEASE += -Os

CLIENT_DIR = $$PWD/../../client
INCLUDEPATH += $$CLIENT_DIR $$PWD/../src
LIBS += $$CLIENT_DIR/libncfg_client.a
# Relink when the client changes, for the reason every other project here
# records: otherwise the probe runs against the old library.
PRE_TARGETDEPS += $$CLIENT_DIR/libncfg_client.a

SOURCES += access_point_block.cpp ../src/access_point_dialog.cpp ../src/ncfg_connection.cpp
HEADERS += ../src/access_point_dialog.h ../src/ncfg_connection.h
