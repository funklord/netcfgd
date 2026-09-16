# gui/tests/device_block.pro -- the `device` block the hardware editor writes.
#
# Its own project, as linkset_block.pro is, and for the same reason: a plain
# `make` in gui/ must not build a test.

TEMPLATE = app
TARGET = device_block
QT += widgets
CONFIG += c++17 console
CONFIG -= app_bundle

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

SOURCES += device_block.cpp ../src/device_dialog.cpp ../src/ncfg_connection.cpp
HEADERS += ../src/device_dialog.h ../src/ncfg_connection.h
