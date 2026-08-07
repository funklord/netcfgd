# gui/tests/tray_icon.pro -- the headless render probe for the tray indicator.
#
# Its own project, as access_frame.pro is, and for the same reason: a plain
# `make` in gui/ must not build a test.

TEMPLATE = app
TARGET = tray_icon
QT += widgets
CONFIG += c++17 console
CONFIG -= app_bundle

# Matching gui.pro, so the probe compiles the code the way it ships.
QMAKE_CXXFLAGS_RELEASE -= -O2
QMAKE_CXXFLAGS_RELEASE += -Os

CLIENT_DIR = $$PWD/../../client
INCLUDEPATH += $$CLIENT_DIR $$PWD/../src
LIBS += $$CLIENT_DIR/libncfg_client.a

SOURCES += tray_icon.cpp ../src/tray.cpp ../src/ncfg_connection.cpp
HEADERS += ../src/tray.h ../src/ncfg_connection.h
