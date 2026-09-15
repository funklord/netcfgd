# gui/tests/link_filter.pro -- the links tab's category filter.
#
# Its own project, as tray_icon.pro is, and for the same reason: a plain
# `make` in gui/ must not build a test.

TEMPLATE = app
TARGET = link_filter
QT += widgets
CONFIG += c++17 console
CONFIG -= app_bundle

QMAKE_CXXFLAGS_RELEASE -= -O2
QMAKE_CXXFLAGS_RELEASE += -Os

CLIENT_DIR = $$PWD/../../client
INCLUDEPATH += $$CLIENT_DIR $$PWD/../src
LIBS += $$CLIENT_DIR/libncfg_client.a

SOURCES += link_filter.cpp ../src/ncfg_connection.cpp
HEADERS += ../src/ncfg_connection.h
