# gui/tests/access_frame.pro -- the headless render probe for 0118's red frame.
#
# Its own project rather than a case inside netcfgd-gui, because
# build-and-commit.md wants tests built by the test target and only by it: a
# plain `make` in gui/ must not compile this.

TEMPLATE = app
TARGET = access_frame
QT += widgets
CONFIG += c++17 console
CONFIG -= app_bundle

# Matching gui.pro, so the probe compiles the views the way they ship.
QMAKE_CXXFLAGS_RELEASE -= -O2
QMAKE_CXXFLAGS_RELEASE += -Os

CLIENT_DIR = $$PWD/../../client
INCLUDEPATH += $$CLIENT_DIR $$PWD/../src
LIBS += $$CLIENT_DIR/libncfg_client.a

SOURCES += access_frame.cpp ../src/access_view.cpp ../src/ncfg_connection.cpp
HEADERS += ../src/access_view.h ../src/ncfg_connection.h
