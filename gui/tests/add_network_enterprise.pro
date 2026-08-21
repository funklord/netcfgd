# gui/tests/add_network_enterprise.pro -- the add dialog's 802.1X arm.
#
# Its own project rather than a case inside netcfgd-gui, because
# build-and-commit.md wants tests built by the test target and only by it: a
# plain `make` in gui/ must not compile this.

TEMPLATE = app
TARGET = add_network_enterprise
QT += widgets
CONFIG += c++17 console
CONFIG -= app_bundle

# Matching gui.pro, so the probe compiles the dialog the way it ships.
QMAKE_CXXFLAGS_RELEASE -= -O2
QMAKE_CXXFLAGS_RELEASE += -Os

CLIENT_DIR = $$PWD/../../client
INCLUDEPATH += $$CLIENT_DIR $$PWD/../src
LIBS += $$CLIENT_DIR/libncfg_client.a

SOURCES += add_network_enterprise.cpp ../src/add_network_dialog.cpp ../src/ncfg_connection.cpp
HEADERS += ../src/add_network_dialog.h ../src/ncfg_connection.h
