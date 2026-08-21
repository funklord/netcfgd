# gui/tests/wifi_radio_states.pro -- the wifi view's radio activation.
#
# Its own project rather than a case inside netcfgd-gui, because
# build-and-commit.md wants tests built by the test target and only by it.

TEMPLATE = app
TARGET = wifi_radio_states
QT += widgets
CONFIG += c++17 console
CONFIG -= app_bundle

QMAKE_CXXFLAGS_RELEASE -= -O2
QMAKE_CXXFLAGS_RELEASE += -Os

CLIENT_DIR = $$PWD/../../client
INCLUDEPATH += $$CLIENT_DIR $$PWD/../src
LIBS += $$CLIENT_DIR/libncfg_client.a

SOURCES += wifi_radio_states.cpp ../src/ncfg_connection.cpp
HEADERS += ../src/ncfg_connection.h
