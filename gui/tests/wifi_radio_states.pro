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
# Relink when the client changes. Without it `make` here considers the probe up
# to date after the library is rebuilt, so the test runs against the old C
# client and passes or fails for reasons that are no longer in the tree -- which
# the live probes' projects already record, and which cost a debugging round
# here too.
PRE_TARGETDEPS += $$CLIENT_DIR/libncfg_client.a

SOURCES += wifi_radio_states.cpp ../src/ncfg_connection.cpp
HEADERS += ../src/ncfg_connection.h
