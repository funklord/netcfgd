# gui/tests/access_policy.pro -- the access tab must load the policy it edits.
#
# Its own project rather than a case inside netcfgd-gui, for the reason
# access_frame.pro gives: a plain `make` in gui/ must not compile a test.

TEMPLATE = app
TARGET = access_policy
QT += widgets
CONFIG += c++17 console
CONFIG -= app_bundle

# Matching gui.pro, so the probe compiles the view the way it ships.
QMAKE_CXXFLAGS_RELEASE -= -O2
QMAKE_CXXFLAGS_RELEASE += -Os

CLIENT_DIR = $$PWD/../../client
INCLUDEPATH += $$CLIENT_DIR $$PWD/../src
LIBS += $$CLIENT_DIR/libncfg_client.a

SOURCES += access_policy.cpp ../src/access_view.cpp ../src/ncfg_connection.cpp
HEADERS += ../src/access_view.h ../src/ncfg_connection.h

# The daemon this drives, by absolute path: the test starts a real one, because
# the policy has to come from somewhere and the socket round trip is the thing
# under test.
DEFINES += NETCFGD_BINARY=\\\"$$PWD/../../target/debug/netcfgd\\\"
