# gui/tests/reconnect.pro -- a client whose daemon was restarted underneath it.
#
# Its own project, as the other probes here are, so a plain `make` in gui/ does
# not build a test.

TEMPLATE = app
TARGET = reconnect
QT += widgets
CONFIG += c++17 console
CONFIG -= app_bundle

QMAKE_CXXFLAGS_RELEASE -= -O2
QMAKE_CXXFLAGS_RELEASE += -Os

CLIENT_DIR = $$PWD/../../client
INCLUDEPATH += $$CLIENT_DIR $$PWD/../src
LIBS += $$CLIENT_DIR/libncfg_client.a
PRE_TARGETDEPS += $$CLIENT_DIR/libncfg_client.a

SOURCES += reconnect.cpp ../src/ncfg_connection.cpp
HEADERS += ../src/ncfg_connection.h

# The daemon this drives, by absolute path: it has to be restarted for the
# property under test to exist at all.
DEFINES += NETCFGD_BINARY=\\\"$$PWD/../../target/debug/netcfgd\\\"
