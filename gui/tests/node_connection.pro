# gui/tests/node_connection.pro -- a connection to another node of the estate.
#
# Its own project, as the other probes here are, so a plain `make` in gui/ does
# not build a test.

TEMPLATE = app
TARGET = node_connection
QT += widgets
CONFIG += c++17 console
CONFIG -= app_bundle

QMAKE_CXXFLAGS_RELEASE -= -O2
QMAKE_CXXFLAGS_RELEASE += -Os

CLIENT_DIR = $$PWD/../../client
INCLUDEPATH += $$CLIENT_DIR $$PWD/../src
LIBS += $$CLIENT_DIR/libncfg_client.a
PRE_TARGETDEPS += $$CLIENT_DIR/libncfg_client.a

SOURCES += node_connection.cpp ../src/ncfg_connection.cpp ../src/events_view.cpp \
           ../src/monitor_stream.cpp
HEADERS += ../src/ncfg_connection.h ../src/events_view.h ../src/monitor_stream.h
