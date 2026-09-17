# gui/tests/bluetooth_block.pro -- the `bluetooth` block the editor writes.
#
# Its own project, as the other block probes are, so a plain `make` in gui/
# does not build a test.

TEMPLATE = app
TARGET = bluetooth_block
QT += widgets
CONFIG += c++17 console
CONFIG -= app_bundle

QMAKE_CXXFLAGS_RELEASE -= -O2
QMAKE_CXXFLAGS_RELEASE += -Os

CLIENT_DIR = $$PWD/../../client
INCLUDEPATH += $$CLIENT_DIR $$PWD/../src
LIBS += $$CLIENT_DIR/libncfg_client.a
PRE_TARGETDEPS += $$CLIENT_DIR/libncfg_client.a

SOURCES += bluetooth_block.cpp ../src/bluetooth_dialog.cpp ../src/ncfg_connection.cpp
HEADERS += ../src/bluetooth_dialog.h ../src/ncfg_connection.h
