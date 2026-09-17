# gui/tests/rule_block.pro -- the `rule` block the editor writes.
#
# Its own project, as the other block probes are, so a plain `make` in gui/
# does not build a test.

TEMPLATE = app
TARGET = rule_block
QT += widgets
CONFIG += c++17 console
CONFIG -= app_bundle

QMAKE_CXXFLAGS_RELEASE -= -O2
QMAKE_CXXFLAGS_RELEASE += -Os

CLIENT_DIR = $$PWD/../../client
INCLUDEPATH += $$CLIENT_DIR $$PWD/../src
LIBS += $$CLIENT_DIR/libncfg_client.a
PRE_TARGETDEPS += $$CLIENT_DIR/libncfg_client.a

SOURCES += rule_block.cpp ../src/rule_dialog.cpp ../src/ncfg_connection.cpp
HEADERS += ../src/rule_dialog.h ../src/ncfg_connection.h
