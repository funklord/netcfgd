# gui/tests/live/live_config.pro -- the files tab against a real daemon.
#
# One directory down from `gui/tests/`, for the reason live_dns.pro records:
# `make -C gui test` globs `tests/*.pro` and would run this without a daemon.

TEMPLATE = app
TARGET = live_config
QT += widgets
CONFIG += c++17 console
CONFIG -= app_bundle

QMAKE_CXXFLAGS_RELEASE -= -O2
QMAKE_CXXFLAGS_RELEASE += -Os

CLIENT_DIR = $$PWD/../../../client
INCLUDEPATH += $$CLIENT_DIR $$PWD/../../src
LIBS += $$CLIENT_DIR/libncfg_client.a
PRE_TARGETDEPS += $$CLIENT_DIR/libncfg_client.a

SOURCES += live_config.cpp ../../src/ncfg_connection.cpp \
	../../src/config_view.cpp ../../src/table_view.cpp
HEADERS += ../../src/ncfg_connection.h ../../src/config_view.h \
	../../src/table_view.h
