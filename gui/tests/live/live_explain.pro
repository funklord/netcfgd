# gui/tests/live/live_explain.pro -- the explanation dialog against a real daemon.
#
# One directory down from `gui/tests/`, for the reason live_dns.pro records:
# `make -C gui test` globs `tests/*.pro` and would run this without a daemon.
# `tests/live/gui_wifi.sh` finds every .pro here and runs it.

TEMPLATE = app
TARGET = live_explain
QT += widgets
CONFIG += c++17 console
CONFIG -= app_bundle

QMAKE_CXXFLAGS_RELEASE -= -O2
QMAKE_CXXFLAGS_RELEASE += -Os

CLIENT_DIR = $$PWD/../../../client
INCLUDEPATH += $$CLIENT_DIR $$PWD/../../src
LIBS += $$CLIENT_DIR/libncfg_client.a
PRE_TARGETDEPS += $$CLIENT_DIR/libncfg_client.a

SOURCES += live_explain.cpp ../../src/ncfg_connection.cpp \
	../../src/explain_dialog.cpp ../../src/table_view.cpp
HEADERS += ../../src/ncfg_connection.h ../../src/explain_dialog.h \
	../../src/table_view.h
