# gui/tests/live/live_secrets.pro -- the secrets tab against a real daemon.
#
# Beside the other live probes for the reason live_dns.pro records: `make -C
# gui test` globs `tests/*.pro`, so a probe that needs a daemon must live one
# directory down or it is run without one and fails at "can reach netcfgd".
# `tests/live/gui_wifi.sh` finds every .pro here and runs it.

TEMPLATE = app
TARGET = live_secrets
QT += widgets
CONFIG += c++17 console
CONFIG -= app_bundle

QMAKE_CXXFLAGS_RELEASE -= -O2
QMAKE_CXXFLAGS_RELEASE += -Os

CLIENT_DIR = $$PWD/../../../client
INCLUDEPATH += $$CLIENT_DIR $$PWD/../../src
LIBS += $$CLIENT_DIR/libncfg_client.a
PRE_TARGETDEPS += $$CLIENT_DIR/libncfg_client.a

SOURCES += live_secrets.cpp ../../src/ncfg_connection.cpp \
	../../src/secrets_view.cpp ../../src/table_view.cpp
HEADERS += ../../src/ncfg_connection.h ../../src/secrets_view.h \
	../../src/table_view.h
