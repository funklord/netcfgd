# gui/tests/firewall_counts.pro -- the firewall tab's `matched` column (0337).
#
# Its own project rather than a case inside netcfgd-gui, for the reason
# access_frame.pro gives: a plain `make` in gui/ must not compile a test.

TEMPLATE = app
TARGET = firewall_counts
QT += widgets
CONFIG += c++17 console
CONFIG -= app_bundle

QMAKE_CXXFLAGS_RELEASE -= -O2
QMAKE_CXXFLAGS_RELEASE += -Os

CLIENT_DIR = $$PWD/../../client
INCLUDEPATH += $$CLIENT_DIR $$PWD/../src
LIBS += $$CLIENT_DIR/libncfg_client.a
# Relink when the client changes, as firewall_load.pro says why.
PRE_TARGETDEPS += $$CLIENT_DIR/libncfg_client.a

SOURCES += firewall_counts.cpp ../src/firewall_view.cpp ../src/firewall_dialog.cpp \
           ../src/table_view.cpp ../src/ncfg_connection.cpp
HEADERS += ../src/firewall_view.h ../src/firewall_dialog.h ../src/table_view.h \
           ../src/ncfg_connection.h

# The C daemon, which is the one that ships (0266), as firewall_load.pro has it.
DEFINES += NETCFGD_BINARY=\\\"$$PWD/../../c/netcfgd\\\"
