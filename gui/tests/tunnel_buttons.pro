# gui/tests/tunnel_buttons.pro -- the devices view brings an IPsec tunnel up.
#
# Its own project rather than a case inside netcfgd-gui, for the reason
# access_frame.pro gives: a plain `make` in gui/ must not compile a test.

TEMPLATE = app
TARGET = tunnel_buttons
QT += widgets
CONFIG += c++17 console
CONFIG -= app_bundle

# Matching gui.pro, so the probe compiles the view the way it ships.
QMAKE_CXXFLAGS_RELEASE -= -O2
QMAKE_CXXFLAGS_RELEASE += -Os

CLIENT_DIR = $$PWD/../../client
INCLUDEPATH += $$CLIENT_DIR $$PWD/../src
LIBS += $$CLIENT_DIR/libncfg_client.a
# Relink when the client changes, as device_load.pro says why.
PRE_TARGETDEPS += $$CLIENT_DIR/libncfg_client.a

# Every window source but main, as fleet_tab.pro takes them: the devices
# view opens the device dialog, which reaches most of the rest.
WINDOW_SOURCES = $$files($$PWD/../src/*.cpp)
WINDOW_SOURCES -= $$PWD/../src/main.cpp
SOURCES += tunnel_buttons.cpp $$WINDOW_SOURCES
HEADERS += $$files($$PWD/../src/*.h)

# The C daemon that ships (0266), started for real: the request crosses the
# socket and the daemon judges it against the document.
DEFINES += NETCFGD_BINARY=\\\"$$PWD/../../c/netcfgd\\\"
