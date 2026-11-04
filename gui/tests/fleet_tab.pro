# gui/tests/fleet_tab.pro -- every node at once (project.md 10.710).
#
# The whole window, so every source of it, and none of `main.cpp`: taken with
# `files()` rather than listed, so the probe builds what the window is made of
# rather than a second copy of gui.pro's list to keep in step.

TEMPLATE = app
TARGET = fleet_tab
QT += widgets
CONFIG += c++17 console
CONFIG -= app_bundle

QMAKE_CXXFLAGS_RELEASE -= -O2
QMAKE_CXXFLAGS_RELEASE += -Os

CLIENT_DIR = $$PWD/../../client
INCLUDEPATH += $$CLIENT_DIR $$PWD/../src
LIBS += $$CLIENT_DIR/libncfg_client.a
PRE_TARGETDEPS += $$CLIENT_DIR/libncfg_client.a

WINDOW_SOURCES = $$files($$PWD/../src/*.cpp)
WINDOW_SOURCES -= $$PWD/../src/main.cpp
SOURCES += fleet_tab.cpp $$WINDOW_SOURCES
HEADERS += $$files($$PWD/../src/*.h)
