# gui/tests/node_menu.pro -- the window's node box (project.md 10.699).
#
# The whole window, so every source of it, and none of `main.cpp`: taken with
# `files()` rather than listed, so the probe builds what the window is made of
# rather than a second copy of gui.pro's list to keep in step.

TEMPLATE = app
TARGET = node_menu
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
SOURCES += node_menu.cpp $$WINDOW_SOURCES
HEADERS += $$files($$PWD/../src/*.h)
