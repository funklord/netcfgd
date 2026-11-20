# gui/tests/about_menu.pro -- Help, About, and a name for the unlabelled box
# (project.md 10.883). The whole window, as fleet_tab.pro builds it.

TEMPLATE = app
TARGET = about_menu
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
SOURCES += about_menu.cpp $$WINDOW_SOURCES
HEADERS += $$files($$PWD/../src/*.h)
