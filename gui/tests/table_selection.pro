# gui/tests/table_selection.pro -- the table's selection across a refresh (10.802).
#
# Its own project, as access_frame.pro is, and for the same reason: a plain
# `make` in gui/ must not build a test.

TEMPLATE = app
TARGET = table_selection
QT += widgets
CONFIG += c++17 console
CONFIG -= app_bundle

# Matching gui.pro, so the probe compiles the code the way it ships.
QMAKE_CXXFLAGS_RELEASE -= -O2
QMAKE_CXXFLAGS_RELEASE += -Os

INCLUDEPATH += $$PWD/../src

SOURCES += table_selection.cpp ../src/table_view.cpp
HEADERS += ../src/table_view.h
