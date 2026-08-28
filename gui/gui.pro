# =============================================================================
# gui/gui.pro -- qmake project for netcfgd-gui, the Qt Widgets client.
#
# Per gui/project.md: this speaks netcfgd's own control socket through
# client/libncfg_client.a, the same bytes `ncfg` and the TUI speak -- not a
# bespoke shim, and not Qt's own socket classes, which would put the framing
# and the reader on this side of the seam where nothing else could reach them.
#
# No QtQuick and no QML, ever (gui/project.md sec 2, non-negotiable). Nothing
# below asks for either; this comment is the tripwire for the next person
# tempted to add `QT += quick`.
#
# Not wired into the repository's root Makefile yet -- deliberate, and the same
# call fuzzypickles/gui makes. Build standalone through gui/Makefile, which
# wraps this.
# =============================================================================

TEMPLATE = app
TARGET = netcfgd-gui

QT += widgets
CONFIG += c++17
CONFIG -= app_bundle

# -Os, because build-and-commit.md asks for it and says that in a Qt project
# file it means saying so rather than accepting the qmake default -- which is
# -O2, and was what this built at until somebody looked. Load-bearing: remove
# these two lines and qmake silently puts -O2 back.
QMAKE_CXXFLAGS_RELEASE -= -O2
QMAKE_CXXFLAGS_RELEASE += -Os

CLIENT_DIR = $$PWD/../client
CLIENT_LIB = $$CLIENT_DIR/libncfg_client.a

INCLUDEPATH += $$CLIENT_DIR
LIBS += $$CLIENT_LIB

# qmake will not build it -- PRE_TARGETDEPS only requires it to exist, and
# gui/Makefile is what builds it first.
PRE_TARGETDEPS += $$CLIENT_LIB

SOURCES += \
	src/access_view.cpp \
	src/dns_view.cpp \
	src/network_dialog.cpp \
	src/add_network_dialog.cpp \
	src/apply_dialog.cpp \
	src/devices_view.cpp \
	src/events_view.cpp \
	src/main.cpp \
	src/main_window.cpp \
	src/monitor_stream.cpp \
	src/ncfg_connection.cpp \
	src/plan_view.cpp \
	src/tray.cpp \
	src/wifi_view.cpp

HEADERS += \
	src/access_view.h \
	src/dns_view.h \
	src/network_dialog.h \
	src/add_network_dialog.h \
	src/apply_dialog.h \
	src/devices_view.h \
	src/events_view.h \
	src/main_window.h \
	src/monitor_stream.h \
	src/ncfg_connection.h \
	src/plan_view.h \
	src/tray.h \
	src/wifi_view.h
