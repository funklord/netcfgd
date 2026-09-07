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

# =============================================================================
# qtty -- the same widgets, rendered on a character-cell terminal.
#
# qtty's premise is that an unmodified Qt Widgets application runs on a
# terminal: one QWidget codebase, no parallel view layer. So netcfgd's TUI is
# not a second program with a second idea of what a device list looks like --
# it is these files, and a `--tui` flag. That is the whole reason to use it,
# and the reason the sources below are not duplicated.
#
# **Optional, and detected rather than required.** qtty is pre-alpha and says
# so ("expect API movement"), and `gui/` has to keep building on a machine
# that has never heard of it. Absent, this file is exactly what it was and
# `--tui` is not offered; present, one binary does both. Same shape as `deny`
# and `gui` skipping in `make check` when their tool is missing -- a gate that
# demands a tool nobody has is a gate people delete.
#
# QTTY_ROOT may be passed in; otherwise a sibling checkout is looked for. The
# library is *not* vendored, which is a departure from harmonization.md's soft
# default and is recorded in gui/project.md rather than left to be noticed:
# pinning a pre-alpha API in a submodule buys a bump every time it moves, and
# netcfgd's GUI is not in the root build yet either.
isEmpty(QTTY_ROOT): QTTY_ROOT = $$PWD/../../qtty
exists($$QTTY_ROOT/qtty.pri) {
	isEmpty(QTTY_LIB_DIR): QTTY_LIB_DIR = $$QTTY_ROOT/build/lib
	exists($$QTTY_LIB_DIR/libqtty.a) {
		include($$QTTY_ROOT/qtty.pri)
		DEFINES += NETCFGD_QTTY
		LIBS += -L$$QTTY_LIB_DIR -lqtty
		PRE_TARGETDEPS += $$QTTY_LIB_DIR/libqtty.a
		message("gui: qtty found, --tui is available")
	} else {
		message("gui: qtty checkout has no built libqtty.a; --tui unavailable")
	}
}

SOURCES += \
	src/access_view.cpp \
	src/dns_view.cpp \
	src/network_dialog.cpp \
	src/interface_dialog.cpp \
	src/probe_dialog.cpp \
	src/add_network_dialog.cpp \
	src/apply_dialog.cpp \
	src/devices_view.cpp \
	src/global_view.cpp \
	src/modems_view.cpp \
	src/table_view.cpp \
	src/secrets_view.cpp \
	src/profiles_view.cpp \
	src/rules_view.cpp \
	src/bluetooth_view.cpp \
	src/hooks_view.cpp \
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
	src/interface_dialog.h \
	src/probe_dialog.h \
	src/add_network_dialog.h \
	src/apply_dialog.h \
	src/devices_view.h \
	src/global_view.h \
	src/modems_view.h \
	src/table_view.h \
	src/secrets_view.h \
	src/profiles_view.h \
	src/rules_view.h \
	src/bluetooth_view.h \
	src/hooks_view.h \
	src/events_view.h \
	src/main_window.h \
	src/monitor_stream.h \
	src/ncfg_connection.h \
	src/plan_view.h \
	src/tray.h \
	src/wifi_view.h
