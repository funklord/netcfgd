# gui/tests/live_wifi.pro -- the wifi view against a real daemon.
#
# In `gui/tests/live/` rather than beside the other probes, and the directory
# is the whole reason: `make -C gui test` globs `tests/*.pro` and runs whatever
# it finds, so a probe left there was picked up and run with no daemon -- which
# fails at "the view can reach netcfgd" and says nothing about the view. A
# subdirectory is the smallest thing that tells the glob apart from the live
# suite, which builds and runs this itself through `tests/live/gui_wifi.sh`.

TEMPLATE = app
TARGET = live_wifi
QT += widgets
CONFIG += c++17 console
CONFIG -= app_bundle

QMAKE_CXXFLAGS_RELEASE -= -O2
QMAKE_CXXFLAGS_RELEASE += -Os

CLIENT_DIR = $$PWD/../../../client
INCLUDEPATH += $$CLIENT_DIR $$PWD/../../src
LIBS += $$CLIENT_DIR/libncfg_client.a
# Relink when the client changes. Without it `make` here considers the probe
# up to date after the library is rebuilt, so the test runs against the old C
# client and passes or fails for reasons that are no longer in the tree --
# which cost one debugging round on the day this was written.
PRE_TARGETDEPS += $$CLIENT_DIR/libncfg_client.a

# `network_dialog` is here because `wifi_view` opens it: the saved-networks
# table's view/change button and the add-by-hand one both construct it, so the
# tab does not link without it. `access_point_dialog` joined the list for the
# same reason when the tab grew the third table -- and the failure is a
# link-time "undefined reference to vtable", which reads like a build problem
# rather than a missing source until you know.
SOURCES += live_wifi.cpp ../../src/ncfg_connection.cpp ../../src/wifi_view.cpp \
	../../src/add_network_dialog.cpp ../../src/network_dialog.cpp \
	../../src/access_point_dialog.cpp
HEADERS += ../../src/ncfg_connection.h ../../src/wifi_view.h \
	../../src/add_network_dialog.h ../../src/network_dialog.h \
	../../src/access_point_dialog.h
