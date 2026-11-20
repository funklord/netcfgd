# qtkit for a qmake consumer: include(path/to/qtkit/qtkit.pri) and qtkit's
# sources are compiled into the application.
#
# Compiled in rather than linked, as softkeys is: a consumer builds it with
# its own flags and its own Qt anyway, and its --gc-sections drops whatever
# of qtkit it does not call.
#
# The portal is asked only where the consumer links QtDBus: say QT += dbus
# BEFORE the include, or this sees no dbus and leaves the portal out.

QTKIT_ROOT = $$PWD

QT += widgets
CONFIG += c++17
INCLUDEPATH += $$QTKIT_ROOT/include
contains(QT, dbus) {
	DEFINES += QTKIT_HAVE_DBUS
	HEADERS += $$QTKIT_ROOT/src/portal_listener.h
}

SOURCES += \
	$$QTKIT_ROOT/src/flow_layout.cpp \
	$$QTKIT_ROOT/src/theme.cpp

HEADERS += \
	$$QTKIT_ROOT/include/qtkit/flow_layout.h \
	$$QTKIT_ROOT/include/qtkit/theme.h
