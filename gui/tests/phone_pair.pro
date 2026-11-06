# gui/tests/phone_pair.pro -- the phone's first screen (project.md 10.720).
#
# Its sources are named, since `gui/src/phone/` is Android's and no other probe
# takes it. qr.c is fuzznet's encoder, so what is read back is what a host draws.

TEMPLATE = app
TARGET = phone_pair
QT += widgets
CONFIG += c++17 console
CONFIG -= app_bundle

QMAKE_CXXFLAGS_RELEASE -= -O2
QMAKE_CXXFLAGS_RELEASE += -Os

CLIENT_DIR = $$PWD/../../client
FUZZNET = $$PWD/../../fuzznet
QUIRC = $$FUZZNET/quirc/lib
INCLUDEPATH += $$CLIENT_DIR $$PWD/../src/phone $$QUIRC $$FUZZNET/qr
LIBS += $$CLIENT_DIR/libncfg_client.a -lm
PRE_TARGETDEPS += $$CLIENT_DIR/libncfg_client.a

SOURCES += phone_pair.cpp ../src/pair_code.cpp \
	../src/phone/phone_host.cpp ../src/phone/code_reader.cpp ../src/phone/pair_view.cpp ../src/layout.cpp \
	$$QUIRC/quirc.c $$QUIRC/decode.c $$QUIRC/identify.c $$QUIRC/version_db.c \
	$$FUZZNET/qr/qr.c
HEADERS += ../src/phone/phone_host.h ../src/phone/code_reader.h ../src/phone/pair_view.h ../src/layout.h
