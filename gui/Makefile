# =============================================================================
# gui/Makefile
#
# PURPOSE
#   Builds netcfgd-gui, the Qt Widgets client. Self-contained: `cd gui && make`
#   builds client/libncfg_client.a first if it is not there, then hands the
#   actual compilation to qmake6 in an out-of-source build/ directory.
#
#   The delegation is the same one fuzzypickles/gui makes, for the same reason:
#   Qt's moc step does not fit a plain pattern rule the way the C sub-projects
#   here do, and qmake already solves it correctly. This file is the outer
#   wrapper that the C directories get from their own Makefiles.
#
# TARGETS
#   make            -- build build/netcfgd-gui
#   make run        -- build and run it
#   make clean      -- the build directory and the client library's objects
#
# BUILD FLAGS
#   DEBUG and SANITIZE are threaded into the client library, which is where the
#   code this project owns mostly lives. qmake's own debug/release split does
#   not map onto them one for one, so the handling is best-effort on this side
#   and exact on the other -- the same compromise the sibling documents.
# =============================================================================

QMAKE ?= qmake6
CC ?= gcc

CLIENT_DIR = ../client
CLIENT_LIB = $(CLIENT_DIR)/libncfg_client.a
BUILD_DIR ?= build
TARGET = $(BUILD_DIR)/netcfgd-gui

.PHONY: all run clean $(CLIENT_LIB)

all: $(TARGET)

# Always asked, never assumed: the client library is a sibling under active
# development, and a stale .a is a debugging session nobody enjoys.
$(CLIENT_LIB):
	$(MAKE) -C $(CLIENT_DIR) DEBUG=$(DEBUG) SANITIZE=$(SANITIZE)

$(TARGET): $(CLIENT_LIB) gui.pro $(wildcard src/*.cpp src/*.h)
	@mkdir -p $(BUILD_DIR)
	cd $(BUILD_DIR) && $(QMAKE) ../gui.pro
	$(MAKE) -C $(BUILD_DIR)

run: $(TARGET)
	./$(TARGET)

clean:
	rm -rf $(BUILD_DIR)
	$(MAKE) -C $(CLIENT_DIR) clean
