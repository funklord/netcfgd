# =============================================================================
# adapter/netcfgd-nm/c/Makefile
#
# PURPOSE
#   The C port of the NetworkManager shim, over `libdbus-1` -- decision 0264's
#   answer, written once the dependency order it named was satisfied (project.md
#   10.384).
#
#   **This is the shim.** It was built beside the Rust one, mirroring the
#   daemon's own arrangement -- `crates/` and `c/` at the top level,
#   `netcfgd-nm/` and `netcfgd-nm/c/` here -- on the condition that the Rust
#   went on shipping until this passed `tests/live/nm.sh`, 0264's acceptance
#   test. That test passed on 2026-10-20 at 124 checks of 124, with the whole
#   guest tier at 214 of 214 and seven scripts of seven, and the copyright
#   holder retired the Rust the next day (0276, project.md 10.503 and 10.504).
#
#   The directory is still `netcfgd-nm/c/` rather than `netcfgd-nm/`, because
#   moving it would rewrite every path in the gates, the live scripts and the
#   records that cite them for no gain a reader can use. The adapter has one
#   implementation and this is it.
#
# TARGETS
#   make            -- the program
#   make test       -- build and run the checks
#   make clean      -- what this build produced, by name
#   make DEBUG=1    -- unoptimized and symbol-rich (-Og -g)
#   make SANITIZE=1 -- ASan and UBSan, independent of DEBUG
# =============================================================================

CC ?= gcc

PROGRAM = netcfgd-nm
SRCS    = src/bus.c src/block.c src/uuid.c src/compat.c src/state.c src/manager.c src/store.c src/device.c src/subtypes.c src/emit.c src/settings.c src/authorize.c src/ipconfig.c src/active.c src/accesspoint.c src/agent.c
OBJS    = $(SRCS:.c=.o)
DEPS    = $(SRCS:.c=.d) src/main.d tests/bus_test.d

# The client's floor, name for name, so moving between these directories costs
# nothing.
WARNINGS = -Wall -Wextra -Wshadow -Wconversion -Wsign-conversion -Wvla \
	   -Wpointer-arith -Wwrite-strings -Wstrict-prototypes
CFLAGS  ?= -std=c11 -Os
# The client library netcfgd already has in C, which is why there is no
# `client.c` here: `state.c` links what `ncfg` links.
CLIENT  = ../../../client
CFLAGS  += $(WARNINGS) -D_DEFAULT_SOURCE -Iinclude -I$(CLIENT) \
	   $(shell pkg-config --cflags dbus-1)
LDLIBS  += $(CLIENT)/libncfg_client.a $(shell pkg-config --libs dbus-1)

ifdef DEBUG
CFLAGS := $(filter-out -Os,$(CFLAGS)) -Og -g
endif

ifdef SANITIZE
CFLAGS  += -fsanitize=address,undefined -fno-omit-frame-pointer
LDFLAGS += -fsanitize=address,undefined
endif

.PHONY: all test clean

all: $(PROGRAM)

%.o: %.c
	$(CC) $(CFLAGS) -MMD -MP -c $< -o $@

# **Built here rather than trusted**, which is the root Makefile's rule for
# every gate: what is sitting in `client/` depends on the last build.
.PHONY: client
client:
	@$(MAKE) --no-print-directory -C $(CLIENT)

$(PROGRAM): src/main.o $(OBJS) client
	$(CC) $(CFLAGS) src/main.o $(OBJS) $(LDFLAGS) $(LDLIBS) -o $@

# The dispatcher against its own tables, with no bus: introspection is a pure
# function of the tables and is the half that can be checked without one.
test: tests/bus_test
	./tests/bus_test

tests/bus_test: tests/bus_test.o $(OBJS) client
	$(CC) $(CFLAGS) tests/bus_test.o $(OBJS) $(LDFLAGS) $(LDLIBS) -o $@

clean:
	rm -f $(PROGRAM) tests/bus_test src/main.o tests/bus_test.o $(OBJS) $(DEPS)
	@echo "clean: removed $(PROGRAM), tests/bus_test, their objects and the .d beside each"

-include $(DEPS)
