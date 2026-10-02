# =============================================================================
# adapter/netcfgd-nm/c/Makefile
#
# PURPOSE
#   The C port of the NetworkManager shim, over `libdbus-1` -- decision 0264's
#   answer, written once the dependency order it named was satisfied (project.md
#   10.353).
#
#   Beside the Rust rather than replacing it, which mirrors the daemon's own
#   arrangement: `crates/` and `c/` at the top level, `netcfgd-nm/` and
#   `netcfgd-nm/c/` here. The Rust goes on shipping until this passes
#   `tests/live/nm.sh`, which is 0264's acceptance test and is the holder's call
#   to act on.
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
SRCS    = src/bus.c src/compat.c
OBJS    = $(SRCS:.c=.o)
DEPS    = $(SRCS:.c=.d) src/main.d tests/bus_test.d

# The client's floor, name for name, so moving between these directories costs
# nothing.
WARNINGS = -Wall -Wextra -Wshadow -Wconversion -Wsign-conversion -Wvla \
	   -Wpointer-arith -Wwrite-strings -Wstrict-prototypes
CFLAGS  ?= -std=c11 -Os
CFLAGS  += $(WARNINGS) -D_DEFAULT_SOURCE -Iinclude $(shell pkg-config --cflags dbus-1)
LDLIBS  += $(shell pkg-config --libs dbus-1)

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

$(PROGRAM): src/main.o $(OBJS)
	$(CC) $(CFLAGS) $^ $(LDFLAGS) $(LDLIBS) -o $@

# The dispatcher against its own tables, with no bus: introspection is a pure
# function of the tables and is the half that can be checked without one.
test: tests/bus_test
	./tests/bus_test

tests/bus_test: tests/bus_test.o $(OBJS)
	$(CC) $(CFLAGS) $^ $(LDFLAGS) $(LDLIBS) -o $@

clean:
	rm -f $(PROGRAM) tests/bus_test src/main.o tests/bus_test.o $(OBJS) $(DEPS)
	@echo "clean: removed $(PROGRAM), tests/bus_test, their objects and the .d beside each"

-include $(DEPS)
