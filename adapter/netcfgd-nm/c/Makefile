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

.PHONY: all test clean fuzz fuzz-list fuzz-replay

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
test: tests/bus_test fuzz-replay
	./tests/bus_test

tests/bus_test: tests/bus_test.o $(OBJS) client
	$(CC) $(CFLAGS) tests/bus_test.o $(OBJS) $(LDFLAGS) $(LDLIBS) -o $@

# ---------------------------------------------------------------- fuzzing
#
# One target: the settings dictionary a client sends to `AddConnection`. The
# arrangement is 0277's and the drivers are shared rather than copied --
# `fuzz.h`, the libFuzzer shim and the replay walker all live in the daemon's
# `c/fuzz/`, which this build already reaches the way it reaches `client/`.
#
# `fuzz/dictionary.c` says why the whole marshalled message is the input and
# what it costs; `fuzz/make_seeds.c` is how the corpus was produced and is
# where to add the next shape.
FUZZ_SHARED_DIR = ../../../c/fuzz
FUZZ_TARGETS    = dictionary settings names
FUZZ_REPLAYS    = $(addprefix fuzz/,$(addsuffix _replay,$(FUZZ_TARGETS)))
FUZZ_PROGRAMS   = $(addprefix fuzz/,$(addsuffix _fuzz,$(FUZZ_TARGETS)))
FUZZ_BUILD_DIR ?= fuzz/build
FUZZ_CC        ?= clang
FUZZ_CFLAGS    ?= -std=c11 -O1 -g
FUZZ_CFLAGS    += $(WARNINGS) -Ifuzz -D_DEFAULT_SOURCE -Iinclude -I$(CLIENT) -I$(FUZZ_SHARED_DIR) \
		  $(shell pkg-config --cflags dbus-1) \
		  -fsanitize=fuzzer-no-link,address,undefined -fno-omit-frame-pointer
FUZZ_OBJS       = $(patsubst %.c,$(FUZZ_BUILD_DIR)/%.o,$(SRCS))

# The deterministic half, in `test` for 0277's reason: a fuzzer explores and
# does not remember, so the corpus is what a regression is caught by.
fuzz-replay: $(FUZZ_REPLAYS)
	@fail=0; \
	for one in $(FUZZ_TARGETS); do \
		files=$$(find fuzz/corpus/$$one -type f 2>/dev/null | sort); \
		if [ -z "$$files" ]; then \
			echo "fuzz-replay: fuzz/corpus/$$one holds no inputs, so this"; \
			echo "fuzz-replay:   target would report success having read none"; \
			fail=1; \
			continue; \
		fi; \
		./fuzz/$${one}_replay $$files || fail=1; \
	done; \
	[ $$fail -eq 0 ] || { echo "fuzz-replay: some inputs failed"; exit 1; }

fuzz/%_replay: fuzz/%.c fuzz/shape.c $(FUZZ_SHARED_DIR)/fuzz_replay.c \
		$(FUZZ_SHARED_DIR)/fuzz_text.c $(OBJS) client
	$(CC) $(CFLAGS) -Ifuzz -I$(FUZZ_SHARED_DIR) $(filter %.c,$^) $(OBJS) $(LDFLAGS) $(LDLIBS) -o $@

fuzz: $(FUZZ_PROGRAMS)

fuzz-list:
	@echo $(FUZZ_TARGETS)

# The seed generator, which needs libdbus and nothing of this program. Its
# output is committed; this is here so the next shape can be added to it.
fuzz/make_seeds: fuzz/make_seeds.c
	$(CC) $(CFLAGS) $< $(shell pkg-config --libs dbus-1) -o $@

$(FUZZ_BUILD_DIR)/%.o: %.c
	@mkdir -p $(dir $@)
	$(FUZZ_CC) $(FUZZ_CFLAGS) -c $< -o $@

fuzz/%_fuzz: fuzz/%.c fuzz/shape.c $(FUZZ_SHARED_DIR)/fuzz_libfuzzer.c \
		$(FUZZ_SHARED_DIR)/fuzz_text.c $(FUZZ_OBJS) client
	$(FUZZ_CC) $(FUZZ_CFLAGS) -fsanitize=fuzzer $(filter %.c,$^) $(FUZZ_OBJS) \
	    $(CLIENT)/libncfg_client.a $(shell pkg-config --libs dbus-1) -o $@

clean:
	rm -f $(PROGRAM) tests/bus_test src/main.o tests/bus_test.o $(OBJS) $(DEPS) \
	    $(FUZZ_REPLAYS) $(FUZZ_PROGRAMS) fuzz/make_seeds $(addsuffix .d,$(FUZZ_REPLAYS))
	@echo "clean: removed $(PROGRAM), tests/bus_test, their objects and the .d beside each"
	@# The one directory cleared wholesale, and only because this build made
	@# it. Guarded as `build-and-commit.md` requires: non-empty, relative, and
	@# not a path that could resolve to a source tree.
	@case "$(FUZZ_BUILD_DIR)" in \
	"") echo "clean: FUZZ_BUILD_DIR is empty, refusing to remove anything"; exit 1 ;; \
	/*) echo "clean: FUZZ_BUILD_DIR is absolute ($(FUZZ_BUILD_DIR)), refusing"; exit 1 ;; \
	*..*) echo "clean: FUZZ_BUILD_DIR escapes the tree, refusing"; exit 1 ;; \
	esac; \
	if [ -d "$(FUZZ_BUILD_DIR)" ]; then \
		echo "clean: removing $(FUZZ_BUILD_DIR)"; \
		rm -rf "$(FUZZ_BUILD_DIR)"; \
	fi

-include $(DEPS)
