# =============================================================================
# client/Makefile
#
# PURPOSE
#   Builds libncfg_client.a, the frontend layer under the widgets: connection
#   handling, framing and the JSON reader for netcfgd's control socket. See
#   gui/project.md section 3 for why this is C and why the seam is here.
#
#   Self-contained: `cd client && make` is all of it. Nothing above needs
#   building first, and this is deliberately not wired into the repository's
#   root Makefile yet -- the same call fuzzypickles/gui makes, and for the same
#   reason: the integration is its own step and doing it early means doing it
#   twice.
#
# TARGETS
#   make            -- the library
#   make test       -- build and run the checks
#   make DEBUG=1    -- unoptimized and symbol-rich (-Og -g)
#   make SANITIZE=1 -- ASan and UBSan, independent of DEBUG; combine freely
#   make clean      -- objects and binaries
#
# BUILD FLAGS
#   DEBUG and SANITIZE are checked for being SET, never for a value, and are
#   given no `?=` default anywhere -- a default would make them permanently set
#   and impossible to turn off. That is the sibling projects' convention and it
#   is worth keeping identical, because moving between these trees should cost
#   nothing.
# =============================================================================

CC ?= gcc
AR ?= ar

LIB    = libncfg_client.a
SRCS   = ncfg_json.c ncfg_client.c
OBJS   = $(SRCS:.c=.o)
HEADERS = ncfg_json.h ncfg_client.h

# -Wall -Wextra are the floor. The three after them are not decoration: this
# code parses bytes from a socket into indices, and every one of the three has
# caught something in code shaped like this before it ran.
WARNINGS = -Wall -Wextra -Wshadow -Wconversion -Wsign-conversion -Wvla \
	   -Wpointer-arith -Wwrite-strings -Wstrict-prototypes
# **The standard is not a default, because a packaging environment replaces
# `CFLAGS` whole.** `?=` is skipped when one arrives from the environment --
# abuild exports its own hardening set -- and `-std=c11` went with it, so
# Alpine compiled this with gcc's `gnu17` and `linux/if_tunnel.h` failed for
# want of `IFNAMSIZ`. The optimisation level is a packager's to choose and the
# language this code is written in is not, so one is a default and the other is
# appended.
CFLAGS  ?= -Os
CFLAGS  += -std=c11 $(WARNINGS) -D_DEFAULT_SOURCE

ifdef DEBUG
CFLAGS := $(filter-out -Os,$(CFLAGS)) -Og -g
endif

ifdef SANITIZE
CFLAGS  += -fsanitize=address,undefined -fno-omit-frame-pointer
LDFLAGS += -fsanitize=address,undefined
endif

.PHONY: all test clean fuzz fuzz-list fuzz-replay FORCE


# A parse and a check of every source, writing nothing: `make syntax CC=clang`
# is what the root `clang` gate runs here. `c/Makefile`'s copy carries the
# reasoning; the short of it is that the flags are `$(CFLAGS)` so they cannot
# be a second copy, `-fsyntax-only` writes no object into gcc's paths, and
# `-MMD -MP` go because they write a `.d` for an object nobody built.
SYNTAX_CFLAGS = $(filter-out -MMD -MP,$(CFLAGS))

syntax:
	@$(CC) $(SYNTAX_CFLAGS) -Werror -fsyntax-only $(SRCS)
	@printf 'syntax: %s read %s source(s) with no warning\n' "$(CC)" \
		"$(words $(SRCS))"

all: $(LIB)

# The flags this was last built with, as a file the objects depend on.
#
# Without it, `make SANITIZE=1 test` followed by a plain build in gui/ links a
# sanitized archive into a binary with no sanitizer runtime -- which fails at
# the link with forty lines about __asan_report_store1 and no clue as to why.
# That happened on the first build of the GUI, which is why this is here rather
# than in somebody's memory. `cmp` rather than a plain write, so an unchanged
# stamp keeps its timestamp and nothing rebuilds.
.build-flags: FORCE
	@echo '$(CC) $(CFLAGS)' > $@.candidate
	@cmp -s $@.candidate $@ || mv $@.candidate $@
	@rm -f $@.candidate

$(LIB): $(OBJS)
	$(AR) rcs $@ $(OBJS)

%.o: %.c $(HEADERS) .build-flags
	$(CC) $(CFLAGS) -c $< -o $@

# The witness is the fixture. tests/client_test.c reads every line of
# doc/schema/socket.json -- the daemon's own frozen surface -- so this goes red
# when the protocol changes, which is the whole reason for pointing at it rather
# than at a copy.
tests/client_test: tests/client_test.c $(LIB) $(HEADERS) .build-flags
	$(CC) $(CFLAGS) $< $(LIB) $(LDFLAGS) -o $@

test: tests/client_test fuzz-replay
	./tests/client_test ../doc/schema/socket.json

# ---------------------------------------------------------------- fuzzing
#
# One target: what netcfgd answers, as the three programs linking this library
# read it. 0277's arrangement, and the drivers are the daemon's rather than a
# copy -- `../c/fuzz/` holds `fuzz.h`, the libFuzzer shim and the replay
# walker, and this directory is self-contained for everything else.
#
# `fuzz/replies.c` says how a reply is delivered without a daemon and why the
# socket boundary is worth fuzzing at all when netcfgd is what answers on it.
FUZZ_SHARED_DIR = ../c/fuzz
FUZZ_TARGETS    = replies monitor
FUZZ_REPLAYS    = $(addprefix fuzz/,$(addsuffix _replay,$(FUZZ_TARGETS)))
FUZZ_PROGRAMS   = $(addprefix fuzz/,$(addsuffix _fuzz,$(FUZZ_TARGETS)))
FUZZ_BUILD_DIR ?= fuzz/build
FUZZ_CC        ?= clang
FUZZ_CFLAGS    ?= -std=c11 -O1 -g
FUZZ_CFLAGS    += $(WARNINGS) -D_DEFAULT_SOURCE -I. -I$(FUZZ_SHARED_DIR) \
		  -fsanitize=fuzzer-no-link,address,undefined -fno-omit-frame-pointer
FUZZ_OBJS       = $(patsubst %.c,$(FUZZ_BUILD_DIR)/%.o,$(SRCS))

# The deterministic half, in `test` for 0277's reason: a fuzzer explores and
# does not remember, so the corpus is what catches a regression. An empty
# corpus directory is refused rather than skipped.
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

fuzz/%_replay: fuzz/%.c $(FUZZ_SHARED_DIR)/fuzz_replay.c $(FUZZ_SHARED_DIR)/fuzz_text.c \
		$(LIB) .build-flags
	$(CC) $(CFLAGS) -I. -I$(FUZZ_SHARED_DIR) $(filter %.c,$^) $(LIB) $(LDFLAGS) -o $@

fuzz: $(FUZZ_PROGRAMS)

fuzz-list:
	@echo $(FUZZ_TARGETS)

$(FUZZ_BUILD_DIR)/%.o: %.c
	@mkdir -p $(dir $@)
	$(FUZZ_CC) $(FUZZ_CFLAGS) -c $< -o $@

fuzz/%_fuzz: fuzz/%.c $(FUZZ_SHARED_DIR)/fuzz_libfuzzer.c $(FUZZ_SHARED_DIR)/fuzz_text.c \
		$(FUZZ_OBJS)
	$(FUZZ_CC) $(FUZZ_CFLAGS) -fsanitize=fuzzer $(filter %.c,$^) $(FUZZ_OBJS) -o $@

clean:
	rm -f $(OBJS) $(LIB) tests/client_test .build-flags \
	    $(FUZZ_REPLAYS) $(FUZZ_PROGRAMS) $(addsuffix .d,$(FUZZ_REPLAYS))
	@# The one directory cleared wholesale, and only because this build made
	@# it. Guarded as `build-and-commit.md` requires: non-empty, relative,
	@# and not a path that could resolve to a source tree.
	@case "$(FUZZ_BUILD_DIR)" in \
	"") echo "clean: FUZZ_BUILD_DIR is empty, refusing to remove anything"; exit 1 ;; \
	/*) echo "clean: FUZZ_BUILD_DIR is absolute ($(FUZZ_BUILD_DIR)), refusing"; exit 1 ;; \
	*..*) echo "clean: FUZZ_BUILD_DIR escapes the tree, refusing"; exit 1 ;; \
	esac; \
	if [ -d "$(FUZZ_BUILD_DIR)" ]; then \
		echo "clean: removing $(FUZZ_BUILD_DIR)"; \
		rm -rf "$(FUZZ_BUILD_DIR)"; \
	fi
