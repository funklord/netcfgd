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
CFLAGS  ?= -std=c11 -Os
CFLAGS  += $(WARNINGS) -D_DEFAULT_SOURCE

ifdef DEBUG
CFLAGS := $(filter-out -Os,$(CFLAGS)) -Og -g
endif

ifdef SANITIZE
CFLAGS  += -fsanitize=address,undefined -fno-omit-frame-pointer
LDFLAGS += -fsanitize=address,undefined
endif

.PHONY: all test clean FORCE

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
# docs/schema/socket.json -- the daemon's own frozen surface -- so this goes red
# when the protocol changes, which is the whole reason for pointing at it rather
# than at a copy.
tests/client_test: tests/client_test.c $(LIB) $(HEADERS) .build-flags
	$(CC) $(CFLAGS) $< $(LIB) $(LDFLAGS) -o $@

test: tests/client_test
	./tests/client_test ../docs/schema/socket.json

clean:
	rm -f $(OBJS) $(LIB) tests/client_test .build-flags
