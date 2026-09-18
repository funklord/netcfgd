# =============================================================================
# c/Makefile
#
# PURPOSE
#   The C port of netcfgd, module by module, while the Rust it replaces is
#   still the thing that runs. Nothing here is installed yet: `make -C c` is a
#   build and a test suite, and the packaging keeps shipping the Rust until a
#   module here is the better of the two.
#
# TARGETS
#   make            -- the library
#   make test       -- build and run every check under tests/
#   make DEBUG=1    -- unoptimized and symbol-rich (-Og -g)
#   make SANITIZE=1 -- ASan and UBSan, independent of DEBUG; combine freely
#   make clean      -- objects and binaries
#
#   DEBUG and SANITIZE are checked for being SET and given no default, which is
#   `client/Makefile`'s convention and the sibling projects': a default would
#   make them permanently on and impossible to turn off.
#
# WHY THE SOURCES ARE A WILDCARD AND THE CLEAN IS NOT
#   `client/Makefile` lists its two files by name, which is right for a library
#   that is finished. This one grows a module at a time, often in more than one
#   working tree at once, and a listed source is a merge conflict per module
#   for no benefit -- the directory *is* the list. `clean` removes what this
#   build produced, by the same wildcard, and nothing else: see the target.
# =============================================================================

CC ?= gcc
AR ?= ar

LIB = libncfg.a

# Every module under src/, and the JSON reader the client already has. That
# file is not copied: two readers of one format is how the GUI and the CLI
# came to disagree about an access point's name, and this port is not starting
# a second copy of anything it can share.
SRCS = $(wildcard src/*/*.c) ../client/ncfg_json.c
OBJS = $(patsubst %.c,%.o,$(SRCS))

TEST_SRCS = $(wildcard tests/*_test.c)
TESTS = $(patsubst %.c,%,$(TEST_SRCS))

# The client's floor, name for name. The three after -Wall -Wextra are not
# decoration: this code turns bytes into indices and every one of them has
# caught something in code shaped like this.
WARNINGS = -Wall -Wextra -Wshadow -Wconversion -Wsign-conversion -Wvla \
	   -Wpointer-arith -Wwrite-strings -Wstrict-prototypes
CFLAGS  ?= -std=c11 -Os
CFLAGS  += $(WARNINGS) -D_DEFAULT_SOURCE -Iinclude -I../client

ifdef DEBUG
CFLAGS := $(filter-out -Os,$(CFLAGS)) -Og -g
endif

ifdef SANITIZE
CFLAGS  += -fsanitize=address,undefined -fno-omit-frame-pointer
LDFLAGS += -fsanitize=address,undefined
endif

.PHONY: all test clean

all: $(LIB)

$(LIB): $(OBJS)
	$(AR) rcs $@ $(OBJS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

# Each test is its own binary, and each is run. A suite that stops at the
# first failure hides how much is broken, so every one runs and the target
# fails at the end if any did.
test: $(TESTS)
	@fail=0; \
	for one in $(TESTS); do \
		echo "== $$one"; \
		./$$one || fail=1; \
	done; \
	[ $$fail -eq 0 ] || { echo "c: some checks failed"; exit 1; }
	@echo "c: every check passed"

tests/%_test: tests/%_test.c $(LIB)
	$(CC) $(CFLAGS) $< $(LIB) $(LDFLAGS) -o $@

# What this build made, by the same wildcard that made it -- and nothing by
# pattern that this directory does not own.
clean:
	rm -f $(OBJS) $(LIB) $(TESTS)
