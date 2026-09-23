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
#   make            -- the library, the program, and the program's second name
#   make test       -- link the program and run every check under tests/
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
#
#   `src/main/` is the one directory held out of that list, and the reason is
#   0263 rather than convenience: a library never exits, and a `main` inside
#   `libncfg.a` would be a program in the archive that rule is enforced by.
#   It is built into the program instead, and `main_test` links the parts of it
#   that are not the entry point.
#
# WHY ONE PROGRAM CARRIES TWO NAMES
#   `netcfgd` and `ncfg` share the model, the compiler, the planner, the
#   executor and the netlink layer -- nearly everything either of them is.
#   Built as two binaries the Rust measured 775 KB duplicated between them
#   against a 2.89 MB install, and merging them is most of what took the
#   install to 1.75 MB (0024). So the program is `netcfgd` and `ncfg` is a
#   symlink to it, made here rather than only on install: a test or a person
#   running `./ncfg` out of this directory would otherwise be running the
#   daemon under a client's arguments. The Rust makes the same link, in the
#   top-level Makefile's `ncfg-link`, for the same reason.
#
#   Nothing here is installed. 0263 is explicit that the packaging keeps
#   shipping the Rust, so this program exists to be linked, measured and
#   tested -- which is the first thing a port of a multi-call binary cannot do
#   until it has a `main`.
# =============================================================================

CC ?= gcc
AR ?= ar

LIB = libncfg.a

# Every module under src/, and the JSON reader the client already has. That
# file is not copied: two readers of one format is how the GUI and the CLI
# came to disagree about an access point's name, and this port is not starting
# a second copy of anything it can share.
# `src/*/*/*.c` is the backends: one directory per daemon under `src/backend/`,
# because four of them share a shape and a flat `src/backend/` would put
# `render.c` there four times. The wildcard is two deep for the same reason it
# is one deep -- the directory is the list.
# `src/main/` is filtered out for the reason the header gives: what is under it
# decides an exit status, and a library may not.
SRCS = $(filter-out src/main/%,$(wildcard src/*/*.c)) $(wildcard src/*/*/*.c)

# The shared reader, compiled **here** rather than where it lives.
#
# `%.o: %.c` next to the source would put the object at
# `../client/ncfg_json.o` -- which is the exact path `client/Makefile` builds
# and archives, with different flags and outside the `.build-flags` stamp that
# exists to stop precisely this. `make SANITIZE=1` in this directory therefore
# left a sanitized object in `client/`, `client`'s own archive picked it up,
# and the link of `client/tests/client_test` failed with forty lines about
# `__asan_report_store1` -- the failure that stamp's comment describes, arriving
# by the one route it cannot see. A clean here made it worse rather than better:
# `clean` removed `$(OBJS)`, so this directory was reaching across and deleting
# another component's object as well as writing it.
#
# One source, two builds, two objects. The file is still shared; only the
# output is ours.
SHARED_SRCS = ../client/ncfg_json.c
SHARED_OBJS = $(notdir $(SHARED_SRCS:.c=.o))
OBJS = $(patsubst %.c,%.o,$(SRCS)) $(SHARED_OBJS)

# The program, its second name, and the entry points that make it one.
PROGRAM       = netcfgd
PROGRAM_LINK  = ncfg
PROGRAM_SRCS  = $(wildcard src/main/*.c)
PROGRAM_OBJS  = $(patsubst %.c,%.o,$(PROGRAM_SRCS))
# What a test may link: the three programs' bodies without the one symbol it
# cannot have twice. A test has its own `main`.
PROGRAM_PARTS = $(filter-out src/main/main.o,$(PROGRAM_OBJS))

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

.PHONY: all test clean FORCE

all: $(LIB) $(PROGRAM) $(PROGRAM_LINK)

$(LIB): $(OBJS)
	$(AR) rcs $@ $(OBJS)

# The library last on the line, because it is an archive: the objects that need
# it are listed before it or the linker has already walked past what it wanted.
$(PROGRAM): $(PROGRAM_OBJS) $(LIB)
	$(CC) $(CFLAGS) $(PROGRAM_OBJS) $(LIB) $(LDFLAGS) -o $@

# The second name, made rather than installed -- see the header.
$(PROGRAM_LINK): $(PROGRAM)
	ln -sf $(PROGRAM) $@

# The flags this was last built with, as a file every object depends on.
#
# `client/Makefile` has carried this since the GUI's first build and this
# directory did not, so `make SANITIZE=1 test` followed by a plain `make test`
# relinked yesterday's sanitized objects against no sanitizer runtime and said
# `__asan_report_store1` forty times. Objects do not record what built them,
# and a timestamp cannot tell an optimized `.o` from an instrumented one.
#
# `cmp` rather than a plain write: an unchanged stamp keeps its timestamp and
# nothing rebuilds.
.build-flags: FORCE
	@echo '$(CC) $(CFLAGS)' > $@.candidate
	@cmp -s $@.candidate $@ || mv $@.candidate $@
	@rm -f $@.candidate

%.o: %.c .build-flags
	$(CC) $(CFLAGS) -c $< -o $@

# Named, because the pattern rule above would write it into `client/`.
$(SHARED_OBJS): $(SHARED_SRCS) .build-flags
	$(CC) $(CFLAGS) -c $< -o $@

# Each test is its own binary, and each is run. A suite that stops at the
# first failure hides how much is broken, so every one runs and the target
# fails at the end if any did.
# The program is a prerequisite, not a separate target somebody remembers.
# `test` used to depend on the binaries under `tests/` alone, so `make check`
# -- which reaches this through the top-level `c-test` -- would have stayed
# green through a program that no longer links. Every object it needs is in
# the library the tests already build, so the only thing this catches is the
# link itself, which is exactly the thing nothing else looks at.
test: $(TESTS) $(PROGRAM) $(PROGRAM_LINK)
	@fail=0; \
	for one in $(TESTS); do \
		echo "== $$one"; \
		./$$one || fail=1; \
	done; \
	[ $$fail -eq 0 ] || { echo "c: some checks failed"; exit 1; }
	@echo "c: every check passed"

tests/%_test: tests/%_test.c $(LIB) .build-flags
	$(CC) $(CFLAGS) $< $(LIB) $(LDFLAGS) -o $@

# The two tests that link more than the library, because what they check is not
# in the library: the entry points and the descriptor loop are under
# `src/main/`, which `SRCS` holds out. An explicit rule beats the pattern above
# it whatever the order.
#
# `main_test` is the command line and the multi-call dispatch; `loop_test` is
# the loop over the descriptors a daemon owns, which is that directory's work
# for the reason 0263 gives -- a library never exits and never owns a `poll`
# that decides when a process stops. `world_test` and `answer_test` are the
# other two halves of the same sentence.
tests/main_test: tests/main_test.c $(PROGRAM_PARTS) $(LIB) .build-flags
	$(CC) $(CFLAGS) $< $(PROGRAM_PARTS) $(LIB) $(LDFLAGS) -o $@

tests/loop_test: tests/loop_test.c $(PROGRAM_PARTS) $(LIB) .build-flags
	$(CC) $(CFLAGS) $< $(PROGRAM_PARTS) $(LIB) $(LDFLAGS) -o $@

# The same two, for the same reason: the four seams a reconcile pass reaches
# the machine through and the request dispatcher are `src/main/`'s work --
# owning the apply lock, the netlink socket and the connections an event is
# written to is what that directory is for.
tests/world_test: tests/world_test.c $(PROGRAM_PARTS) $(LIB) .build-flags
	$(CC) $(CFLAGS) $< $(PROGRAM_PARTS) $(LIB) $(LDFLAGS) -o $@

tests/answer_test: tests/answer_test.c $(PROGRAM_PARTS) $(LIB) .build-flags
	$(CC) $(CFLAGS) $< $(PROGRAM_PARTS) $(LIB) $(LDFLAGS) -o $@

# What this build made, by the same wildcard that made it -- and nothing by
# pattern that this directory does not own. The program and its second name are
# two literal names rather than a wildcard, because this directory is not one
# whose contents a build produced.
clean:
	rm -f $(OBJS) $(PROGRAM_OBJS) $(LIB) $(PROGRAM) $(PROGRAM_LINK) $(TESTS) .build-flags
