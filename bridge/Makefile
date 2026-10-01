# =============================================================================
# bridge/Makefile
#
# PURPOSE
#   Builds `netcfgd-remote`, the unprivileged program that will speak fuzznet's
#   authenticated UDP protocol on netcfgd's behalf. The daemon never grows a
#   network listener (`doc/shared-protocol-brief.md` section 3, design section
#   11.3), so everything fuzznet is linked here and nowhere near the process
#   holding CAP_NET_ADMIN.
#
#   Self-contained, the same way `client/` is: `cd bridge && make` is all of
#   it, and it fetches the fuzznet submodule itself rather than expecting
#   somebody to have read a README.
#
# TARGETS
#   make            -- the program
#   make test       -- build and run the checks
#   make fuzznet    -- fetch and build the submodule, nothing else
#   make clean      -- what this build produced, by name
#   make DEBUG=1    -- unoptimized and symbol-rich (-Og -g)
#   make SANITIZE=1 -- ASan and UBSan, independent of DEBUG; combine freely
#
# WHY THE SUBMODULE IS THIS BUILD'S TO FETCH
#   `build-and-commit.md` sets it: a person who has just cloned the repository
#   types the build command and gets a build, without having to know that
#   `git submodule update --init` exists. And the failure it is written against
#   is silence -- raidcfgd resolved a sibling with `pkg-config --exists` and on
#   a machine with nothing installed built no backend at all, skipped that
#   suite, and said nothing. An absent submodule reaches the same place by a
#   shorter route: the directory is empty, a guard reads it as "not available",
#   and the build succeeds having built less than it was asked for.
#
#   So this fetches it and FAILS when it cannot. The pin is never moved: the
#   gitlink names a commit somebody reviewed, and a build that advanced it
#   would make this tree's history a claim about nobody's code in particular.
# =============================================================================

CC ?= gcc

PROGRAM = netcfgd-remote
SRCS    = netcfgd-remote.c record_encode.c

FUZZNET     = ../fuzznet
CLIENT      = ../client
CLIENT_LIB  = $(CLIENT)/libncfg_client.a
FUZZNET_BLD = build

# The C port, for the one source this directory needs out of it.
#
# **One source, not the library.** `compile/scope.c` holds the scope table and
# the kind registry, and it includes nothing but `ncfg/scope.h` and
# `<string.h>` -- so compiling it here costs one object and states the
# dependency exactly. Linking `../c/libncfg.a` would work, an archive
# contributing only what resolves, and would make this build wait on the
# daemon's and put the whole of it within reach of a program that must stay
# small: section 3 of the brief keeps fuzznet away from the process holding
# CAP_NET_ADMIN, and the same argument runs the other way.
CORE        = ../c
# `scope.c` for the tables, and the front end for `record_emit.c`, which has to
# read a configuration before it can say what of it would travel. Six pure
# sources -- no kernel, no sockets, nothing that opens anything -- which is why
# they are named rather than the whole of `libncfg.a` being linked: an archive
# would prune to the same set today and would stop doing so the moment the
# compiler grew a dependency, in the one program section 3 keeps small.
CORE_SRCS   = $(CORE)/src/compile/scope.c
CORE_FRONT  = $(CORE)/src/compile/walk.c $(CORE)/src/compile/parse.c \
	      $(CORE)/src/compile/lex.c $(CORE)/src/compile/ast.c \
	      $(CORE)/src/base/buf.c $(CORE)/src/base/error.c

# The client's floor, name for name, so moving between these directories costs
# nothing. `-Wno-pedantic` is deliberately absent: this file is ours.
WARNINGS = -Wall -Wextra -Wshadow -Wconversion -Wsign-conversion -Wvla \
	   -Wpointer-arith -Wwrite-strings -Wstrict-prototypes
CFLAGS  ?= -std=c11 -Os
CFLAGS  += $(WARNINGS) -D_DEFAULT_SOURCE -I$(FUZZNET) -I$(FUZZNET)/wire/generated -I$(CLIENT) \
	   -I$(CORE)/include

ifdef DEBUG
CFLAGS := $(filter-out -Os,$(CFLAGS)) -Og -g
endif

ifdef SANITIZE
CFLAGS  += -fsanitize=address,undefined -fno-omit-frame-pointer
LDFLAGS += -fsanitize=address,undefined
endif

# fuzznet's own feature flags, as its Makefile sets them. Named here rather
# than guessed, because a header compiled under different flags from the object
# it calls is the quietest kind of wrong.
FUZZNET_DEFS = -DFZN_PERSIST_FILE_ON -DFZN_CLI_ON -DFZN_RECORD_STORE_FILE_ON \
	       -DFZN_CLAIM_FILE_ON -DFZN_SPOOL_FILE_ON

.PHONY: all fuzznet client test clean

all: $(PROGRAM)

# **Ask git, and report git's absence as its own thing.** `test -d .git` is
# false in a linked worktree and in a submodule checkout -- there `.git` is a
# regular FILE naming the real gitdir, and both are git repositories. The
# `hooks` target in the root Makefile carries the same reasoning and the same
# spelling; this is that idiom, not a second answer to one question.
#
# The fetch is loud because network access is a thing a build does visibly: a
# clone is not a compile, and a build with no network should fail naming the
# submodule rather than timing out inside something else.
fuzznet:
	@# **`--recursive`, and that is not tidiness.** fuzznet vendors Monocypher
	@# as a submodule of its own and the crypto is a vtable: without it the
	@# bindings are not built, `MONOCYPHER_DIR` finds no `src/monocypher.c`,
	@# and fuzznet's own Makefile SKIPS them with a notice rather than
	@# failing. The build would then succeed having produced a library that
	@# cannot verify a frame -- which is raidcfgd's silent-backend failure
	@# (build-and-commit.md) arriving one level of nesting down.
	@if [ ! -e $(FUZZNET)/Makefile ] || [ ! -e $(FUZZNET)/monocypher/src/monocypher.c ]; then \
		if ! command -v git >/dev/null 2>&1; then \
			echo "bridge: fuzznet is absent and git is not installed to fetch it." >&2; \
			exit 1; \
		fi; \
		if ! git -C .. rev-parse --git-common-dir >/dev/null 2>&1; then \
			echo "bridge: fuzznet is absent and this is not a git checkout," >&2; \
			echo "bridge:   so there is no gitlink saying which commit to fetch." >&2; \
			exit 1; \
		fi; \
		echo "bridge: fetching the fuzznet submodule at the commit this tree pins"; \
		git -C .. submodule update --init --recursive -- fuzznet || { \
			echo "bridge: could not fetch the fuzznet submodule." >&2; \
			exit 1; \
		}; \
	fi
	@$(MAKE) --no-print-directory -C $(FUZZNET) BUILD_DIR=$(FUZZNET_BLD) all

# Every object fuzznet's build produced, minus the ones that define `main`.
#
# **Asked of the objects with `nm`, not guessed from their names.** The first
# version of this filtered `/test/|_test\.o|main\.o`, which is a claim about
# fuzznet's file naming rather than about what is in the files -- and it was
# wrong the moment the build grew: `node/fuzznetd.c` carries a `main`, is named
# nothing like any of those, and the link failed with "multiple definition of
# `main'" as soon as Monocypher turned that target on.
#
# A list written here would be worse still: fuzznet grows modules, and the one
# place a list went wrong would be the module somebody had just added. The
# objects know which of them has an entry point; nothing else has to.
FUZZNET_OBJS = $(shell find $(FUZZNET)/$(FUZZNET_BLD) -name '*.o' 2>/dev/null | \
	       while read -r o; do \
	               nm "$$o" 2>/dev/null | grep -qE ' [TtWw] main$$' || echo "$$o"; \
	       done)

# The client library is netcfgd's own local hop, which the brief says netcfgd
# already has: the agent speaks fuzznet outward and this inward, and linking
# both in one program is the seam 0128 describes.
client:
	@$(MAKE) --no-print-directory -C $(CLIENT)

$(PROGRAM): $(SRCS) $(CORE_SRCS) fuzznet client
	$(CC) $(CFLAGS) $(FUZZNET_DEFS) $(SRCS) $(CORE_SRCS) $(FUZZNET_OBJS) $(CLIENT_LIB) \
		$(LDFLAGS) -o $@

# The read path against a frame the library builds, which is the control the
# program itself cannot show: every answer `--peek` gives by hand is a refusal,
# and a program that can only refuse looks like one that refuses everything.
test: tests/peek_test tests/record_encode_test tests/record_emit_test $(PROGRAM)
	./tests/peek_test
	./tests/record_encode_test
	./tests/record_emit_test

tests/peek_test: tests/peek_test.c fuzznet
	$(CC) $(CFLAGS) $(FUZZNET_DEFS) $< $(FUZZNET_OBJS) $(LDFLAGS) -o $@

# The encoder against fuzznet itself, which is the half the tables cannot
# check: every other assertion in that file asks netcfgd about netcfgd.
tests/record_encode_test: tests/record_encode_test.c record_encode.c $(CORE_SRCS) fuzznet
	$(CC) $(CFLAGS) $(FUZZNET_DEFS) $< record_encode.c $(CORE_SRCS) $(FUZZNET_OBJS) \
		$(LDFLAGS) -o $@

# The join between the two: a document in, the records it would put on the wire
# out, and the tally of what it would not. Needs the front end, which the
# program itself does not.
tests/record_emit_test: tests/record_emit_test.c record_emit.c record_encode.c \
		$(CORE_SRCS) $(CORE_FRONT) fuzznet
	$(CC) $(CFLAGS) $(FUZZNET_DEFS) $< record_emit.c record_encode.c $(CORE_SRCS) \
		$(CORE_FRONT) $(FUZZNET_OBJS) $(LDFLAGS) -o $@

# By name, and nothing by pattern this directory does not own. fuzznet's build
# output is fuzznet's to remove, through its own clean.
clean:
	rm -f $(PROGRAM) tests/peek_test tests/record_encode_test tests/record_emit_test
	@echo "clean: removed $(PROGRAM), tests/peek_test, tests/record_encode_test and"
	@echo "clean:   tests/record_emit_test; fuzznet's objects are its own to clean"

