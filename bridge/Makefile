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
SRCS    = netcfgd-remote.c

FUZZNET     = ../fuzznet
FUZZNET_BLD = build

# The client's floor, name for name, so moving between these directories costs
# nothing. `-Wno-pedantic` is deliberately absent: this file is ours.
WARNINGS = -Wall -Wextra -Wshadow -Wconversion -Wsign-conversion -Wvla \
	   -Wpointer-arith -Wwrite-strings -Wstrict-prototypes
CFLAGS  ?= -std=c11 -Os
CFLAGS  += $(WARNINGS) -I$(FUZZNET) -I$(FUZZNET)/wire/generated

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

.PHONY: all fuzznet clean

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
	@if [ ! -e $(FUZZNET)/Makefile ]; then \
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
		git -C .. submodule update --init -- fuzznet || { \
			echo "bridge: could not fetch the fuzznet submodule." >&2; \
			exit 1; \
		}; \
	fi
	@$(MAKE) --no-print-directory -C $(FUZZNET) BUILD_DIR=$(FUZZNET_BLD) all

# Every object fuzznet's build produced, minus the ones carrying a `main` or
# belonging to its suites. Asked of the tree rather than listed: fuzznet grows
# modules, and a list here would be a second thing to keep true and the one
# place it went wrong would be the module somebody had just added.
FUZZNET_OBJS = $(shell find $(FUZZNET)/$(FUZZNET_BLD) -name '*.o' 2>/dev/null | \
	       grep -vE '/test/|_test\.o|main\.o')

$(PROGRAM): $(SRCS) fuzznet
	$(CC) $(CFLAGS) $(FUZZNET_DEFS) $(SRCS) $(FUZZNET_OBJS) $(LDFLAGS) -o $@

# By name, and nothing by pattern this directory does not own. fuzznet's build
# output is fuzznet's to remove, through its own clean.
clean:
	rm -f $(PROGRAM)
	@echo "clean: removed $(PROGRAM); fuzznet's objects are its own to clean"
