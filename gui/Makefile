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

.PHONY: all run test clean $(CLIENT_LIB)

all: $(TARGET)

# Always asked, never assumed: the client library is a sibling under active
# development, and a stale .a is a debugging session nobody enjoys.
$(CLIENT_LIB):
	$(MAKE) -C $(CLIENT_DIR) DEBUG=$(DEBUG) SANITIZE=$(SANITIZE)

# qtty, vendored as a submodule at the repository root, which is where every
# sibling here puts one -- monocypher and flog in fuzzypickles, vterm in
# beerssh, ossacli in raidcfgd.
#
# **Built if the submodule is checked out, skipped if it is not.** A clone
# without `--recurse-submodules` leaves an empty directory, and `gui/` has to
# keep building there: the TUI is what goes missing, not the GUI. Asked on
# every build for the same reason the client library is -- a stale libqtty.a
# against moved headers is the same debugging session, and qtty is pre-alpha.
QTTY_DIR = ../qtty
QTTY_LIB = $(QTTY_DIR)/build/lib/libqtty.a

# **Fetched, not asked for.** This printed `run 'git submodule update --init'`
# and built the window without a terminal frontend -- so a clone made the
# ordinary way produced a package whose `netcfgd-tui` opened a window, and the
# only sign was a line in a build log nobody re-reads. Telling somebody to type
# a command the build could type itself is the failure, not the message.
#
# **Only when it has never been checked out.** The condition is the absence of
# `qtty.pro`, not "is it up to date": `git submodule update` moves HEAD, and a
# qtty developer with the submodule on their own branch would find the build
# had moved it under them. An empty directory belongs to nobody.
#
# **And it stays non-fatal, and it must not hang.** The submodule's URL is ssh,
# so a machine with no key or no network cannot fetch it -- and the GUI is
# meant to build there. Measured while writing this: pointed at a remote that
# does not exist, `git submodule update` did not fail, it **waited** -- for
# credentials it was never going to be given -- and the build sat there until
# an outer timeout killed it. A fetch that asks a question in the middle of
# `make` is worse than one that fails.
#
# So it is told not to ask: `GIT_TERMINAL_PROMPT=0` for http, `BatchMode=yes`
# for ssh, and `GIT_ASKPASS` pointed at something that answers nothing. The
# `timeout` is a backstop against something no environment variable reaches,
# not the mechanism -- and it is generous, because a first fetch of qtty over
# ssh measured 177s here and a build that killed a working clone at two
# minutes would be the fault this rule exists to remove. The `||` keeps a failure a fallback rather
# than an error, so both ends land on the same message they always did -- now
# a report of something attempted rather than an instruction.
.PHONY: qtty
qtty:
	@if [ ! -f $(QTTY_DIR)/qtty.pro ] && git -C .. rev-parse --git-dir >/dev/null 2>&1; then \
		echo "gui: $(QTTY_DIR) is empty; fetching the submodule for the terminal frontend"; \
		GIT_TERMINAL_PROMPT=0 GIT_ASKPASS=/bin/true \
		GIT_SSH_COMMAND='ssh -oBatchMode=yes -oStrictHostKeyChecking=accept-new' \
		timeout 600 git -C .. submodule update --init -- qtty || \
			echo "gui:   could not fetch it (no network, no key, or a source tree \
without git). Building the window only."; \
	fi; \
	if [ -f $(QTTY_DIR)/qtty.pro ]; then \
		$(MAKE) -C $(QTTY_DIR); \
	else \
		echo "gui: no $(QTTY_DIR) -- building the window only, with no --tui."; \
		echo "gui:   netcfgd-tui will say so rather than opening a window (0173)."; \
	fi

$(TARGET): $(CLIENT_LIB) qtty gui.pro $(wildcard src/*.cpp src/*.h)
	@mkdir -p $(BUILD_DIR)
	cd $(BUILD_DIR) && $(QMAKE) ../gui.pro
	$(MAKE) -C $(BUILD_DIR)

run: $(TARGET)
	./$(TARGET)

# The headless render probe. Its own qmake project under tests/, so a plain
# `make` here does not build it -- build-and-commit.md wants tests built by the
# test target and only by it.
#
# Offscreen because the thing under test is *pixels*: 0118's frame is the whole
# argument for administrator mode, and a mode nobody can look at is the feature
# not existing. Qt's offscreen platform runs the real paint path, so this needs
# a graphical session no more than it needs a person.
# Found rather than listed, so a fourth probe needs no edit here. Each gets its
# own directory because two qmake projects in one directory overwrite each
# other's Makefile.
TEST_PROS = $(wildcard tests/*.pro)

test: $(CLIENT_LIB)
	@failed=0; \
	for pro in $(TEST_PROS); do \
		name=$$(basename $$pro .pro); \
		dir=tests/$(BUILD_DIR)/$$name; \
		mkdir -p $$dir; \
		( cd $$dir && $(QMAKE) ../../$$name.pro >/dev/null && \
			$(MAKE) --no-print-directory >/dev/null ) || \
			{ echo "gui test: $$name failed to build"; failed=1; continue; }; \
		QT_QPA_PLATFORM=offscreen $$dir/$$name || failed=1; \
	done; \
	if [ "$$failed" -ne 0 ]; then exit 1; fi; \
	if [ -z "$(TEST_PROS)" ]; then \
		echo "gui test: no probes found under tests/, which is not a pass"; \
		exit 1; \
	fi

clean:
	@# Verified before it is deleted, per build-and-commit.md: this is the
	@# wholesale-directory shape, which is allowed because the build created
	@# the directory -- but only once the variable is known to be non-empty
	@# and relative. An unset or absolute BUILD_DIR here is how a clean target
	@# eats something it should not.
	@case "$(BUILD_DIR)" in \
		"" ) echo "clean: BUILD_DIR is empty, refusing"; exit 1 ;; \
		/* ) echo "clean: BUILD_DIR $(BUILD_DIR) is absolute, refusing"; exit 1 ;; \
	esac
	rm -rf $(BUILD_DIR) tests/$(BUILD_DIR) tests/live/$(BUILD_DIR)
	$(MAKE) -C $(CLIENT_DIR) clean
