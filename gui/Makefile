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
#   make android    -- the same client as an APK, with the rest of
#                      tool/android.mk's vocabulary. Needs a Qt-for-Android
#                      kit and an NDK; ANDROID_ABI=x86_64 for an emulator.
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
# **Three reasons it can be absent, and they are three messages (0273).**
# `build-and-commit.md` asks that git's absence be reported as its own
# condition rather than as a repository that is not one -- and the earlier
# version collapsed "no git installed", "not a checkout" and "the fetch
# failed" into one sentence that guessed between them in parentheses. The
# remedy differs per case: install git, unpack a release that carries qtty,
# or look at the network. Presence of the program is established before git
# is asked anything, which is the spelling that decision asks for.
qtty:
	@if [ -f $(QTTY_DIR)/qtty.pro ]; then \
		:; \
	elif ! command -v git >/dev/null 2>&1; then \
		echo "gui: $(QTTY_DIR) is empty and git is not installed, so the terminal"; \
		echo "gui:   frontend cannot be fetched. Install git, or build from a release"; \
		echo "gui:   that carries qtty."; \
	elif ! git -C .. rev-parse --git-dir >/dev/null 2>&1; then \
		echo "gui: $(QTTY_DIR) is empty and this is not a git checkout, so there is"; \
		echo "gui:   no submodule to fetch."; \
	else \
		echo "gui: $(QTTY_DIR) is empty; fetching the submodule for the terminal frontend"; \
		GIT_TERMINAL_PROMPT=0 GIT_ASKPASS=/bin/true \
		GIT_SSH_COMMAND='ssh -oBatchMode=yes -oStrictHostKeyChecking=accept-new' \
		timeout 600 git -C .. submodule update --init -- qtty || \
			echo "gui:   could not fetch it: no network, or no key for the remote."; \
	fi; \
	if [ -f $(QTTY_DIR)/qtty.pro ]; then \
		$(MAKE) -C $(QTTY_DIR); \
	else \
		echo "gui: no $(QTTY_DIR) -- building the window only, with no --tui."; \
		echo "gui:   netcfgd-tui will say so rather than opening a window (0173)."; \
	fi

# qmake only when its input moved, so a second `make` writes nothing: `qtty` is
# phony, and as a plain prerequisite it ran qmake every time. Order-only here, and
# its library is named, because gui.pro decides `--tui` by whether that exists.
$(BUILD_DIR)/Makefile: gui.pro $(wildcard $(QTTY_LIB)) | qtty
	@mkdir -p $(BUILD_DIR)
	cd $(BUILD_DIR) && $(QMAKE) ../gui.pro

$(TARGET): $(CLIENT_LIB) qtty $(BUILD_DIR)/Makefile $(wildcard src/*.cpp src/*.h)
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

# fuzznetd too, which `phone_pair` pairs with: a test builds what it needs.
test: $(CLIENT_LIB)
	@$(MAKE) --no-print-directory -C ../c fuzznet.a
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

# ------------------------------------------------------------------- Android
#
# The same client as an APK (project.md 10.714). Here and not in the root
# Makefile, since this is where the window is built, and below `all` because an
# `include` is where make first sees a target: above it, a bare `make` would be
# the Android preflight.
VERSION := $(shell cat ../VERSION)
APP_ID = se.vibes.netcfgd
ANDROID_PROGRAM = netcfgd-gui
ANDROID_BUILD_DIR ?= build-android-$(ANDROID_ABI)
ANDROID_ARTIFACT = $(ANDROID_BUILD_DIR)/$(ANDROID_PROGRAM)-$(VERSION)-$(ANDROID_ABI).apk
# fuzznet's floor, and so the app's: it builds at 28.
ANDROID_API = 28

include ../tool/android.mk

.PHONY: android android-build android-node

# The phone's node (10.720), from the pin, in a directory `android-fresh` does
# not empty: it takes minutes and depends on nothing of this tree. The service
# flags are c/Makefile's: a phone carries no stickers or notes either.
ANDROID_TRIPLE_arm64-v8a = aarch64-linux-android
ANDROID_TRIPLE_x86_64    = x86_64-linux-android
ANDROID_NDK_BIN = $(ANDROID_NDK_ROOT)/toolchains/llvm/prebuilt/linux-x86_64/bin
ANDROID_CC = $(ANDROID_NDK_BIN)/$(ANDROID_TRIPLE_$(ANDROID_ABI))$(ANDROID_API)-clang
ANDROID_NODE_DIR = $(abspath build-android-node-$(ANDROID_ABI))
ANDROID_NODE_LIB = $(ANDROID_NODE_DIR)/libfuzznetd.so

android-node: android-check
	CFLAGS='-Os -ffunction-sections -fdata-sections' $(MAKE) -s -C ../fuzznet \
	        BUILD_DIR=$(ANDROID_NODE_DIR) CC=$(ANDROID_CC) FZN_LOG_PACK=0 \
	        FZN_STICKERS=0 FZN_CATALOG=0 FZN_NOTES=0 FZN_GROUPS=0 \
	        $(ANDROID_NODE_DIR)/fuzznetd
	$(ANDROID_NDK_BIN)/llvm-strip -o $(ANDROID_NODE_LIB) $(ANDROID_NODE_DIR)/fuzznetd

# The sed is the one way to say this from qmake: the node has to exist as a
# file to be run, so the libraries are extracted at install, which AGP calls
# legacy packaging and refuses from the manifest. fuzzypickles' Makefile has the
# long form of how that was found.
$(ANDROID_BUILD_DIR)/Makefile: android-check android-node gui.pro
	mkdir -p $(ANDROID_BUILD_DIR)
	cd $(ANDROID_BUILD_DIR) && $(QT_ANDROID_ROOT)/bin/qmake ../gui.pro \
	        NETCFGD_VERSION=$(VERSION) NETCFGD_VERSION_CODE=$(ANDROID_VERSION_CODE) \
	        NETCFGD_NODE_LIB=$(ANDROID_NODE_LIB) && \
	sed -i '1a\   "android-legacy-packaging": true,' android-*-deployment-settings.json

android android-build: android-fresh $(ANDROID_BUILD_DIR)/Makefile
	$(MAKE) -C $(ANDROID_BUILD_DIR) apk
	@src=$$(find $(ANDROID_BUILD_DIR)/android-build/build/outputs/apk -name '*.apk' -print -quit); \
	if [ -z "$$src" ]; then echo "android: no .apk was produced" >&2; exit 1; fi; \
	cp "$$src" $(ANDROID_ARTIFACT); \
	echo "android: $(ANDROID_ARTIFACT)  ($$(du -h $(ANDROID_ARTIFACT) | cut -f1))"
	@abis=$$(unzip -Z1 $(ANDROID_ARTIFACT) 'lib/*' | cut -d/ -f2 | sort -u | tr '\n' ' ' | sed 's/ *$$//'); \
	if [ "$$abis" != "$(ANDROID_ABI)" ]; then \
		echo "android: named $(ANDROID_ABI), carries $$abis" >&2; exit 1; \
	fi; \
	echo "android: carries $$abis, which is what the name says"
	$(call android_verify_signature,$(ANDROID_ARTIFACT))
