# The gates from project.md section 6, as one entry point. Constraint 8 is why this
# exists before there is much to gate: budgets adopted later are budgets
# already blown, and the same goes for every other check here.
#
# `make check` is what CI runs and what to run before committing.
#
# TARGETS
#   make               -- build the workspace and link the `ncfg` name
#   make gui           -- the Qt client, which nothing else builds
#   make cross         -- the cross-compilation check
#   make test          -- the test suite alone
#   make check         -- every gate; the one to run before a commit
#   make check-ci      -- check minus the budgets, which a rented VM cannot
#                         measure honestly
#   make live          -- the supplicant tests that need a real
#                         wpa_supplicant and a privileged netns; not in check
#   make live-container -- the live suite in a container, with the programs
#                         and privileges this machine cannot give it
#   make fuzz          -- the fuzz targets
#   make conformance   -- the two client implementations, asked the same
#                         questions
#   make adapters      -- each adapter, built and checked to the core's bar
#   make nm-containment -- assert the core's manifest has gained no entry
#   make linkage       -- what the shipped binary is allowed to link
#   make style         -- the shared source gate, plus project.md held to the
#                         tree it describes
#   make fmt           -- rustfmt, checking only; `fmt-fix` rewrites. Skips
#                         loudly where rustfmt is not installed
#   make clippy        -- clippy across the workspace; skips loudly where it
#                         is not installed
#   make deny          -- supply chain; reports rather than fails where the
#                         tools are not installed
#   make size          -- the installed-size ratchet
#   make footprint     -- an unused optional feature must leave no trace
#   make rss           -- the resident-memory budget
#   make install       -- the two binaries and the config directory, and
#                         nothing of anybody else's
#   make install-systemd, install-openrc, install-procd
#                      -- the init glue for one system, chosen deliberately
#   make install-gui   -- the Qt client, opt-in; not part of install
#   make install-modem-mbim
#                      -- the reference modem helper; optional on purpose
#   make uninstall     -- remove what install put there
#   make deb           -- the Debian package; Depends read from the ELF
#   make apk           -- the Alpine package. Alpine's `apk`, not Android's
#   make apk-container -- the same, built by `abuild` inside Alpine
#   make apk-source    -- the tarball an APKBUILD builds from
#   make schema-bless  -- re-bless the frozen document and socket witnesses
#   make version-check -- VERSION is the source; debian/changelog and
#                         Cargo.toml are held to it
#   make hooks         -- install the git hooks from tool/hooks/
#   make clean         -- remove build products
#   make veryclean     -- clean, plus the build directories
#   make distclean     -- veryclean, plus what the tooling here wrote
#   make help          -- this list
#

CARGO ?= cargo

# Is the optional component here? Asked in three places, so spelled once: the
# `fmt` and `clippy` gates, and `adapters`, which holds each adapter workspace
# to the same bar as the core and therefore runs both again. That third one is
# the easy one to miss -- it is a `cd` into another workspace rather than a
# gate with the tool's name on it -- and missing it leaves `make check`
# stopping dead exactly as before, only later and after a full build.
#
# Asking cargo whether the subcommand runs, rather than looking for a binary by
# name: rustup and Debian put the shim in different places, and the only thing
# being asked is whether the next line will work.
FMT_OK    = $(CARGO) fmt --version >/dev/null 2>&1
CLIPPY_OK = $(CARGO) clippy --version >/dev/null 2>&1

.PHONY: deb apk apk-source apk-container all check check-ci build test gui conformance FORCE fmt fmt-fix shell clippy unsafe-policy executor-policy packaging ascii size footprint rss live schema-bless install install-gui install-modem-mbim install-systemd install-openrc install-procd fuzz deny clean adapters nm-containment veryclean distclean uninstall style style-source style-docs hooks cross linkage live-container help

# Where each adapter lives. Each is its own cargo workspace with its own
# lockfile, so that its dependencies cannot reach the core's -- see
# `nm-containment` below, and design section 9.2.
ADAPTERS = adapter/netcfgd-nm

all: build

build:
	$(CARGO) build --workspace
	@$(MAKE) --no-print-directory ncfg-link PROFILE=debug

# `ncfg` is the second name of the one binary. Cargo cannot make a symlink, so
# it is made here -- and it is made in the build tree as well as on install,
# because the tests invoke `target/*/ncfg` and would otherwise be running the
# daemon under a client's arguments.
ncfg-link:
	@if [ -f target/$(PROFILE)/netcfgd ]; then \
		ln -sf netcfgd target/$(PROFILE)/ncfg; \
	fi

# Ordered cheapest first, so a formatting slip does not wait on a full test run.
# `nm-containment` is early and costs nothing: it reads two text files, and it
# is the one gate that fails if an adapter's dependencies have leaked into the
# core -- which is the kind of thing that is trivial to prevent and miserable to
# unpick later.
#
# Split into two lists rather than two target lists, so they cannot drift: a
# gate added to PORTABLE_GATES is in both `check` and `check-ci` by
# construction, and there is no second place to forget it.
#
# The division is not "cheap and expensive", it is **what the answer depends
# on**. Everything in PORTABLE_GATES gives the same answer on any machine that
# can build the tree. BUDGET_GATES measure *this* machine, and running them
# somewhere else measures somewhere else -- see `check-ci`.
PORTABLE_GATES = style fmt ascii shell clippy unsafe-policy executor-policy \
                 nm-containment packaging conformance test adapters gui \
                 linkage
BUDGET_GATES   = size footprint rss

check: $(PORTABLE_GATES) $(BUDGET_GATES)

# What a machine nobody owns can honestly check.
#
# `check` minus the budgets, because those are ratchets on a measurement and a
# rented VM measures the VM. `rss` is the clearest case: three runs of an
# identical binary here gave 4240, 4244 and 4392 KB against a 4608 limit, which
# is 152 KB of spread inside 360 KB of headroom, so on unknown hardware it is a
# coin toss. A gate that fails a coin toss teaches people to ignore red, which
# costs more than the gate is worth. `size` and `footprint` are deterministic
# for a given toolchain and not across them, and a CI runner's `stable` moves
# every six weeks.
#
# Constraint 8 is not weakened by this: the size budget is still a gate, it is
# still in `check`, and it still fails on the machine where the number means
# something. What moves is who is asked, not whether.
#
# This does **not** run `make live`, and no CI target should. Those scripts
# drive real daemons and several want namespaces or real root; a green tick
# over a suite that skipped everything is the vacuous pass this tree keeps
# finding, and the live scripts are most of the evidence this project has.
check-ci: $(PORTABLE_GATES)

# Each adapter, built and checked with the same bar as the core.
#
# Separately, because they are separate workspaces. That is the price of
# dependency containment and it is a small one: a `cd` per adapter, against
# never having to ask which binary a `cargo deny` result was about.
#
# The two optional checks skip here exactly as they do in the core gates, and
# announced once rather than per adapter. `if cond; then check; fi` is doing
# real work in the chain: it yields 0 when the tool is absent, and the check's
# own status when it is present, so a genuine formatting failure still breaks
# the `&&` rather than being swallowed by the skip.
adapters:
	@$(FMT_OK) || echo "adapters: rustfmt not installed, skipping that check"
	@$(CLIPPY_OK) || echo "adapters: clippy not installed, skipping that check"
	@for adapter in $(ADAPTERS); do \
		echo "adapters: $$adapter"; \
		( cd $$adapter && \
			if $(FMT_OK); then $(CARGO) fmt --check; fi && \
			if $(CLIPPY_OK); then $(CARGO) clippy --all-targets -- -D warnings; fi && \
			$(CARGO) test && \
			$(CARGO) build ) || exit 1; \
	done

# Design section 9.2 asks for this in as many words: "a mechanically checkable
# CI assertion" that the core's dependency manifest has not gained an entry.
#
# It is not a grep for `zbus`. Naming the thing to keep out only keeps *that*
# thing out, and the next adapter brings something else. Instead the core's
# lockfile is checked against `deny.toml`'s allow list, which is the written
# form of constraint 3 -- so any new core dependency fails this, whether an
# adapter brought it or not.
#
# The second half is the gate checking itself. If the adapter's lockfile has no
# heavy dependency in it, then "the core does not have the adapter's
# dependencies" is true for the boring reason and proves nothing. So it also
# asserts that the adapter really does carry what it is supposed to be
# containing -- a gate that passes on an empty input set is the failure mode
# this project keeps finding.
nm-containment:
	@allowed=$$(sed -n 's/.*{ crate = "\([^"]*\)".*/\1/p' deny.toml | sort -u); \
	present=$$(sed -n 's/^name = "\(.*\)"/\1/p' Cargo.lock | grep -v '^netcfgd' | sort -u); \
	leaked=""; \
	for crate in $$present; do \
		echo "$$allowed" | grep -qx "$$crate" || leaked="$$leaked $$crate"; \
	done; \
	if [ -n "$$leaked" ]; then \
		echo "nm-containment: the core workspace has dependencies deny.toml does not allow:"; \
		echo "nm-containment:  $$leaked"; \
		echo "nm-containment: constraint 3 and design section 9.2 -- an adapter's"; \
		echo "nm-containment: dependencies belong to its own workspace, and a new core"; \
		echo "nm-containment: dependency is a decision, not a lockfile update"; \
		exit 1; \
	fi; \
	for adapter in $(ADAPTERS); do \
		if [ ! -f $$adapter/Cargo.lock ]; then \
			echo "nm-containment: $$adapter has no lockfile, so this proved nothing"; \
			echo "nm-containment: run 'make adapters' first"; \
			exit 1; \
		fi; \
		count=$$(sed -n 's/^name = "\(.*\)"/\1/p' $$adapter/Cargo.lock | wc -l); \
		if [ "$$count" -lt 20 ]; then \
			echo "nm-containment: $$adapter has $$count dependencies, which is too few"; \
			echo "nm-containment: for this check to mean anything -- it is supposed to be"; \
			echo "nm-containment: containing a D-Bus stack"; \
			exit 1; \
		fi; \
	done; \
	echo "nm-containment: ok, $$(echo "$$present" | wc -w) core dependencies, all allowed"

# The shell netcfgd ships. A helper is a program somebody installs and runs as
# root against their modem, so a syntax error in one is not a smaller problem
# than one in the daemon -- and `sh -n` costs nothing.
#
# Counted, because a glob that matches nothing passes: this project has caught
# that exact failure in a `make packaging` check before.
shell:
	@count=0; \
	for script in helper/* tests/live/*.sh; do \
		[ -f "$$script" ] || continue; \
		sh -n "$$script" || exit 1; \
		count=$$((count + 1)); \
	done; \
	if [ "$$count" -lt 10 ]; then \
		echo "shell: only $$count scripts checked, which is too few to mean anything"; \
		exit 1; \
	fi; \
	echo "shell: ok, $$count scripts parse"

# rustfmt and clippy, skipped loudly rather than failed when absent -- the rule
# `gui` and `deny` already follow, and for the same reason each states: a gate
# nobody can run locally is a gate that rots.
#
# Neither ships with a distro rustc, and this tree is developed on one (no
# rustup, per section 10's cross-build note). So `make check` stopped at the
# second of its seventeen gates with `error: no such command: fmt` and never
# reached the other fifteen -- which is the failure `.github/workflows/
# check.yml` names when it installs both by name, "fails in a way that reads
# like a code problem", solved there and left standing here.
#
# Two things keep the skip from being a vacuous pass. CI installs both, so the
# real check runs where a regression would be published; and `make style`
# gates indentation in this tree regardless, so a skipped `fmt` is not an
# unchecked tree -- rustfmt.toml's `hard_tabs` is load-bearing for what the
# tool *writes*, not for what is verified.
#
# The probe asks cargo whether the subcommand runs rather than looking for a
# binary by name, because rustup and Debian put the shim in different places
# and the question is only ever "will the next line work".
fmt:
	@if $(FMT_OK); then \
		$(CARGO) fmt --check; \
	else \
		echo "fmt: rustfmt not installed, skipping"; \
		echo "fmt:   apt install rustfmt, or rustup component add rustfmt"; \
	fi

# Hard failure rather than a skip, matching `apk`: this one is asked for
# deliberately and its whole purpose is to rewrite files, so doing nothing
# quietly is the one answer that would be wrong.
fmt-fix:
	@$(FMT_OK) || { \
		echo "fmt-fix: rustfmt is not installed, so there is nothing to rewrite"; \
		echo "fmt-fix:   apt install rustfmt, or rustup component add rustfmt"; \
		exit 1; }
	$(CARGO) fmt

clippy:
	@if $(CLIPPY_OK); then \
		$(CARGO) clippy --workspace --all-targets -- -D warnings; \
	else \
		echo "clippy: not installed, skipping"; \
		echo "clippy:   apt install rust-clippy, or rustup component add clippy"; \
	fi

# The C client's test binary, which `conformance` and `test` both need.
#
# A FORCE prerequisite and not a bare rule: only the sub-make knows whether
# client/'s sources moved, and a rule with no prerequisites fires solely when
# its target is *missing* -- so once the binary existed it would be treated as
# current forever, and the conformance check would compare against whatever was
# built last week.
client/tests/client_test: FORCE
	@$(MAKE) --no-print-directory -C client tests/client_test

# The two client implementations, asked the same questions.
#
# The only gate here that compares two *clients*. Every other one reads the
# schema witness from one side: it pins what netcfgd sends, and nothing pinned
# what a second implementation made of it -- which is how one access point's
# name came to be spelled three ways, with the TUI's spelling losing the
# network's identity entirely.
#
# In `check` and before `test`, because `test` runs the same comparison as part
# of the workspace and needs the binary to exist. The Rust side *fails* rather
# than skips when it is absent, so a missing binary is a red gate rather than a
# green one that compared nothing.
conformance: client/tests/client_test
	$(CARGO) test -p netcfgd-cli both_client_implementations_extract_the_same_facts

test: client/tests/client_test
	$(CARGO) test --workspace

FORCE:

# section 1 constraint 4: forbid(unsafe_code) holds everywhere except netcfgd-sys,
# which is the sole audited exception. Checked by reading the crate roots rather
# than by trusting that nobody removed the attribute, since its absence is
# silent -- the code still compiles, it just stops being checked.
# Every crate root in the workspace, not just the ones under crates/. This
# globbed `crates/*` alone until M5, so `backend/netcfgd-supplicant` went
# unchecked from the day it was written -- and it was missing the attribute. A
# policy gate that cannot see half the tree enforces nothing, so it now counts
# what it found and fails if that number collapses.
# The directories every crate root lives under. Named once so that the gate
# and its existence check cannot disagree about what is being read.
POLICY_ROOTS = crates backend

unsafe-policy:
	@for path in $(POLICY_ROOTS); do \
		[ -d "$$path" ] || { \
			echo "unsafe-policy: $$path does not exist, so this gate would"; \
			echo "unsafe-policy:   check only part of the tree and still say ok"; \
			exit 1; \
		}; \
	done
	@fail=0; \
	roots=$$(find $(POLICY_ROOTS) -name lib.rs -o -name main.rs | grep '/src/' | sort); \
	if [ "$$(echo "$$roots" | wc -l)" -lt 10 ]; then \
		echo "unsafe-policy: found $$(echo "$$roots" | wc -l) crate roots, expected more"; \
		exit 1; \
	fi; \
	for root in $$roots; do \
		[ -f "$$root" ] || continue; \
		crate=$$(basename $$(dirname $$(dirname "$$root"))); \
		if [ "$$crate" = "netcfgd-sys" ]; then \
			continue; \
		fi; \
		if ! head -n 1 "$$root" | grep -q '^#!\[forbid(unsafe_code)\]$$'; then \
			echo "unsafe-policy: $$root does not open with #![forbid(unsafe_code)]"; \
			fail=1; \
		fi; \
	done; \
	if [ ! -d crates/netcfgd-sys ]; then \
		:; \
	elif ! grep -q 'SAFETY:' -r crates/netcfgd-sys/src 2>/dev/null; then \
		echo "unsafe-policy: netcfgd-sys has no SAFETY comments"; \
		fail=1; \
	fi; \
	[ $$fail -eq 0 ] && echo "unsafe-policy: ok"; \
	exit $$fail

# An executor built without the current document silently loses things: DNS
# stops flattening across scopes, a supplicant gets started with no networks,
# and the run directory reverts to the compiled-in default. Nothing fails; the
# apply just does less than it said.
#
# Four call sites in the daemon used to construct one and exactly one
# remembered `with_context`, so the same apply behaved differently depending on
# whether it arrived at startup, over the socket, from drift, or from a revert.
# `State::executor` is now the only place that may build one, and this is what
# keeps it that way -- a fifth call site is a one-line diff that would
# otherwise be invisible in review.
executor-policy:
	@sites=$$(grep -rn 'KernelExecutor::new' crates/netcfgd-daemon/src \
		--include='*.rs' | grep -v ':[0-9]*:[[:space:]]*//'); \
	count=$$(printf '%s\n' "$$sites" | grep -c . || true); \
	if [ "$$count" != "1" ]; then \
		echo "executor-policy: $$count places build a KernelExecutor, expected 1"; \
		printf '%s\n' "$$sites"; \
		echo "executor-policy: use State::executor, which supplies the document"; \
		exit 1; \
	fi; \
	if ! grep -v '^[[:space:]]*//' crates/netcfgd-daemon/src/state.rs \
		| grep -q 'with_context'; then \
		echo "executor-policy: State::executor no longer supplies the document"; \
		exit 1; \
	fi; \
	echo "executor-policy: ok"

DESTDIR ?=
PREFIX  ?= /usr
SBINDIR ?= $(PREFIX)/sbin
BINDIR  ?= $(PREFIX)/bin
DATADIR ?= $(PREFIX)/share
# Where gui/Makefile leaves its binary. Its own BUILD_DIR defaults to `build`
# and is not visible here, so this tracks it and is overridable the same way.
GUI_BUILD_DIR ?= gui/build
SYSCONFDIR ?= /etc

# Two binaries and a config directory. Nothing else, and nothing that makes
# installing netcfgd install anything of anybody else's.
#
# The init glue is deliberately not here. Each `install-*` target below writes
# one file for one init system, and a machine gets the one it runs -- installing
# a systemd unit on a machine without systemd would be litter, and depending on
# systemd to install netcfgd would be the coupling this project spends its
# constraints avoiding. The unit files are text; they link nothing and require
# nothing.
install:
	$(CARGO) build --release
	@$(MAKE) --no-print-directory ncfg-link PROFILE=release
	install -d $(DESTDIR)$(SBINDIR) $(DESTDIR)$(BINDIR) $(DESTDIR)$(SYSCONFDIR)/netcfgd
	install -m 0755 target/release/netcfgd $(DESTDIR)$(SBINDIR)/netcfgd
	@# One binary, two names. Absolute, so it points at the installed daemon
	@# rather than at whatever happens to sit beside it -- which means it
	@# dangles inside a DESTDIR staging root and resolves once that root is
	@# unpacked at /. That is what a package expects.
	ln -sf $(SBINDIR)/netcfgd $(DESTDIR)$(BINDIR)/ncfg
	@# netifrc's `net.example` shape: every feature, commented, in the
	@# directory being configured. It is documentation for the case the manual
	@# is not reachable -- a machine with no network cannot look anything up,
	@# and that is exactly the machine somebody is configuring by hand.
	@#
	@# Inert by construction rather than by convention: the loader takes
	@# `netcfgd.conf` by exact name and `conf.d/*.conf` by extension, and this
	@# is neither. `crates/netcfgd-compile/tests/example.rs` pins that, and
	@# compiles every example in it so the file cannot describe a language the
	@# compiler has stopped speaking.
	install -m 0644 doc/netcfgd.conf.example \
		$(DESTDIR)$(SYSCONFDIR)/netcfgd/netcfgd.conf.example
	@echo "install: netcfgd and ncfg installed; no init glue"
	@echo "install:   $(SYSCONFDIR)/netcfgd/netcfgd.conf.example documents every feature"
	@echo "install:   make install-systemd | install-openrc | install-procd"
	@# Constraint 2: the filesystem reflects use. conf.d/, secrets/ and hooks/
	@# appear when something needs them, so they are not created here. The
	@# example is not a feature's file and creates no capability, which is why
	@# it does not breach that -- project.md section 1 records the distinction.

# The reference modem helper. Optional and separate on purpose: decision 0045
# says the helper is plural, and installing one by default would make it the
# blessed one. It also needs `mbimcli`, which most machines have no use for.
install-modem-mbim:
	install -d $(DESTDIR)$(BINDIR)
	install -m 0755 helper/netcfgd-modem-mbim $(DESTDIR)$(BINDIR)/netcfgd-modem-mbim
	@echo "install-modem-mbim: installed; it needs mbimcli from libmbim-utils"
	@echo "install-modem-mbim:   doc/interface-report.md is the contract -- write"
	@echo "install-modem-mbim:   your own helper if this one does not fit"

# The Qt client, opt-in the way install-modem-mbim is.
#
# Not part of `make install`, and the reason is the same one that keeps it out
# of the .deb: the daemon's whole claim is that it needs nothing, and a client
# that pulls in a toolkit is not something to install on a machine that did not
# ask for it. `make gui` builds it; this puts it somewhere.
install-gui:
	@[ -x $(GUI_BUILD_DIR)/netcfgd-gui ] || { \
		echo "install-gui: $(GUI_BUILD_DIR)/netcfgd-gui is not built -- run \`make gui\` first"; \
		exit 1; \
	}
	install -d $(DESTDIR)$(BINDIR) $(DESTDIR)$(DATADIR)/applications
	install -m 0755 $(GUI_BUILD_DIR)/netcfgd-gui $(DESTDIR)$(BINDIR)/netcfgd-gui
	install -m 0644 gui/packaging/netcfgd-gui.desktop \
		$(DESTDIR)$(DATADIR)/applications/netcfgd-gui.desktop
	@echo "install-gui: netcfgd-gui installed; it needs libqt6widgets6 at run time"
	@echo "install-gui:   and links libQt6DBus, which the daemon does not"

install-systemd:
	install -d $(DESTDIR)/usr/lib/systemd/system
	install -m 0644 packaging/systemd/netcfgd.service \
		$(DESTDIR)/usr/lib/systemd/system/netcfgd.service
	@echo "install-systemd: netcfgd.service installed, not enabled"
	@echo "install-systemd:   to make netcfgd the only network daemon, see"
	@echo "install-systemd:   packaging/systemd/netcfgd-exclusive.conf"

# The NetworkManager shim, built from its own workspace.
#
# Release, and separate from `make adapters`, which builds debug and runs the
# checks. Kept out of `install` for the reason `install-gui` is: the shim is
# eighty-odd crates of D-Bus that constraint 3 keeps off the daemon's path, and
# a machine installing netcfgd is not thereby asking for them.
nm:
	cd adapter/netcfgd-nm && $(CARGO) build --release

install-nm:
	@[ -x adapter/netcfgd-nm/target/release/netcfgd-nm ] || { \
		echo "install-nm: the shim is not built -- run \`make nm\` first"; \
		exit 1; }
	install -d $(DESTDIR)$(BINDIR) $(DESTDIR)$(DATADIR)/dbus-1/system.d \
		$(DESTDIR)/usr/lib/systemd/system
	install -m 0755 adapter/netcfgd-nm/target/release/netcfgd-nm \
		$(DESTDIR)$(BINDIR)/netcfgd-nm
	@# Its own, rather than relying on NetworkManager's. The right to own that
	@# bus name is granted by NetworkManager's policy file today, so removing
	@# that package would take the grant with it -- on exactly the machine the
	@# shim is for. tool/dbus_policy_gate.py keeps the file and the code in
	@# step.
	install -m 0644 packaging/dbus/netcfgd-nm.conf \
		$(DESTDIR)$(DATADIR)/dbus-1/system.d/netcfgd-nm.conf
	install -m 0644 packaging/systemd/netcfgd-nm.service \
		$(DESTDIR)/usr/lib/systemd/system/netcfgd-nm.service
	@echo "install-nm: netcfgd-nm installed, not enabled and not started"
	@echo "install-nm:   starting it takes NetworkManager's bus name and stops"
	@echo "install-nm:   NetworkManager, so it is enabled deliberately:"
	@echo "install-nm:     systemctl enable --now netcfgd netcfgd-nm"
	@echo "install-nm:   and undone the same way, with no network needed:"
	@echo "install-nm:     systemctl disable --now netcfgd netcfgd-nm"
	@echo "install-nm:     systemctl enable --now NetworkManager"

install-openrc:
	install -d $(DESTDIR)$(SYSCONFDIR)/init.d
	install -m 0755 packaging/openrc/netcfgd $(DESTDIR)$(SYSCONFDIR)/init.d/netcfgd

install-procd:
	install -d $(DESTDIR)$(SYSCONFDIR)/init.d
	install -m 0755 packaging/procd/netcfgd $(DESTDIR)$(SYSCONFDIR)/init.d/netcfgd

# ---------------------------------------------------------------- packages
#
# Two package formats, because netcfgd's two documented init systems live on
# two distributions: Debian runs systemd, Alpine runs OpenRC. Each package
# ships the init glue for the machine it targets and no other -- the same rule
# `install` follows, and for the same reason.
#
# **Installing either one configures nothing and starts nothing.** The unit or
# init script is installed and left disabled. A network daemon that took over
# on `apt install` could take a machine off the network before its operator had
# written a line, and this project's whole shape is that it says what it will
# do before doing it.
#
# The version is the crate's, plus enough of the git history to sort: a package
# built from a later commit must upgrade one built from an earlier, or an
# evaluation cannot install twice.
PKG_NAME    ?= netcfgd
# The one place the version is stated; Cargo.toml and debian/changelog
# are checked against it by `make version-check`.
VERSION     ?= $(shell cat VERSION)
GIT_COUNT   := $(shell git rev-list --count HEAD 2>/dev/null || echo 0)
GIT_SHA     := $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)
# Two spellings of one version, because the two formats disagree about what a
# pre-release looks like. Debian takes `~`, which sorts *before* the release it
# is heading for, and accepts the commit hash. Alpine's grammar takes neither:
# a version is digits and dots with a `_git` suffix, so the hash cannot go in
# it. Both increase with the commit count, which is what an evaluator needs --
# a package built from a later commit must upgrade one built from an earlier.
# Alpine keeps the git suffix: its packages are built from a snapshot
# tarball rather than a release, and the count distinguishes them.
APK_VERSION ?= $(VERSION)_git$(GIT_COUNT)
# Not committed anywhere: a maintainer field belongs to whoever built the
# package, and a name baked into a template is wrong for everybody else.
MAINTAINER  ?= $(shell git config user.name 2>/dev/null || echo netcfgd) <$(shell git config user.email 2>/dev/null || echo netcfgd@localhost)>
DIST        ?= dist

# `Depends` is derived, never guessed: the binary links ncurses behind a
# default-on feature, and a hand-written list would be wrong the first time
# that changed. dpkg-shlibdeps reads the ELF and gives versioned dependencies.
# Native Debian packaging. Only the systemd glue goes in the deb; Alpine and
# OpenWrt have their own packaging under packaging/ and are untouched by this.
# The daemon, the shim and the desktop client.
#
# One source package with a build profile rather than two source packages,
# because `client/` is shared: the GUI links it and so does `conformance`.
# A plain `make deb` needs no Qt at all, which is the property that made the
# separation worth having in the first place. See 0126.
deb-gui:
	@command -v qmake6 >/dev/null 2>&1 || { \
		echo "deb-gui: qmake6 is not installed (apt install qt6-base-dev)"; \
		exit 1; }
	$(MAKE) deb DEB_BUILD_PROFILES="pkg.netcfgd.gui"

deb: version-check
	@test -n "$(DIST)" || { echo "deb: DIST is empty, refusing" >&2; exit 1; }
	DEB_BUILD_PROFILES="$(DEB_BUILD_PROFILES)" dpkg-buildpackage -b -us -uc
	@mkdir -p $(DIST)
	@# Every artifact by name, `-dbgsym` and the shim included. A glob that
	@# names only the source package leaves a binary package in the parent
	@# directory for ever -- which is what raidcfgd's rule found, and adding a
	@# second binary package is exactly when it would have happened again.
	@for f in ../netcfgd_$(VERSION)_*.deb ../netcfgd-dbgsym_$(VERSION)_*.deb \
	          ../netcfgd-nm_$(VERSION)_*.deb ../netcfgd-nm-dbgsym_$(VERSION)_*.deb \
	          ../netcfgd-gui_$(VERSION)_*.deb ../netcfgd-gui-dbgsym_$(VERSION)_*.deb \
	          ../netcfgd_$(VERSION)_*.buildinfo ../netcfgd_$(VERSION)_*.changes; do \
		[ -e "$$f" ] && mv -f "$$f" $(DIST)/ || true; \
	done
	@# The property the whole packaging rests on, checked on the artifact
	@# rather than on the recipe that produced it. `debian/postinst` states it
	@# in a comment, `debian/rules` arranges it with --no-enable --no-start,
	@# and neither is evidence: the snippets are appended by debhelper at
	@# build time, so what a package does on install is only readable from the
	@# package.
	@#
	@# Two markers, both learned from watching the check fail to fire when the
	@# override was removed:
	@#
	@#   - ANY `deb-systemd-invoke` in a postinst starts or restarts something.
	@#     The first version looked for `deb-systemd-invoke.*start` and the
	@#     generated code says `deb-systemd-invoke $$_dh_action`, with the verb
	@#     assigned three lines earlier -- so the check could not have failed
	@#     for the thing it was written to find.
	@#   - `debian-installed` is what distinguishes the two enable forms. Both
	@#     carry a `was-enabled` guard, and debhelper's own comment on the
	@#     default one says "was-enabled defaults to true, so new installations
	@#     run enable" -- so guarding on that word proves nothing.
	@#
	@# Comments are stripped first: this file's prose names the commands it
	@# looks for, and matched itself.
	@#
	@# A package with no unit has no maintainer script and enables nothing by
	@# construction -- netcfgd-gui is that package. It counts as seen and not
	@# as inspected, so the "checked nothing" guard still means what it says.
	@fail=0; \
	seen=0; \
	checked=0; \
	for deb in $(DIST)/netcfgd_$(VERSION)_*.deb $(DIST)/netcfgd-nm_$(VERSION)_*.deb \
	           $(DIST)/netcfgd-gui_$(VERSION)_*.deb; do \
		[ -e "$$deb" ] || continue; \
		seen=$$(( seen + 1 )); \
		script=$$(dpkg-deb -I "$$deb" postinst 2>/dev/null | sed 's/#.*//'); \
		[ -n "$$script" ] || continue; \
		checked=$$(( checked + 1 )); \
		if printf '%s\n' "$$script" | grep -q 'deb-systemd-invoke'; then \
			echo "deb: $$deb starts or restarts a service on install"; fail=1; \
		fi; \
		if printf '%s\n' "$$script" | grep -q 'deb-systemd-helper enable' && \
		   ! printf '%s\n' "$$script" | grep -q 'debian-installed'; then \
			echo "deb: $$deb enables a service on install"; fail=1; \
		fi; \
	done; \
	if [ "$$checked" -eq 0 ]; then \
		echo "deb: no postinst was inspected, so this checked nothing"; fail=1; \
	fi; \
	[ $$fail -eq 0 ] || exit 1; \
	echo "deb: $$seen packages, $$checked with a postinst, none enables or starts anything"
	@ls -1 $(DIST)/*.deb

# VERSION is the source; debian/changelog and Cargo.toml are held to it.
version-check:
	@file=$$(cat VERSION); \
	changelog=$$(dpkg-parsechangelog -SVersion 2>/dev/null); \
	cargo=$$(sed -n 's/^version *= *"\(.*\)"/\1/p' Cargo.toml | head -1); \
	rc=0; \
	if [ -n "$$changelog" ] && [ "$$file" != "$$changelog" ]; then \
		echo "version-check: VERSION says $$file, debian/changelog says $$changelog"; rc=1; \
	fi; \
	case "$$cargo" in \
	"$$file"|"$$file".*) ;; \
	*) echo "version-check: VERSION says $$file, Cargo.toml says $$cargo"; rc=1 ;; \
	esac; \
	[ $$rc -eq 0 ] && echo "version-check: $$file, in step"; \
	exit $$rc

apk:
	@command -v abuild >/dev/null 2>&1 || { \
		echo "apk: abuild is not installed. It is Alpine's own tool and is not"; \
		echo "apk:   packaged for Debian. Build it where it lives:"; \
		echo "apk:     make apk-container"; \
		exit 1; }
	@$(MAKE) --no-print-directory apk-source
	@cd $(DIST) && abuild -F -P "$$PWD" checksum && abuild -F -P "$$PWD" -r

# Alpine's toolchain, in Alpine. Same tarball, same APKBUILD, `abuild` doing the
# work -- so what this produces is a real package built by the distribution's
# own tool, not something this repo approximated. The container is how the
# root-only live scripts are run too; it is the established answer here to "the
# machine at hand is not the machine that matters".
#
# `git archive HEAD` is the source, so uncommitted work is not in the package.
# That is deliberate: a package built from a dirty tree is not reproducible from
# anything.
APK_IMAGE ?= alpine:latest
apk-container:
	@$(MAKE) --no-print-directory apk-source
	@docker run --rm -v "$$PWD/$(DIST)":/dist \
		-v "$$PWD/packaging/alpine":/build:ro -w /dist \
		$(APK_IMAGE) sh /build/build-in-container.sh
	@ls -l $(DIST)/*.apk 2>/dev/null | sed 's/^/apk-container: /' || \
		{ echo "apk-container: no package was produced"; exit 1; }

# The tarball an APKBUILD builds from, plus the APKBUILD with its two blanks
# filled in. Separate so it can be inspected, and so the container target and a
# real Alpine machine share one definition.
apk-source:
	@mkdir -p $(DIST)
	@git archive --format=tar --prefix=$(PKG_NAME)-$(APK_VERSION)/ HEAD \
		| gzip -n > $(DIST)/$(PKG_NAME)-$(APK_VERSION).tar.gz
	@sed -e "s|@PKGVER@|$(APK_VERSION)|" -e "s|@MAINTAINER@|$(MAINTAINER)|" \
		packaging/alpine/APKBUILD.in > $(DIST)/APKBUILD
	@printf 'apk-source: %s and %s\n' "$(DIST)/APKBUILD" \
		"$(DIST)/$(PKG_NAME)-$(APK_VERSION).tar.gz"

# M4 froze the document schema and the socket API. The freeze is enforced by
# two witnesses under doc/schema/: one document with every field and variant
# populated, and one of every socket message. Any change to either wire form
# moves those bytes, and the diff is the review.
#
# The tests run inside `make check`, so there is no separate gate target -- what
# is here is the deliberate way to move the line. Running it is not the
# decision; the commit message is. A field added is a minor bump and fine.
# Anything else is major, and every consumer refuses the document.
schema-bless:
	@NCFG_BLESS=1 $(CARGO) test -q -p netcfgd-model --test frozen >/dev/null
	@NCFG_BLESS=1 $(CARGO) test -q -p netcfgd-model --test observed >/dev/null
	@NCFG_BLESS=1 $(CARGO) test -q -p netcfgd-plan --test frozen >/dev/null
	@NCFG_BLESS=1 $(CARGO) test -q -p netcfgd-proto --test frozen >/dev/null
	@echo "schema-bless: witnesses rewritten; `git diff --stat doc/schema | tail -1`"
	@echo "schema-bless: say in the commit whether this is a minor or a major bump"

# The init glue is data, so nothing compiles it and a typo would be found by
# whoever first tried to boot. These are the checks that can be made without an
# init system to hand: every script parses, the unit passes systemd's own
# verifier where it exists, and every binary path the scripts name is one the
# install targets actually create -- which is the mistake that turns a working
# daemon into one that silently never starts.
#
# The path check extracts what the scripts *declare* -- the Exec lines, the
# OpenRC `command=`, procd's `command` parameter -- rather than grepping for
# paths that look right. The first version did the latter and tested nothing: a
# unit pointing at /usr/local/bin/netcfgd matched no pattern and so raised
# nothing, and /usr/sbin/netcfgdd matched as a prefix of the correct path and
# passed. Both were caught by deliberately breaking it. There is also a guard
# below against the extraction itself finding nothing, which is the failure
# mode a check like this dies of quietly.
#
# No backticks anywhere in this recipe. The first version put one in a message
# and make handed it to the shell, which ran the install target it was warning
# about.
# The tokens the `deb` and `apk-source` recipes substitute. Listed here so the
# gate below can say when a template grows a placeholder nothing fills in --
# an unsubstituted @VERSION@ ships a package versioned literally "@VERSION@",
# which dpkg accepts and which sorts below every real version.
FILLED = @VERSION@ @ARCH@ @DEPENDS@ @MAINTAINER@ @PKGVER@

# The maintainer scripts checked here are `debian/`'s, not
# `packaging/debian/`'s. The latter was the pre-debhelper generation and this
# gate checked it for as long as it existed, so the scripts dpkg actually ships
# were never parsed -- and they had already drifted, the group reservation
# reaching one copy and not the other. That directory is gone.
# One check inside this deserves its reason up here, where it is a make
# comment rather than shell: the unit must grant what the daemon actually
# does. The control socket's group follows the control policy, and giving a
# file to a group the process is not in needs CAP_CHOWN even as root -- so a
# bounding set without it produces a socket no group member can open, under
# systemd only, with everything else looking correct. That is what shipped,
# and an operator hit it. The check is keyed on the code rather than on a
# remembered rule: if the chown goes away the requirement goes with it, and
# if the grep stops matching it says so instead of passing.
packaging:
	@# install and uninstall must agree, checked statically so it runs
	@# everywhere rather than only where a full install works.
	@python3 tool/uninstall_gate.py
	@# Every config key the compiler accepts is classified, so that a key
	@# added later cannot default to "a client may send this". 0127.
	@python3 tool/privilege_gate.py
	@# The shim's bus policy against the interfaces the shim serves. A missing
	@# entry is a client method call denied at run time, and only where
	@# NetworkManager's own policy file is absent -- which is the machine the
	@# shim exists for.
	@python3 tool/dbus_policy_gate.py
	@# Every /etc path netcfgd writes against what its own systemd unit allows.
	@# A disagreement is EROFS at run time on a packaged install and in no test,
	@# because every test writes into a temp directory. 0127's writes were
	@# refused by netcfgd's own sandbox this way.
	@python3 tool/sandbox_gate.py
	@# The tag-implies-origin inference in netcfgd-observe is sound only while
	@# the tag has one producer. That is a property of the tree, so it is
	@# checked here rather than trusted there.
	@python3 tool/tag_producer_gate.py
	@fail=0; \
	FILLED="$(FILLED)"; \
	if [ -z "$$(sed -n 's/^Exec[A-Za-z]*=\([^ ]*\).*/\1/p' packaging/systemd/netcfgd.service)" ]; then \
		echo "packaging: no Exec lines found -- the extraction below is checking nothing"; \
		exit 1; \
	fi; \
	for script in packaging/openrc/netcfgd packaging/procd/netcfgd \
			debian/postinst debian/prerm \
			debian/postrm packaging/alpine/build-in-container.sh; do \
		sh -n "$$script" || { echo "packaging: $$script does not parse"; fail=1; }; \
	done; \
	for script in debian/postinst debian/prerm \
			debian/postrm; do \
		[ -x "$$script" ] || { echo "packaging: $$script is not executable, so dpkg would not run it"; fail=1; }; \
	done; \
	if grep -q 'fn chown_group' crates/netcfgd-daemon/src/server.rs; then \
		for field in CapabilityBoundingSet AmbientCapabilities; do \
			if ! grep -q "^$$field=.*CAP_CHOWN" packaging/systemd/netcfgd.service; then \
				echo "packaging: the daemon chowns the control socket and $$field"; \
				echo "packaging:   in netcfgd.service does not grant CAP_CHOWN, so the"; \
				echo "packaging:   policy's group cannot be given the socket"; \
				fail=1; \
			fi; \
		done; \
	else \
		echo "packaging: chown_group is gone from server.rs; this check is stale"; \
		fail=1; \
	fi; \
	if command -v systemd-analyze >/dev/null 2>&1; then \
		out=$$(systemd-analyze verify packaging/systemd/netcfgd.service \
			packaging/systemd/netcfgd-nm.service 2>&1 \
			| grep -v 'is not executable'); \
		if [ -n "$$out" ]; then echo "$$out"; fail=1; fi; \
	fi; \
	installed="$(SBINDIR)/netcfgd $(BINDIR)/ncfg $(BINDIR)/netcfgd-nm"; \
	declared=$$( { \
		sed -n 's/^Exec[A-Za-z]*=\([^ ]*\).*/\1/p' packaging/systemd/netcfgd.service; \
		sed -n 's/^Exec[A-Za-z]*=\([^ ]*\).*/\1/p' packaging/systemd/netcfgd-nm.service; \
		sed -n 's/^command="\([^"]*\)".*/\1/p' packaging/openrc/netcfgd; \
		sed -n 's/.*procd_set_param command \([^ ]*\).*/\1/p' packaging/procd/netcfgd; \
		sed -n 's/^\t*\(\/[^ ]*ncfg\) .*/\1/p' packaging/procd/netcfgd; \
	} | sort -u); \
	for path in $$declared; do \
		case "$$installed" in \
		*"$$path"*) ;; \
		*) echo "packaging: $$path is named by an init script and never installed"; \
		   fail=1 ;; \
		esac; \
	done; \
	for template in packaging/alpine/APKBUILD.in; do \
		for token in $$(grep -o '@[A-Z]*@' "$$template" | sort -u); do \
			case " $$FILLED " in \
			*" $$token "*) ;; \
			*) echo "packaging: $$template uses $$token, which no recipe substitutes"; \
			   fail=1 ;; \
			esac; \
		done; \
	done; \
	[ $$fail -eq 0 ] && echo "packaging: ok"; \
	exit $$fail

# code-style.md section 4: source, comments and doc comments are ASCII. Markdown
# is exempt and is not checked here. This caught real drift the first time it
# ran -- em dashes and section signs are easy to type and invisible in review,
# which is exactly why the rule needs a gate rather than good intentions.
# `backends` and `tests` are in the list for the reason the unsafe-policy gate
# learned the hard way: a gate that cannot see half the tree enforces nothing.
# This globbed `crates` alone until access points were written, so every line of
# `backend/` had gone unchecked since M2 -- it happened to be clean, which is
# luck rather than evidence. Shell scripts count as source; markdown does not,
# and project.md section 9 says so.
# Every directory that holds source, not just the ones that existed when this
# was written. `adapters` and `helpers` were both outside it -- the same shape
# as the unsafe-policy gate globbing only `crates/*` and missing a whole backend
# for a milestone.
ASCII_PATHS  = crates backend adapter helper tests Cargo.toml Makefile
# `netcfgd-*` catches an installed helper, which is a script with no extension
# because it ends up on a PATH. Filtering by extension alone would have skipped
# the entire helpers directory while appearing to cover it.
#
# `--exclude-dir=target` because that pattern also matches a *compiled* binary,
# and an adapter builds one into its own tree. Widening the gate found it
# immediately, which is the gate working -- on the wrong file.
ASCII_KINDS  = --include='*.rs' --include='*.toml' --include='*.sh' \
	--include='netcfgd-*' --exclude-dir=target

ascii:
	@for path in $(ASCII_PATHS); do \
		[ -e "$$path" ] || { \
			echo "ascii: $$path does not exist, so this gate would read less"; \
			echo "ascii:   than it names and still say ok -- fix ASCII_PATHS"; \
			exit 1; \
		}; \
	done
	@if grep -rlP '[^\x00-\x7F]' $(ASCII_KINDS) \
		$(ASCII_PATHS) 2>/dev/null | grep -q .; then \
		echo "ascii: non-ASCII found in:"; \
		grep -rlP '[^\x00-\x7F]' $(ASCII_KINDS) \
			$(ASCII_PATHS) 2>/dev/null; \
		echo "ascii: write -- for an em dash, and 'section N' for a section sign"; \
		exit 1; \
	fi; \
	echo "ascii: ok"

# Cross-compiling, which is the one thing on `What would prove it` that needs
# no hardware at all.
#
# That list says netcfgd "has never run on the class of device it was designed
# for", and that mips and arm "have not merely failed, they have not been
# attempted" -- because there was no target here to attempt them with. This is
# that target. It does not prove anything runs; it proves the tree builds for a
# machine that is not this one, which is the step before anybody can try.
#
# Deliberately NOT in PORTABLE_GATES, and deliberately not skipping. `gui` and
# `deny` skip when their tool is absent because they run inside `check` on
# machines that are not desktops, and a gate demanding Qt on a router is a gate
# people delete. This is the opposite case: nobody runs `make cross` by
# accident, so a skip would answer the question it was asked with silence. It
# fails, and it names the package that would fix it.
CROSS_TARGET ?= aarch64-unknown-linux-gnu
# The linker for a triple, since cargo will not find one by itself.
#
# A table and not a rule, because the mechanical derivation is wrong and was
# measured to be. Dropping the vendor field turns aarch64-unknown-linux-gnu
# into aarch64-linux-gnu-gcc correctly, and turns armv7-unknown-linux-gnueabihf
# into `armv7-linux-gnueabihf-gcc` -- which does not exist, because Debian
# spells that architecture `arm` where Rust spells it `armv7`. The first draft
# of this target advised `apt install gcc-armv7-linux-gnueabihf`, and no such
# package is in the archive.
#
# A diagnostic that confidently names a package nobody can install is worse
# than one that says less, so an unknown triple gets told it is unknown rather
# than getting a guess wearing the same voice as the two entries that are
# right. Add a row when a triple is actually tried.
CROSS_GNU_aarch64-unknown-linux-gnu      = aarch64-linux-gnu
CROSS_GNU_armv7-unknown-linux-gnueabihf  = arm-linux-gnueabihf
CROSS_GNU_arm-unknown-linux-gnueabi      = arm-linux-gnueabi
CROSS_GNU_mips-unknown-linux-gnu         = mips-linux-gnu
CROSS_GNU_mipsel-unknown-linux-gnu       = mipsel-linux-gnu
CROSS_GNU_riscv64gc-unknown-linux-gnu    = riscv64-linux-gnu
CROSS_GNU = $(CROSS_GNU_$(CROSS_TARGET))
CROSS_CC ?= $(if $(CROSS_GNU),$(CROSS_GNU)-gcc,)
# Cargo takes the linker from an environment variable named after the triple.
CROSS_LINKER_VAR = CARGO_TARGET_$(shell echo $(CROSS_TARGET) | tr 'a-z-' 'A-Z_')_LINKER

cross:
	@std=$$(rustc --print sysroot)/lib/rustlib/$(CROSS_TARGET); \
	skipped=0; \
	if [ -z "$(CROSS_CC)" ]; then \
		echo "cross: no linker known for $(CROSS_TARGET)"; \
		echo "cross:   set CROSS_CC=<triple>-gcc, and add a CROSS_GNU_ row to"; \
		echo "cross:   the Makefile once it is known to be the right one"; \
		skipped=1; \
	elif ! command -v $(CROSS_CC) >/dev/null 2>&1; then \
		echo "cross: no linker $(CROSS_CC) on PATH"; \
		echo "cross:   apt install gcc-$(CROSS_GNU)"; \
		echo "cross:   the workspace also needs the target's ncurses --"; \
		echo "cross:   dpkg --add-architecture, then libncurses-dev:<arch>,"; \
		echo "cross:   or build --no-default-features, which links neither"; \
		skipped=1; \
	else \
		echo "cross: client/ for $(CROSS_TARGET) via $(CROSS_CC)"; \
		$(MAKE) --no-print-directory -C client clean >/dev/null 2>&1; \
		if $(MAKE) --no-print-directory -C client \
			CC=$(CROSS_CC) AR=$(CROSS_GNU)-ar >/dev/null; then \
			printf 'cross:   libncfg_client.a %s bytes\n' \
				"$$(stat -c%s client/libncfg_client.a)"; \
		else \
			echo "cross:   client/ FAILED to build for $(CROSS_TARGET)"; \
			$(MAKE) --no-print-directory -C client clean >/dev/null 2>&1; \
			exit 1; \
		fi; \
		$(MAKE) --no-print-directory -C client clean >/dev/null 2>&1; \
	fi; \
	if [ ! -d "$$std" ]; then \
		echo "cross: no Rust standard library for $(CROSS_TARGET)"; \
		echo "cross:   rustup target add $(CROSS_TARGET)"; \
		echo "cross:   (this toolchain is $$(rustc -vV | awk '/^host/ {print $$2}') and has"; \
		echo "cross:    no rustup; a distro rustc ships one target and cannot add another)"; \
		echo "cross:   a container is the way round it, and has been done:"; \
		echo "cross:     docker run --rm -v \$$PWD:/src:ro rust:1-slim-trixie"; \
		echo "cross:   see section 10, which records what aarch64 measured"; \
		skipped=1; \
	else \
		echo "cross: workspace for $(CROSS_TARGET) via $(CROSS_CC)"; \
		$(CROSS_LINKER_VAR)=$(CROSS_CC) \
			$(CARGO) build --release --target $(CROSS_TARGET) || exit 1; \
		printf 'cross:   netcfgd %s bytes, against %s on x86_64\n' \
			"$$(stat -c%s target/$(CROSS_TARGET)/release/netcfgd)" \
			"$$(awk '/^total/ {print $$2}' size-budget.txt)"; \
	fi; \
	if [ "$$skipped" -ne 0 ]; then \
		echo "cross: $(CROSS_TARGET) was NOT fully attempted -- see above"; \
		exit 1; \
	fi

# The live suite with the things this machine cannot give it.
#
# `make live` skipped six of its thirty-eight scripts here, for two different
# reasons and neither of them a defect: three wanted a program that is not
# installed (hostapd, openvpn, wireguard-tools) and three wanted real root
# (`/dev/ppp`, ports 546 and 547, module loading). A privileged container with
# the packages present answers both, and four of the six then pass.
#
# The remaining two cannot be answered this way and it is worth knowing why
# rather than rediscovering it: `hwsim.sh` loads `mac80211_hwsim`, and a
# container shares the host's kernel, so a module the host does not have cannot
# appear inside one. `delegation.sh` wants `odhcp6c`, which Debian does not
# package at all -- it is OpenWrt's, and that is where that test will first run.
#
# Deliberately not part of `check` or `live`: it pulls an image, installs a
# dozen packages and takes minutes. Nobody should get that by accident.
LIVE_IMAGE ?= rust:1-slim-trixie
# Everything a live script asks for. `dhcpcd-base` was missing from the first
# version, so `dhcpcd.sh` skipped inside the container while passing on the
# host -- a container run that covers *less* than the host is worse than none,
# because it looks like more.
LIVE_PACKAGES = build-essential libncurses-dev iproute2 iputils-ping dnsmasq \
                dhcpcd-base hostapd wpasupplicant openvpn wireguard-tools \
                ppp pppoe iw kmod python3 socat unbound

live-container:
	@command -v docker >/dev/null 2>&1 || { \
		echo "live-container: docker is not installed, and this target is docker"; \
		exit 1; \
	}
	@docker info >/dev/null 2>&1 || { \
		echo "live-container: docker is installed but not usable by this user"; \
		exit 1; \
	}
	@mkdir -p $(DIST)
	@printf '%s\n' \
		'set -eu' \
		'apt-get -qq update >/dev/null' \
		'apt-get -qq install -y $(LIVE_PACKAGES) >/dev/null' \
		'# Copied, not built in place: /src is read-only so the host tree' \
		'# cannot be left holding root-owned build output.' \
		'cp -a /src /work && cd /work' \
		'cargo build --workspace --quiet' \
		'make ncfg-link PROFILE=debug >/dev/null' \
		'exec make live' \
		> $(DIST)/live-container.sh
	docker run --rm --privileged -v "$$PWD":/src:ro -v "$$PWD/$(DIST)":/dist \
		$(LIVE_IMAGE) sh /dist/live-container.sh

# What the shipped binary is allowed to link.
#
# Section 1 constraint 3 and the README's headline both say the core needs
# nothing beyond libc and the kernel, and nothing checked it. `deny` governs
# the *crate* graph, which is a different question: a Rust dependency that
# links a C library adds a NEEDED entry without adding anything `deny` objects
# to, and a build script that finds a system library adds one with no crate at
# all.
#
# Reads the release binary `size` already built, so it costs no rebuild -- and
# runs after it in PORTABLE_GATES for that reason.
#
# ncurses is on the list because `ncfg tui` is a default feature and design
# section 10.2 has always listed it as removable. Measured rather than assumed:
# `--no-default-features` leaves libgcc_s and libc alone, and that build
# produces a byte-identical document, so the feature costs a dependency and
# changes no behaviour.
LINKAGE_ALLOWED = libc.so libgcc_s.so ld-linux libncursesw.so libtinfo.so

linkage:
	@# Built here rather than trusted: whatever is in target/release depends
	@# on the last build's feature set, so a `--no-default-features` binary
	@# left behind would pass this gate while the shipped one links more. It
	@# is a no-op when `size` has already built it.
	@$(CARGO) build --release --quiet
	@bin=target/release/netcfgd; \
	[ -x "$$bin" ] || { \
		echo "linkage: $$bin is missing, so this would check nothing"; \
		exit 1; \
	}; \
	needed=$$(objdump -p "$$bin" 2>/dev/null | awk '/NEEDED/ {print $$2}'); \
	if [ -z "$$needed" ]; then \
		echo "linkage: no NEEDED entries were read at all -- either this is a"; \
		echo "linkage:   static binary or objdump said nothing, and a gate that"; \
		echo "linkage:   cannot tell those apart is not a gate"; \
		exit 1; \
	fi; \
	fail=0; \
	for lib in $$needed; do \
		ok=0; \
		for allowed in $(LINKAGE_ALLOWED); do \
			case "$$lib" in *"$$allowed"*) ok=1 ;; esac; \
		done; \
		[ "$$ok" -eq 1 ] || { \
			echo "linkage: $$bin links $$lib, which constraint 3 does not allow"; \
			echo "linkage:   if this is deliberate, it is a decision to record,"; \
			echo "linkage:   not a line to add to LINKAGE_ALLOWED in passing"; \
			fail=1; \
		}; \
	done; \
	[ "$$fail" -eq 0 ] || exit 1; \
	echo "linkage: $$(echo $$needed | wc -w) shared libraries, all allowed"

# Size, ratcheted, and measured as total installed size.
#
# Per-binary was the wrong metric. What a 16 MB router cares about is how much
# flash the install takes, and per-binary limits actively mislead there: merging
# two binaries that each link most of the workspace makes the one binary bigger
# while making the install a megabyte smaller. A gate that calls that a
# regression is a gate pointing the wrong way.
#
# Per-binary figures are still printed, because "which one grew?" is the next
# question after "did it grow?" -- but the limit is on the sum.
#
# Both verdicts name the ceiling rather than only the limit, because the test
# is against the ceiling and the messages used to report the limit. A passing
# run printed "installed 2341400 of 2337304" -- a number larger than the one it
# was being compared to, beside a green gate -- which reads as a gate that
# failed to enforce, and cost a reader a detour through this recipe to find the
# tolerance. The failing message had the mirror of it: an overage measured from
# the limit, so the arithmetic never explained why a smaller overage had
# passed. A gate nobody can read the output of is one step from a gate nobody
# runs.
size:
	@$(CARGO) build --release --quiet
	@$(MAKE) --no-print-directory ncfg-link PROFILE=release
	@tol=$$(awk '/^tolerance_percent/ {print $$2}' size-budget.txt); \
	limit=$$(awk '/^total/ {print $$2}' size-budget.txt); \
	total=0; \
	while read -r name value; do \
		case "$$name" in ''|\#*|tolerance_percent|total) continue ;; esac; \
		bin=target/release/$$name; \
		[ -f "$$bin" ] || continue; \
		actual=$$(stat -c%s "$$bin"); \
		total=$$(( total + actual )); \
		printf 'size: %-8s %8s\n' "$$name" "$$actual"; \
	done < size-budget.txt; \
	ceiling=$$(( limit + limit * tol / 100 )); \
	if [ "$$total" -gt "$$ceiling" ]; then \
		printf 'size: installed %s bytes, over its %s ceiling by %s\n' \
			"$$total" "$$ceiling" "$$(( total - ceiling ))"; \
		printf 'size:   the limit is %s, with %s%% tolerance on top\n' \
			"$$limit" "$$tol"; \
		echo "size:   raise it in size-budget.txt, and say why in the commit"; \
		exit 1; \
	fi; \
	if [ "$$total" -gt "$$limit" ]; then \
		printf 'size: installed %8s of %s, inside the %s%% tolerance (ceiling %s)\n' \
			"$$total" "$$limit" "$$tol" "$$ceiling"; \
	else \
		printf 'size: installed %8s of %s\n' "$$total" "$$limit"; \
	fi

# Design section 4.6's mechanical test, and constraint 2's enforcement: on a
# machine that has never used an optional feature, the footprint is exactly the
# fixture. A feature that creates a directory unasked has leaked, and the leak
# is a bug rather than a preference.
footprint:
	@$(CARGO) build --quiet
	@$(MAKE) --no-print-directory ncfg-link PROFILE=debug
	@# `ncfg` is a symlink cargo cannot make, and nothing else in `check`
	@# creates the debug one -- `size` makes the release one. So after a
	@# `make clean` this ran a binary that was not there, `|| true` swallowed
	@# it, and the gate reported "/run does not match" for an empty /run. The
	@# check was pointing at the wrong thing entirely, which is why the
	@# missing binary is now its own sentence.
	@[ -x ./target/debug/ncfg ] || { \
		echo "footprint: ./target/debug/ncfg is missing, so this would check nothing"; \
		exit 1; }
	@work=$$(mktemp -d); \
	cp -r tests/footprint/etc "$$work/etc"; \
	mkdir -p "$$work/run"; \
	NCFG_CONFIG_DIR="$$work/etc" NCFG_RUN_DIR="$$work/run" \
		./target/debug/ncfg plan >/dev/null 2>&1 || true; \
	fail=0; \
	for pair in "etc:expected-etc.txt" "run:expected-run.txt"; do \
		dir=$${pair%%:*}; want=tests/footprint/$${pair##*:}; \
		( cd "$$work/$$dir" && find . | sort ) \
			| sed -E 's#^\./observed/.*\.json$$#./observed/<per-interface>#' \
			| sort -u > "$$work/actual.txt"; \
		grep -v '^#' "$$want" | grep -v '^$$' | sort > "$$work/expected.txt"; \
		if ! cmp -s "$$work/actual.txt" "$$work/expected.txt"; then \
			echo "footprint: /$$dir does not match $$want"; \
			diff "$$work/expected.txt" "$$work/actual.txt" | sed 's/^/footprint:   /' || true; \
			fail=1; \
		fi; \
	done; \
	rm -rf "$$work"; \
	[ $$fail -eq 0 ] && echo "footprint: ok"; \
	exit $$fail

# A ratchet on a measurement, exactly like the size gate, and for the same
# reason: design section 10.4's "< 4 MB RSS steady-state" is written **for
# nano**, and decision 0021 dropped the nano tier. What is built today is the
# full tier -- every feature compiled in. size-budget.txt has carried that
# distinction for binary size since M5; this gate did not, and cited the 4 MB
# as though netcfgd were failing a requirement (0104).
#
# It is not, on either reading. Measured on the platform the size posture
# targets -- musl, which is what the apk ships -- the daemon peaks at ~2.9 MB
# with ~205 kB of it anonymous. The glibc figure below is larger because glibc
# is larger: a bigger libc mapping, and allocator arenas worth ~300 kB more.
#
#   glibc, Debian    VmHWM ~4210 kB   RssAnon ~520 kB   Pss ~2465 kB
#   musl,  Alpine    VmHWM ~2920 kB   RssAnon ~205 kB   Pss ~2530 kB
#
# **RssAnon is what netcfgd allocated**; the rest is text, most of it shared
# with every other process on the machine, which is why Pss is little more than
# half of VmHWM. The gate still pins VmHWM -- it is the pessimistic number and
# the one that ratchets honestly -- but it prints the other two, because a
# figure that moves when the C library changes underneath it should not be the
# only thing anybody reads.
#
# **The release binary, which is what ships.** This measured the debug one
# until 0098, and that made the gate sensitive to something it is not about:
# adding an *unused* dependency edge to a crate moved the debug figure by
# ~190 KB, on a binary whose release build was byte-for-byte the same size.
# Measured A/B interleaved, six runs each -- debug 9011 vs 9199 KB for the
# unused edge alone, release 4307 vs 4315, which is no difference at all. A
# 51 MB debug binary's resident set is dominated by metadata layout, and the
# design target was never about that.
#
# `size` already builds release and runs before this in `check`, so measuring
# what ships costs nothing.
#
# The headroom is deliberate: resident size varies with allocator behaviour
# and page reclaim in a way binary size does not, so a limit set at the
# measurement fails on noise. Observed 4208..4384 KB over twelve runs; this is
# the peak plus a noise band of the width the debug measurement showed.

RSS_LIMIT_KB ?= 4608

rss:
	@$(CARGO) build --release --quiet
	@work=$$(mktemp -d); \
	cp -r tests/footprint/etc "$$work/etc"; mkdir -p "$$work/run"; \
	./target/release/netcfgd --config-dir "$$work/etc" --run-dir "$$work/run" \
		--no-apply-on-start >/dev/null 2>&1 & \
	pid=$$!; \
	sleep 2; \
	peak=$$(awk '/VmHWM/ {print $$2}' /proc/$$pid/status 2>/dev/null); \
	anon=$$(awk '/RssAnon/ {print $$2}' /proc/$$pid/status 2>/dev/null); \
	pss=$$(awk '/^Pss:/ {print $$2}' /proc/$$pid/smaps_rollup 2>/dev/null); \
	kill $$pid 2>/dev/null; wait $$pid 2>/dev/null; \
	rm -rf "$$work"; \
	if [ -z "$$peak" ]; then echo "rss: could not measure"; exit 1; fi; \
	printf 'rss: netcfgd peak %s KB of %s limit\n' "$$peak" "$(RSS_LIMIT_KB)"; \
	printf 'rss:   of which %s KB is netcfgd'"'"'s own; %s KB is this process'"'"' share\n' \
		"$${anon:-?}" "$${pss:-?}"; \
	if [ "$$peak" -gt "$(RSS_LIMIT_KB)" ]; then echo "rss: over limit"; exit 1; fi

# section 6 wants a cargo-fuzz target per parser, and there are three:
# netlink messages, the config language, and the document JSON. They need
# nightly and a sanitizer, so they are not part of `make check` -- the
# randomised tests in crates/*/tests/random.rs cover the same entry points on
# stable and do run there. A target nobody can run on the machine they commit
# from is a target that rots; a randomised test that runs every time is not a
# substitute for coverage-guided fuzzing. Both, deliberately.
#
#   make fuzz TARGET=netlink_wire FUZZ_ARGS='-max_total_time=300'
FUZZ_TARGET ?= netlink_wire
FUZZ_ARGS   ?=

# The supplicant tests that need a real wpa_supplicant. Not part of `check`:
# they need a privileged network namespace, and a machine without one should
# get a clean run rather than a failure it cannot act on. NCFG_LIVE turns the
# skips into failures, so running this target proves the tests actually ran --
# without it a missing supplicant would look exactly like a passing suite.
#
# unshare -rn gives CAP_NET_ADMIN in a fresh network namespace without root.
# The suite is built first because the binary has to exist inside it, where
# there is no network for cargo to fetch anything over.
# Debian keeps most of what this suite drives -- `tc`, dnsmasq, openvpn,
# wpa_supplicant, resolvconf -- in /sbin and /usr/sbin, which are on root's
# PATH and not on an ordinary user's. The suite runs unprivileged, through
# `unshare -rn`, so `command -v tc` answered differently depending on who
# typed make.
#
# Both directions are wrong and neither is loud. Outside NCFG_LIVE a script
# skips, so `tunnel.sh` quietly did not run against the openvpn sitting in
# /sbin -- the vacuous pass this tree keeps finding. Inside it a skip is a
# failure, so `qdisc.sh` failed with "no tc" on a machine where tc is
# installed. A suite whose answer depends on whether root started it is not
# measuring the software.
#
# Appended rather than prepended, so a purpose-built binary earlier on PATH
# still wins -- which is how `tunnel.sh`'s own header tells you to point it at
# an unpackaged openvpn.
#
# Target-scoped, so nothing else in this file gains an sbin it did not ask
# for. Checked rather than assumed: the same construct in a scratch makefile
# finds `tc` under this target and does not under a sibling.
#
# A script run by hand still has the caller's PATH, which is what the headers
# in tests/live/ already tell people to set.
live: export PATH := $(PATH):/sbin:/usr/sbin
live:
	$(CARGO) build --workspace
	@$(MAKE) --no-print-directory ncfg-link PROFILE=debug
	$(CARGO) build --tests -p netcfgd-supplicant -p netcfgd-sys
	@# WireGuard needs CAP_NET_ADMIN and the module; it skips without either.
	@binary=$$(ls -t target/debug/deps/wg-* 2>/dev/null | grep -v '\.d$$' | head -1); \
	if [ -n "$$binary" ]; then \
		unshare -rn sh -c "NCFG_LIVE=1 $$binary --test-threads=1"; \
	fi
	@binary=$$(ls -t target/debug/deps/live-* 2>/dev/null | grep -v '\.d$$' | head -1); \
	if [ -z "$$binary" ]; then echo "live: no test binary was built"; exit 1; fi; \
	unshare -rn sh -c "NCFG_LIVE=1 $$binary --test-threads=1" || { \
		echo "live: if this failed to unshare, the kernel may have"; \
		echo "live:   user namespaces restricted; run as root instead"; \
		exit 1; \
	}
	@unshare -rn sh -c "NCFG_LIVE=1 sh tests/live/links.sh"
	@unshare -rn sh -c "NCFG_LIVE=1 sh tests/live/switch.sh"
	@unshare -rn sh -c "NCFG_LIVE=1 sh tests/live/confirm.sh"
	@unshare -rn sh -c "NCFG_LIVE=1 sh tests/live/nat.sh"
	@unshare -rn sh -c "NCFG_LIVE=1 sh tests/live/privacy.sh"
	@# SLAAC against a real advertisement, which is the half privacy.sh will not
	@# do. Neither under NCFG_LIVE nor under unshare: dnsmasq is a package, and it
	@# drops privileges at startup -- which `unshare -rn` forbids, so the script
	@# makes its own namespace the way dhcpcd.sh does.
	@sh tests/live/slaac.sh
	@unshare -rn sh -c "NCFG_LIVE=1 sh tests/live/hooks.sh"
	@# The one hook phase that is not a plan action, and therefore the one
	@# hooks.sh cannot reach: it needs a running daemon rather than an apply.
	@unshare -rn sh -c "NCFG_LIVE=1 sh tests/live/drift.sh"
	@# The other daemon-driven hook: a roam is wpa_supplicant's decision and
	@# reaches netcfgd on its event socket, so no apply can exercise it.
	@unshare -rn sh -c "NCFG_LIVE=1 sh tests/live/roam.sh"
	@# The wireless journey with nothing configured to begin with, which is
	@# the state every M8 wifi fault was found in and no test was ever run
	@# from. It asserts the machine rather than the artifacts: a supplicant
	@# that is running, a scan that returns, a network that reached it.
	@unshare -rn sh -c "NCFG_LIVE=1 sh tests/live/wifi_journey.sh"
	@# The same journey through the GUI's own buttons, which is the client the
	@# "buttons don't work properly" report was about. Skips without Qt, which
	@# is a dependency a machine may reasonably not have.
	@unshare -rn sh -c "NCFG_LIVE=1 sh tests/live/gui_wifi.sh"
	@# The 802.1X path, where the worst fault of M8 was and which had no live
	@# coverage: a certificate must reach the supplicant as a path it can open,
	@# never as the content of a key.
	@unshare -rn sh -c "NCFG_LIVE=1 sh tests/live/enterprise.sh"
	@# Taking a radio over when another manager lets go, which is what
	@# displacement means and the half no test covered: a guard that declines
	@# and never stops declining looks exactly like a daemon that does not work.
	@unshare -rn sh -c "NCFG_LIVE=1 sh tests/live/displace.sh"
	@# A supplicant that died under a radio netcfgd owns, which is the state a
	@# crash leaves behind and the one every client reports as "cannot reach
	@# supplicant". The fix loop has to notice without being asked.
	@unshare -rn sh -c "NCFG_LIVE=1 sh tests/live/revive.sh"
	@# Adopting the network after the ownership record is gone, which is what a
	@# restart does to it. Holding is safe and is not enough: a netcfgd that
	@# cannot recognise its own work can never remove it either.
	@unshare -rn sh -c "NCFG_LIVE=1 sh tests/live/adopt.sh"
	@# The mark netcfgd leaves on a link it creates, which is the one object
	@# kind with no protocol field to stamp -- so it was the last piece of
	@# ownership that lived only in the record a restart deletes.
	@unshare -rn sh -c "NCFG_LIVE=1 sh tests/live/altname.sh"
	@# The sysctls netcfgd set, and the limit of what survives losing the
	@# record -- a value has nothing to stamp, so this is the one part of
	@# ownership that genuinely depends on /run.
	@unshare -rn sh -c "NCFG_LIVE=1 sh tests/live/sysctl.sh"
	@# The captive portal check, against a real HTTP server: the probe is a
	@# question rather than a change, so no apply can exercise it either.
	@unshare -rn sh -c "NCFG_LIVE=1 sh tests/live/portal.sh"
	@# A supplicant that has bound its socket and stopped answering. Both what
	@# netcfgd says about it and how long it takes to say it -- the round trip
	@# is in the reconcile loop.
	@unshare -rn sh -c "NCFG_LIVE=1 sh tests/live/wedged.sh"
	@# Bare, like slaac.sh and dhcpcd.sh: this one picks its own namespace,
	@# because which one it needs depends on which DHCP server it found.
	@# busybox udhcpd wants nothing special; the dnsmasq fallback drops
	@# privileges, which `unshare -rn` forbids.
	@NCFG_LIVE=1 sh tests/live/dhcp.sh
	@# The other client, and the one netcfgd prefers. Neither under NCFG_LIVE
	@# nor under unshare: dhcpcd is a package, and it drops privileges to a user
	@# that a namespace with one mapped uid does not have -- so the script makes
	@# its own namespaces, which is also how it keeps the machine's own dhcpcd
	@# state, hostname and resolv.conf out of reach.
	@sh tests/live/dhcpcd.sh
	@# Not under `unshare -rn`, and that is the point: a network namespace has
	@# none of the machine's real interfaces, so the radio this reads would not be
	@# there. It changes nothing -- `status` and `plan` only -- so running it
	@# against the host is safe.
	@NCFG_LIVE=1 sh tests/live/rfkill.sh
	@# And the event stream, against a fifo rather than the real device: the
	@# write path on /dev/rfkill blocks every radio on the machine, and rfkill
	@# is not namespaced, so `unshare -rn` would be no protection.
	@unshare -rn sh -c "NCFG_LIVE=1 sh tests/live/rfkill_stream.sh"
	@unshare -rn sh -c "NCFG_LIVE=1 sh tests/live/rules.sh"
	@unshare -rn sh -c "NCFG_LIVE=1 sh tests/live/qdisc.sh"
	@unshare -rn sh -c "NCFG_LIVE=1 sh tests/live/ingress.sh"
	@unshare -rn sh -c "NCFG_LIVE=1 sh tests/live/readonly.sh"
	@unshare -rn sh -c "NCFG_LIVE=1 sh tests/live/unmanage.sh"
	@# No namespace: this one touches no interface and no socket. It drives a
	@# process that reads a pipe and writes a file, which is the whole of what
	@# the privileged half of administrator mode does.
	@NCFG_LIVE=1 sh tests/live/control_helper.sh
	@# The interface reporting contract, checked from the side a writer writes.
	@# Under NCFG_LIVE: it needs no modem and no module, only a file.
	@unshare -rn sh -c "NCFG_LIVE=1 sh tests/live/report.sh"
	@# The reference helper, against a fake mbimcli. Under NCFG_LIVE: it
	@# needs no modem and no mbimcli, only the shell.
	@unshare -rn sh -c "NCFG_LIVE=1 sh tests/live/helper.sh"
	@# An OpenVPN tunnel, against a fake daemon that speaks the real
	@# management protocol. Under NCFG_LIVE: it needs no openvpn package.
	@unshare -rn sh -c "NCFG_LIVE=1 sh tests/live/openvpn.sh"
	@# The same tunnel against a *real* openvpn, which is the only thing that
	@# can say what it puts in a --route-up script's environment. Deliberately
	@# not under NCFG_LIVE, for the reason ap.sh is not: openvpn is a package a
	@# machine with no VPN has no reason to have.
	@unshare -rn sh -c "sh tests/live/tunnel.sh"
	@# What netcfgd hands pppd, against a real pppd. Same reasoning: ppp is a
	@# package a machine with no DSL line has no reason to have, and a session
	@# cannot be dialled without real root either way.
	@unshare -rn sh -c "sh tests/live/ppp.sh"
	@# Deliberately not under NCFG_LIVE: it needs the `wireguard` module, which
	@# a kernel may simply not have -- and nothing else in netcfgd does.
	@unshare -rn sh -c "sh tests/live/strand.sh"
	@# The same module, plus `wg` itself as the reference tool -- reading the
	@# state back through netcfgd would only prove netcfgd agrees with itself.
	@# The script's header says how to get `wg` without installing it.
	@unshare -rn sh -c "sh tests/live/wireguard.sh"
	@# The only python test. A TUI needs a pty to say anything about, and
	@# script(1) cannot drive input reliably; see the file's own header.
	@if command -v python3 >/dev/null 2>&1; then \
		unshare -rn sh -c "NCFG_LIVE=1 python3 tests/live/tui.py"; \
	else \
		echo "tui.py: skipping: no python3"; \
	fi
	@# The second python test, and for the same reason: a passphrase prompt has
	@# one property worth checking -- that the passphrase is not echoed -- and a
	@# pipe has no echo to turn off, so only a pty can say. It needs no daemon
	@# and no namespace; it writes a config file in a temporary directory.
	@if command -v python3 >/dev/null 2>&1; then \
		NCFG_LIVE=1 python3 tests/live/wifi_add.py; \
	else \
		echo "wifi_add.py: skipping: no python3"; \
	fi
	@unshare -rn sh -c "NCFG_LIVE=1 sh tests/live/wifi.sh"
	@unshare -rn sh -c "NCFG_LIVE=1 sh tests/live/dot1x.sh"
	@unshare -rn sh -c "NCFG_LIVE=1 sh tests/live/stations.sh"
	@unshare -rn sh -c "NCFG_LIVE=1 sh tests/live/acl.sh"
	@# Deliberately not under NCFG_LIVE: unlike wpa_supplicant, which decision
	@# 0014 makes the floor for wireless, hostapd is an optional package that a
	@# machine never running an access point has no reason to install (0026).
	@# A missing one is a skip rather than a failed suite.
	@unshare -rn sh -c "sh tests/live/ap.sh"
	@# The NetworkManager shim, against a real nmcli on a private bus. Not under
	@# NCFG_LIVE: nmcli comes from the network-manager package, which is exactly
	@# what a netcfgd machine is expected not to have installed.
	@unshare -rn sh -c "sh tests/live/nm.sh"
	@# Association, which needs real root and a loadable mac80211_hwsim. Not
	@# under NCFG_LIVE and not under unshare: it does its own namespace, and a
	@# machine that cannot run it should get a skip rather than a failure.
	@sh tests/live/hwsim.sh
	@# A real PPPoE session, same bucket: /dev/ppp is root-only and the rp-pppoe
	@# plugin opens it as it loads, so an unprivileged machine cannot dial. It
	@# makes its own namespaces too, and skips rather than fails without root.
	@sh tests/live/pppoe-session.sh
	@# A real delegated prefix, from a real kea to a real odhcp6c, advertised
	@# by a real radvd to a host that configures itself. Root because both ends
	@# bind a privileged port, and odhcp6c is not packaged for Debian -- the
	@# script's header says how to build it, and skips without it.
	@sh tests/live/delegation.sh

fuzz:
	@if ! command -v cargo-fuzz >/dev/null 2>&1; then \
		echo "fuzz: cargo-fuzz is not installed"; \
		echo "fuzz:   cargo install cargo-fuzz   (needs a nightly toolchain)"; \
		echo "fuzz: targets are in fuzz/fuzz_targets/, and the randomised"; \
		echo "fuzz: tests in crates/*/tests/random.rs run on stable meanwhile"; \
		exit 1; \
	fi
	$(CARGO) fuzz run $(FUZZ_TARGET) -- $(FUZZ_ARGS)

# The Qt client, which nothing else builds.
#
# `client/` is built by `conformance`, so a change that breaks the C library is
# caught. Nothing built `gui/` at all -- so a change to that library's API
# broke a tree nobody compiled, and the only reason it was ever noticed was
# somebody building it by hand. That is the failure class the dependency rules
# in build-and-commit.md are about: a rule that quietly does not run.
#
# Skipped loudly rather than failed when qmake is absent, matching `deny`
# below: most machines that build netcfgd are not desktops, and a gate that
# demanded Qt on a router would be one people delete. CI installs Qt, which is
# where the skip would otherwise become a vacuous pass.
gui:
	@if command -v qmake6 >/dev/null 2>&1; then \
		$(MAKE) --no-print-directory -C gui; \
		$(MAKE) --no-print-directory -C gui test; \
	else \
		echo "gui: qmake6 not installed, skipping (apt install qt6-base-dev)"; \
	fi

# Supply chain. Both are optional installs, so this reports rather than failing
# when they are absent -- a gate nobody can run locally is a gate that rots.
deny:
	@command -v cargo-deny >/dev/null 2>&1 && $(CARGO) deny check || \
		echo "deny: cargo-deny not installed, skipping"
	@command -v cargo-audit >/dev/null 2>&1 && $(CARGO) audit || \
		echo "deny: cargo-audit not installed, skipping"
	@# Each adapter separately, against its own deny.toml. A separate workspace
	@# is invisible to a `cargo deny` run in the root -- which is the point, and
	@# also the way an adapter's supply chain would go unchecked forever if this
	@# loop were not here.
	@for adapter in $(ADAPTERS); do \
		echo "deny: $$adapter"; \
		( cd $$adapter && \
			{ command -v cargo-deny >/dev/null 2>&1 && $(CARGO) deny check || \
				echo "deny: cargo-deny not installed, skipping"; } && \
			{ command -v cargo-audit >/dev/null 2>&1 && $(CARGO) audit || \
				echo "deny: cargo-audit not installed, skipping"; } ) || exit 1; \
	done

# `clean` removes what it names. `dist/` is the one directory cleared wholesale,
# and only because the build creates it: `deb` and `apk-source` make it, nothing
# else writes there, and it is disposable by construction.
#
# The guard is not decoration. `DIST` is settable, and an unset or mistyped one
# turns `rm -rf $(DIST)` into a command that deletes something else entirely --
# which is exactly how a clean target eats a source tree. So the path is checked
# for being non-empty and relative before anything is removed, and the packages
# are listed rather than swept silently.
clean:
	$(CARGO) clean
	@case "$(DIST)" in \
	"") echo "clean: DIST is empty, refusing to remove anything"; exit 1 ;; \
	/*) echo "clean: DIST is absolute ($(DIST)), refusing"; exit 1 ;; \
	*..*) echo "clean: DIST escapes the tree ($(DIST)), refusing"; exit 1 ;; \
	esac; \
	if [ -d "$(DIST)" ]; then \
		find "$(DIST)" -type f -print | sed 's/^/clean: removing /'; \
		rm -rf "$(DIST)"; \
	fi

# The shared style gate: one tool, copied verbatim from
# ~/.claude/tool/style_gate.py into every private project. It refuses to
# run against a collapsed file list, so a pass means it actually looked.
style: style-source style-docs

style-source:
	python3 tool/style_gate.py check

# project.md is authoritative, so it is held to the tree: a heading
# that appears twice means whichever one you find, the other is the
# one with the answer.
style-docs:
	python3 tool/style_gate.py docs

# The clean ladder, matching the sibling projects: `clean` removes build
# products, `veryclean` adds the build directories themselves, `distclean`
# adds editor and tool droppings. Each names what it removes.
veryclean: clean
	$(CARGO) clean
	rm -rf target

# **`distclean` no longer sweeps the tree for editor droppings.** `*~`,
# `*.swp` and `*.orig` are not build output: they belong to somebody's
# editor, and a `.orig` belongs to a merge they may be in the middle of.
# The sweep was also unbounded -- `find .` walks `.git` and every adapter's
# own workspace, and it was measured deleting files inside `.git`. `git
# clean -xdn` lists that class and is the person's call rather than the
# build system's.
#
# What is left is what the tooling here really wrote. The search is a
# wildcard because a `__pycache__` appears beside whatever Python ran, but
# the thing removed is named exactly and is disposable by construction;
# `.git` is pruned and every removal is printed, because a clean target that
# deletes silently is one nobody can check.
distclean: veryclean
	@find . -name .git -prune -o \
	        -name __pycache__ -type d -prune -print -exec rm -rf {} +

# The counterpart to install: named targets only, no sweeps.
# Removes every file the install targets place, each named, and nothing else.
#
# **It does not touch the configuration**, and that is a fix rather than a
# nicety: this used to `rm -f $(SYSCONFDIR)/netcfgd/netcfgd.conf`, a file
# `install` has never written. `install` creates the *directory* and stops,
# because the configuration is the operator's and netcfgd ships no default one
# -- so the old line could only ever delete something a person wrote by hand.
# Measured on a staged tree: install, put a config in place, uninstall, and it
# was gone.
#
# Named rather than globbed, and covering every install-* target rather than
# only `install`, because an uninstall that leaves root-owned files behind is
# how a machine ends up with a binary nobody can account for. `install-gui`
# and `install-modem-mbim` were both missing.
uninstall:
	rm -f $(DESTDIR)$(BINDIR)/ncfg
	rm -f $(DESTDIR)$(SBINDIR)/netcfgd
	rm -f $(DESTDIR)$(BINDIR)/netcfgd-gui
	rm -f $(DESTDIR)$(DATADIR)/applications/netcfgd-gui.desktop
	rm -f $(DESTDIR)$(BINDIR)/netcfgd-modem-mbim
	rm -f $(DESTDIR)/usr/lib/systemd/system/netcfgd.service
	rm -f $(DESTDIR)$(SYSCONFDIR)/init.d/netcfgd
	rm -f $(DESTDIR)$(BINDIR)/netcfgd-nm
	rm -f $(DESTDIR)$(DATADIR)/dbus-1/system.d/netcfgd-nm.conf
	rm -f $(DESTDIR)/usr/lib/systemd/system/netcfgd-nm.service
	@# This one is ours: `install` wrote it, so `uninstall` takes it away. The
	@# operator's own configuration beside it is not, and is left alone.
	rm -f $(DESTDIR)$(SYSCONFDIR)/netcfgd/netcfgd.conf.example
	@# Only if the operator left nothing in it. Their configuration is not
	@# ours to remove, and an empty directory is not worth keeping.
	@rmdir $(DESTDIR)$(SYSCONFDIR)/netcfgd 2>/dev/null || true
	@echo "uninstall: removed the programs, the example, the desktop entry and"
	@echo "uninstall:   the init glue"
	@echo "uninstall:   any configuration you wrote in $(SYSCONFDIR)/netcfgd is"
	@echo "uninstall:   left alone -- it is yours and this Makefile never wrote it"

# The commit-msg hook lives in the tree so it is reviewable, survives a
# clone, and can be kept in sync. .git/hooks is untracked, so a hook that
# exists only there enforces a rule nobody can see and vanishes silently on
# a fresh clone.
hooks:
	@test -d .git || { echo "hooks: not a git repository" >&2; exit 1; }
	@install -m 0755 tool/hooks/commit-msg .git/hooks/commit-msg
	@echo "hooks: commit-msg installed from tool/hooks/"

# The TARGETS block in the header is the one statement of what the targets
# are, and this reads it back rather than repeating it: a list written twice
# is a list that disagrees with itself eventually.
#
# Defined last on purpose -- make takes the first non-special target in the
# file as the default goal, so a `help` rule above `all` makes plain `make`
# print the help instead of building.
help:
	@sed -n '/^# TARGETS/,/^#$$/p' $(firstword $(MAKEFILE_LIST)) | sed 's/^# \{0,1\}//'
