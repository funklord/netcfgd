# The gates from project.md section 6, as one entry point. Constraint 8 is why this
# exists before there is much to gate: budgets adopted later are budgets
# already blown, and the same goes for every other check here.
#
# `make check` is what CI runs and what to run before committing.
#
# TARGETS
#   make               -- build the workspace and link the `ncfg` name
#   make gui           -- the Qt client, which nothing else builds
#   make tde           -- the TDE control module and tray, likewise
#   make nm            -- the NetworkManager shim, likewise. `make adapters`
#                         built it until 0276 retired the Rust one, and the
#                         suite that skips without it says `make nm` now
#   make cross         -- the cross-compilation check
#   make test          -- the test suite alone
#   make check         -- every gate; the one to run before a commit
#   make check-ci      -- check minus the budgets, which a rented VM cannot
#                         measure honestly
#   make live          -- the supplicant tests that need a real
#                         wpa_supplicant and a privileged netns; not in check
#   make live-container -- the live suite in a container, with the programs
#                         and privileges this machine cannot give it
#   make vm            -- a guest with its own kernel, for what a namespace
#                         cannot do: module loading, /dev/vhci, real init.
#                         `vm-image` fetches the images into ~/vm first and
#                         is the only part that needs the internet
#   make vm-cluster    -- several guests on one layer-2 wire
#   make vm-skipped    -- the live scripts that skip on this machine, run in
#                         a guest where a skip is a failure
#   make vm-delegation -- prefix delegation end to end, with odhcp6c built
#                         from a pinned source Debian does not package
#   make vm-init       -- the LSB init script, started and stopped for real.
#                         Under systemd's sysv-generator, not under sysvinit,
#                         and the payload says what that does not prove
#   make vm-sandbox    -- the systemd unit's sandbox, against real systemd
#   make hull          -- the payloads a namespace or a container cannot host,
#                         in machines `hull` runs. Four need a kernel of their
#                         own: hwsim radios, the systemd sandbox, the OpenRC
#                         init script, and a kernel that cannot do NAT. Two
#                         need a second machine: `hull-wire`, the verdict
#                         collector on a trivial payload, and
#                         `hull-delegation`, an ISP delegating a prefix that
#                         netcfgd configures from -- with
#                         `hull-delegation-lossy` for the same across a wire
#                         dropping frames. `hull-regdom` measures the kernel
#                         rather than netcfgd: what a running machine may do
#                         with its regulatory domain (0296). Each runs alone
#                         by name;
#                         `hull-image` builds the images, which is the only
#                         part needing the internet, and `hull-clean` untags
#                         them
#   make fuzz          -- the C parsers, fuzzed; `fuzz-rust` for the other
#                         implementation's targets. The committed corpus is
#                         replayed by `make c-test` with no clang needed
#   make conformance   -- the two client implementations, asked the same
#                         questions
#   make nm-containment -- assert the core's manifest has gained no entry
#   make linkage       -- what the shipped binaries are allowed to link
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
#   make install-tde   -- the TDE front end, into TDE's own prefix
#   make install-modem
#                      -- the reference modem helper; optional on purpose
#   make uninstall     -- remove what install put there
#   make deb           -- the Debian package; Depends read from the ELF
#   make apk           -- the Alpine package. Alpine's `apk`, not Android's
#   make apk-container -- the same, built by `abuild` inside Alpine
#   make apk-source    -- the tarball an APKBUILD builds from
#   make schema-bless  -- re-bless the four frozen witnesses
#   make version-check -- VERSION is the source; debian/changelog and
#                         Cargo.toml are held to it
#   make hooks         -- install the git hooks from tool/hooks/
#   make clean         -- remove build products
#   make veryclean     -- clean, plus the build directories
#   make distclean     -- veryclean, plus what the tooling here wrote
#   make help          -- this list
#

CARGO ?= cargo

# Is the optional component here? Asked in two places, so spelled once: the
# `fmt` and `clippy` gates.
#
# There was a third, and it is worth knowing why it was the easy one to miss:
# `adapters` held each adapter's own cargo workspace to the same bar as the
# core, so it ran both tools again from a `cd` rather than from a gate with the
# tool's name on it. Forgetting it there left `make check` stopping dead exactly
# as before, only later and after a full build. 0276 retired the one Rust
# adapter and the target with it.
#
# Asking cargo whether the subcommand runs, rather than looking for a binary by
# name: rustup and Debian put the shim in different places, and the only thing
# being asked is whether the next line will work.
FMT_OK    = $(CARGO) fmt --version >/dev/null 2>&1
CLIPPY_OK = $(CARGO) clippy --version >/dev/null 2>&1
# And the second C compiler, for the `clang` gate. A program rather than a
# subcommand, so the question is whether it is on PATH.
CLANG_OK  = command -v clang >/dev/null 2>&1

.PHONY: clang default-goal live-alpine ledger example deb apk apk-source apk-container all check check-ci build rust test gui c-test conformance claims installed-diff icons icon-check install-icons uninstall-icons FORCE fmt fmt-fix shell clippy unsafe-policy executor-policy packaging ascii size footprint rss live schema-bless install install-gui install-modem install-systemd install-openrc install-procd fuzz fuzz-rust deny clean nm-containment veryclean distclean uninstall style style-source style-docs registry bridge-test nm-c-test hooks cross linkage linkage-one live-container tde install-tde deb-tde help

all: build

# **The C port is what this builds and what this ships** (0266). The Rust is
# still here and still built by the gates that compare the two programs --
# `agree`, `conformance`, `test` and the budget gates each build what they need
# -- but it is no longer what `make` produces or what `make install` installs.
#
# `linkage` was in that list and is not any more: it reads the shipped
# binaries' NEEDED lists, so pointing it at the Rust made it a gate about an
# artifact nobody installs.
#
# `make rust` is the old behaviour, for anyone who wants the other binary
# without going through a gate.
build:
	@$(MAKE) --no-print-directory -C c

rust:
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
PORTABLE_GATES = style fmt ascii shell clippy clang default-goal unsafe-policy \
                 executor-policy nm-containment packaging claims client-test \
                 conformance test example gui linkage c-test agree ledger \
                 module-order registry bridge-test nm-c-test
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

# Design section 9.2 asks for this in as many words: "a mechanically checkable
# CI assertion" that the core's dependency manifest has not gained an entry.
#
# It is not a grep for `zbus`. Naming the thing to keep out only keeps *that*
# thing out, and the next adapter brings something else. Instead the core's
# lockfile is checked against `deny.toml`'s allow list, which is the written
# form of constraint 3 -- so any new core dependency fails this, whether an
# adapter brought it or not.
#
# The second half is the gate checking itself. "The core does not have the
# adapter's dependencies" is worth nothing if no adapter has any, which is the
# vacuous pass this project keeps finding -- so it also asserts that the thing
# being contained exists.
#
# **What it asserts changed when 0276 retired the Rust shim, and the claim got
# stronger rather than weaker.** It used to count the adapter's own lockfile and
# require at least twenty entries, on the grounds that a D-Bus stack is not
# small. There is no lockfile to count now: the shim is C over `libdbus-1`, so
# the stack it contains is a system library and no Rust crate for it can appear
# in any lockfile here. The two things checked are therefore that the shim still
# gets D-Bus from outside cargo, and that no adapter has quietly acquired a
# lockfile again -- which is the only way the old leak could come back.
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
	if ! grep -q 'pkg-config --libs dbus-1' adapter/netcfgd-nm/c/Makefile; then \
		echo "nm-containment: the shim no longer links libdbus-1 from the system,"; \
		echo "nm-containment: so nothing here is containing a D-Bus stack and the"; \
		echo "nm-containment: check above proved nothing -- find where the stack went"; \
		exit 1; \
	fi; \
	strays=$$(find adapter -name Cargo.lock -print 2>/dev/null); \
	if [ -n "$$strays" ]; then \
		echo "nm-containment: an adapter has a cargo lockfile again:"; \
		echo "nm-containment:  $$strays"; \
		echo "nm-containment: 0276 retired the one that existed. A new one is a"; \
		echo "nm-containment: decision, and this gate's second half was written for"; \
		echo "nm-containment: the arrangement it replaces -- revisit both"; \
		exit 1; \
	fi; \
	echo "nm-containment: ok, $$(echo "$$present" | wc -w) core dependencies, all allowed"; \
	echo "nm-containment:   and the shim's D-Bus stack is libdbus-1, outside cargo"

# The shell netcfgd ships. A helper is a program somebody installs and runs as
# root against their modem, so a syntax error in one is not a smaller problem
# than one in the daemon -- and `sh -n` costs nothing.
#
# Counted, because a glob that matches nothing passes: this project has caught
# that exact failure in a `make packaging` check before.
# packaging/ is in the list because what ships is what matters: the probe and
# the SIM-select hook are shell this project installs onto other people's
# machines, and neither was parsed by anything until they were added here. A
# shipped script that does not parse is this gate's whole subject.
# **A fixed list is what hid two scripts for months.** `tool/prove-red.sh` and
# the VM tier's scripts live outside `helper/` and `tests/live/`, so nothing
# parsed them -- and `style_gate.py` cannot cover the gap either, because `.sh`
# is in neither its `indent_suffixes` nor its `text_suffixes`, so a shell script
# with four-space indentation and trailing whitespace passes it silently.
# Verified by doing exactly that to `tests/live/rules.sh` and watching the gate
# report a clean pass. Fixing the shared tool is not this tree's to do and is
# raised where those tools are kept; what belongs here is the check below, and
# it stands on its own -- nothing outside this repository is needed to run it.
SHELL_SCRIPTS = helper/* tests/live/*.sh tool/*.sh tool/vm/*.sh \
                tool/vm/payload/*.sh packaging/probe/* packaging/hook/*

shell:
	@count=0; \
	for script in $(SHELL_SCRIPTS); do \
		[ -f "$$script" ] || continue; \
		sh -n "$$script" || exit 1; \
		count=$$((count + 1)); \
	done; \
	if [ "$$count" -lt 10 ]; then \
		echo "shell: only $$count scripts checked, which is too few to mean anything"; \
		exit 1; \
	fi; \
	echo "shell: ok, $$count scripts parse"
	@# And that none of them runs a command out of a heredoc comment, which
	@# `sh -n` cannot see because the construct is valid. Here rather than as a
	@# gate of its own: it asks about the same files for the same reason, and
	@# the one thing `shell` could honestly claim was that they parse.
	@python3 tool/heredoc_gate.py $(SHELL_SCRIPTS)

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

# What a second C compiler sees, and gcc does not.
#
# **This exists because five real findings were sitting where nothing looked.**
# `-Wsign-conversion` in `src/plan/` reported conversions gcc passes over
# silently, and they printed only on `make fuzz`, which builds with clang and
# is not part of `check` -- so the one place they appeared was a target nobody
# runs in the ordinary course of work (10.525). A gate that reads them is the
# difference between a warning and a warning somebody sees.
#
# It compiles nothing: each component's `syntax` target is `-fsyntax-only` with
# that component's own `$(CFLAGS)`, so clang reads exactly what gcc reads,
# writes no object into gcc's paths, and cannot drift from the build the way a
# second copy of the flags would.
#
# **The test sources are not in it, and the gap is a number rather than a
# silence**: clang reports 40 over `c/tests/` as of 2026-10-23, 36 signedness
# conversions and 4 string concatenations, which is its own piece of work.
# `make -C c syntax-tests CC=clang` counts them. It was 41 until the first look
# found a real one -- a `ncfg_block_t` an `&&` could leave unwritten in
# `scope_test.c`, which gcc does not report.
#
# Skipped loudly where clang is absent, which is `clippy`'s shape and the same
# bargain: a machine without the tool still runs the rest of `check`, and the
# skip says what to install. `harmonization.md`'s `make -n` hazard does not
# apply -- this recurses, but nothing harvests what the sub-make prints.
# **A bare `make` in each hand-written build must build that build's program**,
# which is `.DEFAULT_GOAL` and is not something a reader checks.
#
# Paid for the same day the `clang` gate landed: its `syntax` target went in
# ABOVE `all` in `client/` and in `adapter/netcfgd-nm/c/`, so `make -C client`
# and `make nm` ran a syntax check, printed a clean line, exited 0 and built
# nothing. Nothing noticed until a container run an hour later reported the
# shim "not built" -- the one place a missing binary is loud, because
# `c_nm_signals.sh` turns its own skip into a failure under NCFG_LIVE.
#
# Asked of make rather than read out of the file, because the default goal is
# what make computes from the first target it meets and a grep for `all:` would
# agree with a broken makefile. `tool/say-goal.mk` says how that is done
# without running the build.
#
# `gui/` is excluded because qmake writes it, and `fuzznet/` because it is a
# vendored submodule; both answer `all` today and neither is this tree's to
# pin.
#
# **A sub-make harvested in a recipe**, so `make -n default-goal` runs these
# four and prints their answers rather than the recipe -- the hazard
# `harmonization.md` records. They write nothing, which is why it is safe here.
default-goal:
	@fail=0; \
	for dir in c client adapter/netcfgd-nm/c bridge; do \
		goal=$$($(MAKE) -C $$dir --no-print-directory -f Makefile \
			-f $(CURDIR)/tool/say-goal.mk ncfg-say-goal 2>/dev/null | tail -1); \
		if [ "$$goal" = "all" ]; then \
			printf 'default-goal: %s builds `all`\n' "$$dir"; \
		else \
			printf 'default-goal: %s builds `%s`, not `all`, so a bare make there\n' \
				"$$dir" "$$goal" >&2; \
			printf 'default-goal:   builds something other than its program\n' >&2; \
			fail=1; \
		fi; \
	done; \
	[ "$$fail" -eq 0 ]

clang:
	@if $(CLANG_OK); then \
		$(MAKE) --no-print-directory -C c syntax CC=clang && \
		$(MAKE) --no-print-directory -C c syntax-tests CC=clang && \
		$(MAKE) --no-print-directory -C client syntax CC=clang && \
		$(MAKE) --no-print-directory -C client syntax-tests CC=clang && \
		$(MAKE) --no-print-directory -C adapter/netcfgd-nm/c syntax CC=clang && \
		$(MAKE) --no-print-directory -C adapter/netcfgd-nm/c syntax-tests CC=clang; \
	else \
		echo "clang: not installed, skipping"; \
		echo "clang:   apt install clang"; \
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

# The C client's own suite, run rather than merely built.
#
# `conformance` and `test` both name the binary as a prerequisite, so `check`
# has always *compiled* it -- and nothing has ever executed it. Every assertion
# inside was green by never being asked, which is the vacuous pass in its
# purest form: the gate that would have spoken was not run, and a suite that
# compiles looks exactly like a suite that passes.
#
# Found when two new assertions about the link and network conversion passed
# locally and left `make check` completely unmoved. `client/Makefile` has had
# the target the whole time; only the wiring was missing.
# The C port's own suite, one binary per module. Here rather than left to be
# run by hand because 0263 gives the port a rule -- a module lands with its
# tests or it has not landed -- and a suite nobody runs is how that rule
# becomes a sentence in a document.
c-test:
	@$(MAKE) --no-print-directory -C c test

client-test: client/tests/client_test
	@$(MAKE) --no-print-directory -C client test

# The fuzznet-facing side, which `make check` reached through nothing until the
# record encoder landed there.
#
# **A gate that runs only when somebody types `cd bridge && make test` is a
# gate that has stopped running**, and the encoder is the piece least able to
# afford that: it decides what leaves this machine. So it joins the portable
# gates, at the price of the submodule -- which this tree's own rule already
# accepts, since `bridge/Makefile` fetches fuzznet itself and fails loudly
# rather than building less than it was asked for.
#
# Measured incrementally at about eight seconds, fuzznet's own objects being
# cached in `bridge/build`. The first run on a clean tree pays for a fuzznet
# build, once.
bridge-test:
	@$(MAKE) --no-print-directory -C bridge test

# The C shim's own suite, for the reason `bridge-test` gives.
#
# **It was reachable through nothing.** `adapters` drove `cargo test` in each
# Rust adapter workspace and the C port was not one, so 115 checks -- the
# dispatcher's tables, the two stores' path contracts, the write authorization
# and both signal detectors -- ran only when somebody remembered to type it.
# That target is gone with the Rust shim (0276) and this gate is what remains:
# the C suite is now the only adapter suite there is. The
# detectors are the part least able to afford that: each one's failure mode is
# silence, which is also what a converged machine looks like.
#
# It needs libdbus-1's headers, which the shim needs to build at all, so this
# adds no requirement the tree did not already have.
nm-c-test:
	@$(MAKE) --no-print-directory -C adapter/netcfgd-nm/c test

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
# Both depend on `build`, and on the debug binaries rather than on cargo
# having compiled something. `cargo test --workspace` builds every test
# harness and does not relink `target/debug/netcfgd`, and `target/debug/ncfg`
# is a symlink `ncfg-link` makes rather than an artifact cargo knows about --
# so a test that runs the program runs whatever the last `make build` left.
# Measured: `a_reader_that_goes_away_is_not_a_crash` failed against a binary
# three weeks older than the fix it asserts, reporting the CLI as crashing on
# a closed pipe. The test does assert the binary exists, which catches the
# absent case loudly and cannot see a stale one -- and a stale pass or a
# stale failure both read as a verdict on the source.
conformance: build client/tests/client_test
	$(CARGO) test -p netcfgd-cli both_client_implementations_extract_the_same_facts

test: client/tests/client_test
	@# **The `ncfg` symlink first**, for the reason `agree` grew the same two
	@# lines in 0266: `cargo test` builds the binaries but cannot make a
	@# symlink, and the one in `target/debug` used to come from `build`, which
	@# no longer produces the Rust at all. Without this, a `netcfgd-cli` test
	@# that refuses to test nothing fails with "ncfg is not built" -- correctly,
	@# and for a reason that has nothing to do with the code under test.
	$(CARGO) build --workspace --quiet
	@$(MAKE) --no-print-directory ncfg-link PROFILE=debug
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
# Where netcfgd's own executables that are not commands go. `libexec` and not
# `share`, because these are run rather than read -- and not /run, which is the
# whole point: systemd mounts /run `noexec` by default, so a script generated
# there cannot be executed by the client netcfgd hands it to (0178).
LIBEXECDIR ?= $(PREFIX)/libexec
# Where gui/Makefile leaves its binary. Its own BUILD_DIR defaults to `build`
# and is not visible here, so this tracks it and is overridable the same way.
GUI_BUILD_DIR ?= gui/build
# The TDE front end is CMake, so its binary directory is its own rather than
# in-place, and it installs into TDE's prefix and not this one. /opt/trinity
# is where Debian's Trinity packages put everything, which is what the
# control centre and the panel search.
TDE_BUILD_DIR ?= adapter/netcfgd-tde/build
TDE_PREFIX    ?= /opt/trinity
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
	@# **The C port's binary** (0266). Built here rather than trusted, for
	@# `linkage`'s reason: what is sitting in `c/` depends on the last build,
	@# and a package must not ship whatever happened to be left there.
	@$(MAKE) --no-print-directory -C c
	install -d $(DESTDIR)$(SBINDIR) $(DESTDIR)$(BINDIR) $(DESTDIR)$(SYSCONFDIR)/netcfgd
	install -m 0755 c/netcfgd $(DESTDIR)$(SBINDIR)/netcfgd
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
	@# The switcher, installed by `install` rather than by `install-systemd`
	@# because it drives OpenRC and sysvinit too.
	install -m 0755 packaging/netcfgd_select.sh \
		$(DESTDIR)$(SBINDIR)/netcfgd_select.sh
	@# The dhcpcd hook, which netcfgd passes with `-c` and dhcpcd execs. It has
	@# to live on a filesystem that permits execution: netcfgd generated it per
	@# interface under /run/netcfgd until 0178, and systemd mounts /run `noexec`
	@# by default -- so dhcpcd refused it, the lease's nameservers never
	@# reached netcfgd, and `write_resolv_conf` wrote a resolver that resolved
	@# nothing.
	install -d $(DESTDIR)$(LIBEXECDIR)/netcfgd
	install -m 0755 packaging/hooks/dhcpcd-hook \
		$(DESTDIR)$(LIBEXECDIR)/netcfgd/dhcpcd-hook
	@echo "install: netcfgd and ncfg installed; no init glue"
	@echo "install:   $(SYSCONFDIR)/netcfgd/netcfgd.conf.example documents every feature"
	@echo "install:   make install-systemd | install-openrc | install-procd"
	@# The profiles the package ships. Under $(DATADIR) rather than /etc, so
	@# they are the package's to replace on upgrade; an operator's own go in
	@# $(SYSCONFDIR)/netcfgd/profile, which layers over these and which the
	@# package never writes. `offline` is the one profile that can be shipped
	@# at all: every other useful profile names this machine's interfaces, and
	@# a package cannot know them.
	install -d $(DESTDIR)$(DATADIR)/netcfgd/profile/offline
	install -m 0644 packaging/profile/offline/10-offline.conf \
		$(DESTDIR)$(DATADIR)/netcfgd/profile/offline/10-offline.conf
	@echo "install:   ncfg profile list shows the shipped offline profile"
	@# Constraint 2: the filesystem reflects use. conf.d/, secrets/ and hooks/
	@# appear when something needs them, so they are not created here. The
	@# example is not a feature's file and creates no capability, which is why
	@# it does not breach that -- project.md section 1 records the distinction.

# Everything a cellular machine needs and a machine without a modem does not:
# three helpers, the quirks table, a udev rule, a systemd unit and two hook
# examples. `debian/rules` stages it into the `netcfgd-modem` package.
#
# **Separate on purpose, and the reason changed.** It was separate because
# `netcfgd-modem-mbim` needs `mbimcli` and most machines have no use for it,
# and because 0045 says the helper is plural so installing one by default would
# make it the blessed one. Both still hold. What made a *package* out of it is
# that the AT path needs nothing at all -- a tty -- and was reachable only from
# a source tree, so a board whose image is built from debs got none of it.
#
# `Architecture: all`: every file here is a shell script or text.
install-modem:
	install -d $(DESTDIR)$(BINDIR)
	install -m 0755 helper/netcfgd-modem-mbim $(DESTDIR)$(BINDIR)/netcfgd-modem-mbim
	@# The AT helper goes with it: which one a machine needs is a property of
	@# the module, not a choice, and a module offering only ECM has no
	@# /dev/cdc-wdm for the MBIM one to open. Neither has a dependency the
	@# other does not -- mbimcli for one, a tty for the other -- so shipping
	@# both costs nothing and shipping one means guessing.
	install -m 0755 helper/netcfgd-modem-at $(DESTDIR)$(BINDIR)/netcfgd-modem-at
	@# And the umbim one, for the target 0045 named and nothing had been
	@# written for. `mbimcli` costs 6.77 MB of glib beyond libc, measured --
	@# about four times netcfgd itself and seven times the embedded budget --
	@# so a constrained box gets a client that costs libubox.
	install -m 0755 helper/netcfgd-modem-umbim $(DESTDIR)$(BINDIR)/netcfgd-modem-umbim
	@# The quirks table goes under /usr/share, where the helpers look first
	@# after $NCFG_MODEM_QUIRKS and /etc. It explains rather than decides, so a
	@# machine without it behaves identically and merely says less.
	install -d $(DESTDIR)$(PREFIX)/share/netcfgd
	install -m 0644 helper/modem-quirks $(DESTDIR)$(PREFIX)/share/netcfgd/modem-quirks
	@# The SIM-select hook, as an example and not as a working hook: netcfgd
	@# chooses the source and a board drives the mux, so the two lines that
	@# matter are the operator's. Named `.example` and installed non-executable
	@# for that reason -- a hook that ran and did nothing would look like a SIM
	@# switch that worked.
	install -d $(DESTDIR)$(PREFIX)/share/netcfgd/hook
	install -m 0644 packaging/hook/sim-select.example \
		$(DESTDIR)$(PREFIX)/share/netcfgd/hook/sim-select.example
	@# And the same hook filled in for the commonest shape, a select line and a
	@# reset line on a GPIO expander driven with gpiod. Still an example and
	@# still non-executable: which line, which polarity and which chip are
	@# facts about a board that netcfgd cannot know and must not guess (0150).
	install -m 0644 packaging/hook/sim-select-gpiod.example \
		$(DESTDIR)$(PREFIX)/share/netcfgd/hook/sim-select-gpiod.example
	@# A stable name for the AT port, and a request that ModemManager leave it
	@# alone. `/dev/ttyUSB3` is not stable across a modem reset, and a reset is
	@# ordinary operation here -- a SIM switch is one. The rule is data about
	@# modules, checked against the quirks table by `make packaging`.
	install -d $(DESTDIR)$(PREFIX)/lib/udev/rules.d
	install -m 0644 packaging/udev/71-netcfgd-modem.rules \
		$(DESTDIR)$(PREFIX)/lib/udev/rules.d/71-netcfgd-modem.rules
	@# And something to run the helper with. netcfgd does not start or
	@# supervise it (0044), so this is a worked example that happens to be
	@# correct rather than an integration -- installed, enabled by nobody.
	install -d $(DESTDIR)/usr/lib/systemd/system
	install -m 0644 packaging/systemd/netcfgd-modem-at@.service \
		$(DESTDIR)/usr/lib/systemd/system/netcfgd-modem-at@.service
	@echo "install-modem: installed. netcfgd-modem-mbim needs mbimcli from"
	@echo "install-modem:   libmbim-utils; netcfgd-modem-at needs only a tty,"
	@echo "install-modem:   for modules offering neither MBIM nor QMI"
	@echo "install-modem:   doc/interface-report.md is the contract -- write"
	@echo "install-modem:   your own helper if this one does not fit"
	@echo "install-modem: for a board that muxes two SIMs, copy"
	@echo "install-modem:   share/netcfgd/hook/sim-select.example and fill in"
	@echo "install-modem:   the two BOARD lines -- netcfgd has no GPIO"
	@echo "install-modem: nothing runs a helper for you. For an AT module:"
	@echo "install-modem:   udevadm control --reload && udevadm trigger"
	@echo "install-modem:   systemctl enable --now netcfgd-modem-at@wwan0"
	@echo "install-modem:   where wwan0 is the interface the modem presents"

# The Qt client, opt-in the way install-modem is.
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
	@$(MAKE) --no-print-directory install-icons ICON_PREFIX=$(DATADIR)
	@# **One binary, two names**, the way `ncfg` is the daemon's second name.
	@# The program reads argv[0] and a name ending `-tui` selects the terminal
	@# frontend, so this costs a symlink and buys a real command rather than
	@# `netcfgd-gui --tui`, which is an odd thing to type on a server.
	@#
	@# A second *binary* would buy nothing: the TUI is these QWidgets rendered
	@# on a character grid, so it links libQt6Widgets whatever is stripped
	@# from it. Splitting trims code paths, never libraries -- and the Qt-free
	@# TUI already exists and is `ncfg tui` (0025).
	@#
	@# Relative, so it resolves inside a DESTDIR staging root and after it is
	@# unpacked at /, which is the same reason the `ncfg` link is absolute to
	@# SBINDIR rather than to the build tree.
	ln -sf netcfgd-gui $(DESTDIR)$(BINDIR)/netcfgd-tui
	@echo "install-gui: netcfgd-gui installed; it needs libqt6widgets6 at run time"
	@echo "install-gui:   and links libQt6DBus, which the daemon does not"
	@echo "install-gui:   netcfgd-tui is the same binary on a terminal;"
	@echo "install-gui:   netcfgd-gui --tui does the same from either name"

# The LSB init scripts, for the machines that do not run systemd.
#
# Devuan and a Debian machine with sysvinit-core read /etc/init.d, and so does
# OpenRC on Debian -- one script covers both. packaging/openrc is not this and
# is not interchangeable with it: that one is an `openrc-run` script for Gentoo
# and Alpine, which sysvinit cannot read.
#
# Installed and not enabled, like every other init glue here. `update-rc.d
# netcfgd defaults` is the operator's act.
install-sysvinit:
	install -d $(DESTDIR)$(SYSCONFDIR)/init.d
	install -m 0755 packaging/sysvinit/netcfgd $(DESTDIR)$(SYSCONFDIR)/init.d/netcfgd
	@echo "install-sysvinit: /etc/init.d/netcfgd installed, not enabled"
	@echo "install-sysvinit:   to run it as a service: update-rc.d netcfgd defaults"

install-sysvinit-nm:
	install -d $(DESTDIR)$(SYSCONFDIR)/init.d
	install -m 0755 packaging/sysvinit/netcfgd-nm $(DESTDIR)$(SYSCONFDIR)/init.d/netcfgd-nm
	@echo "install-sysvinit-nm: /etc/init.d/netcfgd-nm installed, not enabled"
	@echo "install-sysvinit-nm:   starting it takes NetworkManager's bus name"

install-systemd:
	install -d $(DESTDIR)/usr/lib/systemd/system
	install -m 0644 packaging/systemd/netcfgd.service \
		$(DESTDIR)/usr/lib/systemd/system/netcfgd.service
	install -m 0644 packaging/systemd/netcfgd-wait-online.service \
		$(DESTDIR)/usr/lib/systemd/system/netcfgd-wait-online.service
	@echo "install-systemd: netcfgd.service installed, not enabled"
	@echo "install-systemd:   and netcfgd-wait-online.service, which the"
	@echo "install-systemd:   selector enables: network-online.target means"
	@echo "install-systemd:   nothing without one, and selecting netcfgd masks"
	@echo "install-systemd:   the helpers that belong to the other daemons"
	@echo "install-systemd:   to make netcfgd the only network daemon:"
	@echo "install-systemd:     netcfgd_select.sh"

# The TDE front end: a control centre module and a tray, TQt3, over the same
# client/ library the Qt window uses.
#
# Kept out of the default build and out of `install` for the reason `gui` and
# `nm` are: a daemon whose core links no toolkit must build on a machine that
# has none, and a TDE desktop is a stronger assumption still.
#
# `-C client` first, because the CMake project links libncfg_client.a out of
# that directory and cmake will not build it -- the same shape as gui.pro's
# PRE_TARGETDEPS, which requires the archive to exist without producing it.
# TDE_CMAKE_ARGS is how the packaging passes Debian's hardening flags in.
# This build does not go through dh_auto_configure, so nothing else would.
TDE_CMAKE_ARGS ?=

tde:
	$(MAKE) -C client
	cmake -S adapter/netcfgd-tde -B $(TDE_BUILD_DIR) \
		-DCMAKE_INSTALL_PREFIX=$(TDE_PREFIX) $(TDE_CMAKE_ARGS)
	$(MAKE) -C $(TDE_BUILD_DIR)

# cmake's own install step rather than a list of `install -D` lines, because
# where a kpart and a control-centre desktop file go is TDE's answer and not
# this tree's: PLUGIN_INSTALL_DIR and XDG_APPS_INSTALL_DIR come from
# TDESetupPaths, and hard-coding them here would be a second copy of a layout
# TDE is entitled to change.
install-tde:
	@[ -x $(TDE_BUILD_DIR)/netcfgd-tde-tray ] || { \
		echo "install-tde: $(TDE_BUILD_DIR) is not built -- run \`make tde\` first"; \
		exit 1; \
	}
	$(MAKE) -C $(TDE_BUILD_DIR) install DESTDIR=$(DESTDIR)
	@echo "install-tde: installed into $(TDE_PREFIX); run tdebuildsycoca"
	@echo "install-tde:   as the desktop user before the module appears"

# The NetworkManager shim.
#
# **The C one is what this builds and what it installs** (0276). It was the Rust
# one until that record retired it, and the switch is two lines here because
# everything else about the package -- the bus policy, the unit, the name it
# claims -- belongs to the shim rather than to the language it is written in.
#
# This paragraph used to say the shim is "eighty-odd crates of D-Bus that
# constraint 3 keeps off the daemon's path", and that is the sentence the
# retirement falsifies: it links `libdbus-1` and this tree's own
# `libncfg_client.a`, and the crates are gone. Kept out of `install` all the
# same, for a reason that never was about dependencies -- starting it takes
# NetworkManager's bus name, and a machine installing netcfgd is not thereby
# asking to impersonate NetworkManager. `install-nm` says so at the end.
nm:
	@$(MAKE) --no-print-directory -C adapter/netcfgd-nm/c

install-nm:
	@[ -x adapter/netcfgd-nm/c/netcfgd-nm ] || { \
		echo "install-nm: the shim is not built -- run \`make nm\` first"; \
		exit 1; }
	install -d $(DESTDIR)$(BINDIR) $(DESTDIR)$(DATADIR)/dbus-1/system.d \
		$(DESTDIR)/usr/lib/systemd/system
	install -m 0755 adapter/netcfgd-nm/c/netcfgd-nm \
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

# The presence of the module is a stand-in for "cmake can configure this",
# which only the configure step actually answers -- it is here to fail in one
# second with the package name rather than after dpkg-buildpackage has built
# the daemon. find_package(TDE) is the real test and runs either way.
deb-tde:
	@find /usr/share/cmake*/Modules -name TDEMacros.cmake 2>/dev/null | \
		grep -q . || { \
		echo "deb-tde: TDE's cmake modules are not installed"; \
		echo "deb-tde:   apt install tde-cmake tdelibs14-trinity-dev"; \
		exit 1; }
	$(MAKE) deb DEB_BUILD_PROFILES="pkg.netcfgd.tde"

deb: version-check
	@test -n "$(DIST)" || { echo "deb: DIST is empty, refusing" >&2; exit 1; }
	DEB_BUILD_PROFILES="$(DEB_BUILD_PROFILES)" dpkg-buildpackage -b -us -uc
	@mkdir -p $(DIST)
	@# Every artifact by name, `-dbgsym` and the shim included. A glob that
	@# names only the source package leaves a binary package in the parent
	@# directory for ever -- which is what raidcfgd's rule found, and adding a
	@# second binary package is exactly when it would have happened again.
	@# `netcfgd-modem` has no `-dbgsym`: it is `Architecture: all` and carries
	@# no compiled object to strip. Named anyway rather than globbed, which is
	@# the rule this list exists to follow.
	@for f in ../netcfgd_$(VERSION)_*.deb ../netcfgd-dbgsym_$(VERSION)_*.deb \
	          ../netcfgd-nm_$(VERSION)_*.deb ../netcfgd-nm-dbgsym_$(VERSION)_*.deb \
	          ../netcfgd-modem_$(VERSION)_*.deb \
	          ../netcfgd-gui_$(VERSION)_*.deb ../netcfgd-gui-dbgsym_$(VERSION)_*.deb \
	          ../netcfgd-trinity_$(VERSION)_*.deb \
	          ../netcfgd-trinity-dbgsym_$(VERSION)_*.deb \
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
	@#   - `deb-systemd-invoke start|restart` in a postinst starts something,
	@#     and so does the `invoke-rc.d` form on a machine without systemd.
	@#
	@#     This used to refuse ANY `deb-systemd-invoke`, which was right while
	@#     the only reason one appeared was debhelper's start-on-install. It
	@#     stopped being right when the postinst gained an upgrade-only
	@#     restart, so the check now names the verbs rather than the command.
	@#
	@#     `try-restart` is deliberately allowed, and by the verb rather than
	@#     by reading the guard around it: try-restart acts only on a unit that
	@#     is *already active*, so it cannot start anything on a fresh install
	@#     whatever surrounds it. That is a property of the verb, which a text
	@#     check can rely on, where "is this inside an `if [ -n "$$2" ]`" is
	@#     not something grep can answer honestly.
	@#
	@#     **Written as "any invocation that is not try-restart", and not as a
	@#     list of the bad verbs.** The first attempt matched
	@#     `deb-systemd-invoke +(start|restart)` and was blind to what
	@#     debhelper actually emits, which is
	@#     `deb-systemd-invoke $$_dh_action` -- the verb in a variable. That
	@#     version passed a package built without `--no-start`; the gate only
	@#     appeared to work because the *enable* check below caught the same
	@#     build for a different reason. Verified since by building all three
	@#     ways and watching this line fire on two of them.
	@#
	@#     `command -v invoke-rc.d` is dropped before the test, because a
	@#     script that asks whether the command exists is not a script that
	@#     runs it -- and the first version of this line caught the postinst's
	@#     own availability probe.
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
	@#
	@# **The preinst is checked too, and nothing stops the daemon on upgrade.**
	@# dh_installsystemd generates a preinst that does, as half of a
	@# stop-then-start pair whose other half `--no-start` suppresses -- so the
	@# stop shipped, the start did not, and every upgrade left the machine's
	@# network daemon dead, with the postinst's `try-restart` correctly doing
	@# nothing to a unit the preinst had just stopped. `--no-stop-on-upgrade`
	@# in debian/rules is the fix.
	@#
	@# Read from the artifact rather than the recipe, which is the whole reason
	@# these checks live here: the snippet is generated at build time, so the
	@# flag appearing in debian/rules is not evidence that it took.
	@fail=0; \
	seen=0; \
	checked=0; \
	for deb in $(DIST)/netcfgd_$(VERSION)_*.deb $(DIST)/netcfgd-nm_$(VERSION)_*.deb \
	           $(DIST)/netcfgd-modem_$(VERSION)_*.deb \
	           $(DIST)/netcfgd-gui_$(VERSION)_*.deb; do \
		[ -e "$$deb" ] || continue; \
		seen=$$(( seen + 1 )); \
		script=$$(dpkg-deb -I "$$deb" postinst 2>/dev/null | sed 's/#.*//'); \
		[ -n "$$script" ] || continue; \
		checked=$$(( checked + 1 )); \
		if printf '%s\n' "$$script" | grep 'deb-systemd-invoke' | \
		   grep -qv 'try-restart'; then \
			echo "deb: $$deb starts or restarts a service on install"; fail=1; \
		fi; \
		if printf '%s\n' "$$script" | grep 'invoke-rc\.d' | \
		   grep -v 'command -v' | grep -qv 'try-restart'; then \
			echo "deb: $$deb starts a service on install, without systemd"; fail=1; \
		fi; \
		if printf '%s\n' "$$script" | grep -q 'deb-systemd-helper enable' && \
		   ! printf '%s\n' "$$script" | grep -q 'debian-installed'; then \
			echo "deb: $$deb enables a service on install"; fail=1; \
		fi; \
		pre=$$(dpkg-deb -I "$$deb" preinst 2>/dev/null | sed 's/#.*//'); \
		if printf '%s\n' "$$pre" | grep -q 'deb-systemd-invoke stop'; then \
			echo "deb: $$deb stops the daemon on upgrade and nothing starts it"; \
			fail=1; \
		fi; \
	done; \
	if [ "$$checked" -eq 0 ]; then \
		echo "deb: no postinst was inspected, so this checked nothing"; fail=1; \
	fi; \
	[ $$fail -eq 0 ] || exit 1; \
	echo "deb: $$seen packages, $$checked with a postinst, none enables, starts or stops anything"
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
# **The C writes them, since 0279.** This ran four Rust tests, which was right
# while the Rust was what shipped and wrong from the day it stopped: a witness
# generated by a program nobody runs is 0266's shape in the last place it
# survived, and it came to a head when the C acquired a tenth backend kind the
# Rust has no word for -- `observed.json` could not carry it and no bless could
# have put it there.
#
# Three of the four are a round trip: the witness is read through the C's own
# reader, written through its own writer, and laid out by `ncfg_json_pretty`,
# which reproduces what `serde_json::to_string_pretty` wrote byte for byte --
# the property that made this a move rather than a reformatting. `plan.json`
# is the one built from values in a test, as it was in the Rust.
#
# `socket.json` is a generator, `c/tests/socket_witness_test.c`, and it is the
# only one of the four that is a message set rather than one value: 67 lines,
# each written by the encoder the daemon answers with, in an order the builder
# owns rather than reads. Six of them are the wifi answers and are produced by
# asking the repository's fake supplicant and fake hostapd, which is why this
# target forks three python processes; 0281 re-authored those six lines to what
# the fakes answer, since no fixture here could produce what they used to say.
#
# It compares as well as writes, so `make check` holds all 67 lines byte for
# byte and this target is the deliberate way to move them.
schema-bless:
	@$(MAKE) --no-print-directory -C c tests/observed_test tests/document_test \
		tests/plan_test tests/socket_witness_test
	@cd c && NCFG_BLESS=1 ./tests/observed_test >/dev/null
	@cd c && NCFG_BLESS=1 ./tests/document_test >/dev/null
	@cd c && NCFG_BLESS=1 ./tests/plan_test >/dev/null
	@cd c && NCFG_BLESS=1 ./tests/socket_witness_test >/dev/null
	@echo "schema-bless: four witnesses rewritten; `git diff --stat doc/schema | tail -1`"
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
# A decision record that quotes the tree must quote something the tree still
# says.
#
# Three records in the M9 wifi audit were found asserting what the code
# contradicts, and one of them was falsified by the round immediately before it
# and stood for a week. Prose does not compile, so nothing noticed.
#
# This is the half that can be mechanised: a marked quotation. It catches
# quotations and not paraphrases, which is the honest limit and is written on
# the tool. What catches a paraphrase is somebody reading the code while
# writing the next record -- which is what caught all three, and is a practice
# rather than a gate.
claims:
	@python3 tool/cited_quote_gate.py

# What the packages would actually change on this machine.
#
# Twenty-one of the forty-five commits in the M9 wifi audit touched only
# documents, and every round still paid a full build, install and live
# verification -- decided each time by unpacking the .deb by hand and comparing
# checksums. That is the artifact answering the question, which is the right
# way round; this is it written down so it is one command rather than five.
#
# Reads only. It unpacks into a temporary directory and compares; nothing is
# installed and nothing under /usr is touched.
installed-diff:
	@set -e; \
	found=0; changed=0; \
	tmp=$$(mktemp -d "$${TMPDIR:-/tmp}/ncfg-installed.XXXXXX"); \
	trap 'rm -rf "$$tmp"' EXIT INT TERM; \
	for deb in $(DIST)/*.deb; do \
		[ -e "$$deb" ] || { echo "installed-diff: no packages; run make deb first"; exit 1; }; \
		case "$$deb" in *-dbgsym_*) continue ;; esac; \
		rm -rf "$$tmp/x"; mkdir -p "$$tmp/x"; \
		dpkg-deb -x "$$deb" "$$tmp/x"; \
		cd "$$tmp/x"; \
		for file in $$(find . -type f | sed 's|^\./||'); do \
			found=$$(( found + 1 )); \
			if [ ! -e "/$$file" ]; then \
				echo "new      /$$file"; changed=$$(( changed + 1 )); \
			elif ! cmp -s "$$file" "/$$file"; then \
				echo "changed  /$$file"; changed=$$(( changed + 1 )); \
			fi; \
		done; \
		cd $(CURDIR); \
	done; \
	if [ "$$found" -eq 0 ]; then \
		echo "installed-diff: the packages hold no files, which is not a clean result"; \
		exit 1; \
	fi; \
	if [ "$$changed" -eq 0 ]; then \
		echo "installed-diff: $$found packaged file(s), none of them different \
from what is installed"; \
		echo "installed-diff:   nothing to install; the round changed no shipped file"; \
	else \
		echo "installed-diff: $$found packaged file(s), $$changed of them different"; \
	fi

# The program icon, from one master.
#
# **Every size is committed**, so a machine building netcfgd needs no image
# tooling -- only whoever replaces the master does. Same bargain `doc/schema`
# makes: the generated artifact is in the tree so that building and shipping
# need none of what produced it.
#
# 16 for a menu, 22 and 32 for the TDE panel, 24 for a toolbar, 48 for a
# desktop file, and the rest because hicolor is asked for them and an absent
# size is scaled from the nearest one by whoever is drawing, usually badly.
ICON_SIZES = 16 22 24 32 48 64 128 256
ICON_MASTER = art/netcfgd-master.png

icons:
	@command -v convert >/dev/null 2>&1 || { \
		echo "icons: ImageMagick is not installed (apt install imagemagick)"; \
		exit 1; \
	}
	@test -f $(ICON_MASTER) || { echo "icons: $(ICON_MASTER) is missing"; exit 1; }
	@# Square and big enough, checked rather than assumed: a master smaller
	@# than the largest render would be scaled *up*, which is the one thing
	@# this pipeline must never do quietly.
	@geom=$$(identify -format '%w %h' $(ICON_MASTER)); \
	w=$${geom% *}; h=$${geom#* }; \
	[ "$$w" = "$$h" ] || { echo "icons: the master is $${w}x$${h}, not square"; exit 1; }; \
	[ "$$w" -ge 256 ] || { echo "icons: the master is $${w}px, smaller than the largest render"; exit 1; }
	@mkdir -p art/icon
	@for size in $(ICON_SIZES); do \
		convert $(ICON_MASTER) -filter Lanczos -resize $${size}x$${size} \
			-strip art/icon/netcfgd-$${size}.png || exit 1; \
	done
	@echo "icons: rendered $(words $(ICON_SIZES)) size(s) from $(ICON_MASTER)"
	@echo "icons:   commit art/icon/ -- the build installs these and never rasterises"

# What the gate checks: the renders exist, and every shipped `Icon=` names this
# icon rather than borrowing somebody else's from the theme.
icon-check:
	@python3 tool/icon_gate.py

# Put the rendered icons where a toolkit will look for them.
#
# `hicolor` and not a themed directory, because hicolor is the one theme every
# toolkit falls back to and the only one both front ends agree on -- the Qt
# window under `/usr` and the TDE tray under `/opt/trinity`, which looks in its
# own prefix first. Same files, two prefixes, one name.
#
# `ICON_PREFIX` is the share directory to install under, so the TDE package can
# pass its own without this target knowing anything about TDE.
ICON_PREFIX ?= $(DATADIR)

install-icons:
	@for size in $(ICON_SIZES); do \
		test -f art/icon/netcfgd-$$size.png || { \
			echo "install-icons: art/icon/netcfgd-$$size.png is missing"; \
			echo "install-icons:   run \`make icons\` and commit the result"; \
			exit 1; \
		}; \
		install -d $(DESTDIR)$(ICON_PREFIX)/icons/hicolor/$${size}x$${size}/apps; \
		install -m 0644 art/icon/netcfgd-$$size.png \
			$(DESTDIR)$(ICON_PREFIX)/icons/hicolor/$${size}x$${size}/apps/netcfgd.png; \
	done

uninstall-icons:
	@for size in $(ICON_SIZES); do \
		rm -f $(DESTDIR)$(ICON_PREFIX)/icons/hicolor/$${size}x$${size}/apps/netcfgd.png; \
	done

packaging:
	@# install and uninstall must agree, checked statically so it runs
	@# everywhere rather than only where a full install works.
	@python3 tool/uninstall_gate.py
	@# One program icon, and every front end naming it rather than borrowing
	@# a generic one from whatever theme is installed.
	@python3 tool/icon_gate.py
	@# Every setting netcfgd hands a supplicant has a real one behind it.
	@# The measurements kept being made by hand and thrown away; this is
	@# what stops the next round having to make them again. 0240.
	@python3 tool/supplicant_coverage_gate.py
	@# Every config key the compiler accepts is classified, so that a key
	@# added later cannot default to "a client may send this". 0127.
	@python3 tool/privilege_gate.py
	@# Every op the plan can name is built by the planner and run by the
	@# executor, or named as one that is not. Three were neither, and the
	@# worse direction -- planned with no executor arm -- is a reconcile that
	@# fails every time that op appears.
	@python3 tool/op_gate.py
	@# Neither program prints with `println!`, which panics when the reader
	@# of a pipe goes away. A print site is never wrong, only absent from the
	@# path a test drives. 0261.
	@python3 tool/print_gate.py
	@# No test disarms the process its siblings are in, and no test spawns a
	@# shell it cannot kill as a group. Both cost thirty seconds a run and
	@# said nothing about the cause. 0262.
	@python3 tool/disarm_gate.py
	@# Every module of the C port is reached by a test. 0263 says a module
	@# whose tests are to follow has not been ported; this is that sentence
	@# with something behind it.
	@python3 tool/c_tests_gate.py
	@# Every key the configuration language accepts against what the renderer
	@# writes. `require_lease` was accepted, defaulted on, and written nowhere,
	@# so a saved profile came back requiring a lease its probe had been told
	@# not to -- found by one example setting it, and invisible to every
	@# instrument that starts from a document.
	@python3 tool/key_coverage_gate.py
	@# And the same question from the document's side, which the one above cannot
	@# ask: a field no key expresses is invisible to a key-side gate, and both
	@# renderer defects of that kind cost a `profile save`. `schema_version` was
	@# counted by document equality and unwritable by the renderer, so every
	@# document from an older schema minor failed the round trip.
	@python3 tool/field_coverage_gate.py
	@# And every word table against the enum it indexes. The renderer keeps the
	@# language's spellings rather than the document's, deliberately; a value
	@# added to one of those enums without its word makes the renderer write
	@# `powersave = "?"` and report success, and no round trip covers it because
	@# the value that has just been added is the one no corpus sets.
	@python3 tool/word_table_gate.py
	@# And every named block the renderer can open against the list
	@# `profile save` overrides from. That omission has happened three times --
	@# `device` counted when it should not be, `bluetooth` missed when the
	@# renderer learned it, and `rule`, `access_point` and `linkset` missed for
	@# as long as it could write them -- and each time it made `ncfg profile
	@# save` refuse a faithful snapshot for a redefinition. A round trip cannot
	@# see it: it renders a document with no base to collide with.
	@python3 tool/override_coverage_gate.py
	@# And every public header in one file. `tun.h` declared an enum `document.h`
	@# already had, so any translation unit including both failed to compile --
	@# and none did, so the module built and its tests passed.
	@python3 tool/headers_compose_gate.py
	@# A doc comment written twice on one line, which an edit that pastes over
	@# itself leaves behind and nothing else notices. Four of the wrong-item
	@# kind turned up in one day; this covers the half that needs no judgement.
	@python3 tool/doc_comment_gate.py
	@# Section 4 of the socket protocol against `tier_of`. The table said 23
	@# requests while the code classified 32, and section 2's three honest
	@# things see bytes, shapes and members -- never a tier.
	@python3 tool/tier_table_gate.py
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
	@# Only a declared writer takes `/run/netcfgd/reported/<interface>`. That
	@# file belongs to whatever brought the interface up, and a second writer
	@# replaces it rather than joining it -- which cost a cellular link its
	@# resolvers for one commit. 0212.
	@python3 tool/report_writer_gate.py
	@# The udev rules and the quirks table carry the same USB ids and the same
	@# AT port index. Two files holding one fact is how the quirk somebody
	@# reads stops being the quirk that runs.
	@python3 tool/modem_rules_gate.py
	@# And udev's own opinion of the rules file, which catches what the gate
	@# above cannot: a syntax error. `="` where `=="` was meant is a rule that
	@# *assigns* an attribute instead of matching one, which udev accepts as a
	@# sentence and refuses as a rule -- and a rules file that does not load
	@# fails silently, leaving the port with no stable name and no message
	@# anywhere. Skipped loudly where udevadm cannot do it, which is every
	@# machine this project targets that does not run systemd -- and also every
	@# machine whose systemd is older than `udevadm verify`.
	@#
	@# **The guard asked for the BINARY and meant the SUBCOMMAND**, which is
	@# `evidence.md`'s *a name is not a capability* exactly. Measured on a
	@# machine with udevadm 251: `command -v udevadm` succeeds, `verify` is not
	@# in its command list, and the gate died with `udevadm: missing or unknown
	@# command` -- so `make check` could not complete at all there, for a reason
	@# that had nothing to do with the tree. The lax direction, as that entry
	@# warns: the guard skipped nothing and handed the failure to the gate.
	@#
	@# `<verb> --help` is the probe because it attempts the verb rather than
	@# reading the help text, which is a format that can change. Its ability to
	@# report *present* is controlled with a verb this udevadm does have:
	@# `udevadm info --help` exits 0 where `udevadm verify --help` exits 2.
	@# What is NOT verified here is the verify-present path end to end, which
	@# needs a systemd new enough to carry the verb; the first machine that has
	@# one exercises it.
	@#
	@# Three states and three messages, because "not installed" and "too old"
	@# send a reader to different fixes.
	@if ! command -v udevadm >/dev/null 2>&1; then \
		echo "udev-rules: udevadm not installed, skipping the syntax check"; \
	elif ! udevadm verify --help >/dev/null 2>&1; then \
		echo "udev-rules: this udevadm has no \`verify\` subcommand, skipping"; \
		echo "udev-rules:   the syntax check. It arrived in a later systemd;"; \
		echo "udev-rules:   this machine has udevadm $$(udevadm --version 2>&1 | head -1)."; \
	else \
		udevadm verify packaging/udev/71-netcfgd-modem.rules; \
	fi
	@# Conflicts= stops a unit and does not order against it, so netcfgd could
	@# read another daemon's claim while it was still shutting down and decline
	@# an interface on behalf of something one second from gone. A race, so it
	@# failed intermittently. 0145.
	@python3 tool/conflict_order_gate.py
	@# The switcher keeps four facts about each daemon and three live in case
	@# arms, so a manager added to the list and two of the three is silently
	@# never stood down -- a fall-through reads exactly like a daemon with
	@# nothing to clean up. It also refuses to name a program netcfgd runs
	@# itself, which would be netcfgd disabling its own tools. 0168.
	@python3 tool/select_gate.py
	@# Every write in the shipped crates, against what happens when it fails.
	@# Four records were written with `let _ =` -- a considered decision in each
	@# case, and completely silent in all four, which is how a full /run would
	@# have stopped netcfgd noticing a rotated key or an edited .ovpn without
	@# one word anywhere. 0180.
	@python3 tool/write_gate.py
	@# `kill %1` needs job control, which a non-interactive shell does not
	@# have, so it does nothing and reads as cleanup. Four netcfgd daemons
	@# outlived their probes that way before this existed, and the leak
	@# surfaces an hour later as somebody else's confusing failure.
	@python3 tool/probe_gate.py
	@# A decision record's number is what source cites it by, so a number that
	@# names two records makes every citation of it ambiguous. Three did --
	@# 0263, 0264 and 0265, written within five days of each other -- because
	@# the number of a new record is the highest existing one plus one and
	@# nothing said what the highest was. This says it, which is the half that
	@# stops it recurring.
	@python3 tool/decision_gate.py
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
	: "The Exec* keys that name a program, not every key beginning Exec." \
	  "ExecPaths= is a sandbox directory list, and when 0178 added" \
	  "ExecPaths=/run/netcfgd this check began reporting a run directory as" \
	  "an uninstalled program -- and went on doing it, because whoever added" \
	  "it was running the python gates rather than make check. 0188."; \
	declared=$$( { \
		sed -n 's/^Exec\(Start\|Stop\|Reload\|StartPre\|StartPost\|StopPost\)=-\?\([^ ]*\).*/\2/p' \
			packaging/systemd/netcfgd.service; \
		sed -n 's/^Exec\(Start\|Stop\|Reload\|StartPre\|StartPost\|StopPost\)=-\?\([^ ]*\).*/\2/p' \
			packaging/systemd/netcfgd-nm.service; \
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
ASCII_PATHS  = crates backend adapter helper tests c client Cargo.toml Makefile
# `netcfgd-*` catches an installed helper, which is a script with no extension
# because it ends up on a PATH. Filtering by extension alone would have skipped
# the entire helpers directory while appearing to cover it.
#
# `--exclude-dir=target` because that pattern also matches a *compiled* binary,
# and an adapter builds one into its own tree. Widening the gate found it
# immediately, which is the gate working -- on the wrong file.
#
# **And `-I`, because the line above named a directory when it meant a
# property.** `target` is where *cargo* puts a binary. The TDE adapter builds
# with cmake, into `adapter/netcfgd-tde/build/`, and `netcfgd-tde-tray` is an
# ELF that matches `netcfgd-*` -- so the same fault came back the moment a
# second build system arrived, and `make ascii` failed for anybody who had
# built that adapter. Excluding `build` as well would be the same mistake a
# third time: the question is not which directory a file is in, it is whether
# it is text.
#
# `-I` asks that directly, and it costs the gate nothing it was doing. grep
# calls a file binary when it holds NUL bytes, and a source file with an em
# dash in it holds none -- so exactly the files this gate exists to catch are
# still read.
ASCII_KINDS  = -I --include='*.rs' --include='*.toml' --include='*.sh' \
	--include='*.c' --include='*.h' \
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
# `network-manager`, `libdbus-1-dev`, `pkg-config` and `python3-dbus` arrived
# together and for one reason: `nm.sh` could not run in here at all. It needs
# `nmcli`, which only `network-manager` ships, and it needs the shim, which
# needs libdbus to build -- so the container skipped the whole script and the
# skip read like the two the comment above explains. That is the `dhcpcd-base`
# lesson a second time, and the way to notice it is to run a script in here and
# watch it say `skipping` rather than to read the list.
#
# **`bc` is the same lesson with teeth, and it had stopped this target a third
# of the way in.** `apply_race.sh` pipes a count through `bc`; the host has it
# and this image does not, so the script exited 127, `make live` stopped there,
# and the 66 invocations at or after it -- of 81 -- never ran at all. A skip is
# quiet and an abort is loud, but both end with a container that covered less
# than the host, and the run above it printed 362 passing checks on the way to
# covering a third of the suite.
LIVE_PACKAGES = build-essential libncurses-dev iproute2 iputils-ping dnsmasq \
                dhcpcd-base hostapd wpasupplicant openvpn wireguard-tools \
                ppp pppoe iw kmod python3 python3-dbus socat unbound \
                network-manager libdbus-1-dev pkg-config bc uidmap

# The live scripts on Alpine: musl, busybox and no systemd.
#
# WHY THIS TIER EXISTS
#   netcfgd's stated audience is a machine with no systemd (0001, 0007), and
#   until 2026-10-23 not one live script had ever run against musl or against
#   busybox's userland -- `make live` runs on the developer's glibc machine and
#   `live-container` in Debian. `apk-container` proved the package builds
#   there, which is a different claim: a package that builds is not a daemon
#   that works.
#
#   It found what a second libc always finds. `[ -x binary ]` answers "is there
#   an executable file" rather than "can this machine run it", so six scripts
#   that guard on a comparison binary skipped nothing and reported `not found`
#   as a test failure several checks later; they ask the binary now. And Alpine
#   ships no kernel headers with its libc, which `packaging/alpine/APKBUILD.in`
#   has said since the apk existed -- `linux-headers` is in the list below for
#   that reason and the build fails without it.
#
# WHAT IT IS NOT
#   **A survey rather than a gate, deliberately, and NCFG_LIVE is unset.**
#   `make live` sets it so that a skip is a failure; here many skips are
#   honest -- no `mac80211_hwsim`, no `qmake6`, no systemd, no openssl -- and a
#   tier that is permanently red is one people learn to read past, which this
#   Makefile says about `vm-skipped` too. It fails on a real failure and lists
#   the skips with their reasons.
#
#   **The list and the wrappers come from `live` itself**, read out of this
#   Makefile at run time rather than copied: a loop over `tests/live/*.sh`
#   reported three helpers as failures -- `fake_umbim.sh`, `fake_mbimcli.sh`
#   and `c_daemon_tryout.sh`, which other scripts drive and which `die` when
#   run alone -- and wrapping `control_exposure.sh` in `unshare -rn`, which
#   `live` deliberately does not, failed it on a chown to an unmapped gid.
ALPINE_IMAGE ?= alpine:latest
ALPINE_PACKAGES = make build-base linux-headers iproute2 iputils dnsmasq \
                  dhcpcd hostapd wpa_supplicant openvpn wireguard-tools ppp \
                  ppp-pppoe iw kmod python3 py3-dbus socat unbound \
                  networkmanager networkmanager-cli py3-gobject3 dbus-dev \
                  pkgconf bc shadow-uidmap util-linux openssl

live-alpine:
	@command -v docker >/dev/null 2>&1 || { \
		echo "live-alpine: docker is not installed, and this target is docker"; \
		exit 1; \
	}
	@mkdir -p $(DIST)
	@printf '%s\n' \
		'set -eu' \
		'apk add --quiet --no-progress $(ALPINE_PACKAGES)' \
		'# `dhcpcd_orphan.sh` reads these; an image ships neither.' \
		'printf "root:100000:65536\n" > /etc/subuid' \
		'printf "root:100000:65536\n" > /etc/subgid' \
		'# Copied, because /src is read-only and the build must not leave' \
		'# root-owned output in the host tree.' \
		'cp -a /src /work && cd /work' \
		'# Cleaned first, or the glibc objects copied in are reused and the' \
		'# run measures this machine rather than musl -- which is the same' \
		'# trap `live-container` records at length.' \
		'make -C c clean >/dev/null 2>&1 || true' \
		'make -C adapter/netcfgd-nm/c clean >/dev/null 2>&1 || true' \
		'make -C bridge clean >/dev/null 2>&1 || true' \
		'make -C c' \
		'make nm' \
		'make -C bridge' \
		'make -C c examples' \
		'# **Every script\x27s output is kept while it runs and a passing one is' \
		'# then thrown away**, so the directory holds exactly the failures. Three' \
		'# scripts here fail one check each intermittently -- 335 runs without a' \
		'# reproduction against one failure (10.538) -- and the first attempt to' \
		'# catch one by looping the suite four times caught nothing. A tier that' \
		'# prints only the last line of a failing script cannot be diagnosed' \
		'# after the fact, which is what made that hunt necessary at all.' \
		'rm -rf /dist/live-alpine-log; mkdir -p /dist/live-alpine-log' \
		'list=$$(sed -n "/^live:/,/^$$/p" Makefile |' \
		'	grep -oE "sh tests/live/[a-z_0-9]+\.sh" |' \
		'	sed "s|sh tests/live/||" | awk "!seen[\$$0]++")' \
		'pass=0; skip=0; fail=0; slow=0' \
		'for name in $$list; do' \
		'	line=$$(sed -n "/^live:/,/^$$/p" Makefile | grep -F "tests/live/$$name" | head -1)' \
		'	case "$$line" in *unshare*) run="unshare -rn sh" ;; *) run="sh" ;; esac' \
		'	log=/dist/live-alpine-log/$$name.log' \
		'	timeout -k 10 $(LIVE_TIMEOUT) $$run "tests/live/$$name" >"$$log" 2>&1 && rc=0 || rc=$$?' \
		'	out=$$(cat "$$log")' \
		'	last=$$(printf "%s\n" "$$out" | tail -1)' \
		'	case "$$rc:$$last" in' \
		'	0:*skipping*) skip=$$((skip+1)); rm -f "$$log";' \
		'	              printf "SKIP %-26s %s\n" "$$name" "$${last#*skipping: }" ;;' \
		'	0:*)          pass=$$((pass+1)); rm -f "$$log"; printf "PASS %-26s\n" "$$name" ;;' \
		'	124:*|137:*)  slow=$$((slow+1)); printf "SLOW %-26s bound at $(LIVE_TIMEOUT)s\n" "$$name" ;;' \
		'	*)            fail=$$((fail+1)); printf "FAIL %-26s rc=%s  %s\n" "$$name" "$$rc" "$$last";' \
		'	              grep -A3 "^FAIL" "$$log" | sed "s|^|     ||" || true ;;' \
		'	esac' \
		'done' \
		'# **Handed back to whoever owns /dist**, because a container writing' \
		'# into the host tree otherwise leaves root-owned files the user cannot' \
		'# remove -- which this target did on its first run with logging, and' \
		'# which `live-container` above warns about for build output.' \
		'chown -R "$$(stat -c %u:%g /dist)" /dist/live-alpine-log 2>/dev/null || true' \
		'printf "\nlive-alpine: %s passed, %s skipped, %s failed, %s hit the bound\n" \' \
		'	"$$pass" "$$skip" "$$fail" "$$slow"' \
		'[ "$$fail" -eq 0 ] && [ "$$slow" -eq 0 ] ||' \
		'	echo "live-alpine: the output of each is in $(DIST)/live-alpine-log/"' \
		'[ "$$fail" -eq 0 ] && [ "$$slow" -eq 0 ]' \
		> $(DIST)/live-alpine.sh
	@# Named for the reason `live-container` gives: an outer `timeout` would
	@# bound this client and leave the container running.
	name=netcfgd-alpine-$$$$; \
	echo "live-alpine: $$name; stop it with 'docker kill $$name'"; \
	docker run --rm --privileged --name "$$name" \
		-v "$$PWD":/src:ro -v "$$PWD/$(DIST)":/dist \
		$(ALPINE_IMAGE) sh /dist/live-alpine.sh

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
		'# A subordinate id range for root, which `dhcpcd_orphan.sh` needs' \
		'# and an image does not ship. That script makes its own user,' \
		'# mount and network namespaces with `unshare --map-auto`, which' \
		'# reads these two files; without them it refuses, and because' \
		'# `make live` runs that one with NCFG_LIVE=1 the refusal is a' \
		'# failure that stops the suite. A developer machine has the' \
		'# equivalent line for its own user, which is why nobody here' \
		'# meets this.' \
		'printf "root:100000:65536\\n" > /etc/subuid' \
		'printf "root:100000:65536\\n" > /etc/subgid' \
		'cp -a /src /work && cd /work' \
		'cargo build --workspace --quiet' \
		'make ncfg-link PROFILE=debug >/dev/null' \
		'# **Built in here, not inherited, and cleaned first or it is' \
		'# neither.** The copy above brings the host tree with whatever' \
		'# binaries were sitting in it, and the live scripts drive' \
		'# `c/netcfgd` and the shim by path -- so without this the' \
		'# container runs whatever binaries the host had, where they' \
		'# exist, and skips the rest, which is the one thing a container' \
		'# run must not do: cover less than the host while looking like' \
		'# more.' \
		'#' \
		'# The clean is not tidiness. `cp -a` preserves mtimes and' \
		'# `.build-flags` records the flag string rather than the' \
		'# compiler, so an unclean build here inherits the verdict the' \
		'# host left -- nothing to be done -- and compiles not one file,' \
		'# which is a build step that looks like one and is not. The' \
		'# whole value of building in the image the runner uses is that' \
		'# its toolchain is not the one on this machine.' \
		'make -C c clean >/dev/null' \
		'make -C adapter/netcfgd-nm/c clean >/dev/null' \
		'make -C c >/dev/null' \
		'make nm >/dev/null' \
		'exec make live' \
		> $(DIST)/live-container.sh
	@# **Named, because the name is the only handle on it.** An outer
	@# `timeout` would bound this `docker run` and not the container: the
	@# container is a child of the daemon, so killing the client leaves it
	@# compiling, which `running-code.md` measured at `Up 10 minutes` after
	@# its supervisor had gone. `--name` is what makes `docker ps --filter`
	@# and then `docker kill` possible at all, and the pid suffix is so two
	@# of these can run without colliding.
	@#
	@# The inner `make live` carries `LIVE_TIMEOUT` with it, so the
	@# per-script bound applies in here as well; this is the bound on the
	@# thing that bound cannot reach.
	@# **`--group-add users`, because root in an image has one group.**
	@# `control_exposure.sh` observes a chown onto a secondary group and
	@# skips without one, and `make live` runs that one with NCFG_LIVE=1,
	@# so the skip stops the suite at invocation 57 of 81. Docker's own
	@# flag rather than a `usermod` in the script: membership added to a
	@# passwd file does not reach a process that is already running, and
	@# the suite runs in that process.
	@#
	@# **And it is inert everywhere else, which had to be measured because
	@# a run with it looked like it had broken `link_local.sh`.** Every
	@# other script is wrapped in `unshare -rn`, which denies `setgroups`:
	@# inside it the groups are `0 65534` whether this flag is passed or
	@# not, and on the host they are `0 65534` too, from a user with
	@# eighteen. So the flag cannot reach the scripts that run in there.
	@# That failure is unexplained rather than explained -- see 10.523.
	@#
	@# One recipe line, because each one is its own shell: announcing the
	@# name from a line of its own printed a different `$$$$` from the one
	@# the container got, so the message named a container that did not
	@# exist. Unprefixed, so make echoes what ran -- a docker run is
	@# network access and worth seeing.
	name=netcfgd-live-$$$$; \
	echo "live-container: $$name; stop it with 'docker kill $$name'"; \
	docker run --rm --privileged --name "$$name" --group-add users \
		-v "$$PWD":/src:ro -v "$$PWD/$(DIST)":/dist \
		$(LIVE_IMAGE) sh /dist/live-container.sh

# What the shipped binaries are allowed to link.
#
# Section 1 constraint 3 and the README's headline both say the core needs
# nothing beyond libc and the kernel, and nothing checked it.
#
# **The question it answers is now a link-level one and nothing else answers
# it.** While the shipped daemon was Rust, `deny` governed the crate graph and
# this governed what that graph dragged in -- a dependency linking a C library
# adds a NEEDED entry without adding anything `deny` objects to, and a build
# script finding a system library adds one with no crate at all. In C there is
# no graph and no build script: a NEEDED entry arrives because somebody added
# `-l` or an `#include` of something pkg-config knows about, which no other
# gate here reads.
#
# **It checked the Rust binary until 0276's follow-up, which is the wrong
# artifact and had been since 0266.** That record named `size`, `rss` and
# `footprint` as gates measuring a binary nobody ships; this is the fourth of
# that family and nobody listed it. A gate whose own comment says "what the
# SHIPPED binary is allowed to link" and reads `target/release/netcfgd` is
# worse than no gate, because the sentence is exactly what stops anybody
# looking.
#
# ncurses came off the core's list in the same change. It was there because
# `ncfg tui` is a default *cargo feature* and design section 10.2 lists it as
# removable -- and the C's TUI writes its own escape sequences, which
# `c/src/cli/tui_term.c` argues at length, so the shipped daemon links libc
# alone. Measured 2026-10-21: `objdump -p c/netcfgd` has one NEEDED entry.
# libgcc_s came off for the same reason and is the sharper case, since nothing
# chose to drop it -- the C simply does not pull it, and an allow list carrying
# a library the binary does not link is a gate that would not notice it
# arriving.
#
# **Two lists, because they are two claims.** The core's is constraint 3: libc
# and the kernel. The shim's is 0264's answer -- the D-Bus stack the core must
# not have, taken from the system rather than vendored -- so it is libc plus
# `libdbus-1` and that is the whole of it. `nm-containment` asserts the shim
# HAS that stack; this asserts the core has not acquired it and the shim has
# acquired nothing else.
LINKAGE_ALLOWED     = libc.so ld-linux
LINKAGE_ALLOWED_NM  = libc.so ld-linux libdbus-1.so
# The shim's positive control: the one library it is supposed to link.
LINKAGE_REQUIRED_NM = libdbus-1.so

linkage:
	@# Built here rather than trusted, which is the half worth keeping from
	@# the Rust version: what is sitting in a build directory depends on the
	@# last build, and `make install` builds before it installs for the same
	@# reason. Both are no-ops when the gates ahead of this have run.
	@$(MAKE) --no-print-directory -C c
	@$(MAKE) --no-print-directory linkage-one BIN=c/netcfgd \
		ALLOWED="$(LINKAGE_ALLOWED)" WHOSE="constraint 3"
	@# Guarded the way every other gate that needs the shim is guarded. A skip
	@# is said out loud: a machine with no libdbus headers cannot build the
	@# shim, so it cannot link anything it should not either, but a silent
	@# skip is how a gate stops being a gate.
	@if pkg-config --exists dbus-1 2>/dev/null; then \
		$(MAKE) --no-print-directory -C adapter/netcfgd-nm/c >/dev/null; \
		$(MAKE) --no-print-directory linkage-one \
			BIN=adapter/netcfgd-nm/c/netcfgd-nm \
			ALLOWED="$(LINKAGE_ALLOWED_NM)" \
			REQUIRED="$(LINKAGE_REQUIRED_NM)" WHOSE="0264's containment"; \
	else \
		echo "linkage: libdbus-1 is not installed, so the shim was not built"; \
		echo "linkage:   and its link list was not checked"; \
	fi

# One binary, against one list. Its own target rather than a shell function in
# the recipe above, so that the failure arm names which binary and which claim
# -- the same list twice with a different verdict is how a reader ends up
# reading the recipe to find out which half failed.
linkage-one:
	@[ -x "$(BIN)" ] || { \
		echo "linkage: $(BIN) is missing, so this would check nothing"; \
		exit 1; \
	}
	@needed=$$(objdump -p "$(BIN)" 2>/dev/null | awk '/NEEDED/ {print $$2}'); \
	if [ -z "$$needed" ]; then \
		echo "linkage: $(BIN) has no NEEDED entries at all -- either it is a"; \
		echo "linkage:   static binary or objdump said nothing, and a gate that"; \
		echo "linkage:   cannot tell those apart is not a gate"; \
		exit 1; \
	fi; \
	fail=0; \
	for lib in $$needed; do \
		ok=0; \
		for allowed in $(ALLOWED); do \
			case "$$lib" in *"$$allowed"*) ok=1 ;; esac; \
		done; \
		[ "$$ok" -eq 1 ] || { \
			echo "linkage: $(BIN) links $$lib, which $(WHOSE) does not allow"; \
			echo "linkage:   if this is deliberate, it is a decision to record,"; \
			echo "linkage:   not a line to add to an allow list in passing"; \
			fail=1; \
		}; \
	done; \
	for want in $(REQUIRED); do \
		found=0; \
		for lib in $$needed; do \
			case "$$lib" in *"$$want"*) found=1 ;; esac; \
		done; \
		[ "$$found" -eq 1 ] || { \
			echo "linkage: $(BIN) does not link $$want, which $(WHOSE) is about"; \
			echo "linkage:   -- so this gate was passing for the boring reason"; \
			fail=1; \
		}; \
	done; \
	[ "$$fail" -eq 0 ] || exit 1; \
	echo "linkage: $(BIN): $$(echo $$needed | wc -w) shared librar$$([ $$(echo $$needed | wc -w) -eq 1 ] && echo y || echo ies), all allowed"

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
	@# **The C, because the C is what `make install` installs** (0266). This
	@# measured `target/release/netcfgd` until then, so after 0266 it was
	@# ratcheting a binary nobody ships -- and at a third the size the gate
	@# would have passed for a reason that has nothing to do with the budget
	@# holding. The basis changed with it: the Rust profile stripped on the way
	@# out and the C build does not, so the number here is what lands in
	@# `$(SBINDIR)` rather than what a packager's `dh_strip` leaves behind.
	@$(MAKE) --no-print-directory -C c
	@tol=$$(awk '/^tolerance_percent/ {print $$2}' size-budget.txt); \
	limit=$$(awk '/^total/ {print $$2}' size-budget.txt); \
	total=0; \
	while read -r name value; do \
		case "$$name" in ''|\#*|tolerance_percent|total) continue ;; esac; \
		bin=c/$$name; \
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
	@# The C, for 0266's reason and the size gate's. `c/ncfg` is the symlink
	@# the C build makes itself, so there is no `ncfg-link` step here any more.
	@$(MAKE) --no-print-directory -C c
	@# `ncfg` is a symlink cargo cannot make, and nothing else in `check`
	@# creates the debug one -- `size` makes the release one. So after a
	@# `make clean` this ran a binary that was not there, `|| true` swallowed
	@# it, and the gate reported "/run does not match" for an empty /run. The
	@# check was pointing at the wrong thing entirely, which is why the
	@# missing binary is now its own sentence.
	@[ -x ./c/ncfg ] || { \
		echo "footprint: ./c/ncfg is missing, so this would check nothing"; \
		exit 1; }
	@work=$$(mktemp -d); \
	cp -r tests/footprint/etc "$$work/etc"; \
	mkdir -p "$$work/run"; \
	NCFG_CONFIG_DIR="$$work/etc" NCFG_RUN_DIR="$$work/run" \
		./c/ncfg plan >/dev/null 2>&1 || true; \
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

# **Raised from 4608 deliberately, and it is not a memory regression.** The
# profile feature and the document renderer added 32 KB of text (2583064 ->
# 2615832 bytes, still inside the size gate's 3% tolerance), and VmHWM counts
# resident text page by page -- so the number this gate pins moved while the
# allocation it is nominally about did not: RssAnon went 488 -> 500 KB.
# Measured five runs before the feature (4320..4500) and four after
# (4520..4656), on glibc. On musl, which is what the apk ships, the same
# daemon peaks around 2920 KB.
#
# Left as a ratchet rather than tightened, because tuning a footprint budget
# while the design is still moving is optimising the wrong end. Re-derive the
# band from measurement once the feature set settles.

# **Re-derived 2026-09-07, because the band had stopped covering the noise.**
# `make check` went red at 4880 of 4864 and five runs of `make rss` on the same
# build gave 4716, 4732, 4724, 4764, 4764 -- so the gate was failing on where
# the measurement landed rather than on anything the daemon did. That is the
# failure this limit's own headroom exists to prevent, and a gate that goes red
# at random is one people re-run until it is green, which is worse than no gate.
#
# Two things moved it, and both are the mechanism this comment already
# describes rather than an allocation regression:
#
#   * VmHWM counts resident TEXT page by page, and the binary grew 2,800,152 ->
#     2,812,440 bytes across `wifi_forget` and the write diagnostics -- three
#     pages, about 12 KB, arriving directly in the number this gate pins.
#   * The measurement is sensitive to load. Idle it sits at 4716..4764; with a
#     `make check` running beside it, 4808 and 4880. Page reclaim under memory
#     pressure is exactly what the original band was sized for, and this
#     machine has more sessions on it than it did.
#
# `RssAnon` -- what netcfgd actually allocated -- is 532 KB, against 500 KB when
# the limit was last raised. That is the honest number for "is it using more
# memory", and 32 KB of it is real. The other 300 KB of the raise is text and
# noise, which is why both figures are printed on every run.
#
# 5120 was the observed peak plus a band wider than the observed spread
# (4880 + 240; the spread across seven runs is 164). Still a ratchet: raising
# it stays a deliberate edit with the measurement in the commit.
#
# **3072 SINCE 0266, BECAUSE THE DAEMON MEASURED IS NOW THE C ONE.** Everything
# above this paragraph is about the Rust binary and is kept because it is the
# history of the band, not because it still describes what runs.
#
# Method, so the number can be re-taken rather than believed: the same fixture
# this gate uses (`tests/footprint/etc`, `--no-apply-on-start`, two seconds),
# three runs, reading `VmHWM` from `/proc/<pid>/status`.
#
#     c      2840  2848  2900      RssAnon 344..348   Pss 1154..1190
#     rust   4800  4856  4720      RssAnon 540..544   Pss 2931..3031
#
# So the C peaks about 1.9 MB lower and allocates about 195 KB less. 3072 is
# 5.9% above the highest of the three, which is the headroom 5120 had over the
# Rust's 4856 -- the band is the same shape, moved down with the measurement,
# rather than a round number chosen because it looked safe.
RSS_LIMIT_KB ?= 3072

# **The control directory is redirected too, and was not (0224).**
# `--config-dir` and `--run-dir` send this daemon's own state into a scratch
# directory, which reads as complete isolation and is not: the wpa_supplicant
# control directory is a third path, it defaults to the host's
# `/run/wpa_supplicant`, and `NCFG_WPA_CTRL_DIR` exists precisely so a test does
# not share it -- its own documentation says so.
#
# So this gate reached into the running machine's directory twice over. It left
# two reply sockets there on every run, because the `kill` below is a SIGTERM
# and netcfgd installs no handler, so nothing runs `Drop`. And on start it ran
# the reaper across the host's entries -- harmless while that reaper could not
# identify a stale socket, and no longer harmless now that it can.
#
# Found by watching three days of real evidence disappear from
# `/run/wpa_supplicant` during a `make check` that was only supposed to be
# measuring how much memory the daemon uses.
rss:
	@$(MAKE) --no-print-directory -C c
	@work=$$(mktemp -d); \
	cp -r tests/footprint/etc "$$work/etc"; mkdir -p "$$work/run" "$$work/wpa"; \
	NCFG_WPA_CTRL_DIR="$$work/wpa" \
	./c/netcfgd --config-dir "$$work/etc" --run-dir "$$work/run" \
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

# Section 6 wants a target per parser. **The variables that drive them live
# beside the `fuzz` target itself now**, because there were two sets: this
# block defaulted `FUZZ_TARGET` to `netlink_wire` for the cargo-fuzz recipe,
# and a second `?=` further down could not override it -- so a loop over every
# target would silently have fuzzed one.
#
# The argument this block made is still the right one and is kept: a target
# nobody can run on the machine they commit from is a target that rots, and a
# randomised test that runs every time is not a substitute for coverage-guided
# fuzzing. Both, deliberately. What changed is which half runs every time --
# the C corpus replay, in `make c-test`, rather than the Rust's
# `crates/*/tests/random.rs`.

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
# The VM tier (0275): what a namespace cannot do, which is its own kernel, its
# own modules and its own init. Not in `check` and not in `live` -- it wants a
# network for the first fetch, a writable /dev/kvm, and about a quarter of a
# minute per guest. `live` stays the inner loop.
#
# Measured on the machine this was written on: a guest reaches a payload in
# ten seconds, reports kernel 6.12.1-3-lts against the host's 6.12.107, runs
# OpenRC 0.55.1, and loads mac80211_hwsim, hci_vhci and pppoe -- which gives
# two radios at phy0 and phy1 and a /dev/vhci. Those are exactly the three
# capabilities the eight skipping live scripts name.
vm: vm-image
	sh tool/vm/run.sh tool/vm/payload/capability.sh

# Several guests on one wire, which is what the tier was asked for. Three by
# default; `VM_COUNT` or a second argument to run.sh takes one to five.
#
# The wire is a qemu multicast socket -- real layer 2 between real kernels,
# where `unshare -rn` plus veth gives real layer 2 inside ONE kernel, which
# delegation.sh already uses. What this adds is everything above the wire.
# Measured: three guests, every pair reachable, 0% loss.
vm-cluster: vm-image
	sh tool/vm/run.sh tool/vm/payload/cluster.sh $${VM_COUNT:-3}

# The Debian guest, which is the one netcfgd's own tests can run in: it matches
# this machine's libc, so `target/debug/netcfgd` runs straight off the
# read-only share with nothing cross-built and no toolchain installed here.
# Measured: `netcfgd 0.1.0` printed from inside a guest, 20 seconds to the
# payload, under systemd -- which is also what sandbox_writes.sh refuses for.
vm-debian: vm-image
	VM_GUEST=debian sh tool/vm/run.sh tool/vm/payload/share.sh

# `tests/live/sandbox_writes.sh` under a real systemd, which is the script this
# whole tier was built for: on a sysvinit machine it ends `make live` with a
# non-zero exit because its last block cannot run at all.
#
# Measured on 2026-10-07: 31 checks in the guest against 25 here, and three of
# the six it adds are the script's own CONTROLS -- the two "cannot without this
# line, so that line is load-bearing" sabotages and the probe's own positive
# control. So the guest does not merely assert more, it supplies the checks
# that make the others mean something.
vm-sandbox: vm-image
	VM_GUEST=debian sh tool/vm/run.sh tool/vm/payload/sandbox_writes.sh

# Every live script that skips here, run in a guest that can run them. It
# installs what they need inside the guest first, so this one wants a network
# and takes several minutes; `VM_TIMEOUT` is set high for that reason.
#
# It is expected to FAIL today, and the failures are the point: scripts that
# never ran anywhere run here, and 0265 records what is established about each
# remaining failure and what is not.
#
# **The two kinds of failure are not the same and the payload now only carries
# one.** `delegation.sh` cannot run here at all -- it wants odhcp6c, which
# Debian does not package -- so it has left the payload's list for
# `vm-delegation` below, which exists to pay for that build separately.
# Keeping it in the list bought one permanent red verdict for a reason this
# tree had already decided was not this payload's, and a tier whose verdict
# cannot change is one nobody reads.
#
# **`association.sh` was the other kind: a prerequisite nobody built.** Its
# probe is `c/examples/live_association`, which `association.sh` resolves
# correctly off `$$build` -- the source is `c/examples/live_association.c` and
# `c/Makefile` has an `examples` target for it. It is simply not part of `all`,
# for the same reason tests are not, so neither `make live` nor this payload
# had ever built it and the script reported "the probe is not built" in a tier
# built to run it. Built here, on the host, because the guest reads these
# binaries off the read-only share exactly as it reads `netcfgd` itself.
vm-skipped: vm-image
	@$(MAKE) --no-print-directory -C c examples
	@# **The shim the guest drives is this tree's binary, built here.** The
	@# repository is mounted into the guest read-only over 9p, so what
	@# `nm.sh` runs is whatever is sitting in the working tree -- and
	@# `make test` in the adapter relinks the test binary and NOT the
	@# program, so a change can be built, unit-tested and then driven in the
	@# guest in its absence. Measured 2026-10-19: a fix for a real failure
	@# was read as having not worked, over a twenty-minute cycle, because
	@# the guest ran the binary from before it. `build-and-commit.md` names
	@# exactly this -- never conclude a test's verdict from a binary the
	@# build step did not rebuild -- and `live` already guards the same
	@# build for `c_nm_signals.sh`, which is where this shape comes from.
	@if pkg-config --exists dbus-1 2>/dev/null; then \
		$(MAKE) --no-print-directory -C adapter/netcfgd-nm/c >/dev/null || \
			{ echo "vm-skipped: the C NetworkManager shim does not build against this tree" >&2; \
			  exit 1; }; \
	fi
	VM_GUEST=debian VM_TIMEOUT=900 sh tool/vm/run.sh tool/vm/payload/skipped.sh

# `delegation.sh`, the one live script that has never run anywhere: it needs
# real root and `odhcp6c`, which Debian does not package. Its own target rather
# than a step in `vm-skipped`, because the build pulls `build-essential` and
# charging that to the other eight scripts is how a suite stops being run.
# Longer, because two source builds happen before the test does.
vm-delegation: vm-image
	VM_GUEST=debian VM_TIMEOUT=1800 sh tool/vm/run.sh \
		tool/vm/payload/delegation.sh

# The two init integrations nothing has ever executed: the LSB script and the
# `openrc-run` one. Debian packages `openrc`, so one guest runs both against
# the ordinary glibc binary -- which Alpine cannot, being musl.
vm-init: vm-image
	VM_GUEST=debian VM_TIMEOUT=900 sh tool/vm/run.sh tool/vm/payload/init.sh

# Separate, because the fetch is the only part that needs the internet and it
# is a no-op once the images are in place. Both guests: Alpine for kernel and
# module work, Debian for netcfgd's own suite and for systemd.
vm-image:
	sh tool/vm/fetch.sh

.PHONY: vm vm-cluster vm-debian vm-delegation vm-image vm-init vm-sandbox \
	vm-skipped

# The hull tier: the same payloads, in a machine `hull` runs.
#
# WHY THESE TARGETS EXIST, WHICH IS NOT CONVENIENCE
#   Three rigs under `tests/hull/` had no target and were run by hand, so
#   nothing could notice them rotting -- and each is the only place one of
#   netcfgd's payloads runs at all. `hwsim.sh` needs `mac80211_hwsim`, which a
#   namespace cannot load; `sandbox_writes.sh` needs systemd as pid 1, which a
#   container cannot be talked into; `packaging/openrc/netcfgd` needs an
#   OpenRC-booted guest, which this tree's own VM tier cannot build because
#   `openrc` depends on `insserv` and `systemd-sysv` conflicts with it.
#
#   **The fourth is there for the opposite reason: it needs a kernel that
#   cannot do something.** `natcap` measures what the kernel answers when a
#   construct netcfgd asks for is unreachable -- the `nat` chain type, the
#   masquerade, a scheduler, the `ifb` device, the mirror's filter and its
#   action -- which no tier here could ask: this host has all of them, and a
#   container and a namespace share this host's kernel, where a chain type and
#   a qdisc kind are registered globally. A guest's module autoload is the
#   rig's to block, and that is the whole of why it exists.
#
# NOT IN `check` AND NOT IN `live`, for the VM tier's reasons (0275) plus one
# of its own: each wants `/dev/kvm`, minutes, and a sibling project's binary.
#
# **`hull` is a sibling checkout, not vendored**, so `HULL` is a variable and
# nothing here hard-codes a path. That is the live-sibling cost
# `harmonization.md` names -- what it builds against is whatever that session
# left it as -- which is why every run prints the version and commit it rested
# on rather than leaving a report to claim one.
HULL           ?= $(HOME)/src/hull/build/hull
HULL_TIMEOUT   ?= 900

# **The images are hull's, not this tree's, since 2026-10-25** (project.md
# 10.558). Each rig's `hull.conf` carries a `(build ...)` form beside its
# machine, and the image is a stored ref -- `netcfgd/hwsim` and the rest --
# rather than a directory under `dist/`. `$(DIST)/hull` is therefore no longer
# produced; `hull-clean` removes a stale one if an older checkout left it.
#
# They need a hull carrying `b7126fe`, which made a materialized tree root
# traversable; before it no non-root uid could run anything during a step, so
# apt's sandbox fell back to root and a maintainer script could not act as its
# own system user. Each build step checks that property rather than a version,
# and says what it needs when it fails.

# Refuse early with something actionable, then say what we are standing on.
# `command -v` so that `HULL=hull` off a PATH works as well as a path does.
#
# **The commit comes from `hull --version`, not from the checkout the binary
# sits in**, since hull `f48d7c2` puts it on a line of its own. The first
# version of this asked git for the HEAD of that directory, and the difference
# is not theoretical: measured 2026-10-23, the binary answered
# `f48d7c28516b-dirty` while that checkout's HEAD was `48139be` -- two commits
# on, because a binary is as old as the last build and a tree is as new as the
# last pull. The git lookup stays as the fall-back for a hull too old to say,
# marked as derived so a reader is not told the binary claimed it.
hull_says = command -v $(HULL) >/dev/null 2>&1 || \
		{ echo "hull: $(HULL) is not runnable. hull is a sibling project," >&2; \
		  echo "hull:   not vendored here -- build it there and set HULL=<path>." >&2; \
		  exit 1; }; \
	said=$$($(HULL) --version 2>/dev/null); \
	commit=$$(printf '%s\n' "$$said" | sed -n 's/^commit //p' | head -1); \
	if [ -z "$$commit" ]; then \
		derived=$$(git -C "$$(dirname "$$(command -v $(HULL))")" rev-parse --short HEAD \
			2>/dev/null); \
		commit=$${derived:+$$derived, derived from its checkout}; \
	fi; \
	printf 'hull: %s (%s), image %s\n' \
		"$$(printf '%s\n' "$$said" | head -1)" \
		"$${commit:-commit unknown}" "$(1)"

# Build a rig's image when the store has no ref for it. `hull build` is itself
# cached per step, so asking again is cheap -- but asking only when the ref is
# absent keeps a rig run from reaching the network at all on the common path.
hull_image = $(HULL) images 2>/dev/null | grep -q "^netcfgd/$(1)[[:space:]]" || \
	{ echo "hull: netcfgd/$(1) is not in the store, building it from its spec"; \
	  timeout -k 30 $(HULL_TIMEOUT) $(HULL) build -f tests/hull/$(1)/hull.conf \
		netcfgd/$(1); }

# **`timeout` is the right bound here and would not be for a container.** A
# `(backend vm)` machine is qemu, a child of this shell, so a signal reaches
# it; hull's docker engine would leave the container running with the
# supervisor dead, which `running-code.md` measures. These four specs all say
# `(backend vm)`, and a spec that changes that wants its own bound.
hull: hull-hwsim hull-sandbox hull-openrc hull-natcap hull-wire hull-delegation \
      hull-delegation-lossy hull-regdom

# DHCPv6 prefix delegation across a wire, on the harness `hull-wire` proved.
#
# **The assertion is relational and lives in the guest that can make it.** The
# prefix kea delegates is known to the ISP's config and the address drawn from
# it is known to the CPE, so `cpe.sh` compares them and the host compares
# verdicts -- which is the division `hull-wire` was built to establish.
#
# The C is built first because `cpe.sh` runs the binary off the read-only
# share: `build-and-commit.md` forbids reading a verdict off a binary the build
# step did not rebuild, and a guest cycle is exactly where that costs.
hull-delegation:
	@$(MAKE) --no-print-directory -C c
	@$(call hull_says,netcfgd/delegation)
	@$(HULL) images 2>/dev/null | grep -q "^netcfgd/delegation[[:space:]]" || \
		{ echo "hull: netcfgd/delegation is not in the store, building it"; \
		  timeout -k 30 $(HULL_TIMEOUT) $(HULL) build \
			-f tests/hull/delegation/hull.conf netcfgd/delegation; }
	@rm -f tests/hull/delegation/verdict/isp tests/hull/delegation/verdict/cpe
	@mkdir -p tests/hull/delegation/verdict
	@timeout -k 30 $(HULL_TIMEOUT) $(HULL) run -f tests/hull/delegation/hull.conf || true
	@missing=0; \
	for name in isp cpe; do \
		file=tests/hull/delegation/verdict/$$name; \
		if [ ! -f "$$file" ]; then \
			echo "delegation: $$name left no verdict, so it never reached its payload"; \
			missing=$$((missing + 1)); \
			continue; \
		fi; \
		sed "s/^/delegation: $$name: /" "$$file"; \
		grep -q '^VERDICT ok' "$$file" || missing=$$((missing + 1)); \
	done; \
	if [ "$$missing" -ne 0 ]; then \
		echo "delegation: $$missing of 2 machine(s) did not pass"; \
		exit 1; \
	fi; \
	echo "delegation: a prefix crossed the wire and netcfgd configured from it"

# The same rig with the wire losing three frames in ten each way, which is the
# test netcfgd has never been able to write.
#
# **It shares the delegation rig's payloads and verdict collector**, differing
# only in the spec's impairment, so a pass here and a failure there is about
# loss rather than about two rigs drifting apart.
hull-delegation-lossy:
	@$(MAKE) --no-print-directory -C c
	@$(call hull_says,netcfgd/delegation)
	@$(HULL) images 2>/dev/null | grep -q "^netcfgd/delegation[[:space:]]" || \
		{ echo "hull: netcfgd/delegation is not in the store, building it"; \
		  timeout -k 30 $(HULL_TIMEOUT) $(HULL) build \
			-f tests/hull/delegation/hull.conf netcfgd/delegation; }
	@rm -f tests/hull/delegation/verdict/isp tests/hull/delegation/verdict/cpe
	@mkdir -p tests/hull/delegation/verdict
	@timeout -k 30 $(HULL_TIMEOUT) $(HULL) run -f tests/hull/delegation/lossy.conf || true
	@missing=0; \
	for name in isp cpe; do \
		file=tests/hull/delegation/verdict/$$name; \
		if [ ! -f "$$file" ]; then \
			echo "lossy: $$name left no verdict, so it never reached its payload"; \
			missing=$$((missing + 1)); \
			continue; \
		fi; \
		sed "s/^/lossy: $$name: /" "$$file"; \
		grep -q '^VERDICT ok' "$$file" || missing=$$((missing + 1)); \
	done; \
	if [ "$$missing" -ne 0 ]; then \
		echo "lossy: $$missing of 2 machine(s) did not pass under the spec's loss"; \
		exit 1; \
	fi; \
	echo "lossy: a prefix crossed the wire under the impairment lossy.conf sets"; \
	grep -o '(loss [0-9.]*)' tests/hull/delegation/lossy.conf | sort -u | \
		sed 's/^/lossy:   /'

# Two machines on one wire, and the verdict collector 10.570 says the
# delegation rig turns on.
#
# **The collector is the point and the payload is not.** A single-machine rig
# reads one `VERDICT` line from one stdout with one exit; several machines need
# a verdict each, and a machine that never reached its payload must not read as
# one that passed. So each machine writes `verdict/<name>` and this target
# refuses unless **every** expected name is there and says ok -- an absent file
# being the case that cannot be faked by a payload going wrong.
#
# The directory is cleared first, by name, for the reason `evidence.md` gives
# about a stale artifact: a verdict left by the previous run would make a
# machine that never booted look like one that passed, which is this target's
# own failure mode arriving through its own evidence.
hull-wire:
	@$(call hull_says,netcfgd/natcap)
	@$(call hull_image,natcap)
	@rm -f tests/hull/wire/verdict/isp tests/hull/wire/verdict/cpe
	@mkdir -p tests/hull/wire/verdict
	@timeout -k 30 $(HULL_TIMEOUT) $(HULL) run -f tests/hull/wire/hull.conf || true
	@missing=0; \
	for name in isp cpe; do \
		file=tests/hull/wire/verdict/$$name; \
		if [ ! -f "$$file" ]; then \
			echo "wire: $$name left no verdict at all, so it never reached its payload"; \
			missing=$$((missing + 1)); \
			continue; \
		fi; \
		sed "s/^/wire: $$name: /" "$$file"; \
		grep -q '^VERDICT ok' "$$file" || missing=$$((missing + 1)); \
	done; \
	if [ "$$missing" -ne 0 ]; then \
		echo "wire: $$missing of 2 machine(s) did not pass"; \
		exit 1; \
	fi; \
	echo "wire: both machines reported, each with the segment NIC up and carrying"; \
	echo "wire:   the address it set itself. Frames across a segment are hull's own"; \
	echo "wire:   tested property; what this proves is the verdict collector"

# 27 checks. The guest builds netcfgd itself, so no host build is needed:
# hull `7b47668` gave the workload a PATH, and the payload falls back to the
# read-only share loudly if it cannot.
#
# **A failed run says whether the guest was alive**, which it could not before.
# `tool/hull-guest-cpu.sh` samples the machine's guest-side cpu while this runs
# and leaves one line behind; it is printed only when the run fails, because a
# diagnosis belongs beside a failure and a passing run does not need one. The
# sampler cannot end the run and cannot fail it -- every unhappy path it has
# writes a sentence and exits 0 -- so the worst it does is say nothing useful.
#
# It needs hull `d0582b6` for `stats --guest`; an older one answers nothing and
# the line says so rather than failing.
hull-hwsim:
	@$(call hull_says,netcfgd/hwsim)
	@$(call hull_image,hwsim)
	@verdict=$$(mktemp -t netcfgd-hwsim-guest.XXXXXX); \
	sh tool/hull-guest-cpu.sh hwsim "$$verdict" & watcher=$$!; \
	rc=0; \
	timeout -k 30 $(HULL_TIMEOUT) $(HULL) run -f tests/hull/hwsim/hull.conf || rc=$$?; \
	kill $$watcher 2>/dev/null; \
	wait $$watcher 2>/dev/null; \
	if [ "$$rc" -ne 0 ]; then \
		echo "hull-hwsim: the run failed (rc=$$rc). From outside the guest:"; \
		sed 's/^/hull-hwsim:   /' "$$verdict"; \
	fi; \
	rm -f "$$verdict"; \
	exit $$rc

# What cfg80211 lets a running machine do with its regulatory domain, for
# 0296 (project.md 10.585). It measures the kernel, not netcfgd, so nothing is
# built first. It fails only when one of its own instruments did not work --
# no database, no access point, a country nobody heard -- and otherwise prints
# what the kernel did, whatever that was.
#
# Two halves. `hull.conf` is one vm, three radios in one kernel. `wire.conf` is
# two vms on a segment with `relay.py` carrying hwsim's frames between them,
# for the case one kernel cannot hold: an access point on a channel the
# station's domain forbids. Its payloads report through ./verdict, read here.
hull-regdom:
	@$(call hull_says,netcfgd/regdom)
	@$(call hull_image,regdom)
	@timeout -k 30 $(HULL_TIMEOUT) $(HULL) run -f tests/hull/regdom/hull.conf
	@rm -f tests/hull/regdom/verdict/ap tests/hull/regdom/verdict/station
	@mkdir -p tests/hull/regdom/verdict
	@timeout -k 30 $(HULL_TIMEOUT) $(HULL) run -f tests/hull/regdom/wire.conf || true
	@missing=0; \
	for name in ap station; do \
		file=tests/hull/regdom/verdict/$$name; \
		if [ ! -f "$$file" ]; then \
			echo "regdom: $$name left no verdict, so it never reached its payload"; \
			missing=$$((missing + 1)); \
			continue; \
		fi; \
		sed "s/^/regdom: $$name: /" "$$file"; \
		grep -q '^VERDICT ok' "$$file" || missing=$$((missing + 1)); \
	done; \
	if [ "$$missing" -ne 0 ]; then \
		echo "regdom: $$missing of 2 machine(s) did not pass"; \
		exit 1; \
	fi

# 31 checks, which is every one the native tier gets (10.530) since hull
# `828f72d` mounted the guest's `/run` as an initramfs leaves it.
#
# The C is built first because the payload runs the binary off the read-only
# share: `build-and-commit.md` forbids reading a verdict off a binary the
# build step did not rebuild, and a twenty-minute guest cycle is exactly where
# that costs.
hull-sandbox:
	@$(call hull_says,netcfgd/sandbox)
	@$(call hull_image,sandbox)
	@$(MAKE) --no-print-directory -C c
	timeout -k 30 $(HULL_TIMEOUT) $(HULL) run -f tests/hull/sandbox/hull.conf

# 13 checks: the LSB script under a non-systemd init, and the `openrc-run`
# script under the one it is written for (10.531).
hull-openrc:
	@$(call hull_says,netcfgd/openrc)
	@$(call hull_image,openrc)
	@$(MAKE) --no-print-directory -C c
	timeout -k 30 $(HULL_TIMEOUT) $(HULL) run -f tests/hull/openrc/hull.conf

# 37 checks: what a kernel answers when it cannot do what netcfgd asks, which
# is the one thing no gate here could ask. The host has `nft_chain_nat` and `nft_masq`, a
# container shares that kernel, and a namespace shares it too -- so the states
# netcfgd's capability sentence is *about* were unreachable, and the sentence
# was keyed on a guessed errno until this rig measured it (10.552).
#
# The C is built first, as `hull-sandbox` is and for the same reason: the
# payload runs the binary off the read-only share, and a verdict read off a
# binary the build step did not rebuild is what `build-and-commit.md` forbids.
hull-natcap:
	@$(call hull_says,netcfgd/natcap)
	@$(call hull_image,natcap)
	@$(MAKE) --no-print-directory -C c
	timeout -k 30 $(HULL_TIMEOUT) $(HULL) run -f tests/hull/natcap/hull.conf

# The kernel tier: netcfgd against kernels built without what it asks for.
#
# WHY IT IS NOT PART OF `hull` ABOVE
#   It is a hull tier now -- the kernel key works -- but not a `hull` target:
#   three kernel builds and a source tree are not something `make hull` should
#   reach for, and nothing here can supply the tree.
#
# WHY IT EXISTS AT ALL, GIVEN `hull-natcap` MEASURES THE SAME STATES
#   That rig blocks module autoload on the host's kernel, which is the same
#   lookup failing -- an argument. This is the experiment that argument
#   predicts, with `CONFIG_MODULES` off so there is no loader to blame, and
#   the two agreed exactly (10.553). Keep both: the rig runs in minutes and
#   guards the sentences, and this answers "but is a blocked loader really
#   the same as a kernel without it".
#
# **It drives hull since 2026-10-25**, hull's `(kernel "path:FILE")` having
# landed -- so the tier lost its initramfs packing and its qemu command line,
# and its userland is the natcap image rather than a cpio. A rebuilt hull
# needs its `hull core` restarted or the old engine serves the new plan, which
# `run.sh` records at length.
#
# BY HAND, ALWAYS. It wants a 1.6 GB source tree this repository does not
# ship, three kernel builds, and `KERNEL_SRC` naming the tree:
#
#   apt-get download linux-source-6.12 && dpkg-deb -x linux-source-6.12_*_all.deb x
#   tar -xf x/usr/src/linux-source-6.12.tar.xz
#   make kernel-natcap KERNEL_SRC=linux-source-6.12
KERNEL_SRC ?=
KERNEL_OUT ?= $(DIST)/kernel

# The natcap image is its userland, materialized by `run.sh` when no
# NATCAP_ROOTFS is given -- so the image must exist, and the rig target's own
# builder is what makes it.
kernel-natcap:
	@$(call hull_image,natcap)
	@$(MAKE) --no-print-directory -C c
	sh tests/kernel/run.sh "$(KERNEL_SRC)" $(KERNEL_OUT)

# Named and printed, like `hull-clean`: three bzImages and an initramfs, about
# 95 MB, which `clean` leaves alone for the reason it leaves the guest images.
kernel-clean:
	@for f in $(KERNEL_OUT)/bzImage-k0 $(KERNEL_OUT)/bzImage-k1 \
	          $(KERNEL_OUT)/bzImage-k2 $(KERNEL_OUT)/initramfs.cpio.gz \
	          $(KERNEL_OUT)/initramfs.spec $(KERNEL_OUT)/gen_init_cpio; do \
		if [ -f "$$f" ]; then \
			printf 'kernel-clean: removing %s (%s)\n' "$$f" "$$(du -h "$$f" | cut -f1)"; \
			rm -f "$$f"; \
		fi; \
	done
	@rm -f $(KERNEL_OUT)/build-k[012].log $(KERNEL_OUT)/run-k[012].log
	@rmdir $(KERNEL_OUT) 2>/dev/null || true

.PHONY: kernel-natcap kernel-clean

# **Built when absent and never on a whim.** A build pulls a base and runs an
# apt install, so it wants a network and a few minutes; the ref being in the
# store is the signal that it is done, and `hull build` caches each step by
# the hash of its own form, so asking again when nothing changed costs a
# lookup. `make hull-image` is how you ask for all of them on purpose.
hull-image:
	@$(call hull_says,all six)
	@# `delegation` joined on 2026-10-26, `regdom` on 2026-10-27, and `wire`
	@# has no image of its own, running on `natcap`'s. A rig missing from this list still builds its
	@# image lazily on first run -- which is the quiet way the claim above,
	@# that this is the only part needing the internet, stops being true.
	@for r in hwsim sandbox openrc natcap delegation regdom; do \
		timeout -k 30 $(HULL_TIMEOUT) $(HULL) build -f tests/hull/$$r/hull.conf \
			netcfgd/$$r || exit 1; \
	done

# Named, printed, and only the refs this tree builds.
#
# **It untags rather than collecting.** The store is one per account and other
# projects keep images in it, so `hull gc` is the holder's call and not a side
# effect of cleaning netcfgd -- untagging leaves this tree's objects
# collectable whenever they choose to run it.
#
# It also removes a `$(DIST)/hull/*-rootfs` left by a checkout from before
# 2026-10-25, when the images were `docker export` directories. Named, not
# swept: a glob there would take whatever else somebody had put under it.
hull-clean:
	@# The same list as `hull-image`, and it has to stay the same list: a rig
	@# added to one and not the other leaves an image tagged that nobody
	@# believes is there.
	@for r in hwsim sandbox openrc natcap delegation regdom; do \
		if $(HULL) images 2>/dev/null | grep -q "^netcfgd/$$r[[:space:]]"; then \
			printf 'hull-clean: untagging netcfgd/%s\n' "$$r"; \
			$(HULL) tag -d netcfgd/$$r || exit 1; \
		fi; \
	done
	@echo "hull-clean: the store itself is shared; \`$(HULL) gc\` is yours to run"
	@for d in $(DIST)/hull/hwsim-rootfs $(DIST)/hull/sandbox-rootfs \
	          $(DIST)/hull/openrc-rootfs $(DIST)/hull/natcap-rootfs; do \
		if [ -d "$$d" ]; then \
			printf 'hull-clean: removing %s (%s), which predates the built images\n' \
				"$$d" "$$(du -sh "$$d" | cut -f1)"; \
			rm -rf "$$d"; \
		fi; \
	done
	@rmdir $(DIST)/hull 2>/dev/null || true

.PHONY: hull hull-hwsim hull-sandbox hull-openrc hull-natcap hull-regdom hull-image hull-clean

# WHICH BUILD THE SCRIPTS DRIVE
#   Every script under `tests/live/` takes its pair of binaries from one
#   directory, `$$build`, so `NCFG_LIVE_BUILD` points the same suite at another
#   build without a script being edited. Both trees present the same pair:
#   `netcfgd` with `ncfg` a symlink beside it.
#
#   That is what 0263 asks for before a module of the C port may replace its
#   Rust half -- "only once it passes the Rust's own tests for the same
#   behaviour". The Rust's own *unit* tests cannot be pointed anywhere: 536 of
#   them across 24 files, and only 2 of those files drive a binary at all; the
#   rest call Rust functions directly. These scripts drive a binary, and they
#   are therefore the whole of the Rust's suite that the C can be put under
#   (project.md 10.293).
#
#   **The default is the C build and this block said the opposite.** Counted
#   2026-10-10 across the 83 scripts: 69 take `$${NCFG_LIVE_BUILD:-$$repo/c}`,
#   none defaults to `target/debug`, and 14 need no binary. So pointing the
#   suite at the Rust is now the thing that takes a variable:
#
#       make live                                            the C
#       NCFG_LIVE_BUILD=$$PWD/target/debug make live         the Rust
#
#   The `live` target still builds the Rust workspace, because the three test
#   binaries it runs beside the scripts -- `wg-*`, `netcfgd_sys-*`, `live-*` --
#   are Rust ones. The scripts themselves need neither cargo nor that target: a
#   script is standalone shell and runs under `unshare -rn` on its own, which
#   is how 10.467 came to measure all 83 of them.
# How long any one live script may run before the suite stops waiting for it.
#
# **The target had no bound at all on any of its 85 invocations**, so a script
# that wedged wedged `make live` for as long as anybody left it -- and that is
# not hypothetical: `gui_wifi.sh` ran to a 180-second ceiling twice in one
# evening's sweeps, and the only reason it was noticed is that the sweep had a
# ceiling of its own. `running-code.md` is explicit that a wrapper is not the
# bound that matters and the program should refuse on its own; these scripts do
# not, so until they do this is the bound there is.
#
# **`timeout` and not a kill, deliberately.** Every one of these scripts traps
# `INT` and `TERM` and removes its work directory, stops the daemon it started
# and unmounts what it mounted. A signal runs that trap; the harness's own way
# of stopping a task does not, which is how a stopped `check-ci.sh` once left a
# container `Up 7 minutes`. So the bound signals, and `-k 30` is the second
# half: a script that ignores `TERM` gets thirty seconds and then `KILL`, which
# is worse than a clean stop and better than hanging for ever.
#
# **600 seconds, from a measurement rather than a feeling.** Across two full
# sweeps of the 83 scripts there were on 2026-10-11, every one completed inside
# 150 seconds, so this is four times the measured worst case. `link_local.sh`
# arrived afterwards and is not in that figure: timed on its own, under a
# second. The date is here because the count is the kind of number that goes
# stale the next time somebody adds a script, which is exactly what happened. `make live LIVE_TIMEOUT=1200` raises it,
# and `LIVE_TIMEOUT=0` removes it -- coreutils treats a zero duration as no
# timeout -- which is what to reach for when bisecting a slow script rather
# than editing this file.
LIVE_TIMEOUT ?= 600

live: export PATH := $(PATH):/sbin:/usr/sbin
live:
	$(CARGO) build --workspace
	@$(MAKE) --no-print-directory ncfg-link PROFILE=debug
	$(CARGO) build --tests -p netcfgd-supplicant -p netcfgd-sys
	@# WireGuard needs CAP_NET_ADMIN and the module; it skips without either.
	@binary=$$(ls -t target/debug/deps/wg-* 2>/dev/null | grep -v '\.d$$' | head -1); \
	if [ -n "$$binary" ]; then \
		timeout -k 30 $(LIVE_TIMEOUT) unshare -rn sh -c "NCFG_LIVE=1 $$binary --test-threads=1"; \
	fi
	@# netcfgd-sys's own unit tests, and this is the only place they can say
	@# anything. `shed()` is observable only from a process that has something
	@# to give up, so under `cargo test` as a person they skip -- which is how
	@# the half that asserted the wrong thing about a uid broadcast survived
	@# until a root run met it. `unshare -r` is the full set they need.
	@binary=$$(ls -t target/debug/deps/netcfgd_sys-* 2>/dev/null | grep -v '\.d$$' | head -1); \
	if [ -n "$$binary" ]; then \
		timeout -k 30 $(LIVE_TIMEOUT) unshare -rn sh -c "NCFG_LIVE=1 $$binary --test-threads=1"; \
	fi
	@binary=$$(ls -t target/debug/deps/live-* 2>/dev/null | grep -v '\.d$$' | head -1); \
	if [ -z "$$binary" ]; then echo "live: no test binary was built"; exit 1; fi; \
	timeout -k 30 $(LIVE_TIMEOUT) unshare -rn sh -c "NCFG_LIVE=1 $$binary --test-threads=1" || { \
		echo "live: if this failed to unshare, the kernel may have"; \
		echo "live:   user namespaces restricted; run as root instead"; \
		exit 1; \
	}
	@timeout -k 30 $(LIVE_TIMEOUT) unshare -rn sh -c "NCFG_LIVE=1 sh tests/live/links.sh"
	@# What a device the C port creates actually carries, compared against the
	@# Rust on one kernel and read back by `ip -d`. Most kinds ride along in the
	@# create message; a bridge deliberately does not (0057) and this port was
	@# making every one of them on the kernel's defaults.
	@timeout -k 30 $(LIVE_TIMEOUT) unshare -rn sh -c "NCFG_LIVE=1 sh tests/live/c_link_settings.sh"
	@# What the two implementations *say* about a document. The gate compares
	@# `show --json` because a plan observes the machine; a fresh namespace is
	@# what holds the machine still enough to compare one.
	@timeout -k 30 $(LIVE_TIMEOUT) unshare -rn sh -c "NCFG_LIVE=1 sh tests/live/c_warnings.sh"
	@# Both daemons, one client, the same requests. The ledger says the two
	@# request taxonomies are whole; this is what says the answers are. Nothing
	@# in it applies, because a daemon watching a machine a third process is
	@# changing reports whichever instant it sampled -- which is true of both
	@# and is not a difference between them.
	@timeout -k 30 $(LIVE_TIMEOUT) unshare -rn sh -c "NCFG_LIVE=1 sh tests/live/c_daemon_answers.sh"
	@# And what the switcher does when the network goes, against stubs for
	@# `ping`, `getent` and `systemctl`. `c_daemon_tryout.sh` is a safety net,
	@# and a safety net nobody has dropped anything into is a claim: this is
	@# the 26 checks that drop something into it, both halves -- it stops the C
	@# daemon and starts the Rust one when the network stops answering, and
	@# does neither when the network is fine.
	@#
	@# **Named here from 2026-10-11, having been named nowhere.** Of the 83
	@# scripts in `tests/live/`, this target named 79; the four it left out
	@# were the two fake modem CLIs and `c_daemon_tryout.sh`, which are
	@# fixtures other scripts drive, and this, which is a test. So it ran only
	@# for somebody globbing the directory by hand. It passes, and it is not
	@# quick -- the tryout waits out its own deadlines.
	@timeout -k 30 $(LIVE_TIMEOUT) unshare -rn sh -c "NCFG_LIVE=1 sh tests/live/c_daemon_watch.sh"
	@# **`-rmn`, and it is the only one.** A resolver delivery writes the file
	@# that decides whether this machine can resolve a name, so the script
	@# bind-mounts a sentinel over `/etc/resolv.conf` before it runs anything
	@# and checks the sentinel afterwards. A test for the defect that sends a
	@# delivery to the wrong place must not be able to cause it -- which is not
	@# hypothetical here (project.md 10.277).
	@timeout -k 30 $(LIVE_TIMEOUT) unshare -rmn sh -c "NCFG_LIVE=1 sh tests/live/c_dns_delivery.sh"
	@timeout -k 30 $(LIVE_TIMEOUT) unshare -rn sh -c "NCFG_LIVE=1 sh tests/live/switch.sh"
	@timeout -k 30 $(LIVE_TIMEOUT) unshare -rn sh -c "NCFG_LIVE=1 sh tests/live/confirm.sh"
	@timeout -k 30 $(LIVE_TIMEOUT) unshare -rn sh -c "NCFG_LIVE=1 sh tests/live/nat.sh"
	@timeout -k 30 $(LIVE_TIMEOUT) unshare -rn sh -c "NCFG_LIVE=1 sh tests/live/privacy.sh"
	@# SLAAC against a real advertisement, which is the half privacy.sh will not
	@# do. Neither under NCFG_LIVE nor under unshare: dnsmasq is a package, and it
	@# drops privileges at startup -- which `unshare -rn` forbids, so the script
	@# makes its own namespace the way dhcpcd.sh does.
	@timeout -k 30 $(LIVE_TIMEOUT) sh tests/live/slaac.sh
	@timeout -k 30 $(LIVE_TIMEOUT) unshare -rn sh -c "NCFG_LIVE=1 sh tests/live/hooks.sh"
	@# A write that fails after the file is already open, which is what a full
	@# filesystem produces and what every unit test beside those writers
	@# cannot reach: they refuse at the open. It also holds the only check on
	@# `replace` declining to fall back on a full disk -- the fallback there
	@# truncates a working resolv.conf and then reports success. 0180.
	@timeout -k 30 $(LIVE_TIMEOUT) unshare -rn sh -c "NCFG_LIVE=1 sh tests/live/write_full.sh"
	@# The read side of the same question, and the more expensive half: a
	@# configuration that could not be *read* was compiled as an empty one,
	@# which is a meaningful state -- so `ncfg apply` took the address off the
	@# interface and exited 0. `Path::is_file` answers false for a file it
	@# cannot examine. 0181.
	@timeout -k 30 $(LIVE_TIMEOUT) unshare -rn sh -c "NCFG_LIVE=1 sh tests/live/config_unreadable.sh"
	@# The third audit: a program netcfgd runs and cannot. `Permission denied`
	@# is two faults with one message from the kernel -- no executable bit, or
	@# an executable file on a `noexec` mount -- and 0178 is the second one
	@# costing a day. 0182.
	@timeout -k 30 $(LIVE_TIMEOUT) unshare -rn sh -c "NCFG_LIVE=1 sh tests/live/exec_refused.sh"
	@# Two applies at once. An apply is observe, plan, act, and nothing
	@# serialised the three: measured, two simultaneous applies produced a
	@# failed `route.add` every run, because the second planned against a
	@# machine the first then changed. 0184.
	@timeout -k 30 $(LIVE_TIMEOUT) unshare -rn sh -c "NCFG_LIVE=1 sh tests/live/apply_race.sh"
	@# A daemon that has done work does not keep growing. `make rss` measures
	@# one two seconds after it starts, which is the floor and not the risk: a
	@# kilobyte per reconcile is invisible at startup and is 100 MB by the end
	@# of a quarter. No namespace: it binds a socket and touches no interface.
	@NCFG_LIVE=1 timeout -k 30 $(LIVE_TIMEOUT) sh tests/live/steady_state.sh
	@# Every message carries a severity and a subsystem, and a level turns them
	@# down -- flog's shape, from the sibling projects. Before it, fifty
	@# `eprintln!` calls with no severity, no subsystem and no filter. 0187.
	@NCFG_LIVE=1 timeout -k 30 $(LIVE_TIMEOUT) sh tests/live/log_shape.sh
	@# Stopping, killing and restarting the daemon. netcfgd has no signal
	@# handler and no ExecStop on purpose (0134): stopping it must not take the
	@# network down, and that was a claim nothing checked. 0188.
	@timeout -k 30 $(LIVE_TIMEOUT) unshare -rn sh -c "NCFG_LIVE=1 sh tests/live/restart.sh"
	@# The one hook phase that is not a plan action, and therefore the one
	@# hooks.sh cannot reach: it needs a running daemon rather than an apply.
	@timeout -k 30 $(LIVE_TIMEOUT) unshare -rn sh -c "NCFG_LIVE=1 sh tests/live/drift.sh"
	@# Write a file, touch nothing else, does the machine change. Thirty
	@# scripts here write configuration while a daemon runs and every one of
	@# them then calls `ncfg apply` or drives the daemon by hand, so the one
	@# question project.md 10.338 asks had no witness at all. It calls `apply`
	@# nowhere, which is the point of it.
	@timeout -k 30 $(LIVE_TIMEOUT) unshare -rn sh -c "NCFG_LIVE=1 sh tests/live/config_arrives.sh"
	@# **The same eleven questions of the other config-watching mechanism.**
	@# `watch_test.c` makes `ncfg_watch_open_polling` public and asks both the
	@# same question, because the fallback "only runs when something else has
	@# already gone wrong, which makes it exactly the code nobody has ever seen
	@# work". The daemon's matching seam is `--poll-config`, and nothing here
	@# used it -- so the path was covered at unit level and not end to end.
	@#
	@# That gap is specific to this machine's history rather than theoretical:
	@# two real defects were found only because it had run out of inotify
	@# instances and the daemon was therefore polling (project.md 10.477), and
	@# the fixed sleeps in that script are 6 seconds for the same reason. With
	@# the instances back, nothing exercised the slower path at all.
	@#
	@# The run proves which mechanism it got, from the daemon's own log line, so
	@# a flag silently dropped fails rather than passing as a second inotify
	@# run. Controlled by pointing that assertion at `inotify` while the daemon
	@# was told to poll: 1 of 12 failed, and it was that one.
	@timeout -k 30 $(LIVE_TIMEOUT) unshare -rn sh -c "NCFG_LIVE=1 NCFG_LIVE_DAEMON_FLAGS=--poll-config sh tests/live/config_arrives.sh"
	@# The same question one layer up, on a radio and a supplicant netcfgd
	@# started, which is the shape 10.338 actually had. `switch_network.sh`
	@# shares this fixture and drives it with `ncfg apply` at every step; this
	@# one asks whether the daemon does it unasked.
	@timeout -k 30 $(LIVE_TIMEOUT) unshare -rn sh -c "NCFG_LIVE=1 sh tests/live/network_arrives.sh"
	@# A linkset choosing between two links, and the case metrics cannot
	@# handle on their own: a link that is up, has carrier and reaches
	@# nothing keeps its better metric while doing so, and only a probe tells
	@# it apart from one that works. Needs a running daemon for the same
	@# reason drift.sh does -- a probe is a question asked on a timer, not a
	@# plan action.
	@timeout -k 30 $(LIVE_TIMEOUT) unshare -rn sh -c "NCFG_LIVE=1 sh tests/live/linkset.sh"
	@timeout -k 30 $(LIVE_TIMEOUT) unshare -rn sh -c "NCFG_LIVE=1 sh tests/live/resolv_owned.sh"
	@# Bare, and it must stay bare: it makes its own *pid* namespace so the
	@# sweep it exercises can only see its own children. Under the suite's
	@# usual `unshare -rn` -- a network namespace only -- /proc still shows
	@# every process on the machine, and the test would terminate the
	@# developer's real NetworkManager or dhclient.
	@NCFG_LIVE=1 timeout -k 30 $(LIVE_TIMEOUT) sh tests/live/resolv_defended.sh
	@# The switcher's systemd paths, driven with a recording systemctl on a
	@# machine that has none. Bare, because it makes its own mount namespace
	@# to put a tmpfs over /run.
	@NCFG_LIVE=1 timeout -k 30 $(LIVE_TIMEOUT) sh tests/live/select.sh
	@# The other daemon-driven hook: a roam is wpa_supplicant's decision and
	@# reaches netcfgd on its event socket, so no apply can exercise it.
	@timeout -k 30 $(LIVE_TIMEOUT) unshare -rn sh -c "NCFG_LIVE=1 sh tests/live/roam.sh"
	@# The other half of that event socket, which was read for one event and
	@# throwing away every one that says a link is failing. Both ends: the
	@# supplicant's trouble events becoming lines in netcfgd's log, and the
	@# `LIST_NETWORKS` flags reaching `ncfg wifi status`.
	@timeout -k 30 $(LIVE_TIMEOUT) unshare -rn sh -c "NCFG_LIVE=1 sh tests/live/wifi_trouble.sh"
	@# And the thing a roam is not: the station moving to a DIFFERENT network,
	@# where the association netcfgd observes has to follow and the new lease's
	@# resolver has to replace the old one rather than sit beside it. roam.sh
	@# is one network under two access points and says so in its first line;
	@# this was the half nothing drove.
	@timeout -k 30 $(LIVE_TIMEOUT) unshare -rn sh -c "NCFG_LIVE=1 sh tests/live/switch_network.sh"
	@# The wireless journey with nothing configured to begin with, which is
	@# the state every M8 wifi fault was found in and no test was ever run
	@# from. It asserts the machine rather than the artifacts: a supplicant
	@# that is running, a scan that returns, a network that reached it.
	@timeout -k 30 $(LIVE_TIMEOUT) unshare -rn sh -c "NCFG_LIVE=1 sh tests/live/wifi_journey.sh"
	@# The same journey through the GUI's own buttons, which is the client the
	@# "buttons don't work properly" report was about. Skips without Qt, which
	@# is a dependency a machine may reasonably not have.
	@#
	@# **Built here rather than inside the namespace.** `unshare -rn` as root
	@# leaves the tree's own files owned by an unmapped user, so every write
	@# into it is refused -- and the script's build step failed on that and
	@# skipped, which meant the GUI's live probes had never run under
	@# `make live` on this machine. The build belongs outside the namespace;
	@# the script checks the artifacts.
	@if command -v qmake6 >/dev/null 2>&1; then 		$(MAKE) --no-print-directory -C client >/dev/null; 		for project in gui/tests/live/*.pro; do 			name=$$(basename $$project .pro); 			mkdir -p gui/tests/live/build/$$name; 			( cd gui/tests/live/build/$$name && qmake6 ../../$$name.pro >/dev/null && 			  $(MAKE) --no-print-directory >/dev/null ) || 				{ echo "live: $$name does not build against this tree" >&2; exit 1; }; 		done; 	fi
	@timeout -k 30 $(LIVE_TIMEOUT) unshare -rn sh -c "NCFG_LIVE=1 sh tests/live/gui_wifi.sh"
	@# The profile verbs against a running daemon. The gui's tray lists and
	@# switches profiles over the socket rather than off its own disk, so what
	@# the tray can do is exactly what these two verbs do -- and neither had
	@# ever been spoken to a daemon. No namespace: this touches no interface,
	@# it reads and writes configuration.
	@timeout -k 30 $(LIVE_TIMEOUT) sh tests/live/profile.sh
	@# The 802.1X path, where the worst fault of M8 was and which had no live
	@# coverage: a certificate must reach the supplicant as a path it can open,
	@# never as the content of a key.
	@timeout -k 30 $(LIVE_TIMEOUT) unshare -rn sh -c "NCFG_LIVE=1 sh tests/live/enterprise.sh"
	@# Taking a radio over when another manager lets go, which is what
	@# displacement means and the half no test covered: a guard that declines
	@# and never stops declining looks exactly like a daemon that does not work.
	@timeout -k 30 $(LIVE_TIMEOUT) unshare -rn sh -c "NCFG_LIVE=1 sh tests/live/displace.sh"
	@# A supplicant that died under a radio netcfgd owns, which is the state a
	@# crash leaves behind and the one every client reports as "cannot reach
	@# supplicant". The fix loop has to notice without being asked.
	@timeout -k 30 $(LIVE_TIMEOUT) unshare -rn sh -c "NCFG_LIVE=1 sh tests/live/revive.sh"
	@# The supplicant netcfgd left running when it stopped, after the run
	@# directory took its pid file. The process lives, the handle does not --
	@# and without recovering it netcfgd refuses its own child for ever.
	@timeout -k 30 $(LIVE_TIMEOUT) unshare -rn sh -c "NCFG_LIVE=1 sh tests/live/orphan.sh"
	@# What systemd does to the backends when the unit stops. Checks the
	@# declaration rather than the behaviour, and says so: the defect was an
	@# absent setting, and an absent setting is what this catches.
	@timeout -k 30 $(LIVE_TIMEOUT) sh tests/live/killmode.sh
	@# The other half of 0140, one backend over: udhcpc keeps netcfgd's marker
	@# in argv but has no instance lock, so a lost handle means a second client
	@# and a second lease rather than a refusal.
	@timeout -k 30 $(LIVE_TIMEOUT) unshare -rn sh -c "NCFG_LIVE=1 sh tests/live/udhcpc_orphan.sh"
	@# The tenth backend kind, wired end to end: `config = "link-local"` to a
	@# client running on the interface and back. The unit suite drives every
	@# part of this separately, so what this asks is whether they are joined --
	@# a missing arm in the plan, the executor or the observation leaves a
	@# green suite and a setting that does nothing, which is what the warning
	@# this feature replaced described for two generations.
	@timeout -k 30 $(LIVE_TIMEOUT) unshare -rn sh -c "NCFG_LIVE=1 sh tests/live/link_local.sh"
	@# The backend whose mark cannot be read from the process: dhcpcd destroys
	@# argv and environ alike, so netcfgd asks it over its control socket which
	@# config it was started with. Makes its own namespace, like dhcpcd.sh.
	@NCFG_LIVE=1 timeout -k 30 $(LIVE_TIMEOUT) sh tests/live/dhcpcd_orphan.sh
	@# Adopting the network after the ownership record is gone, which is what a
	@# restart does to it. Holding is safe and is not enough: a netcfgd that
	@# cannot recognise its own work can never remove it either.
	@timeout -k 30 $(LIVE_TIMEOUT) unshare -rn sh -c "NCFG_LIVE=1 sh tests/live/adopt.sh"
	@# The mark netcfgd leaves on a link it creates, which is the one object
	@# kind with no protocol field to stamp -- so it was the last piece of
	@# ownership that lived only in the record a restart deletes.
	@timeout -k 30 $(LIVE_TIMEOUT) unshare -rn sh -c "NCFG_LIVE=1 sh tests/live/altname.sh"
	@# The sysctls netcfgd set, and the limit of what survives losing the
	@# record -- a value has nothing to stamp, so this is the one part of
	@# ownership that genuinely depends on /run.
	@timeout -k 30 $(LIVE_TIMEOUT) unshare -rn sh -c "NCFG_LIVE=1 sh tests/live/sysctl.sh"
	@# The captive portal check, against a real HTTP server: the probe is a
	@# question rather than a change, so no apply can exercise it either.
	@timeout -k 30 $(LIVE_TIMEOUT) unshare -rn sh -c "NCFG_LIVE=1 sh tests/live/portal.sh"
	@# A supplicant that has bound its socket and stopped answering. Both what
	@# netcfgd says about it and how long it takes to say it -- the round trip
	@# is in the reconcile loop.
	@timeout -k 30 $(LIVE_TIMEOUT) unshare -rn sh -c "NCFG_LIVE=1 sh tests/live/wedged.sh"
	@# Bare, like slaac.sh and dhcpcd.sh: this one picks its own namespace,
	@# because which one it needs depends on which DHCP server it found.
	@# busybox udhcpd wants nothing special; the dnsmasq fallback drops
	@# privileges, which `unshare -rn` forbids.
	@NCFG_LIVE=1 timeout -k 30 $(LIVE_TIMEOUT) sh tests/live/dhcp.sh
	@# The other client, and the one netcfgd prefers. Neither under NCFG_LIVE
	@# nor under unshare: dhcpcd is a package, and it drops privileges to a user
	@# that a namespace with one mapped uid does not have -- so the script makes
	@# its own namespaces, which is also how it keeps the machine's own dhcpcd
	@# state, hostname and resolv.conf out of reach.
	@timeout -k 30 $(LIVE_TIMEOUT) sh tests/live/dhcpcd.sh
	@# Not under `unshare -rn`, and that is the point: a network namespace has
	@# none of the machine's real interfaces, so the radio this reads would not be
	@# there. It changes nothing -- `status` and `plan` only -- so running it
	@# against the host is safe.
	@NCFG_LIVE=1 timeout -k 30 $(LIVE_TIMEOUT) sh tests/live/rfkill.sh
	@# And the event stream, against a fifo rather than the real device: the
	@# write path on /dev/rfkill blocks every radio on the machine, and rfkill
	@# is not namespaced, so `unshare -rn` would be no protection.
	@timeout -k 30 $(LIVE_TIMEOUT) unshare -rn sh -c "NCFG_LIVE=1 sh tests/live/rfkill_stream.sh"
	@timeout -k 30 $(LIVE_TIMEOUT) unshare -rn sh -c "NCFG_LIVE=1 sh tests/live/rules.sh"
	@timeout -k 30 $(LIVE_TIMEOUT) unshare -rn sh -c "NCFG_LIVE=1 sh tests/live/qdisc.sh"
	@timeout -k 30 $(LIVE_TIMEOUT) unshare -rn sh -c "NCFG_LIVE=1 sh tests/live/ingress.sh"
	@timeout -k 30 $(LIVE_TIMEOUT) unshare -rn sh -c "NCFG_LIVE=1 sh tests/live/readonly.sh"
	@timeout -k 30 $(LIVE_TIMEOUT) unshare -rn sh -c "NCFG_LIVE=1 sh tests/live/unmanage.sh"
	@# No namespace: this one touches no interface and no socket. It drives a
	@# process that reads a pipe and writes a file, which is the whole of what
	@# the privileged half of administrator mode does.
	@NCFG_LIVE=1 timeout -k 30 $(LIVE_TIMEOUT) sh tests/live/control_helper.sh
	@# What the control sockets expose to a local caller, from a real daemon. No
	@# namespace: it binds unix sockets and reads their modes, and it needs a
	@# real uid with a real secondary group, which `unshare -r` does not have.
	@NCFG_LIVE=1 timeout -k 30 $(LIVE_TIMEOUT) sh tests/live/control_exposure.sh
	@# What a remote connection may DO, which is the other half of the one
	@# above: that checks who may open the remote socket (0159), this asks the
	@# daemon what a caller on it is allowed, and the discriminator is that the
	@# same daemon answers differently on its two sockets. No namespace, for
	@# the same reason -- it binds unix sockets and needs a real uid. Skipped
	@# where `bridge/` is not built, since the bridge is what connects.
	@NCFG_LIVE=1 timeout -k 30 $(LIVE_TIMEOUT) sh tests/live/remote_tiers.sh
	@# The interface reporting contract, checked from the side a writer writes.
	@# Under NCFG_LIVE: it needs no modem and no module, only a file.
	@timeout -k 30 $(LIVE_TIMEOUT) unshare -rn sh -c "NCFG_LIVE=1 sh tests/live/report.sh"
	@# The reference helper, against a fake mbimcli. Under NCFG_LIVE: it
	@# needs no modem and no mbimcli, only the shell.
	@timeout -k 30 $(LIVE_TIMEOUT) unshare -rn sh -c "NCFG_LIVE=1 sh tests/live/helper.sh"
	@# An OpenVPN tunnel, against a fake daemon that speaks the real
	@# management protocol. Under NCFG_LIVE: it needs no openvpn package.
	@timeout -k 30 $(LIVE_TIMEOUT) unshare -rn sh -c "NCFG_LIVE=1 sh tests/live/openvpn.sh"
	@# The same tunnel against a *real* openvpn, which is the only thing that
	@# can say what it puts in a --route-up script's environment. Deliberately
	@# not under NCFG_LIVE, for the reason ap.sh is not: openvpn is a package a
	@# machine with no VPN has no reason to have.
	@timeout -k 30 $(LIVE_TIMEOUT) unshare -rn sh -c "sh tests/live/tunnel.sh"
	@# What netcfgd hands pppd, against a real pppd. Same reasoning: ppp is a
	@# package a machine with no DSL line has no reason to have, and a session
	@# cannot be dialled without real root either way.
	@timeout -k 30 $(LIVE_TIMEOUT) unshare -rn sh -c "sh tests/live/ppp.sh"
	@# Deliberately not under NCFG_LIVE: it needs the `wireguard` module, which
	@# a kernel may simply not have -- and nothing else in netcfgd does.
	@timeout -k 30 $(LIVE_TIMEOUT) unshare -rn sh -c "sh tests/live/strand.sh"
	@# The same module, plus `wg` itself as the reference tool -- reading the
	@# state back through netcfgd would only prove netcfgd agrees with itself.
	@# The script's header says how to get `wg` without installing it.
	@timeout -k 30 $(LIVE_TIMEOUT) unshare -rn sh -c "sh tests/live/wireguard.sh"
	@# The same module, asking the question before that one: whether the device
	@# the C port *creates* carries anything at all. It did not, and no unit
	@# check could say so -- everything after the netlink send needs
	@# CAP_NET_ADMIN. `wg` is not needed here: the independent reader is the
	@# Rust ncfg, observing the same kernel through its own code.
	@timeout -k 30 $(LIVE_TIMEOUT) unshare -rn sh -c "sh tests/live/c_wireguard.sh"
	@# The only python test. A TUI needs a pty to say anything about, and
	@# script(1) cannot drive input reliably; see the file's own header.
	@if command -v python3 >/dev/null 2>&1; then \
		timeout -k 30 $(LIVE_TIMEOUT) unshare -rn sh -c "NCFG_LIVE=1 python3 tests/live/tui.py"; \
	else \
		echo "tui.py: skipping: no python3"; \
	fi
	@# The second python test, and for the same reason: a passphrase prompt has
	@# one property worth checking -- that the passphrase is not echoed -- and a
	@# pipe has no echo to turn off, so only a pty can say. It needs no daemon
	@# and no namespace; it writes a config file in a temporary directory.
	@if command -v python3 >/dev/null 2>&1; then \
		NCFG_LIVE=1 timeout -k 30 $(LIVE_TIMEOUT) python3 tests/live/wifi_add.py; \
	else \
		echo "wifi_add.py: skipping: no python3"; \
	fi
	@timeout -k 30 $(LIVE_TIMEOUT) unshare -rn sh -c "NCFG_LIVE=1 sh tests/live/wifi.sh"
	@timeout -k 30 $(LIVE_TIMEOUT) unshare -rn sh -c "NCFG_LIVE=1 sh tests/live/dot1x.sh"
	@timeout -k 30 $(LIVE_TIMEOUT) unshare -rn sh -c "NCFG_LIVE=1 sh tests/live/stations.sh"
	@timeout -k 30 $(LIVE_TIMEOUT) unshare -rn sh -c "NCFG_LIVE=1 sh tests/live/acl.sh"
	@# Deliberately not under NCFG_LIVE: unlike wpa_supplicant, which decision
	@# 0014 makes the floor for wireless, hostapd is an optional package that a
	@# machine never running an access point has no reason to install (0026).
	@# A missing one is a skip rather than a failed suite.
	@timeout -k 30 $(LIVE_TIMEOUT) unshare -rn sh -c "sh tests/live/ap.sh"
	@# The NetworkManager shim, against a real nmcli on a private bus. Not under
	@# NCFG_LIVE: nmcli comes from the network-manager package, which is exactly
	@# what a netcfgd machine is expected not to have installed.
	@timeout -k 30 $(LIVE_TIMEOUT) unshare -rn sh -c "sh tests/live/nm.sh"
	@# The shim's signals, with a link forced in and out so the bus has to say
	@# something. Under NCFG_LIVE, unlike nm.sh: this needs dbus-daemon and
	@# dbus-monitor and no NetworkManager, where nm.sh needs nmcli -- and a
	@# quiet bus is what a converged machine and a broken emitter both look
	@# like, so a skip here must be loud.
	@# **The shim is built here, because that script's skip is deliberately
	@# loud.** This target already builds the Qt live projects before
	@# `gui_wifi.sh` and did not build this, so the one script whose skip is
	@# a failure by design was the one thing the suite could not get past:
	@# measured 2026-10-11, `make live` ran 69 scripts, failed none, and
	@# stopped here on `the C shim is not built`. With it built the script
	@# passes its 10 checks.
	@#
	@# Guarded on libdbus rather than built unconditionally: without it the
	@# shim cannot compile and the script cannot run either, and the script's
	@# own sentence is a better thing to read than a compile error. Its own
	@# build recurses into `client/`, so one step covers the archive too.
	@if pkg-config --exists dbus-1 2>/dev/null; then \
		$(MAKE) --no-print-directory -C adapter/netcfgd-nm/c >/dev/null || \
			{ echo "live: the C NetworkManager shim does not build against this tree" >&2; \
			  exit 1; }; \
	fi
	@timeout -k 30 $(LIVE_TIMEOUT) unshare -rn sh -c "NCFG_LIVE=1 sh tests/live/c_nm_signals.sh"
	@# The AT modem helper, against a modem that is a pty. No root and no
	@# hardware: the fake is a real character device, so termios, CR-terminated
	@# writes and byte-at-a-time reads are exercised rather than stubbed.
	@timeout -k 30 $(LIVE_TIMEOUT) sh tests/live/modem_at.sh
	@# The gpiod SIM-select hook, against an expander that is a Python script.
	@# No root and no board: what is faked is the expander, and what runs is
	@# the hook -- its backgrounding, its bounded wait, its kill, its check
	@# after the release, and its trap.
	@timeout -k 30 $(LIVE_TIMEOUT) sh tests/live/sim_select.sh
	@timeout -k 30 $(LIVE_TIMEOUT) sh tests/live/umbim.sh
	@# A Bluetooth adapter, which needs real root: /dev/vhci is root-only and
	@# the module autoloads on the open. Not under NCFG_LIVE and not under
	@# unshare -- the adapter belongs to the machine, and a machine that
	@# cannot make one gets a skip rather than a failure.
	@timeout -k 30 $(LIVE_TIMEOUT) sh tests/live/bluetooth.sh
	@# Association, which needs real root and a loadable mac80211_hwsim. Not
	@# under NCFG_LIVE and not under unshare: it does its own namespace, and a
	@# machine that cannot run it should get a skip rather than a failure.
	@timeout -k 30 $(LIVE_TIMEOUT) sh tests/live/hwsim.sh
	@# The same question against the radio this machine actually has, which is
	@# the one thing hwsim.sh cannot be: a real association, to a real access
	@# point, resolved against the document a real daemon is running. Reads
	@# only -- no reconfigure and no write under /run -- so it is safe on the
	@# machine somebody is using, over the very wifi it asks about. Skips when
	@# there is no radio, no association, or no root.
	@timeout -k 30 $(LIVE_TIMEOUT) sh tests/live/association.sh
	@# A real PPPoE session, same bucket: /dev/ppp is root-only and the rp-pppoe
	@# plugin opens it as it loads, so an unprivileged machine cannot dial. It
	@# makes its own namespaces too, and skips rather than fails without root.
	@timeout -k 30 $(LIVE_TIMEOUT) sh tests/live/pppoe-session.sh
	@# A real delegated prefix, from a real kea to a real odhcp6c, advertised
	@# by a real radvd to a host that configures itself. Root because both ends
	@# bind a privileged port, and odhcp6c is not packaged for Debian -- the
	@# script's header says how to build it, and skips without it.
	@timeout -k 30 $(LIVE_TIMEOUT) sh tests/live/delegation.sh
	@# Writing files under the sandbox a systemd unit imposes. No
	@# outer namespace: it makes its own mount namespace, and it must, because
	@# a chmod reproduces the symptom for an unprivileged process and not for
	@# root -- CAP_DAC_OVERRIDE walks through a mode and not through a mount.
	@#
	@# **Last, because it is the one script here that refuses rather than
	@# skips.** It drives the unit's real sandbox through systemd, and under
	@# `NCFG_LIVE` a machine with no systemd gets a failure rather than a quiet
	@# pass -- which is right, and make stops at the first failing recipe line.
	@# Anywhere earlier it therefore hides every script after it: on
	@# `ml350g6-01`, which runs sysvinit, it halted the suite two thirds of the
	@# way through and the whole tunnel, wifi, modem and bluetooth tail went
	@# unexercised for as long as that was where it sat. Moved here so the
	@# refusal is the last thing a run reports rather than the only thing.
	@NCFG_LIVE=1 timeout -k 30 $(LIVE_TIMEOUT) sh tests/live/sandbox_writes.sh

# **`fuzz` is the C now, and that is the point rather than a rename** (0277).
# Section 12 asked for a target per parser, continuously fuzzed "as part of CI,
# not as an occasional exercise". It had that through cargo-fuzz, and the day
# the C became what runs it had a fuzzer pointed at parsers nobody executes.
# `fuzz-rust` is the old target, kept because the Rust is still the instrument
# `make agree` compares against.
#
# **The deterministic half is in `make check` and is not here.** Every target's
# committed corpus is replayed by `make -C c test` with the ordinary compiler,
# which is what makes a crash stay fixed rather than stay findable. This target
# is the exploring half: it needs clang, it goes somewhere different every run,
# and a gate whose verdict depends on where its seed took it is not a gate.
#
# HOW IT STOPS, which `running-code.md` asks to be able to say before starting
# anything: each target runs until `-runs` or `-max_total_time`, whichever
# comes first, with `-timeout` on a single input and libFuzzer's own 2 GB RSS
# ceiling. Five targets, so the wall clock is five times FUZZ_SECONDS at worst.
# Raise them for a real session -- `make fuzz FUZZ_SECONDS=600` -- and the
# defaults stay short enough that somebody who typed this to see what it does
# gets their shell back.
# Named here as well as in `c/Makefile`, and passed down, so the two cannot
# disagree about which compiler was asked for.
FUZZ_CC      ?= clang
FUZZ_RUNS    ?= 50000
FUZZ_SECONDS ?= 30
FUZZ_MAX_LEN ?= 65536
# One target by name, or empty for all of them.
FUZZ_TARGET  ?=
FUZZ_ARGS    ?=

fuzz:
	@if ! command -v $(FUZZ_CC) >/dev/null 2>&1; then \
		echo "fuzz: $(FUZZ_CC) is not installed, and libFuzzer comes with it"; \
		echo "fuzz:   apt install clang"; \
		echo "fuzz: the corpus still replays without it: make c-test runs"; \
		echo "fuzz:   every committed input through the same targets"; \
		exit 1; \
	fi
	@$(MAKE) --no-print-directory -C c fuzz FUZZ_CC=$(FUZZ_CC)
	@set -e; \
	targets="$(FUZZ_TARGET)"; \
	[ -n "$$targets" ] || targets=$$($(MAKE) --no-print-directory -C c fuzz-list); \
	for one in $$targets; do \
		echo "fuzz: $$one"; \
		mkdir -p c/fuzz/build/found/$$one; \
		( cd c && ./fuzz/$${one}_fuzz \
			fuzz/build/found/$$one fuzz/corpus/$$one \
			-runs=$(FUZZ_RUNS) -max_total_time=$(FUZZ_SECONDS) \
			-max_len=$(FUZZ_MAX_LEN) -timeout=10 \
			-artifact_prefix=fuzz/build/ -print_final_stats=1 \
			$(FUZZ_ARGS) ); \
	done
	@# The client library's reader, which `ncfg`, the Qt client and the shim
	@# all read netcfgd's answers through. No guard: it needs nothing this
	@# tree does not already build.
	@$(MAKE) --no-print-directory -C client fuzz FUZZ_CC=$(FUZZ_CC)
	@for one in $$($(MAKE) --no-print-directory -C client fuzz-list); do \
		echo "fuzz: client $$one"; \
		mkdir -p client/fuzz/build/found/$$one; \
		( cd client && ./fuzz/$${one}_fuzz \
			fuzz/build/found/$$one fuzz/corpus/$$one \
			-runs=$(FUZZ_RUNS) -max_total_time=$(FUZZ_SECONDS) \
			-max_len=$(FUZZ_MAX_LEN) -timeout=10 \
			-artifact_prefix=fuzz/build/ -print_final_stats=1 \
			$(FUZZ_ARGS) ) || exit 1; \
	done
	@# The shim's own targets, guarded the way every gate that needs it is:
	@# they need libdbus to build at all.
	@if pkg-config --exists dbus-1 2>/dev/null; then \
		$(MAKE) --no-print-directory -C adapter/netcfgd-nm/c fuzz FUZZ_CC=$(FUZZ_CC); \
		for one in $$($(MAKE) --no-print-directory -C adapter/netcfgd-nm/c fuzz-list); do \
			echo "fuzz: netcfgd-nm $$one"; \
			mkdir -p adapter/netcfgd-nm/c/fuzz/build/found/$$one; \
			( cd adapter/netcfgd-nm/c && ./fuzz/$${one}_fuzz \
				fuzz/build/found/$$one fuzz/corpus/$$one \
				-runs=$(FUZZ_RUNS) -max_total_time=$(FUZZ_SECONDS) \
				-max_len=$(FUZZ_MAX_LEN) -timeout=10 \
				-artifact_prefix=fuzz/build/ -print_final_stats=1 \
				$(FUZZ_ARGS) ) || exit 1; \
		done; \
	else \
		echo "fuzz: libdbus-1 is not installed, so the shim's dictionary reader"; \
		echo "fuzz:   was not fuzzed; make nm-c-test still replays its corpus"; \
	fi
	@echo "fuzz: anything new is in c/fuzz/build/found/, and a crash is a file"
	@echo "fuzz:   named crash-* beside it. **An input worth keeping belongs in"
	@echo "fuzz:   c/fuzz/corpus/<target>/ and committed**, which is what makes"
	@echo "fuzz:   it replay for everybody afterwards"

fuzz-rust:
	@if ! command -v cargo-fuzz >/dev/null 2>&1; then \
		echo "fuzz-rust: cargo-fuzz is not installed"; \
		echo "fuzz-rust:   cargo install cargo-fuzz   (needs a nightly toolchain)"; \
		echo "fuzz-rust: targets are in fuzz/fuzz_targets/, and the randomised"; \
		echo "fuzz-rust: tests in crates/*/tests/random.rs run on stable meanwhile"; \
		exit 1; \
	fi
	@[ -n "$(FUZZ_TARGET)" ] || { \
		echo "fuzz-rust: name one with FUZZ_TARGET=<name>. They are:"; \
		ls fuzz/fuzz_targets | sed 's/\.rs$$//' | sed 's/^/fuzz-rust:   /'; \
		exit 2; \
	}
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
	@# One workspace, since 0276. There was a loop here over each adapter's own
	@# deny.toml, because a separate workspace is invisible to a `cargo deny` run
	@# in the root -- which was the point of the containment and also the way an
	@# adapter's supply chain would have gone unchecked forever. The shim is C
	@# now and has no cargo dependencies to check; `nm-containment` asserts that
	@# no adapter has acquired a lockfile again, which is what would make this
	@# loop necessary a second time.

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
	@# **Skipped loudly where cargo is absent, since 0276.** The Rust core is
	@# still in the tree and `cargo clean` is how its `target/` goes, but the
	@# Debian build reaches this through `dh_auto_clean` -- and retiring the
	@# Rust shim took the Rust toolchain out of `debian/control` entirely, so
	@# the one remaining cargo call in a package build would be this line.
	@# `if cond; then run; fi` rather than `cond && run || echo`, which would
	@# report the skip for a cargo that IS there and failed.
	@if command -v $(CARGO) >/dev/null 2>&1; then \
		$(CARGO) clean; \
	else \
		echo "clean: cargo not installed, leaving target/ alone"; \
	fi
# **`$(KERNEL_OUT)` is kept, and the guest images are no longer here to keep.**
# Until 2026-10-25 `$(DIST)/hull` held four `docker export` trees, spared
# because rebuilding one cost docker, a network and minutes where everything
# else under `$(DIST)` costs a recompile -- and because `find -type f` over
# three of them printed 14,975 lines, which is a clean target nobody can read.
# The images are hull's store refs now (10.558), so nothing of theirs is under
# `$(DIST)` at all; `make hull-clean` untags them.
#
# The kernel tier's output stays spared for the first of those reasons: six
# files, but rebuilding them is three kernel builds. `make kernel-clean` names
# them.
#
# **The pruned path is parenthesised** although only one remains, which
# `build-and-commit.md` requires by name: in `find`, `-a` binds tighter than
# `-o`, so `-path A -o -path B -prune` means "A, or (B and prune)" and the
# first path would be printed and then swept. Both arms were fixture-tested
# when there were two, and the grouping stays so that adding a second path
# back cannot reintroduce it.
	@case "$(DIST)" in \
	"") echo "clean: DIST is empty, refusing to remove anything"; exit 1 ;; \
	/*) echo "clean: DIST is absolute ($(DIST)), refusing"; exit 1 ;; \
	*..*) echo "clean: DIST escapes the tree ($(DIST)), refusing"; exit 1 ;; \
	esac; \
	if [ -d "$(DIST)" ]; then \
		find "$(DIST)" \( -path "$(KERNEL_OUT)" \) \
			-prune -o -type f -print | sed 's/^/clean: removing /'; \
		find "$(DIST)" -mindepth 1 -maxdepth 1 \
			! -path "$(KERNEL_OUT)" -exec rm -rf {} +; \
		kept=0; \
		if [ -d "$(KERNEL_OUT)" ]; then \
			kept=1; \
			printf 'clean: keeping %s (%s, three kernel build(s)); make kernel-clean removes them\n' \
				"$(KERNEL_OUT)" "$$(du -sh "$(KERNEL_OUT)" | cut -f1)"; \
		fi; \
		[ "$$kept" -eq 1 ] || rmdir "$(DIST)" 2>/dev/null || true; \
	fi

# The shared style gate: `tool/style_gate.py`, a copy committed in this
# repository and the one this build runs. It is kept byte-identical to the
# copies these projects share, so **fix drift rather than editing it here** --
# a local change is lost the next time the copies are reconciled, and the
# divergence is invisible until then. It refuses to run against a collapsed
# file list, so a pass means it actually looked.
style: style-source style-docs

style-source:
	python3 tool/style_gate.py check

# project.md is authoritative, so it is held to the tree: a heading
# that appears twice means whichever one you find, the other is the
# one with the answer.
style-docs:
	python3 tool/style_gate.py docs

# The shipped reference, compiled rather than trusted.
#
# `netcfgd.conf.example` calls itself "every feature, with the syntax to use
# it" and the postinst points an operator at it as the thing to read on a
# machine with no network. Nothing checked a word of it until this: the
# Makefile installed it and removed it, and that was the whole relationship.
# Two faults had been found in it by hand -- a missing `probe` block, and a
# `mac_policy` value the compiler rejects.
#
# After `test`, because it compiles each block with the debug `ncfg` that the
# test target has just built.
example:
	@python3 tool/example_gate.py

# The two programs compile the same configuration to the same document.
#
# After `c-test` in the gate list, because it needs both binaries and that
# target is what builds the C one. The comparison is `tool/agree_gate.py`'s and
# the argument for it being `show` and nothing else is in that file's header:
# every other verb observes the machine, so two runs of it are answering
# questions about two moments.
agree: c-test
	@# **Both programs built here rather than trusted**, which is `linkage`'s
	@# reason and became this gate's on the day `build` stopped producing the
	@# Rust one (0266). `c-test` above builds the C. The Rust binary and the
	@# `ncfg` symlink beside it were made by `build`; nothing in `check` makes
	@# them before this runs now, and the gate fails rather than skips when a
	@# binary is missing -- so without these two lines a clean tree would go red
	@# here for a reason that has nothing to do with the two programs agreeing.
	@$(CARGO) build --release --quiet
	@$(MAKE) --no-print-directory ncfg-link PROFILE=release
	@python3 tool/agree_gate.py

# What the C build carries out, against the frozen witnesses.
#
# `doc/c-transition.md` section 5 asks for a completeness ledger and forbids it
# being a checklist. So one side is `netcfgd --supported`, which asks the code
# that decides and prints what it answers, and the other is `doc/schema/`.
# Neither is written by hand, and what the gate compares is the taxonomy: a
# name in the witnesses this build has never heard of is the two enumerations
# drifting apart.
#
# After `c-test` for `agree`'s reason: it needs the C binary, and that target
# builds it. It also prints what is refused and why, which is the answer to
# "what does the C side not do yet" and is why the output is worth reading
# rather than just being green.
ledger: c-test
	@python3 tool/ledger_gate.py

# Decision 0263's module order, against what the sources include. Needs no
# build: it reads the tree, so it answers on a machine that cannot compile.
module-order:
	@python3 tool/module_order_gate.py

# The scope and kind tables name configuration keys as strings, and nothing in
# C connects those strings to the lowering that recognises them. This reads the
# lowering's own `strcmp` chains and refuses a row naming a key the block does
# not have -- which is what the first kind registry needed and did not have.
registry:
	@python3 tool/registry_gate.py

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
# and `install-modem` were both missing.
uninstall:
	rm -f $(DESTDIR)$(BINDIR)/ncfg
	rm -f $(DESTDIR)$(SBINDIR)/netcfgd
	rm -f $(DESTDIR)$(SBINDIR)/netcfgd_select.sh
	rm -f $(DESTDIR)$(LIBEXECDIR)/netcfgd/dhcpcd-hook
	@# Named, and removed only if this is the last thing in it -- the directory
	@# is netcfgd's, so an empty one is ours to take away and a non-empty one
	@# holds something a later version installed that this uninstall does not
	@# know about.
	@rmdir $(DESTDIR)$(LIBEXECDIR)/netcfgd 2>/dev/null || true
	rm -f $(DESTDIR)$(BINDIR)/netcfgd-gui
	rm -f $(DESTDIR)$(BINDIR)/netcfgd-tui
	rm -f $(DESTDIR)$(DATADIR)/applications/netcfgd-gui.desktop
	@$(MAKE) --no-print-directory uninstall-icons ICON_PREFIX=$(DATADIR)
	rm -f $(DESTDIR)$(BINDIR)/netcfgd-modem-mbim
	rm -f $(DESTDIR)$(BINDIR)/netcfgd-modem-at
	rm -f $(DESTDIR)$(BINDIR)/netcfgd-modem-umbim
	rm -f $(DESTDIR)$(PREFIX)/share/netcfgd/modem-quirks
	rm -f $(DESTDIR)$(PREFIX)/share/netcfgd/hook/sim-select-gpiod.example
	rm -f $(DESTDIR)$(PREFIX)/lib/udev/rules.d/71-netcfgd-modem.rules
	rm -f $(DESTDIR)/usr/lib/systemd/system/netcfgd-modem-at@.service
	rm -f $(DESTDIR)/usr/lib/systemd/system/netcfgd.service
	rm -f $(DESTDIR)/usr/lib/systemd/system/netcfgd-wait-online.service
	rm -f $(DESTDIR)$(SYSCONFDIR)/init.d/netcfgd
	rm -f $(DESTDIR)$(BINDIR)/netcfgd-nm
	rm -f $(DESTDIR)$(DATADIR)/dbus-1/system.d/netcfgd-nm.conf
	rm -f $(DESTDIR)/usr/lib/systemd/system/netcfgd-nm.service
	rm -f $(DESTDIR)$(SYSCONFDIR)/init.d/netcfgd-nm
	@# The example SIM-select hook, which install-modem ships beside the
	@# quirk table. An operator's copy of it lives elsewhere and is theirs.
	rm -f $(DESTDIR)$(PREFIX)/share/netcfgd/hook/sim-select.example
	@rmdir $(DESTDIR)$(PREFIX)/share/netcfgd/hook 2>/dev/null || true
	@# The shipped profile, by name. An operator's own profiles live under
	@# $(SYSCONFDIR)/netcfgd/profile and are not touched.
	rm -f $(DESTDIR)$(DATADIR)/netcfgd/profile/offline/10-offline.conf
	@rmdir $(DESTDIR)$(DATADIR)/netcfgd/profile/offline 2>/dev/null || true
	@rmdir $(DESTDIR)$(DATADIR)/netcfgd/profile 2>/dev/null || true
	@# This one is ours: `install` wrote it, so `uninstall` takes it away. The
	@# operator's own configuration beside it is not, and is left alone.
	rm -f $(DESTDIR)$(SYSCONFDIR)/netcfgd/netcfgd.conf.example
	@# Only if the operator left nothing in it. Their configuration is not
	@# ours to remove, and an empty directory is not worth keeping.
	@rmdir $(DESTDIR)$(SYSCONFDIR)/netcfgd 2>/dev/null || true
	@echo "uninstall: removed the programs, the example, the shipped profile,"
	@echo "uninstall:   the desktop entry and"
	@echo "uninstall:   the init glue"
	@echo "uninstall:   any configuration you wrote in $(SYSCONFDIR)/netcfgd is"
	@echo "uninstall:   left alone -- it is yours and this Makefile never wrote it"

# The commit-msg hook lives in the tree so it is reviewable, survives a
# clone, and can be kept in sync. .git/hooks is untracked, so a hook that
# exists only there enforces a rule nobody can see and vanishes silently on
# a fresh clone.
# **Where the hooks live is git's question, not the filesystem's.** This
# asked `test -d .git`, which is false in a linked worktree and in a
# submodule checkout: there `.git` is a regular FILE naming the real
# gitdir, and both are git repositories. So `make hooks` refused with
# "not a git repository" inside one that is.
#
# Testing -e instead would only move the failure one line down, because
# the install writes into `.git/hooks/`, which is not a directory there
# either. Asking git answers both halves at once, and from a worktree it
# returns the MAIN repository's hooks directory -- which is the one git
# actually runs.
#
# git's absence is reported as its own thing rather than as "not a git
# repository", which would be a message naming a cause nothing tested.
hooks:
	@if ! command -v git >/dev/null 2>&1; then \
		echo "hooks: git is not installed, so there is nowhere to install to." >&2; \
		exit 1; \
	fi; \
	dir=$$(git rev-parse --git-common-dir 2>/dev/null); \
	if [ -z "$$dir" ]; then \
		echo "hooks: not a git repository, so there is nowhere to install to." >&2; \
		exit 1; \
	fi; \
	mkdir -p "$$dir/hooks"; \
	install -m 0755 tool/hooks/commit-msg "$$dir/hooks/commit-msg"; \
	echo "hooks: commit-msg installed from tool/hooks/ into $$dir/hooks/"

# The TARGETS block in the header is the one statement of what the targets
# are, and this reads it back rather than repeating it: a list written twice
# is a list that disagrees with itself eventually.
#
# Defined last on purpose -- make takes the first non-special target in the
# file as the default goal, so a `help` rule above `all` makes plain `make`
# print the help instead of building.
help:
	@sed -n '/^# TARGETS/,/^#$$/p' $(firstword $(MAKEFILE_LIST)) | sed 's/^# \{0,1\}//'
