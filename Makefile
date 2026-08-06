# The gates from project.md section 6, as one entry point. Constraint 8 is why this
# exists before there is much to gate: budgets adopted later are budgets
# already blown, and the same goes for every other check here.
#
# `make check` is what CI runs and what to run before committing.

CARGO ?= cargo

.PHONY: deb apk apk-source apk-container all check build test conformance FORCE fmt fmt-fix shell clippy unsafe-policy executor-policy packaging ascii size footprint rss live schema-bless install install-modem-mbim install-systemd install-openrc install-procd fuzz deny clean adapters nm-containment veryclean distclean uninstall style style-source style-docs hooks

# Where each adapter lives. Each is its own cargo workspace with its own
# lockfile, so that its dependencies cannot reach the core's -- see
# `nm-containment` below, and design section 9.2.
ADAPTERS = adapters/netcfgd-nm

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
check: style fmt ascii shell clippy unsafe-policy executor-policy nm-containment packaging conformance test size footprint rss adapters

# Each adapter, built and checked with the same bar as the core.
#
# Separately, because they are separate workspaces. That is the price of
# dependency containment and it is a small one: a `cd` per adapter, against
# never having to ask which binary a `cargo deny` result was about.
adapters:
	@for adapter in $(ADAPTERS); do \
		echo "adapters: $$adapter"; \
		( cd $$adapter && \
			$(CARGO) fmt --check && \
			$(CARGO) clippy --all-targets -- -D warnings && \
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
	for script in helpers/* tests/live/*.sh; do \
		[ -f "$$script" ] || continue; \
		sh -n "$$script" || exit 1; \
		count=$$((count + 1)); \
	done; \
	if [ "$$count" -lt 10 ]; then \
		echo "shell: only $$count scripts checked, which is too few to mean anything"; \
		exit 1; \
	fi; \
	echo "shell: ok, $$count scripts parse"

fmt:
	$(CARGO) fmt --check

fmt-fix:
	$(CARGO) fmt

clippy:
	$(CARGO) clippy --workspace --all-targets -- -D warnings

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
# globbed `crates/*` alone until M5, so `backends/netcfgd-supplicant` went
# unchecked from the day it was written -- and it was missing the attribute. A
# policy gate that cannot see half the tree enforces nothing, so it now counts
# what it found and fails if that number collapses.
unsafe-policy:
	@fail=0; \
	roots=$$(find crates backends -name lib.rs -o -name main.rs | grep '/src/' | sort); \
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
	@echo "install: netcfgd and ncfg installed; no init glue"
	@echo "install:   make install-systemd | install-openrc | install-procd"
	@# Constraint 2: the filesystem reflects use. conf.d/, secrets/ and hooks/
	@# appear when something needs them, so they are not created here.

# The reference modem helper. Optional and separate on purpose: decision 0045
# says the helper is plural, and installing one by default would make it the
# blessed one. It also needs `mbimcli`, which most machines have no use for.
install-modem-mbim:
	install -d $(DESTDIR)$(BINDIR)
	install -m 0755 helpers/netcfgd-modem-mbim $(DESTDIR)$(BINDIR)/netcfgd-modem-mbim
	@echo "install-modem-mbim: installed; it needs mbimcli from libmbim-utils"
	@echo "install-modem-mbim:   docs/interface-report.md is the contract -- write"
	@echo "install-modem-mbim:   your own helper if this one does not fit"

install-systemd:
	install -d $(DESTDIR)/usr/lib/systemd/system
	install -m 0644 packaging/systemd/netcfgd.service \
		$(DESTDIR)/usr/lib/systemd/system/netcfgd.service
	@echo "install-systemd: netcfgd.service installed, not enabled"
	@echo "install-systemd:   to make netcfgd the only network daemon, see"
	@echo "install-systemd:   packaging/systemd/netcfgd-exclusive.conf"

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
deb: version-check
	@test -n "$(DIST)" || { echo "deb: DIST is empty, refusing" >&2; exit 1; }
	dpkg-buildpackage -b -us -uc
	@mkdir -p $(DIST)
	@for f in ../netcfgd_$(VERSION)_*.deb ../netcfgd-dbgsym_$(VERSION)_*.deb \
	          ../netcfgd_$(VERSION)_*.buildinfo ../netcfgd_$(VERSION)_*.changes; do \
		[ -e "$$f" ] && mv -f "$$f" $(DIST)/ || true; \
	done
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
# two witnesses under docs/schema/: one document with every field and variant
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
	@echo "schema-bless: witnesses rewritten; `git diff --stat docs/schema | tail -1`"
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

packaging:
	@fail=0; \
	FILLED="$(FILLED)"; \
	if [ -z "$$(sed -n 's/^Exec[A-Za-z]*=\([^ ]*\).*/\1/p' packaging/systemd/netcfgd.service)" ]; then \
		echo "packaging: no Exec lines found -- the extraction below is checking nothing"; \
		exit 1; \
	fi; \
	for script in packaging/openrc/netcfgd packaging/procd/netcfgd \
			packaging/debian/postinst packaging/debian/prerm \
			packaging/debian/postrm packaging/alpine/build-in-container.sh; do \
		sh -n "$$script" || { echo "packaging: $$script does not parse"; fail=1; }; \
	done; \
	for script in packaging/debian/postinst packaging/debian/prerm \
			packaging/debian/postrm; do \
		[ -x "$$script" ] || { echo "packaging: $$script is not executable, so dpkg would not run it"; fail=1; }; \
	done; \
	if command -v systemd-analyze >/dev/null 2>&1; then \
		out=$$(systemd-analyze verify packaging/systemd/netcfgd.service 2>&1 \
			| grep -v 'is not executable'); \
		if [ -n "$$out" ]; then echo "$$out"; fail=1; fi; \
	fi; \
	installed="$(SBINDIR)/netcfgd $(BINDIR)/ncfg"; \
	declared=$$( { \
		sed -n 's/^Exec[A-Za-z]*=\([^ ]*\).*/\1/p' packaging/systemd/netcfgd.service; \
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
	for template in packaging/debian/control.in packaging/alpine/APKBUILD.in; do \
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
# `backends/` had gone unchecked since M2 -- it happened to be clean, which is
# luck rather than evidence. Shell scripts count as source; markdown does not,
# and project.md section 9 says so.
# Every directory that holds source, not just the ones that existed when this
# was written. `adapters` and `helpers` were both outside it -- the same shape
# as the unsafe-policy gate globbing only `crates/*` and missing a whole backend
# for a milestone.
ASCII_PATHS  = crates backends adapters helpers tests Cargo.toml Makefile
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
	@if grep -rlP '[^\x00-\x7F]' $(ASCII_KINDS) \
		$(ASCII_PATHS) 2>/dev/null | grep -q .; then \
		echo "ascii: non-ASCII found in:"; \
		grep -rlP '[^\x00-\x7F]' $(ASCII_KINDS) \
			$(ASCII_PATHS) 2>/dev/null; \
		echo "ascii: write -- for an em dash, and 'section N' for a section sign"; \
		exit 1; \
	fi; \
	echo "ascii: ok"

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
		printf 'size: installed %s bytes, over its %s limit by %s\n' \
			"$$total" "$$limit" "$$(( total - limit ))"; \
		echo "size:   raise it in size-budget.txt, and say why in the commit"; \
		exit 1; \
	fi; \
	printf 'size: installed %8s of %s\n' "$$total" "$$limit"

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
# ~/.claude/tools/style_gate.py into every private project. It refuses to
# run against a collapsed file list, so a pass means it actually looked.
style: style-source style-docs

style-source:
	python3 tools/style_gate.py check

# project.md is authoritative, so it is held to the tree: a heading
# that appears twice means whichever one you find, the other is the
# one with the answer.
style-docs:
	python3 tools/style_gate.py docs

# The clean ladder, matching the sibling projects: `clean` removes build
# products, `veryclean` adds the build directories themselves, `distclean`
# adds editor and tool droppings. Each names what it removes.
veryclean: clean
	$(CARGO) clean
	rm -rf target

distclean: veryclean
	find . -name '*~' -o -name '*.swp' -o -name '*.orig' | xargs -r rm -f
	find . -name __pycache__ -type d -prune -exec rm -rf {} +

# The counterpart to install: named targets only, no sweeps.
uninstall:
	rm -f $(DESTDIR)$(BINDIR)/ncfg
	rm -f $(DESTDIR)$(SBINDIR)/netcfgd
	rm -f $(DESTDIR)$(SYSCONFDIR)/netcfgd/netcfgd.conf

# The commit-msg hook lives in the tree so it is reviewable, survives a
# clone, and can be kept in sync. .git/hooks is untracked, so a hook that
# exists only there enforces a rule nobody can see and vanishes silently on
# a fresh clone.
hooks:
	@test -d .git || { echo "hooks: not a git repository" >&2; exit 1; }
	@install -m 0755 tools/hooks/commit-msg .git/hooks/commit-msg
	@echo "hooks: commit-msg installed from tools/hooks/"
