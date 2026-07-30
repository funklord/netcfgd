# The gates from project.md section 6, as one entry point. Constraint 8 is why this
# exists before there is much to gate: budgets adopted later are budgets
# already blown, and the same goes for every other check here.
#
# `make check` is what CI runs and what to run before committing.

CARGO ?= cargo

.PHONY: all check build test fmt fmt-fix clippy unsafe-policy executor-policy packaging ascii size footprint rss live schema-bless install install-systemd install-openrc install-procd fuzz deny clean

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
check: fmt ascii clippy unsafe-policy executor-policy packaging test size footprint rss

fmt:
	$(CARGO) fmt --check

fmt-fix:
	$(CARGO) fmt

clippy:
	$(CARGO) clippy --workspace --all-targets -- -D warnings

test:
	$(CARGO) test --workspace

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
packaging:
	@fail=0; \
	if [ -z "$$(sed -n 's/^Exec[A-Za-z]*=\([^ ]*\).*/\1/p' packaging/systemd/netcfgd.service)" ]; then \
		echo "packaging: no Exec lines found -- the extraction below is checking nothing"; \
		exit 1; \
	fi; \
	for script in packaging/openrc/netcfgd packaging/procd/netcfgd; do \
		sh -n "$$script" || { echo "packaging: $$script does not parse"; fail=1; }; \
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
ASCII_PATHS  = crates backends tests Cargo.toml Makefile
ASCII_KINDS  = --include='*.rs' --include='*.toml' --include='*.sh'

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

# section 10.4: under 4 MB resident. What is measured here is
# the full-tier daemon, so the number is a ratchet like the size one rather
# than the tier target -- see size-budget.txt for why that distinction exists.
# Measured at 5400 KB. The headroom is deliberate: resident size varies with
# allocator behaviour and page reclaim in a way binary size does not, so a
# limit set at the measurement would fail on noise. A genuine regression --
# holding every observed snapshot, say -- clears this easily.
RSS_LIMIT_KB ?= 8192

rss:
	@$(CARGO) build --quiet
	@work=$$(mktemp -d); \
	cp -r tests/footprint/etc "$$work/etc"; mkdir -p "$$work/run"; \
	./target/debug/netcfgd --config-dir "$$work/etc" --run-dir "$$work/run" \
		--no-apply-on-start >/dev/null 2>&1 & \
	pid=$$!; \
	sleep 2; \
	peak=$$(awk '/VmHWM/ {print $$2}' /proc/$$pid/status 2>/dev/null); \
	kill $$pid 2>/dev/null; wait $$pid 2>/dev/null; \
	rm -rf "$$work"; \
	if [ -z "$$peak" ]; then echo "rss: could not measure"; exit 1; fi; \
	printf 'rss: netcfgd peak %s KB of %s limit\n' "$$peak" "$(RSS_LIMIT_KB)"; \
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
	@unshare -rn sh -c "NCFG_LIVE=1 sh tests/live/rules.sh"
	@unshare -rn sh -c "NCFG_LIVE=1 sh tests/live/qdisc.sh"
	@unshare -rn sh -c "NCFG_LIVE=1 sh tests/live/ingress.sh"
	@unshare -rn sh -c "NCFG_LIVE=1 sh tests/live/readonly.sh"
	@# The only python test. A TUI needs a pty to say anything about, and
	@# script(1) cannot drive input reliably; see the file's own header.
	@if command -v python3 >/dev/null 2>&1; then \
		unshare -rn sh -c "NCFG_LIVE=1 python3 tests/live/tui.py"; \
	else \
		echo "tui.py: skipping: no python3"; \
	fi
	@unshare -rn sh -c "NCFG_LIVE=1 sh tests/live/wifi.sh"
	@unshare -rn sh -c "NCFG_LIVE=1 sh tests/live/dot1x.sh"
	@# Deliberately not under NCFG_LIVE: unlike wpa_supplicant, which decision
	@# 0014 makes the floor for wireless, hostapd is an optional package that a
	@# machine never running an access point has no reason to install (0026).
	@# A missing one is a skip rather than a failed suite.
	@unshare -rn sh -c "sh tests/live/ap.sh"
	@# Association, which needs real root and a loadable mac80211_hwsim. Not
	@# under NCFG_LIVE and not under unshare: it does its own namespace, and a
	@# machine that cannot run it should get a skip rather than a failure.
	@sh tests/live/hwsim.sh

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

clean:
	$(CARGO) clean
