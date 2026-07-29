# The gates from project.md section 6, as one entry point. Constraint 8 is why this
# exists before there is much to gate: budgets adopted later are budgets
# already blown, and the same goes for every other check here.
#
# `make check` is what CI runs and what to run before committing.

CARGO ?= cargo

.PHONY: all check build test fmt fmt-fix clippy unsafe-policy ascii size fuzz deny clean

all: build

build:
	$(CARGO) build --workspace

# Ordered cheapest first, so a formatting slip does not wait on a full test run.
check: fmt ascii clippy unsafe-policy test size

fmt:
	$(CARGO) fmt --check

fmt-fix:
	$(CARGO) fmt

clippy:
	$(CARGO) clippy --workspace --all-targets -- -D warnings

test:
	$(CARGO) test --workspace

# section 1 constraint 4: forbid(unsafe_code) holds everywhere except netcfgd-netlink,
# which is the sole audited exception. Checked by reading the crate roots rather
# than by trusting that nobody removed the attribute, since its absence is
# silent -- the code still compiles, it just stops being checked.
unsafe-policy:
	@fail=0; \
	for root in crates/*/src/lib.rs crates/*/src/main.rs; do \
		[ -f "$$root" ] || continue; \
		crate=$$(echo "$$root" | cut -d/ -f2); \
		if [ "$$crate" = "netcfgd-netlink" ]; then \
			continue; \
		fi; \
		if ! head -n 1 "$$root" | grep -q '^#!\[forbid(unsafe_code)\]$$'; then \
			echo "unsafe-policy: $$root does not open with #![forbid(unsafe_code)]"; \
			fail=1; \
		fi; \
	done; \
	if [ ! -d crates/netcfgd-netlink ]; then \
		:; \
	elif ! grep -q 'SAFETY:' -r crates/netcfgd-netlink/src 2>/dev/null; then \
		echo "unsafe-policy: netcfgd-netlink has no SAFETY comments"; \
		fail=1; \
	fi; \
	[ $$fail -eq 0 ] && echo "unsafe-policy: ok"; \
	exit $$fail

# code-style.md section 4: source, comments and doc comments are ASCII. Markdown
# is exempt and is not checked here. This caught real drift the first time it
# ran -- em dashes and section signs are easy to type and invisible in review,
# which is exactly why the rule needs a gate rather than good intentions.
ascii:
	@if grep -rlP '[^\x00-\x7F]' --include='*.rs' --include='*.toml' \
		crates Cargo.toml Makefile 2>/dev/null | grep -q .; then \
		echo "ascii: non-ASCII found in:"; \
		grep -rlP '[^\x00-\x7F]' --include='*.rs' --include='*.toml' \
			crates Cargo.toml Makefile 2>/dev/null; \
		echo "ascii: write -- for an em dash, and 'section N' for a section sign"; \
		exit 1; \
	fi; \
	echo "ascii: ok"

# Size, ratcheted. See size-budget.txt for why this is not section 10.2's tier
# budget, and what would have to change for it to become one.
size:
	@$(CARGO) build --release --quiet
	@tol=$$(awk '/^tolerance_percent/ {print $$2}' size-budget.txt); \
	fail=0; \
	while read -r name limit; do \
		case "$$name" in ''|\#*|tolerance_percent) continue ;; esac; \
		bin=target/release/$$name; \
		[ -f "$$bin" ] || continue; \
		actual=$$(stat -c%s "$$bin"); \
		ceiling=$$(( limit + limit * tol / 100 )); \
		if [ "$$actual" -gt "$$ceiling" ]; then \
			printf 'size: %s %s bytes, over its %s limit by %s\n' \
				"$$name" "$$actual" "$$limit" "$$(( actual - limit ))"; \
			echo "size:   raise it in size-budget.txt, and say why in the commit"; \
			fail=1; \
		else \
			printf 'size: %-8s %8s of %s\n' "$$name" "$$actual" "$$limit"; \
		fi; \
	done < size-budget.txt; \
	exit $$fail

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
