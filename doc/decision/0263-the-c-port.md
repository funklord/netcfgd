# 0263: the C port

Status: accepted
Date: 2026-09-18
Milestone: M9; the window can configure the machine

## What this is

netcfgd is being converted to C, on the branch `c-port`, module by module,
while the Rust it replaces goes on being the thing that runs. This record is
the contract the modules are written against, because a port done in parallel
with no contract is a pile of C that does not link.

**The size, so that nobody is surprised by it.** 112,282 lines of Rust across
`crates/`, `backend/` and `adapter/` -- a large part of which is doc comments
and tests, both of which come across too. The existing C is 10,293 lines: the
client library and the shell helpers. This is a campaign, not a round, and
every module lands with its tests or it has not landed.

**What is given up, stated once rather than rediscovered.** The Rust confines
`unsafe` to `netcfgd-sys` and the build gate `make unsafe-policy` proves it; in
C every module is that crate. Ownership stops being checked and becomes a rule
this record writes down. The compiler stops noticing an unhandled case in a
`match`. Those are the things the tests and the gates now have to carry, and
the discipline below is what carries them.

## The layout

    c/
      Makefile              one library, one test per module
      include/ncfg/*.h      the public face of each module
      src/<module>/*.c      base, json, model, compile, plan, apply, sys,
                            host, proto, daemon, cli
      tests/*_test.c        one binary per module, all of them run

Sources are a wildcard and the reason is in the Makefile: this tree grows a
module at a time, often in more than one working tree at once, and a listed
source is a merge conflict per module for nothing. `clean` removes what the
build produced and nothing by a pattern this directory does not own.

`client/ncfg_json.c` is compiled in rather than copied. Two readers of one
format is how the GUI and the CLI came to spell an access point's name three
ways, and the port is not starting a second copy of anything it can share.

## The three conventions

They are `client/ncfg_client.h`'s, unchanged, because that library has faced a
live daemon since M4 and a port that answered the same questions differently
would make two halves of one program argue about what a failure is.

* A call that can fail returns **1 for success, 0 for failure**, and takes
  `char *err, size_t err_size` last. Not `errno`, not a negative code: these
  failures are sentences an operator reads, and an integer cannot carry one.
* A call returning a pointer returns `NULL` for failure, same buffer.
* Every aggregate has an `ncfg_x_free` beside it, and freeing something never
  filled in is nothing.

Two more, which the base module makes cheap:

* **Text is built in `ncfg_buf_t`, which has a ceiling and a sticky failure.**
  A daemon rendering what a client sent it has to bound the result, and a
  buffer that reports failure once at the end is a buffer whose errors are
  actually checked. A failed buffer hands out the empty string rather than the
  part that fitted: half a configuration block that looks whole is the failure
  mode this refuses.
* **A library never exits, never asserts and never prints.** The one place in
  this project that ends a process on its own is `netcfgd_sys::out`, and it
  does it for a closed pipe (0261).

## The order, and why

Dependencies first, and each module is worth having on its own before the next
one starts:

1. **base** -- errors and the buffer. Done.
2. **json** -- the reader exists; the writer is what the model needs.
3. **model** -- the value types first (addresses, hardware addresses, the
   closed sets and their spellings), then the document.
4. **compile** -- lexer, parser, merge, lower, render.
5. **sys** -- the wire layer first, which is pure bytes and testable without a
   kernel; then the sockets and the ioctls.
6. **proto**, **host**, **plan**, **apply**, **daemon**, **cli**.

The first wave is the writer, the value types, the lexer and the wire layer:
four modules that depend on nothing but `base` and on each other not at all,
which is what makes them safe to write at the same time.

## What a module owes

Its header, its sources, and **its tests in the same wave** -- not afterwards.
The Rust being ported carries its tests beside it, most of them naming a defect
that shipped; those cases come across with the code, because the case is the
part that is expensive to rediscover. A module whose tests are "to follow" is a
module that has not been ported, and the wire layer in particular ships with
the adversarial cases or not at all.

The spellings are read from the Rust, never from memory. This project has twice
shipped a configuration key spelled the model's way rather than the language's
-- `wire_guard` for `wireguard`, `open_vpn` for `openvpn` -- and each compiled
into a block with the feature silently missing.

## What is not being decided here

Whether the C replaces the Rust, and when. Nothing in `c/` is installed, the
packaging keeps shipping the Rust, and a module is a candidate only once it
passes the Rust's own tests for the same behaviour. That comparison is the next
decision and it needs the modules to exist first.
