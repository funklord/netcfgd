/*
 * fuzz.h -- one entry point per parser, and two ways to drive it.
 *
 * WHY A HEADER AND NOT libFuzzer'S OWN SIGNATURE
 *   `LLVMFuzzerTestOneInput` is clang's name and clang is optional here. A
 *   target that spelled it directly would be reachable only on a machine with
 *   libFuzzer, which is the machine least likely to be the one a regression
 *   arrives on. So a target defines `ncfg_fuzz_one` and two drivers call it:
 *   `fuzz_libfuzzer.c` hands it to libFuzzer, and `fuzz_replay.c` walks the
 *   committed corpus with the ordinary compiler.
 *
 *   The second is the half that makes a fix stick. A crash becomes a file in
 *   `corpus/<target>/` and is replayed by `make test` from then on, on every
 *   machine, for ever -- which is what the design document asks for and what
 *   "run the fuzzer again and hope" does not give.
 *
 * WHAT A TARGET MAY ASSUME
 *   Nothing. `data` is any byte string including the empty one, it is NOT
 *   NUL-terminated, and `length` may be larger than anything the program
 *   would ever really see. A target that needs a C string makes its own copy;
 *   `ncfg_fuzz_text` is that copy, so the allocation is in one place rather
 *   than five.
 *
 * WHAT A TARGET MUST NOT DO
 *   Exit, abort on bad input, print, or leak. The first three are what is
 *   being tested; the leak matters because a target runs millions of times in
 *   one process and the sanitizer's limit is the only thing between a leak
 *   and a machine with no memory. Every target frees what it took, including
 *   on the refusal paths, which is where leaks live.
 */
#ifndef NCFG_FUZZ_H
#define NCFG_FUZZ_H

#include <stddef.h>

/* One input. The return value is ignored; it exists so a target can `return`
 * early without a bare `return;` in a function somebody later gives a value. */
int ncfg_fuzz_one(const unsigned char *data, size_t length);

/* `data` as a NUL-terminated string the caller frees, or NULL out of memory.
 * An embedded NUL is left in place: a parser handed one is exactly the case
 * worth reaching, and truncating here would hide it. */
char *ncfg_fuzz_text(const unsigned char *data, size_t length);

#endif /* NCFG_FUZZ_H */
