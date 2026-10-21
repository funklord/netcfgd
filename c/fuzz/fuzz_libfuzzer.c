/*
 * libFuzzer's entry point, handed straight to the target.
 *
 * Its own file so that a target never mentions clang's name: see `fuzz.h` for
 * why the indirection is worth one function.
 */
#include "fuzz.h"

int LLVMFuzzerTestOneInput(const unsigned char *data, size_t length);

int LLVMFuzzerTestOneInput(const unsigned char *data, size_t length)
{
	return ncfg_fuzz_one(data, length);
}
