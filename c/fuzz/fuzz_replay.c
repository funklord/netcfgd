/*
 * The corpus, replayed through the same target function, with no clang.
 *
 * WHY THIS EXISTS AND NOT JUST `make fuzz`
 *   A fuzzer explores; it does not remember. Run it again on a different
 *   machine with a different seed and it goes somewhere else, so "the crash is
 *   fixed" is a claim nothing re-checks. This replays a committed set of
 *   inputs and is therefore the half that makes a fix stick: the input that
 *   crashed goes in `corpus/<target>/`, and from then on every `make test` on
 *   every machine runs it.
 *
 *   It also carries the seeds, which is what makes a fuzz run start from real
 *   syntax rather than spending its budget rediscovering that a config file
 *   has braces in it.
 *
 * WHAT IT IS NOT
 *   Not a fuzzer. It mutates nothing and finds nothing new. Under
 *   `make SANITIZE=1` it is ASan and UBSan over known-interesting inputs,
 *   which is most of the value of a fuzzer's *first* second and none of the
 *   value of its millionth.
 *
 * TERMINATION
 *   One pass over the files named on the command line. No loop over anything
 *   else, nothing spawned, nothing written.
 */
#include "fuzz.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* The ceiling on a corpus file, which is also a statement about what belongs
 * in one: an input this big is not a reproducer anybody will read. */
#define REPLAY_MAX (1u << 20)

static int one_file(const char *path)
{
	unsigned char *bytes;
	size_t         length;
	FILE          *handle = fopen(path, "rb");

	if (!handle) {
		fprintf(stderr, "fuzz-replay: cannot open %s\n", path);
		return 0;
	}
	bytes = malloc(REPLAY_MAX);
	if (!bytes) {
		fprintf(stderr, "fuzz-replay: out of memory\n");
		(void)fclose(handle);
		return 0;
	}
	length = fread(bytes, 1u, REPLAY_MAX, handle);
	if (!feof(handle)) {
		/* Refused rather than truncated: a target handed half a file is a
		 * target reporting on an input nobody committed. */
		fprintf(stderr, "fuzz-replay: %s is larger than %u bytes\n", path,
		    (unsigned)REPLAY_MAX);
		free(bytes);
		(void)fclose(handle);
		return 0;
	}
	(void)fclose(handle);
	(void)ncfg_fuzz_one(bytes, length);
	free(bytes);
	return 1;
}

int main(int argc, char **argv)
{
	int at;
	int failed = 0;

	if (argc < 2) {
		/* **A replay over no files is a pass that inspected nothing**, which
		 * is this project's own recurring failure. So it is an error. */
		fprintf(stderr, "fuzz-replay: no corpus files given, so this would\n");
		fprintf(stderr, "fuzz-replay:   check nothing and report success\n");
		return 2;
	}
	for (at = 1; at < argc; at++) {
		if (!one_file(argv[at])) {
			failed = 1;
		}
	}
	if (failed) {
		return 1;
	}
	printf("fuzz-replay: %d input(s) through %s, no crash\n", argc - 1, argv[0]);
	return 0;
}
