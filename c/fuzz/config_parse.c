/*
 * The configuration language, from text to a validated document.
 *
 * A config file is input a privileged daemon reads at boot and on every
 * reload. It is less hostile than netlink -- an operator usually writes it --
 * but "usually" is not a security argument, and `conf.d/` is writable by
 * anything that can write to /etc.
 *
 * The whole chain, because the interesting failures are at the seams: the
 * lexer refusing a token the parser then dereferences, a merge of one file
 * against itself, a lowerer handed an AST no file could produce. The Rust's
 * `config_parse` target makes the same argument and calls `compile`, which is
 * this.
 *
 * Canonicalisation and the writer run on whatever compiled, for the reason
 * that target gives: those paths are reachable only through a successful
 * compile and would otherwise never see a fuzzed document at all.
 */
#include "fuzz.h"

#include "ncfg/base.h"
#include "ncfg/buf.h"
#include "ncfg/config.h"
#include "ncfg/hooks.h"
#include "ncfg/document.h"
#include "ncfg/lower.h"

#include <stdlib.h>
#include <string.h>

int ncfg_fuzz_one(const unsigned char *data, size_t length)
{
	ncfg_config_sources_t sources = { 0 };
	ncfg_document_t      *document;
	char                  err[NCFG_ERROR_MAX];
	char                 *text = ncfg_fuzz_text(data, length);

	if (!text) {
		return 0;
	}
	/*
	 * **The whole set on the heap, so `ncfg_config_sources_free` can have it.**
	 * The tests that compile a string put a `ncfg_config_file_t` on the stack,
	 * point `at` at it and never free -- which is correct for a test and wrong
	 * here: the free walks the array and then frees the array itself, so a
	 * stack pointer aborts in `free()`. It did, on the first corpus file, which
	 * is a target bug and not a finding. Doing it properly also fuzzes the free
	 * path, which is where a leak would be.
	 *
	 * The name is allocated for the same reason, and is a name rather than
	 * empty because a diagnostic carries it -- an unnamed source would not
	 * reach the rendering of one.
	 */
	sources.at = calloc(1u, sizeof(*sources.at));
	if (!sources.at) {
		free(text);
		return 0;
	}
	sources.at[0].name = strdup("fuzz.conf");
	if (!sources.at[0].name) {
		free(sources.at);
		free(text);
		return 0;
	}
	sources.at[0].text = text;
	sources.at[0].length = length;
	sources.count = 1u;
	sources.capacity = 1u;

	document = ncfg_config_compile(&sources, ncfg_hook_sink_unwritten(), NULL, err,
	    sizeof(err));
	if (document) {
		ncfg_buf_t out;

		ncfg_document_canonicalize(document);
		ncfg_buf_init(&out, 0);
		(void)ncfg_document_write_canonical(document, &out, err, sizeof(err));
		ncfg_buf_free(&out);
		ncfg_document_free(document);
	}
	/* Frees the name, the text and the array -- see above. */
	ncfg_config_sources_free(&sources);
	return 0;
}
