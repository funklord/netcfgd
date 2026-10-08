/*
 * round_trip.c -- whether a document survives being written out and read back.
 *
 * WHY IT IS HERE AND NOT BESIDE THE RENDERER
 *   The check is three steps and the third is a document comparison, which is
 *   `document_compare.c`'s and lives in this layer. The renderer is in
 *   `compile/` and cannot reach it; a copy of the comparison beside the
 *   renderer would be a second thing to be wrong, and the one member it has to
 *   leave out is the member a naive comparison gets wrong -- see below.
 *
 *   `host/profile_save.c` already performs this sequence against the machine's
 *   observed state. What this adds is the same property asked of any document a
 *   suite already has, which is where it finds things: a corpus written to
 *   exercise planning has no reason to ask about rendering, and that
 *   non-overlap is the whole argument for asking more than one.
 *
 * WHAT A NAIVE VERSION GETS WRONG
 *   Comparing the two documents' canonical JSON as strings reports a
 *   difference for every document carrying `generated_by`, because the writer
 *   emits provenance and the renderer deliberately does not write it -- so the
 *   recompiled document has none. `document.h` says in as many words that
 *   `generated_by` is excluded from equality, and `ncfg_config_documents_agree`
 *   is where that exclusion is implemented. Measured: a string comparison
 *   reported 67 of the plan suites' fixtures as renderer faults, and every one
 *   of them differed in that member alone.
 */

#include "ncfg/config.h"

#include "config_internal.h"

#include "ncfg/base.h"
#include "ncfg/buf.h"
#include "ncfg/document.h"
#include "ncfg/lower.h"
#include "ncfg/parse.h"
#include "ncfg/render.h"

#include <stdio.h>
#include <string.h>

int ncfg_config_round_trips(const ncfg_document_t *document, char *err, size_t err_size)
{
	ncfg_buf_t          text;
	ncfg_unrenderable_t missing;
	ncfg_ast_file_t    *file = NULL;
	ncfg_source_t       source;
	ncfg_lower_diags_t  diags = { 0 };
	ncfg_document_t    *again = NULL;
	char                why[NCFG_ERROR_MAX];
	char                where[NCFG_ERROR_MAX];
	int                 ok = 0;

	ncfg_buf_init(&text, 0);
	ncfg_unrenderable_init(&missing);
	why[0] = '\0';
	if (!ncfg_render(document, NULL, &text, &missing, why, sizeof(why))) {
		/* The first refusal rather than all of them: a caller is told what is
		 * in the way, and the whole list is what `ncfg profile save` prints. */
		ncfg_error_set(err, err_size, "it cannot be rendered at all: %s",
		    missing.count ? missing.items[0] : why);
		goto done;
	}
	if (!ncfg_parse(ncfg_buf_text(&text), strlen(ncfg_buf_text(&text)), &file, NULL,
	    why, sizeof(why))) {
		ncfg_error_set(err, err_size, "what it wrote does not parse: %s\nrendered:\n%s",
		    why, ncfg_buf_text(&text));
		goto done;
	}
	source.name = "rendered.conf";
	source.file = file;
	again = ncfg_compile(&source, 1, ncfg_hook_sink_refusing(), &diags, why, sizeof(why));
	if (!again) {
		ncfg_error_set(err, err_size, "what it wrote does not compile: %s\nrendered:\n%s",
		    diags.count ? diags.at[0].message : why, ncfg_buf_text(&text));
		goto done;
	}
	where[0] = '\0';
	/* No profile name: neither side is being selected, so `globals.profile` is
	 * compared like anything else. */
	if (!ncfg_config_documents_agree(document, NULL, again, where, sizeof(where))) {
		ncfg_error_set(err, err_size,
		    "what it wrote compiles to a DIFFERENT document%s\nrendered:\n%s",
		    where, ncfg_buf_text(&text));
		goto done;
	}
	ok = 1;
done:
	ncfg_document_free(again);
	ncfg_lower_diags_free(&diags);
	ncfg_ast_file_free(file);
	ncfg_unrenderable_free(&missing);
	ncfg_buf_free(&text);
	return ok;
}
