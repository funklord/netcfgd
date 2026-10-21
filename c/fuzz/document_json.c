/*
 * The desired-state document, read back from JSON.
 *
 * `/run` holds this document and a client reads it; section 2 requires that an
 * unknown member is refused rather than dropped, and this is where refusing
 * must not become crashing.
 *
 * **The round trip is the assertion, not the parse.** A document that read has
 * to survive its own writer and parse again to the same thing, because section
 * 2 says the encoding is a function. Checking only that the parse returned
 * would pass a reader that silently dropped half the file -- which is the
 * defect the requirement exists for. The comparison is on the canonical text
 * rather than on the trees, since the writer is what a client sees.
 */
#include "fuzz.h"

#include "ncfg/base.h"
#include "ncfg/buf.h"
#include "ncfg/document.h"

#include <stdlib.h>
#include <string.h>

int ncfg_fuzz_one(const unsigned char *data, size_t length)
{
	ncfg_document_t *document;
	ncfg_document_t *again;
	ncfg_buf_t       first;
	ncfg_buf_t       second;
	char             err[NCFG_ERROR_MAX];
	char            *text = ncfg_fuzz_text(data, length);

	if (!text) {
		return 0;
	}
	document = ncfg_document_read(text, length, err, sizeof(err));
	free(text);
	if (!document) {
		return 0;
	}
	ncfg_buf_init(&first, 0);
	if (!ncfg_document_write_canonical(document, &first, err, sizeof(err))) {
		/* A document that read and cannot be written is a finding, but it is
		 * the buffer's ceiling that reports it, and a fuzzer can reach that
		 * ceiling with a legitimately enormous document. So this is not an
		 * assertion -- the sticky failure is the contract and it held. */
		ncfg_buf_free(&first);
		ncfg_document_free(document);
		return 0;
	}
	again = ncfg_document_read(first.data, first.length, err, sizeof(err));
	if (!again) {
		abort(); /* its own output must parse */
	}
	ncfg_buf_init(&second, 0);
	if (ncfg_document_write_canonical(again, &second, err, sizeof(err))) {
		if (first.length != second.length ||
		    memcmp(first.data, second.data, first.length) != 0) {
			abort(); /* the encoding is not a function */
		}
	}
	ncfg_buf_free(&second);
	ncfg_buf_free(&first);
	ncfg_document_free(again);
	ncfg_document_free(document);
	return 0;
}
