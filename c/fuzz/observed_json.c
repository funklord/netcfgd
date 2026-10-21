/*
 * The observation netcfgd writes to `/run` and reads back.
 *
 * WHY THIS IS A SECOND TARGET AND NOT PART OF `document_json`
 *   They are two schemas and two readers. A document is what the operator
 *   asked for; an observation is what the machine turned out to be, and
 *   `doc/schema/observed.json` is its own file for that reason. The reader
 *   refuses an unknown member rather than ignoring it -- the header says why:
 *   an observation is written by one netcfgd and read by a client that may be
 *   older, and a client acting on a subset of what it was sent is the failure
 *   that rule exists to prevent.
 *
 * WHO WRITES THE INPUT
 *   netcfgd, into a root-owned directory -- so this is the same kind of
 *   boundary as the control socket rather than netlink's. It is a boundary
 *   twice over all the same: **the file survives a crash**, so what is read
 *   back may be half of what was being written, and `/run` outlives neither
 *   the daemon's version nor the schema's. A client reading `observed.json`
 *   from a newer netcfgd is the ordinary case on an upgraded machine.
 *
 * THE ROUND TRIP IS THE ASSERTION
 *   An observation that reads has to survive its own canonical writer and
 *   read again to the same text, for `document_json`'s reason: the encoding is
 *   a function, and a reader that silently dropped half the file would pass a
 *   check that only looked for crashes.
 */
#include "fuzz.h"

#include "ncfg/base.h"
#include "ncfg/buf.h"
#include "ncfg/observed.h"

#include <stdlib.h>
#include <string.h>

int ncfg_fuzz_one(const unsigned char *data, size_t length)
{
	ncfg_observed_t *observed;
	ncfg_observed_t *again;
	ncfg_buf_t       first;
	ncfg_buf_t       second;
	char             err[NCFG_ERROR_MAX];

	observed = ncfg_observed_read((const char *)data, length, err, sizeof(err));
	if (!observed) {
		return 0;
	}
	ncfg_buf_init(&first, 0);
	if (!ncfg_observed_write_canonical(observed, &first, err, sizeof(err))) {
		/* The buffer's ceiling, which a legitimately enormous observation can
		 * reach. The sticky failure is the contract and it held. */
		ncfg_buf_free(&first);
		ncfg_observed_free(observed);
		return 0;
	}
	again = ncfg_observed_read(first.data, first.length, err, sizeof(err));
	if (!again) {
		abort(); /* its own output must read */
	}
	ncfg_buf_init(&second, 0);
	if (ncfg_observed_write_canonical(again, &second, err, sizeof(err))) {
		if (first.length != second.length ||
		    memcmp(first.data, second.data, first.length) != 0) {
			abort(); /* the encoding is not a function */
		}
	}
	ncfg_buf_free(&second);
	ncfg_buf_free(&first);
	ncfg_observed_free(again);
	ncfg_observed_free(observed);
	return 0;
}
