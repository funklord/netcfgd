/*
 * explain.h -- why is it like this?
 *
 * WHAT THIS MODULE IS FOR
 *   The question the whole project exists to answer. Design section 1.1 calls
 *   the inability to answer it Pain 1, and everything else -- plain-text
 *   configuration, a greppable run directory, a plan somebody can read -- is
 *   machinery in service of it.
 *
 *   Pure, like the Rust it replaces: four artifacts in, an explanation out. No
 *   sockets, no kernel, no clock. `ncfg explain` answers locally and the
 *   daemon answers over the socket, and they produce the same words because
 *   they run this function.
 *
 * WHAT IT CAN AND CANNOT ANSWER IN THIS BUILD, SAID IN THE OUTPUT
 *   `ncfg explain` exists to say **where a value came from**, and the strongest
 *   form of that answer is a file and a line: "because
 *   `/etc/netcfgd/conf.d/10-lan.conf` line 4 says so" rather than "because the
 *   configuration says so". That answer needs the compiler's provenance side
 *   table, and 0263 does not port the half of the compiler that fills one in --
 *   `state.h` declares the table and reads and writes the file, and nothing in
 *   `src/compile/` records an entry.
 *
 *   So this takes the table as an argument, exactly as the Rust does, and is
 *   complete the day lowering starts recording one. Until then every lookup
 *   misses, and **an explanation whose every lookup missed says so, in its own
 *   output, as its first fact** -- because the alternative is an answer that
 *   silently stops naming files and a reader who cannot tell that from a
 *   configuration with nothing to name. It is the first fact and not the last
 *   for the reason the radio fact comes before the addresses: a caveat about
 *   what an answer cannot contain is worth nothing after the answer.
 *
 *   **Nothing here invents a position.** A file and line this build did not
 *   record is a file and line it does not print. The notice disappears by
 *   itself the moment a real table arrives, and where the table has an entry
 *   for some fields and not others -- a real state, once a compiler fills one
 *   in partially -- the gap is per field and no blanket claim is made.
 *
 * WHERE THIS DIVERGES FROM THE RUST
 *   The list lives in `doc/decision/0263-the-c-port.md`, which is where a
 *   reader asking "is this the same program?" can see all of them at once.
 *   Three are worth knowing before reading a call:
 *
 *     * **An explanation is bounded** at `NCFG_EXPLAIN_FACTS_MAX`, with
 *       `total` counting past it -- the parser's arrangement, applied to a
 *       renderer whose input arrives over a socket.
 *     * **A subject's names are bounded** at `NCFG_EXPLAIN_SUBJECT_MAX`, and a
 *       longer one is refused by name rather than truncated.
 *     * **Rendering is a buffer, not a print.** A library never prints; the
 *       caller hands the text to `ncfg_out_*`.
 *
 * ERRORS AND OWNERSHIP
 *   base.h's conventions: NULL and a sentence for the build, 1 or 0 and a
 *   sentence for the render. One `ncfg_explanation_free` takes the whole thing
 *   apart, and freeing something never filled in is nothing.
 */
#ifndef NCFG_EXPLAIN_H
#define NCFG_EXPLAIN_H

#include <stddef.h>

#include "ncfg/buf.h"
#include "ncfg/document.h"
#include "ncfg/observed.h"
#include "ncfg/proto.h"
#include "ncfg/state.h"

/*
 * How many facts one explanation holds.
 *
 * The Rust grows a `Vec` from whatever the observation carried, and an
 * observation is a file in the run directory and a message on the control
 * socket -- so the fact count is chosen by whoever wrote it. An interface with
 * two thousand addresses is two facts each; the bound is what stops that being
 * an allocation somebody else sizes.
 *
 * **Published so a test cannot spell the number itself**, which is the
 * linkset walk's rule and right for the same reason: a test carrying its own
 * copy of a bound stops testing the bound the moment the bound moves.
 */
#define NCFG_EXPLAIN_FACTS_MAX 256

/*
 * The longest interface name, address or destination a subject may carry.
 *
 * An interface name is 15 characters to the kernel and an address renders to
 * at most 49, so this is generous by a factor of two. It exists because the
 * subject arrives from a client: the Rust's `Subject` holds `String`s and a
 * request naming a two-megabyte interface is a request that allocates two
 * megabytes. The refusal names the field and the bound.
 */
#define NCFG_EXPLAIN_SUBJECT_MAX 128

/*
 * One statement.
 *
 * `topic` is the short word a reader scans down the left-hand column --
 * `desired`, `observed`, `ownership`, `guard`, `probe`, `radio`, `backend`,
 * `origin`, `safety`, `drift`, `next`, `provenance`. `source` is where the
 * fact came from and is NULL where it came from nowhere nameable: a derived
 * answer, or a policy read off the document without a recorded position.
 */
typedef struct {
	char *topic;
	char *detail;
	char *source;
} ncfg_explain_fact_t;

/*
 * What is known about one subject.
 *
 * `count` is what is held and `total` is how many there were. They differ only
 * where `NCFG_EXPLAIN_FACTS_MAX` was reached, and a renderer that shows "40 of
 * 900" is showing more than one that shows nine hundred nobody scrolls
 * through.
 */
typedef struct {
	char                *subject;
	ncfg_explain_fact_t *facts;
	size_t               count;
	size_t               total;
} ncfg_explanation_t;

/*
 * Explain something.
 *
 * `desired` is NULL where the configuration does not compile, which is not an
 * edge case: the moment somebody reaches for `explain` is often the moment the
 * configuration has stopped compiling, and the observation half of the answer
 * is worth having on its own.
 *
 * `provenance` may be NULL, which reads exactly as an empty table: nothing can
 * be located, and the explanation says so. It is borrowed and is not kept.
 *
 * Returns NULL with a sentence in `err` for a subject outside the set, a name
 * past `NCFG_EXPLAIN_SUBJECT_MAX`, or an allocation that failed.
 */
ncfg_explanation_t *ncfg_explain(const ncfg_proto_subject_t *subject,
    const ncfg_document_t *desired, const ncfg_observed_t *observed,
    const ncfg_provenance_t *provenance, char *err, size_t err_size);

/* Release it. A NULL explanation, and one never filled in, are nothing. */
void ncfg_explanation_free(ncfg_explanation_t *explanation);

/*
 * Write what `ncfg explain` prints into `out`, newline-terminated.
 *
 * The subject on its own line, then one line per fact: two spaces, the topic
 * in a nine-column field, the detail, and the source in brackets where there
 * is one. That layout is the Rust's `command_explain` exactly -- **the output
 * is the product**, and a port that rewrote it would have ported the data and
 * not the command.
 *
 * A bounded explanation ends with a line saying how many facts there were, for
 * the reason the count is carried at all.
 *
 * This is a buffer rather than a print because a library never prints: the
 * caller hands the result to `ncfg_out_text`. **`ncfg explain` is wired**: this
 * said it was not, because the verb's first step is a local observation and
 * the observer was not ported -- which stopped being true when
 * `ncfg_observe_current` landed, and went on being said.
 */
int ncfg_explanation_render(const ncfg_explanation_t *explanation, ncfg_buf_t *out, char *err,
    size_t err_size);

#endif /* NCFG_EXPLAIN_H */
