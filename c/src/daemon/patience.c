/*
 * patience.c -- how long an apply against a document may legitimately take.
 *
 * `daemon.h` carries why this exists and what it deliberately leaves out. This
 * carries the walk.
 *
 * **Beside `idempotence.c` rather than in it.** Both answer a question the
 * order queue asks about a piece of work -- may it run twice, and how long may
 * it take -- and they answer from different places: one from the verb alone,
 * this from the document the verb will act on. One file each, so neither
 * becomes the place per-order facts accumulate.
 */
#include "ncfg/daemon.h"

#include "ncfg/apply.h"
#include "ncfg/document.h"
#include "ncfg/supplicant.h"

/* Every hook is stopped at the default; there is no other timeout (0339). */
static unsigned long hooks_seconds(size_t count)
{
	return (unsigned long)count * (unsigned long)NCFG_HOOK_DEFAULT_TIMEOUT_SECONDS;
}

unsigned long ncfg_apply_stated_patience_seconds(const ncfg_document_t *desired)
{
	unsigned long total = 0ul;
	size_t        at;

	if (!desired) {
		return 0ul;
	}

	/*
	 * Every hook on every interface, at its own timeout. Summed rather than
	 * maximised: the phases run in sequence -- `pre_up` before the interface
	 * comes up and `post_up` after it -- so an apply that runs four of them
	 * waits for four of them.
	 */
	for (at = 0u; at < desired->interface_count; at++) {
		total += hooks_seconds(desired->interfaces[at].hook_count);
	}

	/*
	 * And every hook on every configured network, which all run: the event
	 * phases on the interface associated to it, up and down at association
	 * and disassociation (project.md 10.34). An association they run on can
	 * be caused by an apply.
	 */
	for (at = 0u; at < desired->network_count; at++) {
		total += hooks_seconds(desired->networks[at].hook_count);
	}

	/*
	 * **One association's patience where any network is configured at all,
	 * not one per network.** A radio associates to one network; the others
	 * are alternatives it did not pick, and charging for each would make a
	 * machine that lists ten fallbacks appear to need ten associations.
	 *
	 * Per radio would be more precise still, and is deliberately not done
	 * here: which interfaces are radios is an observation rather than a
	 * property of the document, and reaching for one would make this
	 * function need a machine. It is a floor already, and this keeps it a
	 * floor computable from the document alone.
	 */
	if (desired->network_count > 0u) {
		total += (unsigned long)NCFG_SUPPLICANT_CONNECT_PATIENCE_MS / 1000ul;
	}

	return total;
}
