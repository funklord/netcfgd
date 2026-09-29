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

/*
 * One hook's timeout: its own where it states one, the default where it does
 * not.
 *
 * **A stated zero is taken at face value.** `ncfg_optint_t` distinguishes
 * absent from present, so a hook configured with no timeout is the author
 * saying something rather than saying nothing, and substituting the default
 * would be this file overruling the document -- which `project.md` puts the
 * wrong way round.
 */
static unsigned long hook_seconds(const ncfg_hook_ref_t *hook)
{
	if (!hook) {
		return 0ul;
	}
	if (hook->timeout.has && hook->timeout.value > 0) {
		return (unsigned long)hook->timeout.value;
	}
	if (hook->timeout.has) {
		return 0ul;
	}
	return (unsigned long)NCFG_HOOK_DEFAULT_TIMEOUT_SECONDS;
}

static unsigned long hooks_seconds(const ncfg_hook_ref_t *hooks, size_t count)
{
	unsigned long total = 0ul;
	size_t        at;

	for (at = 0u; at < count; at++) {
		total += hook_seconds(&hooks[at]);
	}
	return total;
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
		total += hooks_seconds(desired->interfaces[at].hooks,
		    desired->interfaces[at].hook_count);
	}

	/*
	 * And every hook on every configured network. A network's hooks run when
	 * it is joined, which an apply may cause.
	 */
	for (at = 0u; at < desired->network_count; at++) {
		total += hooks_seconds(desired->networks[at].hooks,
		    desired->networks[at].hook_count);
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
