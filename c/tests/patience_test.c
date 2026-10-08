/*
 * patience_test.c -- what an apply's stated patience adds up to.
 *
 * WHAT IS WORTH CHECKING IN AN ARITHMETIC FUNCTION
 *   Not that it adds. What separates a right version from a wrong one:
 *
 *     * **hooks SUM rather than MAX**, because the phases run in sequence --
 *       a four-phase interface waits for four timeouts, and a function that
 *       maximised would return 60 where the truth is 240. That is the number
 *       10.352 measured the whole design against;
 *     * **a stated zero is honoured**, because `ncfg_optint_t` distinguishes
 *       absent from present and substituting the default for a zero somebody
 *       wrote would be this file overruling the document;
 *     * **one association, not one per network**, so a machine listing ten
 *       fallbacks does not appear to need ten associations;
 *     * **an empty document is zero**, which is the single-machine case with
 *       no hooks and no radio and must not acquire a term from nowhere.
 */
#include "ncfg/daemon.h"

#include "ncfg/apply.h"
#include "ncfg/document.h"
#include "ncfg/supplicant.h"

#include <stdio.h>
#include <string.h>

static int failures;
static int checks;

static void check(int condition, const char *what)
{
	checks++;
	printf("%-72s %s\n", what, condition ? "ok" : "FAILED");
	if (!condition) {
		failures++;
	}
}

/* A hook with no stated timeout, which is the default case. */
static ncfg_hook_ref_t defaulted(void)
{
	ncfg_hook_ref_t hook;

	memset(&hook, 0, sizeof(hook));
	return hook;
}

/* A hook that states one, including zero. */
static ncfg_hook_ref_t stated(int64_t seconds)
{
	ncfg_hook_ref_t hook;

	memset(&hook, 0, sizeof(hook));
	hook.timeout.has = 1;
	hook.timeout.value = seconds;
	return hook;
}

static void an_empty_document_costs_nothing(void)
{
	ncfg_document_t document;

	memset(&document, 0, sizeof(document));
	check(ncfg_apply_stated_patience_seconds(&document) == 0ul,
	    "a document with no hooks and no networks states no patience at all");
	check(ncfg_apply_stated_patience_seconds(NULL) == 0ul, "and neither does no document");
}

/*
 * **The case the measurement turned on.** Four phases on one interface is 240
 * seconds, not 60. A version that maximised would pass every other case here.
 */
static void four_phases_are_four_timeouts(void)
{
	ncfg_document_t  document;
	ncfg_interface_t iface;
	ncfg_hook_ref_t  hooks[4];
	size_t           at;

	memset(&document, 0, sizeof(document));
	memset(&iface, 0, sizeof(iface));
	for (at = 0u; at < 4u; at++) {
		hooks[at] = defaulted();
	}
	iface.hooks = hooks;
	iface.hook_count = 4u;
	document.interfaces = &iface;
	document.interface_count = 1u;

	check(ncfg_apply_stated_patience_seconds(&document) ==
	        4ul * (unsigned long)NCFG_HOOK_DEFAULT_TIMEOUT_SECONDS,
	    "four default hooks on one interface sum rather than maximise");
}

static void a_stated_timeout_wins_including_zero(void)
{
	ncfg_document_t  document;
	ncfg_interface_t iface;
	ncfg_hook_ref_t  hooks[2];

	memset(&document, 0, sizeof(document));
	memset(&iface, 0, sizeof(iface));
	hooks[0] = stated(5);
	hooks[1] = stated(0);
	iface.hooks = hooks;
	iface.hook_count = 2u;
	document.interfaces = &iface;
	document.interface_count = 1u;

	check(ncfg_apply_stated_patience_seconds(&document) == 5ul,
	    "a hook's own timeout is used, and a stated zero is honoured as zero");
}

/*
 * A radio associates to one network. Charging per configured network would
 * make a machine that lists fallbacks look like one that joins all of them.
 */
static void networks_cost_one_association_between_them(void)
{
	ncfg_document_t     document;
	ncfg_wifi_network_t networks[3];
	unsigned long       one;
	unsigned long       three;

	memset(&document, 0, sizeof(document));
	memset(networks, 0, sizeof(networks));

	document.networks = networks;
	document.network_count = 1u;
	one = ncfg_apply_stated_patience_seconds(&document);
	document.network_count = 3u;
	three = ncfg_apply_stated_patience_seconds(&document);

	check(one == (unsigned long)NCFG_SUPPLICANT_CONNECT_PATIENCE_MS / 1000ul,
	    "one configured network costs one association's patience");
	check(three == one, "and three cost the same, because a radio joins one of them");
}

/*
 * The machine this was measured on, end to end: one radio, two networks, no
 * hooks. 10.352 put its worst stated apply at the association alone.
 */
static void the_reporting_machine_adds_up(void)
{
	ncfg_document_t     document;
	ncfg_interface_t    iface;
	ncfg_wifi_network_t networks[2];

	memset(&document, 0, sizeof(document));
	memset(&iface, 0, sizeof(iface));
	memset(networks, 0, sizeof(networks));
	document.interfaces = &iface;
	document.interface_count = 1u;
	document.networks = networks;
	document.network_count = 2u;

	check(ncfg_apply_stated_patience_seconds(&document) == 20ul,
	    "a radio with two networks and no hooks states 20 seconds");
}

int main(void)
{
	an_empty_document_costs_nothing();
	four_phases_are_four_timeouts();
	a_stated_timeout_wins_including_zero();
	networks_cost_one_association_between_them();
	the_reporting_machine_adds_up();

	printf("patience_test: %d check(s)\n", checks);
	if (failures == 0) {
		printf("patience_test: all checks passed\n");
	} else {
		printf("patience_test: %d check(s) failed\n", failures);
	}
	return failures == 0 ? 0 : 1;
}
