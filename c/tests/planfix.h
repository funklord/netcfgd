/*
 * planfix.h -- the plumbing the planner's fixture tests share.
 *
 * WHY A HEADER AND NOT A COPY PER FILE
 *   `plan_test.c` grew its own copy of this first and is deliberately left
 *   alone: it is the witness comparison and the ordering rules, and it is
 *   shared with whoever is working on the addressing half. The passes that
 *   arrived afterwards are four more files, and four copies of "read a
 *   document, read an observation, plan, and say what came out" is four places
 *   for the fixture shape to drift. A fixture that quietly stopped building
 *   what it claims to build is a check that passes over nothing, which is what
 *   `evidence.md` is about.
 *
 *   Everything here is `static inline`, so a file that uses two of these does
 *   not have to explain the other nine to `-Wunused-function`.
 *
 * WHAT A FIXTURE IS
 *   Two JSON documents and nothing else. A plan is a pure function of a
 *   document and an observation, so none of these tests touches a socket, a
 *   file, a radio or a kernel -- which is the whole reason the planner is
 *   written the way it is, and the reason this suite can run on a workstation
 *   whose network must not be disturbed.
 */
#ifndef NCFG_TESTS_PLANFIX_H
#define NCFG_TESTS_PLANFIX_H

#include "ncfg/base.h"
#include "ncfg/document.h"
#include "ncfg/observed.h"
#include "ncfg/plan.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

/* The model's own structs hold `char *`, and a test's values are literals.
 * `-Wwrite-strings` makes a literal `const char[]`, so the cast is what lets a
 * fixture be written as data. Nothing here is ever modified or freed. */
#define LIT(text) ((char *)(uintptr_t)(text))

/* A link that exists and is up, which is what a converged machine looks like.
 * `index` is 2 so that a bridge VLAN fixture can name it. */
#define PLANFIX_LINK(name, extra) \
	"{\"name\":\"" name "\",\"index\":2,\"mtu\":1500,\"up\":true,\"carrier\":true," \
	"\"ownership\":\"unknown\"" extra "}"

/*
 * A document out of its four interesting lists.
 *
 * Four arguments rather than one blob because `devices`, `interfaces` and
 * `networks` are **required members** -- the reader refuses a document without
 * them by name -- so a one-argument helper makes every fixture repeat two
 * empty arrays, and a fixture that forgot one fails to read rather than
 * failing the check it was written for. `extra` is whatever else a case needs,
 * leading comma included: `rules`, `access_points`, `linksets`.
 */
static inline ncfg_document_t *planfix_document(const char *devices, const char *interfaces,
    const char *networks, const char *extra)
{
	char             text[16384];
	char             message[NCFG_ERROR_MAX];
	ncfg_document_t *document;

	(void)snprintf(text, sizeof(text),
	    "{\"schema_version\":{\"major\":1,\"minor\":1},\"generated_by\":\"planfix\","
	    "\"globals\":{},\"devices\":[%s],\"interfaces\":[%s],\"networks\":[%s]%s}",
	    devices, interfaces, networks, extra);
	message[0] = '\0';
	document = ncfg_document_read(text, strlen(text), message, sizeof(message));
	if (!document) {
		printf("  fixture document did not read: %s\n", message);
	}
	return document;
}

static inline ncfg_observed_t *planfix_observed(const char *body)
{
	char             text[16384];
	char             message[NCFG_ERROR_MAX];
	ncfg_observed_t *observed;

	(void)snprintf(text, sizeof(text), "{%s}", body);
	message[0] = '\0';
	observed = ncfg_observed_read(text, strlen(text), message, sizeof(message));
	if (!observed) {
		printf("  fixture observation did not read: %s\n", message);
	}
	return observed;
}

/* One fixture: read the two documents, plan, and hand the plan to the caller. */
static inline ncfg_plan_t *planfix_plan(const char *devices, const char *interfaces,
    const char *networks, const char *extra, const char *observation,
    ncfg_document_t **document_out, ncfg_observed_t **observed_out)
{
	char             message[NCFG_ERROR_MAX];
	ncfg_document_t *document = planfix_document(devices, interfaces, networks, extra);
	ncfg_observed_t *observed = planfix_observed(observation);
	ncfg_plan_t     *plan;

	*document_out = document;
	*observed_out = observed;
	if (!document || !observed) {
		return NULL;
	}
	message[0] = '\0';
	plan = ncfg_plan_build(document, observed, NULL, message, sizeof(message));
	if (!plan) {
		printf("  could not build the plan: %s\n", message);
	}
	return plan;
}

static inline void planfix_release(ncfg_plan_t *plan, ncfg_document_t *document,
    ncfg_observed_t *observed)
{
	ncfg_plan_free(plan);
	ncfg_document_free(document);
	ncfg_observed_free(observed);
}

/* The op names of a plan, in order, joined so a mismatch prints readably. */
static inline void planfix_names(const ncfg_plan_t *plan, char *out, size_t out_size)
{
	size_t at = 0;
	size_t i;

	out[0] = '\0';
	for (i = 0; i < plan->action_count; i++) {
		int wrote = snprintf(out + at, out_size - at, "%s%s", at ? "," : "",
		    ncfg_op_name(&plan->actions[i].op));

		if (wrote < 0 || (size_t)wrote >= out_size - at) {
			return;
		}
		at += (size_t)wrote;
	}
}

/* The first action of this name, or NULL. */
static inline const ncfg_action_t *planfix_action(const ncfg_plan_t *plan, const char *name)
{
	size_t i;

	for (i = 0; i < plan->action_count; i++) {
		if (strcmp(ncfg_op_name(&plan->actions[i].op), name) == 0) {
			return &plan->actions[i];
		}
	}
	return NULL;
}

/* How many actions of this name a plan holds. */
static inline size_t planfix_count(const ncfg_plan_t *plan, const char *name)
{
	size_t count = 0;
	size_t i;

	for (i = 0; i < plan->action_count; i++) {
		if (strcmp(ncfg_op_name(&plan->actions[i].op), name) == 0) {
			count++;
		}
	}
	return count;
}

/* The first action of this name whose reason names this field, or NULL. */
static inline const ncfg_action_t *planfix_for_field(const ncfg_plan_t *plan, const char *name,
    const char *field)
{
	size_t i;

	for (i = 0; i < plan->action_count; i++) {
		if (strcmp(ncfg_op_name(&plan->actions[i].op), name) != 0) {
			continue;
		}
		if (plan->actions[i].reason.field &&
		    strcmp(plan->actions[i].reason.field, field) == 0) {
			return &plan->actions[i];
		}
	}
	return NULL;
}

static inline int planfix_depends_on(const ncfg_action_t *action, uint32_t id)
{
	size_t i;

	for (i = 0; i < action->depends_count; i++) {
		if (action->depends_on[i] == id) {
			return 1;
		}
	}
	return 0;
}

/* Whether any warning contains this text. */
static inline int planfix_warned(const ncfg_plan_t *plan, const char *fragment)
{
	size_t i;

	for (i = 0; i < plan->warning_count; i++) {
		if (plan->warnings[i].message && strstr(plan->warnings[i].message, fragment)) {
			return 1;
		}
	}
	return 0;
}

/* The whole warning that contains this text, so a check can look at the rest of
 * it rather than only at the fragment it matched on. */
static inline const char *planfix_warning_with(const ncfg_plan_t *plan, const char *fragment)
{
	size_t i;

	for (i = 0; plan && i < plan->warning_count; i++) {
		if (plan->warnings[i].message && strstr(plan->warnings[i].message, fragment)) {
			return plan->warnings[i].message;
		}
	}
	return NULL;
}

/*
 * Whether a message arrived whole, checked by its **last** words.
 *
 * `ncfg_plan_warnf` formats into `NCFG_ERROR_MAX` and marks what it had to cut
 * at the *end*, so a check asserting a fragment near the front of a long
 * warning cannot fail -- the front is the half a cut keeps. That is
 * `evidence.md`'s shape, and it is how the first draft of a warning here
 * reached an operator as "still means t" with every check on it green.
 *
 * **Here rather than in one test file**, because three of them now assert the
 * tail of a sentence that goes through `ncfg_plan_warn_unbuilt`: that helper
 * appends 196 characters after whatever the caller wrote, so every warning
 * routed through it is a sentence whose end is the part at risk.
 */
static inline int planfix_whole(const char *message, const char *ending)
{
	size_t length;
	size_t tail;

	if (!message) {
		return 0;
	}
	length = strlen(message);
	tail = strlen(ending);
	return length >= tail && length < NCFG_ERROR_MAX &&
	    strcmp(message + (length - tail), ending) == 0;
}

/*
 * The whole of what `ncfg_plan_warn_unbuilt` appends, so that asserting it as a
 * message's tail proves two things at once: that the block was marked as
 * nobody's gap rather than as this port's, and that the whole of the sentence
 * fitted.
 *
 * **All of it, not its last few words.** The first draft of this macro was
 * "still means this when the code arrives" -- which is the tail of the sentence
 * `warn_unbuilt` *replaced* as well as of the one it writes, so a check using
 * it passed against a warning that had gone back to promising a release of this
 * port. Found by sabotage: putting the old wording back turned nothing red.
 */
#define PLANFIX_UNBUILT_TAIL \
	". That is not this port catching up: nothing acts on it in the Rust either, " \
	"so there is nothing to wait for. The block is kept so a configuration written " \
	"now still means this when the code arrives"

/* Whether any warning, reason or refusal anywhere in the plan contains this
 * text. What a secret must never appear in. */
static inline int planfix_mentions(const ncfg_plan_t *plan, const char *fragment)
{
	size_t i;

	for (i = 0; i < plan->warning_count; i++) {
		if (plan->warnings[i].message && strstr(plan->warnings[i].message, fragment)) {
			return 1;
		}
	}
	for (i = 0; i < plan->action_count; i++) {
		const ncfg_reason_t *reason = &plan->actions[i].reason;

		if ((reason->field && strstr(reason->field, fragment)) ||
		    (reason->desired && strstr(reason->desired, fragment)) ||
		    (reason->observed && strstr(reason->observed, fragment))) {
			return 1;
		}
	}
	return 0;
}

#endif /* NCFG_TESTS_PLANFIX_H */
