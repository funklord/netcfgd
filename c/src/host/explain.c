/*
 * explain.c -- the answer to "why is it like this?", assembled from four
 * artifacts and nothing else.
 *
 * `explain.h` says what the module is for and what this build can and cannot
 * answer. What is worth knowing while reading the code:
 *
 *   * **The order of the facts is part of the answer** and is the Rust's,
 *     except where a comment here says otherwise and 0263 records it. A fact
 *     nobody reaches is a fact nobody read, which is why the radio comes before
 *     the addresses and the provenance notice comes before everything.
 *   * **Every failure is sticky**, `ncfg_buf_t`'s discipline: a run of twenty
 *     appends is checked once, at the end, and a half-built explanation is
 *     never handed out.
 *   * **One rule is spelled here that belongs elsewhere**, because this port
 *     has one caller for it so far: `takes_reports` is `netcfgd-plan`'s and
 *     this build's planner keeps it private. It says so at its definition, and
 *     the second caller takes this one rather than writing its own.
 *     `derive_from_delegation` was the other, and is no longer here: the
 *     planner became its second caller, so it is `ncfg_address_from_delegation`
 *     in `value.h` where 0263 said it belonged.
 */
#include "ncfg/explain.h"

#include "ncfg/base.h"
#include "ncfg/plan.h"
#include "ncfg/value.h"

#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Where the two indirect sources end, which is the other half of following
 * one: the next question after "why is this here" is "where does that come
 * from", and an answer stopping at "a report" has only moved the question. */
#define REPORTED_DIR  "/run/netcfgd/reported/"
#define PREFIXES_DIR  "/run/netcfgd/prefixes/"
#define OWNED_FILE    "/run/netcfgd/owned.json"

/* Room for a dotted path: a subject's name, and the longest field spelling
 * after it. */
#define PATH_MAX_TEXT (NCFG_EXPLAIN_SUBJECT_MAX + 64u)

/* ------------------------------------------------------------------------ *
 * Building one
 * ------------------------------------------------------------------------ */

typedef struct {
	ncfg_explanation_t      *explanation;
	const ncfg_provenance_t *provenance;
	/* How many times a position was asked for, and how many came back with
	 * one. The notice is emitted where the first is non-zero and the second is
	 * zero *and the table itself is empty* -- a table with entries that does
	 * not happen to cover this field is a gap in the table, not the absence of
	 * one, and a blanket claim about it would be wrong. */
	size_t                   lookups;
	size_t                   located;
	/* Set by the first allocation failure and never cleared. */
	int                      failed;
} builder_t;

/* `malloc`ed text from a format, or NULL. */
static char *format_text(const char *format, ...)
{
	va_list args;
	va_list again;
	char   *text;
	int     wanted;

	va_start(args, format);
	va_copy(again, args);
	wanted = vsnprintf(NULL, 0, format, args);
	va_end(args);
	if (wanted < 0) {
		va_end(again);
		return NULL;
	}
	text = malloc((size_t)wanted + 1u);
	if (text) {
		(void)vsnprintf(text, (size_t)wanted + 1u, format, again);
	}
	va_end(again);
	return text;
}

static void fact_free(ncfg_explain_fact_t *fact)
{
	free(fact->topic);
	free(fact->detail);
	free(fact->source);
	memset(fact, 0, sizeof(*fact));
}

/* Fill in one fact, or report that it could not be. `source` may be NULL. */
static int fact_fill(ncfg_explain_fact_t *fact, const char *topic, const char *source,
    char *detail)
{
	memset(fact, 0, sizeof(*fact));
	fact->detail = detail;
	fact->topic = format_text("%s", topic);
	if (source) {
		fact->source = format_text("%s", source);
	}
	if (!fact->topic || !fact->detail || (source && !fact->source)) {
		fact_free(fact);
		return 0;
	}
	return 1;
}

/*
 * Append a fact, or count it where the bound has been reached.
 *
 * `source` is copied and may be NULL. Nothing here reports a failure to its
 * caller: the flag is sticky and `ncfg_explain` checks once, which is what
 * makes forty call sites readable.
 */
static void add(builder_t *builder, const char *topic, const char *source, const char *format, ...)
{
	ncfg_explanation_t  *explanation = builder->explanation;
	ncfg_explain_fact_t *grown;
	va_list              args;
	char                *detail;
	int                  wanted;

	explanation->total++;
	if (builder->failed || explanation->count >= NCFG_EXPLAIN_FACTS_MAX) {
		return;
	}

	va_start(args, format);
	wanted = vsnprintf(NULL, 0, format, args);
	va_end(args);
	if (wanted < 0) {
		builder->failed = 1;
		return;
	}
	detail = malloc((size_t)wanted + 1u);
	if (!detail) {
		builder->failed = 1;
		return;
	}
	va_start(args, format);
	(void)vsnprintf(detail, (size_t)wanted + 1u, format, args);
	va_end(args);

	grown = realloc(explanation->facts, (explanation->count + 1u) * sizeof(*grown));
	if (!grown) {
		free(detail);
		builder->failed = 1;
		return;
	}
	explanation->facts = grown;
	if (!fact_fill(&explanation->facts[explanation->count], topic, source, detail)) {
		builder->failed = 1;
		return;
	}
	explanation->count++;
}

/*
 * Put one fact in front of the rest.
 *
 * Only the provenance notice uses this, and it is in front for the reason
 * `explain.h` gives. Where the explanation is already full the last fact makes
 * room: the caveat is worth more than the four-hundredth address, and `total`
 * still says how many there were.
 */
static void prepend(builder_t *builder, const char *topic, const char *detail)
{
	ncfg_explanation_t  *explanation = builder->explanation;
	ncfg_explain_fact_t *grown;
	ncfg_explain_fact_t  one;
	char                *copy;

	explanation->total++;
	if (builder->failed) {
		return;
	}
	copy = format_text("%s", detail);
	if (!copy) {
		builder->failed = 1;
		return;
	}
	/* `fact_fill` owns `copy` from here, on the failing path as well. */
	if (!fact_fill(&one, topic, NULL, copy)) {
		builder->failed = 1;
		return;
	}
	if (explanation->count >= NCFG_EXPLAIN_FACTS_MAX) {
		fact_free(&explanation->facts[explanation->count - 1u]);
		explanation->count--;
	}
	grown = realloc(explanation->facts, (explanation->count + 1u) * sizeof(*grown));
	if (!grown) {
		fact_free(&one);
		builder->failed = 1;
		return;
	}
	explanation->facts = grown;
	if (explanation->count > 0u) {
		memmove(&explanation->facts[1], &explanation->facts[0],
		    explanation->count * sizeof(*explanation->facts));
	}
	explanation->facts[0] = one;
	explanation->count++;
}

/*
 * Where a field was written, into `out`, or NULL where nothing recorded it.
 *
 * Every call is counted whether or not it found anything, because "was a
 * position ever asked for" is what decides whether the notice is worth saying.
 */
static const char *location_of(builder_t *builder, char *out, size_t out_size,
    const char *path_format, ...)
{
	const ncfg_provenance_entry_t *entry;
	char                           path[PATH_MAX_TEXT];
	va_list                        args;

	builder->lookups++;
	va_start(args, path_format);
	(void)vsnprintf(path, sizeof(path), path_format, args);
	va_end(args);

	entry = ncfg_provenance_lookup(builder->provenance, path);
	if (!entry) {
		return NULL;
	}
	builder->located++;
	ncfg_provenance_location(entry, out, out_size);
	return out;
}

/* ------------------------------------------------------------------------ *
 * Small questions the model does not answer for us
 * ------------------------------------------------------------------------ */

static const ncfg_interface_t *interface_named(const ncfg_document_t *document, const char *name)
{
	size_t i;

	if (!document) {
		return NULL;
	}
	for (i = 0; i < document->interface_count; i++) {
		if (document->interfaces[i].name && strcmp(document->interfaces[i].name, name) == 0) {
			return &document->interfaces[i];
		}
	}
	return NULL;
}

static const ncfg_device_t *device_named(const ncfg_document_t *document, const char *name)
{
	size_t i;

	if (!document) {
		return NULL;
	}
	for (i = 0; i < document->device_count; i++) {
		if (document->devices[i].name && strcmp(document->devices[i].name, name) == 0) {
			return &document->devices[i];
		}
	}
	return NULL;
}

/*
 * Whether two addresses are the same address, whatever either was spelled.
 *
 * **This is where the C answers a question the Rust gets wrong**, and the
 * difference is one line. The document's addresses come through the compiler's
 * `canonical_address`, so comparing them to the kernel's spelling as text is
 * safe; a *report's* addresses do not -- `read_report` keeps them as the text
 * somebody's shell script wrote -- and the kernel reports back its own
 * spelling of whatever was installed. `2001:0DB8::1/64` in a report and
 * `2001:db8::1/64` from the kernel are one address and two strings, and the
 * Rust's `held == address` says they are different. Reproduced against the
 * shipped binary; the planner has the same comparison and pays more for it.
 *
 * A destination that is not an address -- `default` -- is handled by the text
 * comparison first, and canonicalising it fails harmlessly.
 */
static int same_address(const char *one, const char *other)
{
	char first[NCFG_ADDRESS_MAX];
	char second[NCFG_ADDRESS_MAX];

	if (!one || !other) {
		return 0;
	}
	if (strcmp(one, other) == 0) {
		return 1;
	}
	if (!ncfg_address_canonical(one, first, sizeof(first), NULL, 0)) {
		return 0;
	}
	if (!ncfg_address_canonical(other, second, sizeof(second), NULL, 0)) {
		return 0;
	}
	return strcmp(first, second) == 0;
}

/*
 * Whether netcfgd believes a report about this interface.
 *
 * **This is `netcfgd_plan::takes_reports`**, which the Rust calls from here so
 * that the explanation and the planner cannot disagree about which reports are
 * believed. This build's planner keeps the rule private -- it holds `reported`
 * addressing rather than acting on it -- so the rule is spelled here. It
 * belongs in `plan.h` beside `ncfg_plan_build`, and the second caller takes
 * this one rather than writing a third.
 */
static int takes_reports(const ncfg_document_t *document, const ncfg_interface_t *interface)
{
	const ncfg_device_t *device;
	size_t               i;

	for (i = 0; i < interface->addressing_count; i++) {
		if (interface->addressing[i].kind == NCFG_ADDRESS_SOURCE_REPORTED) {
			return 1;
		}
	}
	/* The kind comes from the device of the same name since 0155 pass 1b;
	 * absent means physical, which takes no reports. */
	device = device_named(document, interface->name);
	if (!device) {
		return 0;
	}
	return device->kind.kind == NCFG_KIND_OPENVPN || device->kind.kind == NCFG_KIND_PPPOE;
}

/* The report for an interface the document gave netcfgd a reason to believe. */
static const ncfg_observed_report_t *report_for(const ncfg_document_t *desired,
    const ncfg_observed_t *observed, const char *interface)
{
	const ncfg_interface_t *declared_interface = interface_named(desired, interface);
	size_t                  i;

	if (!declared_interface || !takes_reports(desired, declared_interface)) {
		return NULL;
	}
	for (i = 0; i < observed->report_count; i++) {
		if (observed->reports[i].interface &&
		    strcmp(observed->reports[i].interface, interface) == 0) {
			return &observed->reports[i];
		}
	}
	return NULL;
}

/* ------------------------------------------------------------------------ *
 * The facts two subjects share
 * ------------------------------------------------------------------------ */

/*
 * How ownership was decided, which decision 0002 requires to be reported.
 *
 * The two mechanisms are not equally strong, and an operator deciding whether
 * to trust a drift report needs to know which one produced it. Saying only
 * "foreign" hides that on a pre-5.18 kernel the answer is a guess from
 * recorded state.
 *
 * `about` names the address where the subject is not already one -- the Rust
 * omits it, and on an interface holding four addresses the ownership line sits
 * among four others with nothing saying which it describes -- and what it says
 * is whether netcfgd may delete that address.
 */
static void ownership_fact(builder_t *builder, const ncfg_observed_t *observed, int ownership,
    ncfg_optint_t proto, const char *about)
{
	const char *word = ncfg_ownership_name(ownership);
	const char *where = observed->address_proto_supported ? "kernel" : OWNED_FILE;
	char        mechanism[NCFG_ERROR_MAX];

	if (!word) {
		word = "unknown";
	}
	if (observed->address_proto_supported) {
		if (proto.has) {
			(void)snprintf(mechanism, sizeof(mechanism),
			    "the kernel reports IFA_PROTO %lld", (long long)proto.value);
		} else {
			(void)snprintf(mechanism, sizeof(mechanism),
			    "the kernel reports no IFA_PROTO on it");
		}
	} else {
		(void)snprintf(mechanism, sizeof(mechanism),
		    "no address here carries IFA_PROTO, so this comes from recorded state in "
		    "/run and is the weaker answer");
	}
	if (about) {
		add(builder, "ownership", where, "%s is %s: %s", about, word, mechanism);
	} else {
		add(builder, "ownership", where, "%s: %s", word, mechanism);
	}
}

/*
 * What netcfgd would do next, which is half of "why is it like this".
 *
 * An explanation that describes only the present tense leaves the reader
 * asking the obvious follow-up. Planning here is cheap -- it is a function of
 * two things already in hand -- and it is the reason an explanation is worth
 * asking for while something is still wrong.
 *
 * **A plan that could not be built is a fact rather than a failure.** The Rust
 * cannot reach this: its planner allocates through a `Vec` and cannot say no.
 * Here it can, and refusing the whole explanation over it would withhold the
 * observation half at exactly the moment somebody needs it.
 */
static void pending(builder_t *builder, const char *interface, const ncfg_document_t *desired,
    const ncfg_observed_t *observed)
{
	char         err[NCFG_ERROR_MAX];
	ncfg_plan_t *plan;
	size_t       before;
	size_t       i;

	if (!desired) {
		add(builder, "next", NULL,
		    "there is no compiled configuration, so nothing is planned");
		return;
	}
	before = builder->explanation->total;
	plan = ncfg_plan_build(desired, observed, NULL, err, sizeof(err));
	if (!plan) {
		add(builder, "next", NULL, "what happens next is not known: %s", err);
		return;
	}
	for (i = 0; i < plan->action_count; i++) {
		const ncfg_action_t *action = &plan->actions[i];
		const char          *on = ncfg_op_interface(&action->op);

		if (!on || strcmp(on, interface) != 0) {
			continue;
		}
		add(builder, "next", NULL, "%s because %s is %s and should be %s",
		    ncfg_op_name(&action->op),
		    action->reason.field ? action->reason.field : "<absent>",
		    action->reason.observed ? action->reason.observed : "<absent>",
		    action->reason.desired ? action->reason.desired : "<absent>");
	}
	for (i = 0; i < plan->refusal_count; i++) {
		const ncfg_refusal_t *refusal = &plan->refusals[i];

		if (!refusal->interface || strcmp(refusal->interface, interface) != 0) {
			continue;
		}
		add(builder, "next", NULL,
		    "%s is refused because %s depends on this interface; allow it with `%s`",
		    refusal->op ? refusal->op : "<absent>",
		    refusal->guard ? refusal->guard : "<absent>",
		    refusal->override_with ? refusal->override_with : "<absent>");
	}
	ncfg_plan_free(plan);

	if (builder->explanation->total == before) {
		add(builder, "next", NULL, "nothing; the interface matches its config");
	}
}

/* ------------------------------------------------------------------------ *
 * The interface subject
 * ------------------------------------------------------------------------ */

/* How an addressing source reads in one clause. */
static void render_source(const ncfg_address_source_t *source, char *out, size_t out_size)
{
	const char *word;

	switch (source->kind) {
	case NCFG_ADDRESS_SOURCE_STATIC:
		(void)snprintf(out, out_size, "%s",
		    source->static_address.address ? source->static_address.address : "");
		return;
	case NCFG_ADDRESS_SOURCE_DELEGATED:
		(void)snprintf(out, out_size, "a prefix delegated to %s",
		    source->delegated.prefix.source ? source->delegated.prefix.source : "");
		return;
	default:
		word = ncfg_address_source_kind_name(source->kind);
		(void)snprintf(out, out_size, "%s", word ? word : "");
		return;
	}
}

/*
 * What the configuration says about this interface.
 *
 * Split from the observation half so that neither grows past the point where a
 * reader can hold it: an explanation is a list of facts from two different
 * worlds, and the code should read that way too.
 */
static void declared(builder_t *builder, const char *name, const ncfg_interface_t *interface,
    const ncfg_document_t *document)
{
	const ncfg_device_t *device;
	char                 where[NCFG_ERROR_MAX];
	char                 rendered[NCFG_ERROR_MAX];
	const char          *policy;
	size_t               i;

	add(builder, "desired", location_of(builder, where, sizeof(where), "interfaces[%s]", name),
	    "declared in the configuration");

	/* The MTU describes the adapter and lives on the device now (0155 pass
	 * 1a). Looked up rather than dropped: `explain` exists to say where a value
	 * came from, and a value that quietly stopped being explainable would be
	 * the feature failing silently. */
	device = device_named(document, name);
	if (device && device->mtu.has) {
		add(builder, "desired",
		    location_of(builder, where, sizeof(where), "interfaces[%s].mtu", name),
		    "mtu %lld", (long long)device->mtu.value);
	}
	for (i = 0; i < interface->addressing_count; i++) {
		render_source(&interface->addressing[i], rendered, sizeof(rendered));
		add(builder, "desired",
		    location_of(builder, where, sizeof(where), "interfaces[%s].addressing[%zu]",
		        name, i),
		    "addressing[%zu] is %s", i, rendered);
	}
	if (interface->guard) {
		add(builder, "guard",
		    location_of(builder, where, sizeof(where), "interfaces[%s].guard", name),
		    "%s depends on this interface, so disruptive changes are refused",
		    interface->guard->reason ? interface->guard->reason : "");
	}
	if (interface->on_drift.has) {
		policy = ncfg_drift_policy_name((ncfg_drift_policy_t)interface->on_drift.value);
		add(builder, "drift", NULL, "on_drift is %s", policy ? policy : "unknown");
	} else {
		policy = ncfg_drift_policy_name((ncfg_drift_policy_t)document->globals.on_drift_default);
		add(builder, "drift", NULL, "on_drift is %s (from globals)",
		    policy ? policy : "unknown");
	}
}

/*
 * What netcfgd started on this interface, and whether it is still current.
 *
 * The interface's own facts come from the kernel; a backend's cannot. hostapd
 * and radvd read a file once and report almost nothing back, so what netcfgd
 * knows is what it wrote -- and decisions 0052 and 0053 turned that into three
 * answers worth surfacing here, because "why did my access point restart" is
 * the question `ncfg explain` exists for and the plan alone answers it only
 * while the restart is still pending.
 */
static void backends_on(builder_t *builder, const char *interface, const ncfg_observed_t *observed)
{
	static const char hex[] = "0123456789abcdef";
	size_t            i;

	for (i = 0; i < observed->backend_count; i++) {
		const ncfg_observed_backend_t *backend = &observed->backends[i];
		const char                    *kind;
		char                           line[NCFG_ERROR_MAX];
		size_t                         at = 0;
		size_t                         j;

		if (!backend->interface || strcmp(backend->interface, interface) != 0 ||
		    !backend->running) {
			continue;
		}
		kind = ncfg_backend_kind_name(backend->kind);
		add(builder, "backend", OWNED_FILE, "%s is running", kind ? kind : "a backend");

		if (backend->started_with) {
			const ncfg_observed_access_point_t *started = backend->started_with;
			/* Hex rather than text, for `document.h`'s reason: an SSID is 0 to
			 * 32 arbitrary octets and is not guaranteed to be text. */
			char                                ssid[NCFG_SSID_MAX_LEN * 2u + 1u];

			for (j = 0; j < started->ssid.length && j < NCFG_SSID_MAX_LEN; j++) {
				ssid[j * 2u] = hex[started->ssid.bytes[j] >> 4];
				ssid[j * 2u + 1u] = hex[started->ssid.bytes[j] & 0x0fu];
			}
			ssid[j * 2u] = '\0';

			at = (size_t)snprintf(line, sizeof(line), "started with ssid %s", ssid);
			if (at < sizeof(line) && started->channel.has) {
				at += (size_t)snprintf(line + at, sizeof(line) - at, ", channel %lld",
				    (long long)started->channel.value);
			}
			if (at < sizeof(line) && started->band) {
				(void)snprintf(line + at, sizeof(line) - at, ", %s GHz", started->band);
			}
			add(builder, "backend", NULL, "%s", line);
		}
		/* Only the answers that mean something is wrong. "Still current" is the
		 * ordinary case and would be a line every reader learns to skip, which
		 * is how the one line that matters gets skipped with it. */
		if (backend->secret_matches.has && !backend->secret_matches.value) {
			add(builder, "backend", NULL,
			    "the passphrase in the secret store is not the one it was started with, "
			    "so it will be restarted");
		}
		if (backend->config_matches.has && !backend->config_matches.value) {
			add(builder, "backend", NULL,
			    "the configuration file it was started from has changed since, so it "
			    "will be restarted");
		}
		if (backend->advertised_count > 0u) {
			at = 0;
			line[0] = '\0';
			for (j = 0; j < backend->advertised_count && at < sizeof(line); j++) {
				at += (size_t)snprintf(line + at, sizeof(line) - at, "%s%s",
				    j ? " " : "", backend->advertised[j] ? backend->advertised[j] : "");
			}
			add(builder, "backend", NULL, "advertising %s", line);
		}
	}
}

static void explain_interface(builder_t *builder, const char *name,
    const ncfg_document_t *desired, const ncfg_observed_t *observed)
{
	const ncfg_interface_t     *declared_interface = interface_named(desired, name);
	const ncfg_observed_link_t *link;
	size_t                      i;

	if (declared_interface) {
		declared(builder, name, declared_interface, desired);
	} else {
		add(builder, "desired", NULL,
		    "not mentioned in the configuration; netcfgd does not manage it");
	}

	link = ncfg_observed_link(observed, name);
	if (!link) {
		add(builder, "observed", NULL, "no such interface is present");
	} else {
		add(builder, "observed", "kernel", "%s, %s, mtu %lld", link->up ? "up" : "down",
		    link->carrier ? "carrier" : "no carrier", (long long)link->mtu);

		/* Beside carrier and before the addresses, because it answers the same
		 * question and is the harder one to guess at: a link with carrier and
		 * no routes looks like a netcfgd bug until something says a program was
		 * asked and said no. Constraint 7 -- a route that is missing because a
		 * probe exited non-zero is exactly what an operator will be staring
		 * at. */
		if (link->reachable.has) {
			const char *command = NULL;

			if (declared_interface && declared_interface->probe) {
				command = declared_interface->probe->command;
			}
			if (link->reachable.value && command) {
				add(builder, "probe", "probe", "%s says this link is reaching the network",
				    command);
			} else if (link->reachable.value) {
				add(builder, "probe", "probe", "says this link is reaching the network");
			} else if (command) {
				add(builder, "probe", "probe",
				    "%s says it is not, so this interface's routes are not installed",
				    command);
			} else {
				add(builder, "probe", "probe",
				    "says it is not, so this interface's routes are not installed");
			}
		}

		/* Before the addresses, because it is the answer to the question
		 * somebody is asking when they run this on a radio that will not
		 * associate. A blocked radio has no addresses to list, so a fact buried
		 * after them would be a fact nobody reached. */
		if (link->rfkill) {
			const char *which = link->rfkill->switch_ ? link->rfkill->switch_ : "";

			if (link->rfkill->hard) {
				add(builder, "radio", "rfkill",
				    "switched off at %s by hardware -- a physical switch, which nothing "
				    "in software can clear", which);
			} else if (link->rfkill->soft) {
				add(builder, "radio", "rfkill",
				    "switched off at %s in software -- `rfkill unblock wifi` clears it",
				    which);
			} else {
				add(builder, "radio", "rfkill", "on (%s is not blocked)", which);
			}
		}

		for (i = 0; i < observed->address_count; i++) {
			const ncfg_observed_address_t *address = &observed->addresses[i];

			if (!address->interface || strcmp(address->interface, name) != 0) {
				continue;
			}
			add(builder, "observed", "kernel", "address %s",
			    address->address ? address->address : "");
			ownership_fact(builder, observed, address->ownership, address->proto,
			    address->address);
		}
	}

	backends_on(builder, name, observed);
	pending(builder, name, desired, observed);
}

/* ------------------------------------------------------------------------ *
 * The address subject
 * ------------------------------------------------------------------------ */

/*
 * The indirection that produced an address, where one did.
 *
 * Two of the seven addressing sources name a *source* rather than a value, and
 * both used to explain as "the configuration does not ask for this address"
 * about an address netcfgd had installed itself and would withdraw itself:
 *
 *   * a **report**, whose value is in a file something else wrote (0045,
 *     0047), and
 *   * a **delegated prefix**, whose value did not exist until an ISP handed
 *     one out (0009).
 *
 * Following the indirection is the whole of what `ncfg explain` is for on
 * these two. Naming the file it ends at is the other half.
 *
 * Writes the detail and the source and answers 1, or answers 0 where neither
 * indirection produced this address.
 */
static int indirect_source(const ncfg_document_t *desired, const ncfg_observed_t *observed,
    const char *interface, const char *address, char *detail, size_t detail_size, char *source,
    size_t source_size)
{
	const ncfg_observed_report_t *report = report_for(desired, observed, interface);
	const ncfg_interface_t       *block;
	size_t                        i;

	if (report) {
		for (i = 0; i < report->address_count; i++) {
			if (!same_address(report->addresses[i], address)) {
				continue;
			}
			(void)snprintf(detail, detail_size,
			    "the configuration takes this interface's addresses from a report, and "
			    "the report names this one");
			(void)snprintf(source, source_size, "%s%s", REPORTED_DIR, interface);
			return 1;
		}
	}

	/* A delegated address is derived rather than reported, so the check is the
	 * derivation the planner performs. */
	block = interface_named(desired, interface);
	if (!block) {
		return 0;
	}
	for (i = 0; i < block->addressing_count; i++) {
		const ncfg_delegated_t  *delegated = &block->addressing[i].delegated;
		const ncfg_delegation_t *delegation;
		char                     derived[NCFG_ADDRESS_MAX];

		if (block->addressing[i].kind != NCFG_ADDRESS_SOURCE_DELEGATED) {
			continue;
		}
		delegation = ncfg_observed_delegation(observed, delegated->prefix.source);
		if (!delegation || delegated->prefix.index < 0 ||
		    (size_t)delegated->prefix.index >= delegation->prefix_count) {
			continue;
		}
		/* A malformed pair is simply not this address, so the sentence the
		 * derivation would give is dropped here. The planner is the caller
		 * that shows it, because there the same configuration is what will
		 * never produce an address at all. */
		if (!ncfg_address_from_delegation(
		        delegation->prefixes[(size_t)delegated->prefix.index],
		        delegated->prefix.subnet, delegated->suffix, derived, sizeof(derived), NULL,
		        0)) {
			continue;
		}
		if (!same_address(derived, address)) {
			continue;
		}
		(void)snprintf(detail, detail_size,
		    "the configuration builds it from `%s`, which %s was delegated as %s",
		    delegated->suffix ? delegated->suffix : "",
		    delegated->prefix.source ? delegated->prefix.source : "",
		    delegation->prefixes[(size_t)delegated->prefix.index]);
		(void)snprintf(source, source_size, "%s%s", PREFIXES_DIR,
		    delegated->prefix.source ? delegated->prefix.source : "");
		return 1;
	}
	return 0;
}

/* What netcfgd's own record says an address came from. */
static const char *origin_detail(ncfg_optint_t origin)
{
	if (!origin.has) {
		return "netcfgd has no record of installing it";
	}
	switch ((int)origin.value) {
	case NCFG_ORIGIN_STATIC:
		return "netcfgd installed it from the configuration";
	case NCFG_ORIGIN_DHCP4:
	case NCFG_ORIGIN_DHCP6:
		return "it came from a lease, so the backend owns it, not the planner";
	case NCFG_ORIGIN_SLAAC:
		return "it came from a router advertisement";
	case NCFG_ORIGIN_LINK_LOCAL:
		return "it is link-local autoconfiguration";
	case NCFG_ORIGIN_DELEGATED:
		return "it was built from a delegated prefix";
	default:
		return "netcfgd has no record of installing it";
	}
}

static void explain_address(builder_t *builder, const char *interface, const char *address,
    const ncfg_document_t *desired, const ncfg_observed_t *observed)
{
	const ncfg_interface_t *block = interface_named(desired, interface);
	char                    where[NCFG_ERROR_MAX];
	char                    detail[NCFG_ERROR_MAX];
	char                    source[NCFG_ERROR_MAX];
	size_t                  found = (size_t)-1;
	size_t                  i;

	if (block) {
		for (i = 0; i < block->addressing_count; i++) {
			if (block->addressing[i].kind == NCFG_ADDRESS_SOURCE_STATIC &&
			    same_address(block->addressing[i].static_address.address, address)) {
				found = i;
				break;
			}
		}
	}
	if (found != (size_t)-1) {
		add(builder, "desired",
		    location_of(builder, where, sizeof(where), "interfaces[%s].addressing[%zu]",
		        interface, found),
		    "the configuration asks for this address");
	} else if (indirect_source(desired, observed, interface, address, detail, sizeof(detail),
	    source, sizeof(source))) {
		/* The document names a source rather than a value, so "does not ask for
		 * it" would be wrong about an address netcfgd installed itself. */
		add(builder, "desired", source, "%s", detail);
	} else {
		add(builder, "desired", NULL, "the configuration does not ask for this address");
	}

	for (i = 0; i < observed->address_count; i++) {
		const ncfg_observed_address_t *held = &observed->addresses[i];

		if (!held->interface || strcmp(held->interface, interface) != 0 ||
		    !same_address(held->address, address)) {
			continue;
		}
		add(builder, "observed", "kernel", "present on the interface");
		ownership_fact(builder, observed, held->ownership, held->proto, NULL);
		add(builder, "origin", NULL, "%s", origin_detail(held->origin));
		if (!ncfg_ownership_may_remove(held->ownership)) {
			add(builder, "safety", NULL,
			    "netcfgd will never remove this address, because it is not recorded as "
			    "its own");
		}
		break;
	}
	if (i == observed->address_count) {
		add(builder, "observed", NULL, "not present on the interface");
	}

	pending(builder, interface, desired, observed);
}

/* ------------------------------------------------------------------------ *
 * The route subject
 * ------------------------------------------------------------------------ */

static void explain_route(builder_t *builder, const char *interface, const char *destination,
    const ncfg_document_t *desired, const ncfg_observed_t *observed)
{
	const ncfg_interface_t *block = interface_named(desired, interface);
	const ncfg_route_t     *wanted = NULL;
	char                    where[NCFG_ERROR_MAX];
	size_t                  i;

	if (block) {
		for (i = 0; i < block->route_count; i++) {
			if (same_address(block->routes[i].destination, destination)) {
				wanted = &block->routes[i];
				break;
			}
		}
	}
	if (wanted) {
		if (wanted->via) {
			add(builder, "desired",
			    location_of(builder, where, sizeof(where), "interfaces[%s].routes[%s]",
			        interface, destination),
			    "the configuration asks for it via %s", wanted->via);
		} else {
			add(builder, "desired",
			    location_of(builder, where, sizeof(where), "interfaces[%s].routes[%s]",
			        interface, destination),
			    "the configuration asks for it");
		}
	} else {
		/* Same indirection as an address: a reported gateway becomes a default
		 * route and a reported `route=` line names its own destination, and
		 * neither appears in the document. */
		const ncfg_observed_report_t *report = report_for(desired, observed, interface);
		const char                   *what = NULL;
		char                          file[NCFG_ERROR_MAX];

		if (report && strcmp(destination, "default") == 0 && report->gateway_count > 0u) {
			what = "a gateway, which becomes this default route";
		} else if (report) {
			for (i = 0; i < report->route_count; i++) {
				if (same_address(report->routes[i].destination, destination)) {
					what = "this route";
					break;
				}
			}
		}
		if (what) {
			(void)snprintf(file, sizeof(file), "%s%s", REPORTED_DIR, interface);
			add(builder, "desired", file,
			    "the configuration takes this interface's routes from a report, and the "
			    "report names %s", what);
		} else {
			add(builder, "desired", NULL, "the configuration does not ask for it");
		}
	}

	for (i = 0; i < observed->route_count; i++) {
		const ncfg_observed_route_t *held = &observed->routes[i];
		const char                  *word;

		if (!held->interface || strcmp(held->interface, interface) != 0 ||
		    !same_address(held->destination, destination)) {
			continue;
		}
		if (held->via) {
			add(builder, "observed", "kernel", "present via %s", held->via);
		} else {
			add(builder, "observed", "kernel", "present");
		}
		word = ncfg_ownership_name(held->ownership);
		if (!word) {
			word = "unknown";
		}
		/* Unlike addresses, a route's protocol comes straight from the kernel
		 * on every supported version, so this needs no fallback and no
		 * caveat. */
		if (held->proto.has && held->proto.value == NCFG_ROUTE_PROTO) {
			add(builder, "ownership", "kernel", "%s: rtm_protocol %lld is netcfgd's own tag",
			    word, (long long)held->proto.value);
		} else if (held->proto.has) {
			add(builder, "ownership", "kernel",
			    "%s: rtm_protocol %lld belongs to something else", word,
			    (long long)held->proto.value);
		} else {
			add(builder, "ownership", "kernel", "%s: no protocol tag", word);
		}
		break;
	}
	if (i == observed->route_count) {
		add(builder, "observed", NULL, "not present");
	}

	pending(builder, interface, desired, observed);
}

/* ------------------------------------------------------------------------ *
 * The entry point
 * ------------------------------------------------------------------------ */

/*
 * A subject's name as a C string, bounded.
 *
 * The Rust's `Subject` holds `String`s that came off the wire; here the bound
 * is the refusal `explain.h` promises. An embedded NUL is refused rather than
 * silently compared as the part before it: a name that stops early would match
 * an interface nobody asked about.
 */
static int take_name(ncfg_proto_str_t text, const char *what, char *out, size_t out_size,
    char *err, size_t err_size)
{
	if (!ncfg_proto_str_present(text)) {
		ncfg_error_set(err, err_size, "explain was given no %s", what);
		return 0;
	}
	if (text.length >= out_size) {
		ncfg_error_set(err, err_size,
		    "the %s is %zu bytes, and explain takes at most %zu", what, text.length,
		    out_size - 1u);
		return 0;
	}
	if (memchr(text.bytes, '\0', text.length)) {
		ncfg_error_set(err, err_size, "the %s carries a NUL, which no name does", what);
		return 0;
	}
	memcpy(out, text.bytes, text.length);
	out[text.length] = '\0';
	return 1;
}

ncfg_explanation_t *ncfg_explain(const ncfg_proto_subject_t *subject,
    const ncfg_document_t *desired, const ncfg_observed_t *observed,
    const ncfg_provenance_t *provenance, char *err, size_t err_size)
{
	builder_t           builder;
	ncfg_explanation_t *explanation;
	char                interface[NCFG_EXPLAIN_SUBJECT_MAX];
	char                second[NCFG_EXPLAIN_SUBJECT_MAX];

	if (!subject || !observed) {
		ncfg_error_set(err, err_size, "explain needs a subject and an observation");
		return NULL;
	}
	explanation = calloc(1u, sizeof(*explanation));
	if (!explanation) {
		ncfg_error_set(err, err_size, "out of memory explaining");
		return NULL;
	}
	memset(&builder, 0, sizeof(builder));
	builder.explanation = explanation;
	builder.provenance = provenance;

	switch (subject->kind) {
	case NCFG_PROTO_SUBJECT_INTERFACE:
		if (!take_name(subject->name, "interface name", interface, sizeof(interface), err,
		    err_size)) {
			free(explanation);
			return NULL;
		}
		explanation->subject = format_text("interface %s", interface);
		explain_interface(&builder, interface, desired, observed);
		break;
	case NCFG_PROTO_SUBJECT_ADDRESS:
		if (!take_name(subject->interface, "interface name", interface, sizeof(interface),
		        err, err_size) ||
		    !take_name(subject->address, "address", second, sizeof(second), err, err_size)) {
			free(explanation);
			return NULL;
		}
		explanation->subject = format_text("address %s on %s", second, interface);
		explain_address(&builder, interface, second, desired, observed);
		break;
	case NCFG_PROTO_SUBJECT_ROUTE:
		if (!take_name(subject->interface, "interface name", interface, sizeof(interface),
		        err, err_size) ||
		    !take_name(subject->destination, "destination", second, sizeof(second), err,
		        err_size)) {
			free(explanation);
			return NULL;
		}
		explanation->subject = format_text("route %s on %s", second, interface);
		explain_route(&builder, interface, second, desired, observed);
		break;
	default:
		ncfg_error_set(err, err_size,
		    "explain takes an interface, an address or a route, and %d is none of them",
		    (int)subject->kind);
		free(explanation);
		return NULL;
	}

	/*
	 * What this build cannot answer, said rather than left to be noticed.
	 *
	 * See `explain.h`: the compiler records no positions here, so every lookup
	 * missed, and an answer that silently stops naming files is one a reader
	 * cannot tell from a configuration with nothing to name.
	 */
	if (builder.lookups > 0u && builder.located == 0u &&
	    (!provenance || provenance->count == 0u)) {
		prepend(&builder, "provenance",
		    "this build's compiler records no file positions, so no fact below names the "
		    "file and line it was written in");
	}

	if (!explanation->subject || builder.failed) {
		ncfg_explanation_free(explanation);
		ncfg_error_set(err, err_size, "out of memory explaining");
		return NULL;
	}
	return explanation;
}

void ncfg_explanation_free(ncfg_explanation_t *explanation)
{
	size_t i;

	if (!explanation) {
		return;
	}
	for (i = 0; i < explanation->count; i++) {
		fact_free(&explanation->facts[i]);
	}
	free(explanation->facts);
	free(explanation->subject);
	free(explanation);
}

int ncfg_explanation_render(const ncfg_explanation_t *explanation, ncfg_buf_t *out, char *err,
    size_t err_size)
{
	size_t i;

	if (!explanation || !out) {
		ncfg_error_set(err, err_size, "there is nothing to render");
		return 0;
	}
	ncfg_buf_addf(out, "%s\n", explanation->subject ? explanation->subject : "");
	for (i = 0; i < explanation->count; i++) {
		const ncfg_explain_fact_t *fact = &explanation->facts[i];

		if (fact->source) {
			ncfg_buf_addf(out, "  %-9s %s   [%s]\n", fact->topic, fact->detail,
			    fact->source);
		} else {
			ncfg_buf_addf(out, "  %-9s %s\n", fact->topic, fact->detail);
		}
	}
	/* The parser's arrangement: a reader shown "40 of 900" is shown more than
	 * one shown nine hundred nobody scrolls through. */
	if (explanation->total > explanation->count) {
		ncfg_buf_addf(out, "  %-9s showing %zu of %zu facts\n", "note", explanation->count,
		    explanation->total);
	}
	if (ncfg_buf_failed(out)) {
		ncfg_error_set(err, err_size, "the explanation did not fit in the buffer");
		return 0;
	}
	return 1;
}
