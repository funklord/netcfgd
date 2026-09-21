/*
 * explain_test.c -- what `ncfg explain` answers, and what it says it cannot.
 *
 * WHAT THESE CASES ARE FOR
 *   Eleven of them are the Rust's own, kept with the sentence that says which
 *   defect each is about -- six of those name an address or a route netcfgd
 *   installed itself and once explained as "the configuration does not ask for
 *   this". The rest are this port's:
 *
 *     * **The provenance notice**, which is the whole of 0263's answer to a
 *       command whose subject is where a value came from. It appears exactly
 *       where every lookup missed and the table is empty, it names no file and
 *       no line, and it is *gone* the moment a table with an entry is handed
 *       in -- which is what stops it becoming a line nobody reads. The third
 *       case is the one that matters: an interface the configuration never
 *       mentions asks for no position, so it gets no caveat either. The
 *       fourth runs the compiler: the other three build a table by hand and
 *       so say nothing about whether anything produces one keyed the way this
 *       module asks, which is the seam where a full table and a silent notice
 *       could still name no file at all.
 *     * **A report spelled another way still explains.** The Rust compares the
 *       report's text against the kernel's spelling of it, and the two are one
 *       address written twice. The planner has the same comparison and pays
 *       more for it.
 *     * **The ownership of the second address is about the second address.**
 *       The Rust emits the ownership line before the address it describes and
 *       does not name it, so on any interface with two the reader attaches it
 *       to the wrong one.
 *     * **The bound and the refusals**, which are C's and not the Rust's: an
 *       explanation is bounded and a subject's names are, and neither
 *       truncates silently.
 *     * **The rendered lines**, byte for byte. The output is the product.
 *
 * NOTHING OUTSIDE ITS OWN MEMORY
 *   Every fixture here is JSON read through the model's own readers, so the
 *   test touches no file, no socket and no kernel, and the daemon this is a
 *   port of goes on running on this machine undisturbed.
 */
#include "ncfg/base.h"
#include "ncfg/buf.h"
#include "ncfg/document.h"
#include "ncfg/explain.h"
#include "ncfg/lower.h"
#include "ncfg/observed.h"
#include "ncfg/parse.h"
#include "ncfg/proto.h"
#include "ncfg/state.h"

#include <stdio.h>
#include <stdlib.h>
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

/* ------------------------------------------------------------------------ *
 * Fixtures
 * ------------------------------------------------------------------------ */

static ncfg_document_t *document_of(const char *body)
{
	char             text[8192];
	char             message[NCFG_ERROR_MAX];
	ncfg_document_t *document;

	(void)snprintf(text, sizeof(text),
	    "{\"schema_version\":{\"major\":1,\"minor\":1},\"generated_by\":\"explain_test\","
	    "\"globals\":{},\"networks\":[],%s}",
	    body);
	message[0] = '\0';
	document = ncfg_document_read(text, strlen(text), message, sizeof(message));
	if (!document) {
		printf("  fixture document did not read: %s\n", message);
	}
	return document;
}

static ncfg_observed_t *observed_of(const char *body)
{
	char             text[65536];
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

/* A link that is up with a cable in it, which is what a working one looks
 * like. */
#define LINK_UP(name) \
	"{\"name\":\"" name "\",\"index\":2,\"mtu\":1500,\"up\":true,\"carrier\":true," \
	"\"ownership\":\"unknown\"}"

static ncfg_proto_subject_t about_interface(const char *name)
{
	ncfg_proto_subject_t subject;

	memset(&subject, 0, sizeof(subject));
	subject.kind = NCFG_PROTO_SUBJECT_INTERFACE;
	subject.name = ncfg_proto_str(name);
	return subject;
}

static ncfg_proto_subject_t about_address(const char *interface, const char *address)
{
	ncfg_proto_subject_t subject;

	memset(&subject, 0, sizeof(subject));
	subject.kind = NCFG_PROTO_SUBJECT_ADDRESS;
	subject.interface = ncfg_proto_str(interface);
	subject.address = ncfg_proto_str(address);
	return subject;
}

static ncfg_proto_subject_t about_route(const char *interface, const char *destination)
{
	ncfg_proto_subject_t subject;

	memset(&subject, 0, sizeof(subject));
	subject.kind = NCFG_PROTO_SUBJECT_ROUTE;
	subject.interface = ncfg_proto_str(interface);
	subject.destination = ncfg_proto_str(destination);
	return subject;
}

/*
 * Every detail on one topic, joined, which is the Rust's own `detail` helper.
 *
 * Joined rather than indexed because an explanation's fact order is checked by
 * the rendering case and asserted nowhere else: a case about what is said
 * should not fail because something true was said before it.
 */
static const char *detail_of(const ncfg_explanation_t *explanation, const char *topic)
{
	static char joined[8192];
	size_t      at = 0;
	size_t      i;

	joined[0] = '\0';
	for (i = 0; i < explanation->count; i++) {
		if (strcmp(explanation->facts[i].topic, topic) != 0) {
			continue;
		}
		at += (size_t)snprintf(joined + at, sizeof(joined) - at, "%s%s", at ? " | " : "",
		    explanation->facts[i].detail);
		if (at >= sizeof(joined)) {
			break;
		}
	}
	return joined;
}

static int names_source(const ncfg_explanation_t *explanation, const char *source)
{
	size_t i;

	for (i = 0; i < explanation->count; i++) {
		if (explanation->facts[i].source &&
		    strcmp(explanation->facts[i].source, source) == 0) {
			return 1;
		}
	}
	return 0;
}

static int has_topic(const ncfg_explanation_t *explanation, const char *topic)
{
	size_t i;

	for (i = 0; i < explanation->count; i++) {
		if (strcmp(explanation->facts[i].topic, topic) == 0) {
			return 1;
		}
	}
	return 0;
}

/* Says what it got when a check about wording fails, which is the difference
 * between a red line and a red line somebody can act on. */
static int says(const ncfg_explanation_t *explanation, const char *topic, const char *wanted)
{
	const char *got = detail_of(explanation, topic);

	if (strstr(got, wanted)) {
		return 1;
	}
	printf("  %s said: %s\n", topic, got);
	return 0;
}

/* ------------------------------------------------------------------------ *
 * The Rust's own cases
 * ------------------------------------------------------------------------ */

#define ETH0_STATIC \
	"\"devices\":[{\"name\":\"eth0\",\"kind\":{\"kind\":\"physical\"}}]," \
	"\"interfaces\":[{\"name\":\"eth0\"," \
	"\"addressing\":[{\"source\":\"static\",\"address\":\"10.0.0.1/24\"}]}]"

static void an_address_we_installed_says_so_and_says_how_we_know(void)
{
	ncfg_document_t     *document = document_of(ETH0_STATIC);
	ncfg_observed_t     *observed = observed_of("\"links\":[" LINK_UP("eth0") "],"
	    "\"addresses\":[{\"interface\":\"eth0\",\"address\":\"10.0.0.1/24\",\"proto\":110,"
	    "\"ownership\":\"ours\",\"origin\":\"static\"}],\"address_proto_supported\":true");
	ncfg_proto_subject_t subject = about_address("eth0", "10.0.0.1/24");
	char                 message[NCFG_ERROR_MAX];
	ncfg_explanation_t  *explanation;

	explanation = ncfg_explain(&subject, document, observed, NULL, message, sizeof(message));
	check(explanation != NULL, "an address netcfgd installed explains");
	if (explanation) {
		check(says(explanation, "ownership", "IFA_PROTO"),
		    "and says how ownership was decided");
		check(says(explanation, "origin", "from the configuration"),
		    "and that netcfgd installed it from the configuration");
	} else {
		check(0, "and says how ownership was decided");
	}
	ncfg_explanation_free(explanation);
	ncfg_document_free(document);
	ncfg_observed_free(observed);
}

/*
 * Decision 0002 requires `explain` to say which mechanism produced the
 * ownership answer, because the fallback is weaker and an operator deciding
 * whether to trust a drift report needs to know.
 */
static void the_weaker_mechanism_is_named_as_weaker(void)
{
	ncfg_document_t     *document = document_of(ETH0_STATIC);
	ncfg_observed_t     *observed = observed_of("\"links\":[" LINK_UP("eth0") "],"
	    "\"addresses\":[{\"interface\":\"eth0\",\"address\":\"10.0.0.1/24\","
	    "\"ownership\":\"unknown\",\"origin\":\"static\"}]");
	ncfg_proto_subject_t subject = about_address("eth0", "10.0.0.1/24");
	char                 message[NCFG_ERROR_MAX];
	ncfg_explanation_t  *explanation;

	explanation = ncfg_explain(&subject, document, observed, NULL, message, sizeof(message));
	if (explanation) {
		check(says(explanation, "ownership", "recorded state"),
		    "the weaker mechanism says it came from recorded state");
		check(says(explanation, "ownership", "weaker"), "and says in as many words that it is");
		/* And it must say netcfgd will not remove it, which is the consequence
		 * the operator actually cares about. */
		check(says(explanation, "safety", "never remove"),
		    "and that netcfgd will never remove the address");
	} else {
		check(0, "the weaker mechanism says it came from recorded state");
	}
	ncfg_explanation_free(explanation);
	ncfg_document_free(document);
	ncfg_observed_free(observed);
}

/*
 * Decision 0006 rule 7 in words: a lease's address belongs to the backend, and
 * explaining it any other way invites somebody to delete it.
 */
static void a_lease_address_says_the_backend_owns_it(void)
{
	ncfg_document_t     *document = document_of(ETH0_STATIC);
	ncfg_observed_t     *observed = observed_of("\"links\":[" LINK_UP("eth0") "],"
	    "\"addresses\":[{\"interface\":\"eth0\",\"address\":\"10.0.0.1/24\",\"proto\":110,"
	    "\"ownership\":\"ours\",\"origin\":\"dhcp4\"}],\"address_proto_supported\":true");
	ncfg_proto_subject_t subject = about_address("eth0", "10.0.0.1/24");
	char                 message[NCFG_ERROR_MAX];
	ncfg_explanation_t  *explanation;

	explanation = ncfg_explain(&subject, document, observed, NULL, message, sizeof(message));
	if (explanation) {
		check(says(explanation, "origin", "backend owns it"),
		    "a lease's address says the backend owns it, not the planner");
	} else {
		check(0, "a lease's address says the backend owns it, not the planner");
	}
	ncfg_explanation_free(explanation);
	ncfg_document_free(document);
	ncfg_observed_free(observed);
}

/*
 * The other of the two sources the document names by reference rather than by
 * value (decision 0009). It explained as "the configuration does not ask for
 * this address" about an address netcfgd derived itself -- and the answer an
 * operator wants is which delegation it came from, because that is where the
 * next question goes.
 */
static void a_delegated_address_names_the_delegation_it_came_from(void)
{
	ncfg_document_t     *document = document_of(
	    "\"devices\":[{\"name\":\"lan0\",\"kind\":{\"kind\":\"physical\"}}],"
	    "\"interfaces\":[{\"name\":\"lan0\",\"addressing\":[{\"source\":\"delegated\","
	    "\"prefix\":{\"source\":\"wan0\",\"index\":0,\"subnet\":0},\"suffix\":\"::1/64\"}]}]");
	ncfg_observed_t     *observed = observed_of(
	    "\"addresses\":[{\"interface\":\"lan0\",\"address\":\"2001:db8:1234::1/64\","
	    "\"proto\":110,\"ownership\":\"ours\",\"origin\":\"delegated\"}],"
	    "\"delegations\":[{\"interface\":\"wan0\",\"prefixes\":[\"2001:db8:1234::/56\"]}],"
	    "\"address_proto_supported\":true");
	ncfg_proto_subject_t subject = about_address("lan0", "2001:db8:1234::1/64");
	char                 message[NCFG_ERROR_MAX];
	ncfg_explanation_t  *explanation;

	explanation = ncfg_explain(&subject, document, observed, NULL, message, sizeof(message));
	if (explanation) {
		check(says(explanation, "desired", "2001:db8:1234::/56"),
		    "a delegated address names the prefix it was built from");
		check(says(explanation, "desired", "wan0"), "and the interface that was delegated it");
		check(names_source(explanation, "/run/netcfgd/prefixes/wan0"),
		    "and the file the prefix arrived in");
	} else {
		check(0, "a delegated address names the prefix it was built from");
	}
	ncfg_explanation_free(explanation);
	ncfg_document_free(document);
	ncfg_observed_free(observed);
}

/*
 * An access point that is about to be restarted says why, and says it where
 * somebody asking about the interface will see it.
 *
 * The plan answers this too, and only while the restart is pending. What an
 * operator asks after the fact is "what is this thing running", and hostapd
 * cannot be asked -- so netcfgd's own record is the answer (0052, 0053).
 */
static void a_stale_backend_says_so_on_the_interface(void)
{
	ncfg_document_t     *document = document_of(
	    "\"devices\":[{\"name\":\"wlan0\",\"kind\":{\"kind\":\"physical\"}}],"
	    "\"interfaces\":[{\"name\":\"wlan0\",\"addressing\":[{\"source\":\"static\","
	    "\"address\":\"10.0.0.1/24\"}]}]");
	ncfg_observed_t     *observed = observed_of(
	    "\"backends\":[{\"kind\":\"access_point\",\"interface\":\"wlan0\",\"running\":true,"
	    "\"started_with\":{\"ssid\":\"686f6d65\",\"channel\":6},\"secret_matches\":false}]");
	ncfg_proto_subject_t subject = about_interface("wlan0");
	char                 message[NCFG_ERROR_MAX];
	ncfg_explanation_t  *explanation;

	explanation = ncfg_explain(&subject, document, observed, NULL, message, sizeof(message));
	if (explanation) {
		check(says(explanation, "backend", "686f6d65"),
		    "a running access point says which ssid it was started with");
		check(says(explanation, "backend", "channel 6"), "and on which channel");
		check(says(explanation, "backend", "passphrase"),
		    "and that a changed passphrase will restart it");
	} else {
		check(0, "a running access point says which ssid it was started with");
	}
	ncfg_explanation_free(explanation);
	ncfg_document_free(document);
	ncfg_observed_free(observed);
}

#define WWAN0_REPORTED \
	"\"devices\":[{\"name\":\"wwan0\",\"kind\":{\"kind\":\"physical\"}}]," \
	"\"interfaces\":[{\"name\":\"wwan0\",\"addressing\":[{\"source\":\"reported\"}]}]"

/* Every member of a report is required by the reader -- an absent list and an
 * empty one are the same answer, and the model refuses rather than guessing
 * which was meant -- so a fixture names all five. */
#define REPORT(interface, addresses, gateways, routes) \
	"\"reports\":[{\"interface\":\"" interface "\",\"addresses\":" addresses \
	",\"gateways\":" gateways ",\"nameservers\":[],\"search\":[],\"routes\":" routes "}]"

/*
 * It used to answer "the configuration does not ask for this address" about an
 * address netcfgd had installed itself and would withdraw itself, because the
 * document names a source rather than a value and the explanation only looked
 * for values.
 */
static void a_reported_address_says_where_the_value_came_from(void)
{
	ncfg_document_t     *document = document_of(WWAN0_REPORTED);
	ncfg_observed_t     *observed = observed_of(
	    "\"addresses\":[{\"interface\":\"wwan0\",\"address\":\"10.64.1.23/30\",\"proto\":110,"
	    "\"ownership\":\"ours\"}],"
	    REPORT("wwan0", "[\"10.64.1.23/30\"]", "[\"10.64.1.24\"]", "[]")
	    ",\"address_proto_supported\":true");
	ncfg_proto_subject_t subject = about_address("wwan0", "10.64.1.23/30");
	char                 message[NCFG_ERROR_MAX];
	ncfg_explanation_t  *explanation;

	explanation = ncfg_explain(&subject, document, observed, NULL, message, sizeof(message));
	if (explanation) {
		check(says(explanation, "desired", "from a report"),
		    "a reported address says the value came from a report");
		check(names_source(explanation, "/run/netcfgd/reported/wwan0"),
		    "and names the file it came from");
	} else {
		check(0, "a reported address says the value came from a report");
	}
	ncfg_explanation_free(explanation);
	ncfg_document_free(document);
	ncfg_observed_free(observed);
}

/* And so does the default route a reported gateway implies. */
static void a_reported_gateway_explains_the_default_route_it_implies(void)
{
	ncfg_document_t     *document = document_of(WWAN0_REPORTED);
	ncfg_observed_t     *observed = observed_of(
	    REPORT("wwan0", "[]", "[\"10.64.1.24\"]", "[]"));
	ncfg_proto_subject_t subject = about_route("wwan0", "default");
	char                 message[NCFG_ERROR_MAX];
	ncfg_explanation_t  *explanation;

	explanation = ncfg_explain(&subject, document, observed, NULL, message, sizeof(message));
	if (explanation) {
		check(says(explanation, "desired", "a gateway"),
		    "a reported gateway explains the default route it implies");
	} else {
		check(0, "a reported gateway explains the default route it implies");
	}
	ncfg_explanation_free(explanation);
	ncfg_document_free(document);
	ncfg_observed_free(observed);
}

/*
 * A report for an interface the document says nothing about is still not an
 * answer. The explanation follows the planner's gate rather than the existence
 * of a file, or it would explain routes netcfgd never installed.
 */
static void a_report_the_document_never_asked_for_explains_nothing(void)
{
	ncfg_document_t     *document = document_of(
	    "\"devices\":[{\"name\":\"wwan0\",\"kind\":{\"kind\":\"physical\"}}],"
	    "\"interfaces\":[{\"name\":\"wwan0\",\"addressing\":[{\"source\":\"static\","
	    "\"address\":\"10.0.0.1/24\"}]}]");
	ncfg_observed_t     *observed = observed_of(
	    REPORT("wwan0", "[]", "[\"10.64.1.24\"]", "[]"));
	ncfg_proto_subject_t subject = about_route("wwan0", "default");
	char                 message[NCFG_ERROR_MAX];
	ncfg_explanation_t  *explanation;

	explanation = ncfg_explain(&subject, document, observed, NULL, message, sizeof(message));
	if (explanation) {
		check(says(explanation, "desired", "does not ask"),
		    "a report the document never asked for explains nothing");
	} else {
		check(0, "a report the document never asked for explains nothing");
	}
	ncfg_explanation_free(explanation);
	ncfg_document_free(document);
	ncfg_observed_free(observed);
}

/*
 * A guard is the reason a change is not happening, so explaining an interface
 * has to mention both the guard and the refusal it causes.
 */
static void a_guarded_interface_explains_what_is_blocked_and_how_to_allow_it(void)
{
	ncfg_document_t     *document = document_of(
	    "\"devices\":[{\"name\":\"eth0\",\"kind\":{\"kind\":\"physical\"}}],"
	    "\"interfaces\":[{\"name\":\"eth0\",\"addressing\":[{\"source\":\"static\","
	    "\"address\":\"10.0.0.1/24\"}],\"guard\":{\"reason\":\"nfs root\"}}]");
	/* An address netcfgd owns that the config no longer wants: teardown would
	 * remove it, and the guard refuses. */
	ncfg_observed_t     *observed = observed_of("\"links\":[" LINK_UP("eth0") "],"
	    "\"addresses\":[{\"interface\":\"eth0\",\"address\":\"10.0.0.1/24\",\"proto\":110,"
	    "\"ownership\":\"ours\",\"origin\":\"static\"},"
	    "{\"interface\":\"eth0\",\"address\":\"10.0.0.99/24\",\"proto\":110,"
	    "\"ownership\":\"ours\",\"origin\":\"static\"}],\"address_proto_supported\":true");
	ncfg_proto_subject_t subject = about_interface("eth0");
	char                 message[NCFG_ERROR_MAX];
	ncfg_explanation_t  *explanation;

	explanation = ncfg_explain(&subject, document, observed, NULL, message, sizeof(message));
	if (explanation) {
		check(says(explanation, "guard", "nfs root"), "a guarded interface names its guard");
		check(says(explanation, "next", "refused"), "and says what is refused because of it");
		check(says(explanation, "next", "--allow-disruption"),
		    "and the exact invocation that consents to it");
	} else {
		check(0, "a guarded interface names its guard");
	}
	ncfg_explanation_free(explanation);
	ncfg_document_free(document);
	ncfg_observed_free(observed);
}

/*
 * An interface netcfgd does not manage should say so plainly, rather than
 * producing an explanation that reads like it is managed and idle.
 */
static void an_unmanaged_interface_says_it_is_unmanaged(void)
{
	ncfg_document_t     *document = document_of("\"devices\":[],\"interfaces\":[]");
	ncfg_observed_t     *observed = observed_of("\"links\":[" LINK_UP("eth0") "]");
	ncfg_proto_subject_t subject = about_interface("eth0");
	char                 message[NCFG_ERROR_MAX];
	ncfg_explanation_t  *explanation;

	explanation = ncfg_explain(&subject, document, observed, NULL, message, sizeof(message));
	if (explanation) {
		check(says(explanation, "desired", "does not manage it"),
		    "an interface nothing configures says it is unmanaged");
		/* Nothing was looked up, so there is nothing for the notice to be
		 * about. A caveat that fires on every explanation is a caveat nobody
		 * reads by the third one. */
		check(!has_topic(explanation, "provenance"),
		    "and asks for no position, so it carries no provenance notice");
	} else {
		check(0, "an interface nothing configures says it is unmanaged");
	}
	ncfg_explanation_free(explanation);
	ncfg_document_free(document);
	ncfg_observed_free(observed);
}

/*
 * Explaining without a compiled configuration must still work, because the
 * moment somebody reaches for `explain` is often the moment the config has
 * stopped compiling.
 */
static void explaining_without_a_configuration_still_answers(void)
{
	ncfg_observed_t     *observed = observed_of("\"links\":[" LINK_UP("eth0") "],"
	    "\"addresses\":[{\"interface\":\"eth0\",\"address\":\"10.0.0.1/24\",\"proto\":110,"
	    "\"ownership\":\"ours\",\"origin\":\"static\"}],\"address_proto_supported\":true");
	ncfg_proto_subject_t subject = about_interface("eth0");
	char                 message[NCFG_ERROR_MAX];
	ncfg_explanation_t  *explanation;

	explanation = ncfg_explain(&subject, NULL, observed, NULL, message, sizeof(message));
	if (explanation) {
		check(explanation->count > 0u, "explaining without a configuration still answers");
		check(says(explanation, "next", "no compiled configuration"),
		    "and says that nothing is planned because there is none");
	} else {
		check(0, "explaining without a configuration still answers");
	}
	ncfg_explanation_free(explanation);
	ncfg_observed_free(observed);
}

/* ------------------------------------------------------------------------ *
 * What this build cannot answer, and says so
 * ------------------------------------------------------------------------ */

static void an_empty_table_is_said_rather_than_left_to_be_noticed(void)
{
	ncfg_document_t     *document = document_of(ETH0_STATIC);
	ncfg_observed_t     *observed = observed_of("\"links\":[" LINK_UP("eth0") "]");
	ncfg_proto_subject_t subject = about_interface("eth0");
	ncfg_provenance_t    empty;
	char                 message[NCFG_ERROR_MAX];
	ncfg_explanation_t  *explanation;

	memset(&empty, 0, sizeof(empty));
	explanation = ncfg_explain(&subject, document, observed, &empty, message, sizeof(message));
	if (explanation) {
		check(says(explanation, "provenance", "table of file positions"),
		    "an explanation that could locate nothing says so");
		check(explanation->count > 0u &&
		    strcmp(explanation->facts[0].topic, "provenance") == 0,
		    "and says it first, before the answer it is a caveat about");
		check(!names_source(explanation, "10-lan.conf:4:2"),
		    "and invents no file and no line to put in its place");
	} else {
		check(0, "an explanation that could locate nothing says so");
	}
	ncfg_explanation_free(explanation);

	/* And a NULL table reads exactly as an empty one, because a caller with
	 * nothing to hand in and a caller handing in nothing are the same caller. */
	explanation = ncfg_explain(&subject, document, observed, NULL, message, sizeof(message));
	check(explanation != NULL && has_topic(explanation, "provenance"),
	    "a table that is not there reads as one with nothing in it");
	ncfg_explanation_free(explanation);

	ncfg_document_free(document);
	ncfg_observed_free(observed);
}

/*
 * And the day a compiler fills one in, the answer is the file and the line and
 * the notice is gone.
 *
 * This is the case that makes the notice honest rather than permanent: nothing
 * about `explain` has to change when lowering starts recording, and this check
 * is what says so.
 */
static void a_table_with_an_entry_names_the_file_and_the_line(void)
{
	ncfg_document_t     *document = document_of(ETH0_STATIC);
	ncfg_observed_t     *observed = observed_of("\"links\":[" LINK_UP("eth0") "]");
	ncfg_proto_subject_t subject = about_interface("eth0");
	ncfg_provenance_t    provenance;
	char                 message[NCFG_ERROR_MAX];
	ncfg_explanation_t  *explanation;

	memset(&provenance, 0, sizeof(provenance));
	check(ncfg_provenance_record(&provenance, "interfaces[eth0]",
	    "/etc/netcfgd/conf.d/10-lan.conf", 4, 2, message, sizeof(message)),
	    "a position can be recorded for an interface");

	explanation = ncfg_explain(&subject, document, observed, &provenance, message,
	    sizeof(message));
	if (explanation) {
		check(names_source(explanation, "/etc/netcfgd/conf.d/10-lan.conf:4:2"),
		    "and the explanation names the file, the line and the column");
		check(!has_topic(explanation, "provenance"),
		    "and says nothing about a table it was given");
	} else {
		check(0, "and the explanation names the file, the line and the column");
	}
	ncfg_explanation_free(explanation);
	ncfg_provenance_free(&provenance);
	ncfg_document_free(document);
	ncfg_observed_free(observed);
}

/*
 * And the compiler that fills one in, against the same explanation.
 *
 * The two cases above hand in a table built by hand, which proves what
 * `explain` does with one and nothing about whether anything produces one it
 * can read. **A table keyed differently is worse than no table**: every lookup
 * misses while the table is non-empty, so the notice is correctly silent and
 * the answer names no file -- the exact failure both halves were written to
 * prevent, arriving through the seam between them.
 *
 * So this compiles real text through `ncfg_compile_with_provenance` and
 * explains against what came out. It is the only case here that runs the
 * compiler, and it runs it on a string: no file, no socket, no kernel.
 */
static ncfg_document_t *compiled_of(const char *text, ncfg_provenance_t *provenance)
{
	ncfg_source_t      source;
	ncfg_ast_file_t   *tree = NULL;
	ncfg_diags_t       parse_diags = { 0 };
	ncfg_lower_diags_t diags = { 0 };
	ncfg_document_t   *document;
	char               message[NCFG_ERROR_MAX];

	if (!ncfg_parse(text, strlen(text), &tree, &parse_diags, message, sizeof(message))) {
		printf("  fixture did not parse: %s\n", message);
		ncfg_diags_free(&parse_diags);
		return NULL;
	}
	ncfg_diags_free(&parse_diags);
	source.name = "/etc/netcfgd/conf.d/10-lan.conf";
	source.file = tree;
	document = ncfg_compile_with_provenance(&source, 1u, ncfg_hook_sink_refusing(), provenance,
	    &diags, message, sizeof(message));
	if (!document) {
		printf("  fixture did not compile: %s\n", message);
	}
	ncfg_lower_diags_free(&diags);
	/* The document copies every string it keeps, so the tree has no reader
	 * left once the compile is over. */
	ncfg_ast_file_free(tree);
	return document;
}

static void the_compilers_own_table_is_the_one_explain_reads(void)
{
	static const char *const text = "device eth0 {\n"
	                                "\tmtu = 1400\n"
	                                "}\n"
	                                "interface eth0 {\n"
	                                "\tconfig = \"10.0.0.1/24\"\n"
	                                "\tguard = \"the office link\"\n"
	                                "}\n";
	ncfg_provenance_t    provenance;
	ncfg_provenance_t    empty;
	ncfg_document_t     *document;
	ncfg_observed_t     *observed = observed_of("\"links\":[" LINK_UP("eth0") "]");
	ncfg_proto_subject_t subject = about_interface("eth0");
	char                 message[NCFG_ERROR_MAX];
	ncfg_explanation_t  *explanation;

	memset(&provenance, 0, sizeof(provenance));
	memset(&empty, 0, sizeof(empty));
	document = compiled_of(text, &provenance);
	if (!document) {
		check(0, "a configuration compiles with the positions beside it");
		ncfg_provenance_free(&provenance);
		ncfg_observed_free(observed);
		return;
	}
	check(provenance.count > 0u, "a configuration compiles with the positions beside it");

	explanation = ncfg_explain(&subject, document, observed, &provenance, message,
	    sizeof(message));
	if (explanation) {
		/* One per key `declared` builds, and each is the line somebody wrote
		 * rather than the top of the block: the interface, the MTU that moved
		 * to the device, the addressing entry and the guard. */
		check(names_source(explanation, "/etc/netcfgd/conf.d/10-lan.conf:4:1"),
		    "the compiler's own table locates the interface block");
		check(names_source(explanation, "/etc/netcfgd/conf.d/10-lan.conf:2:2"),
		    "  and the mtu, which is written in the device block");
		check(names_source(explanation, "/etc/netcfgd/conf.d/10-lan.conf:5:11"),
		    "  and the addressing entry, by the position of the entry");
		check(names_source(explanation, "/etc/netcfgd/conf.d/10-lan.conf:6:2"),
		    "  and the guard");
		check(!has_topic(explanation, "provenance"),
		    "and the notice is gone, because this build's compiler does record them");
	} else {
		check(0, "the compiler's own table locates the interface block");
	}
	ncfg_explanation_free(explanation);

	/*
	 * And the other direction, against the same document: a caller with no
	 * table still gets the caveat. This is what stops the notice from being
	 * deleted along with the reason it was written -- it has to go on
	 * appearing for an explanation that genuinely cannot locate anything.
	 */
	explanation = ncfg_explain(&subject, document, observed, &empty, message, sizeof(message));
	if (explanation) {
		check(says(explanation, "provenance", "table of file positions"),
		    "and the same document with no table still says it can locate nothing");
		check(!names_source(explanation, "/etc/netcfgd/conf.d/10-lan.conf:4:1"),
		    "  and names no file, having been given none");
	} else {
		check(0, "and the same document with no table still says it can locate nothing");
	}
	ncfg_explanation_free(explanation);

	ncfg_provenance_free(&provenance);
	ncfg_document_free(document);
	ncfg_observed_free(observed);
}

/* ------------------------------------------------------------------------ *
 * Where the C answers something the Rust gets wrong
 * ------------------------------------------------------------------------ */

/*
 * A report's addresses are the text somebody's shell script wrote and are
 * never canonicalised; the kernel reports back its own spelling of whatever
 * was installed. `2001:0DB8:...` and `2001:db8:...` are one address written
 * twice, and comparing them as text answers "the configuration does not ask
 * for this address" about an address netcfgd installed itself.
 */
static void a_report_spelled_another_way_is_still_the_same_address(void)
{
	ncfg_document_t     *document = document_of(WWAN0_REPORTED);
	ncfg_observed_t     *observed = observed_of(
	    "\"addresses\":[{\"interface\":\"wwan0\",\"address\":\"2001:db8::1/64\","
	    "\"proto\":110,\"ownership\":\"ours\"}],"
	    REPORT("wwan0", "[\"2001:0DB8:0:0::1/64\"]", "[]", "[]")
	    ",\"address_proto_supported\":true");
	ncfg_proto_subject_t subject = about_address("wwan0", "2001:db8::1/64");
	char                 message[NCFG_ERROR_MAX];
	ncfg_explanation_t  *explanation;

	explanation = ncfg_explain(&subject, document, observed, NULL, message, sizeof(message));
	if (explanation) {
		check(says(explanation, "desired", "from a report"),
		    "a report spelled another way still explains the address it named");
	} else {
		check(0, "a report spelled another way still explains the address it named");
	}
	ncfg_explanation_free(explanation);
	ncfg_document_free(document);
	ncfg_observed_free(observed);
}

/*
 * The Rust pushes the ownership fact *before* the address it describes and
 * names no address in it, so on an interface holding two the reader attaches
 * each answer to the line above it -- which is the other address, and the
 * opposite answer about whether netcfgd may remove it.
 */
static void the_ownership_of_the_second_address_is_about_the_second_address(void)
{
	ncfg_document_t     *document = document_of(ETH0_STATIC);
	ncfg_observed_t     *observed = observed_of("\"links\":[" LINK_UP("eth0") "],"
	    "\"addresses\":[{\"interface\":\"eth0\",\"address\":\"10.0.0.1/24\",\"proto\":110,"
	    "\"ownership\":\"ours\",\"origin\":\"static\"},"
	    "{\"interface\":\"eth0\",\"address\":\"192.168.9.5/24\",\"ownership\":\"foreign\"}],"
	    "\"address_proto_supported\":true");
	ncfg_proto_subject_t subject = about_interface("eth0");
	char                 message[NCFG_ERROR_MAX];
	ncfg_explanation_t  *explanation;

	explanation = ncfg_explain(&subject, document, observed, NULL, message, sizeof(message));
	if (explanation) {
		check(says(explanation, "ownership", "192.168.9.5/24 is foreign"),
		    "the ownership of an address names the address it is about");
		check(says(explanation, "ownership", "10.0.0.1/24 is ours"),
		    "and so does the ownership of the one beside it");
	} else {
		check(0, "the ownership of an address names the address it is about");
	}
	ncfg_explanation_free(explanation);
	ncfg_document_free(document);
	ncfg_observed_free(observed);
}

/* ------------------------------------------------------------------------ *
 * The bounds, the refusals and the rendering
 * ------------------------------------------------------------------------ */

/*
 * An observation arrives over a socket and out of `/run`, so the number of
 * facts is chosen by whoever wrote it. The bound holds and `total` says what
 * was there, which is the parser's arrangement (0263).
 */
static void an_explanation_is_bounded_and_says_how_many_there_were(void)
{
	ncfg_document_t    *document = document_of(ETH0_STATIC);
	ncfg_observed_t    *observed;
	ncfg_buf_t          buf;
	char                body[65536];
	size_t              at;
	size_t              i;
	char                message[NCFG_ERROR_MAX];
	ncfg_explanation_t *explanation;
	ncfg_proto_subject_t subject = about_interface("eth0");

	at = (size_t)snprintf(body, sizeof(body), "\"links\":[" LINK_UP("eth0") "],\"addresses\":[");
	/* Two facts each -- the address and its ownership -- so this is four times
	 * the bound and nothing can pass by accident. */
	for (i = 0; i < 600u; i++) {
		at += (size_t)snprintf(body + at, sizeof(body) - at,
		    "%s{\"interface\":\"eth0\",\"address\":\"10.%zu.%zu.1/24\",\"ownership\":"
		    "\"foreign\"}", i ? "," : "", i / 250u, i % 250u);
		if (at >= sizeof(body)) {
			break;
		}
	}
	(void)snprintf(body + at, sizeof(body) - at, "]");
	observed = observed_of(body);

	explanation = ncfg_explain(&subject, document, observed, NULL, message, sizeof(message));
	if (explanation) {
		check(explanation->count == NCFG_EXPLAIN_FACTS_MAX,
		    "an explanation holds no more facts than its bound");
		check(explanation->total > explanation->count, "and counts the ones it dropped");
		ncfg_buf_init(&buf, 0);
		check(ncfg_explanation_render(explanation, &buf, message, sizeof(message)),
		    "and renders");
		check(strstr(ncfg_buf_text(&buf), "showing 256 of ") != NULL,
		    "and the rendering says how many of how many are shown");
		ncfg_buf_free(&buf);
	} else {
		check(0, "an explanation holds no more facts than its bound");
	}
	ncfg_explanation_free(explanation);
	ncfg_document_free(document);
	ncfg_observed_free(observed);
}

static void a_subject_this_module_cannot_read_is_refused_by_name(void)
{
	ncfg_observed_t     *observed = observed_of("\"links\":[" LINK_UP("eth0") "]");
	ncfg_proto_subject_t subject;
	char                 long_name[NCFG_EXPLAIN_SUBJECT_MAX + 8];
	char                 message[NCFG_ERROR_MAX];
	ncfg_explanation_t  *explanation;

	subject = about_interface("eth0");
	subject.kind = (ncfg_proto_subject_kind_t)NCFG_PROTO_SUBJECT_COUNT;
	message[0] = '\0';
	explanation = ncfg_explain(&subject, NULL, observed, NULL, message, sizeof(message));
	check(explanation == NULL && strstr(message, "none of them") != NULL,
	    "a subject outside the set is refused and the refusal says so");
	ncfg_explanation_free(explanation);

	memset(long_name, 'a', sizeof(long_name) - 1u);
	long_name[sizeof(long_name) - 1u] = '\0';
	subject = about_interface(long_name);
	message[0] = '\0';
	explanation = ncfg_explain(&subject, NULL, observed, NULL, message, sizeof(message));
	check(explanation == NULL && strstr(message, "at most 127") != NULL,
	    "a name past the bound is refused, naming the bound rather than truncating");
	ncfg_explanation_free(explanation);

	subject = about_interface("eth0");
	subject.name.length = 9;
	subject.name.bytes = "eth0\0junk";
	message[0] = '\0';
	explanation = ncfg_explain(&subject, NULL, observed, NULL, message, sizeof(message));
	check(explanation == NULL && strstr(message, "NUL") != NULL,
	    "a name carrying a NUL is refused rather than compared as the part before it");
	ncfg_explanation_free(explanation);

	subject = about_interface("eth0");
	message[0] = '\0';
	explanation = ncfg_explain(&subject, NULL, NULL, NULL, message, sizeof(message));
	check(explanation == NULL && message[0] != '\0',
	    "and explaining without an observation is refused with a sentence");
	ncfg_explanation_free(explanation);

	ncfg_observed_free(observed);
}

/*
 * The output is the product.
 *
 * Two spaces, the topic in a nine-column field, the detail, and the source in
 * brackets after three spaces -- which is `command_explain`'s format string in
 * the Rust, character for character. A port that rewrote the layout would have
 * ported the data and not the command.
 */
static void the_rendering_is_the_rust_command_line_for_line(void)
{
	ncfg_document_t     *document = document_of("\"devices\":[],\"interfaces\":[]");
	ncfg_observed_t     *observed = observed_of("\"links\":[]");
	ncfg_proto_subject_t subject = about_interface("eth0");
	ncfg_buf_t           buf;
	char                 message[NCFG_ERROR_MAX];
	ncfg_explanation_t  *explanation;
	static const char    wanted[] =
	    "interface eth0\n"
	    "  desired   not mentioned in the configuration; netcfgd does not manage it\n"
	    "  observed  no such interface is present\n"
	    "  next      nothing; the interface matches its config\n";

	explanation = ncfg_explain(&subject, document, observed, NULL, message, sizeof(message));
	ncfg_buf_init(&buf, 0);
	check(explanation != NULL &&
	    ncfg_explanation_render(explanation, &buf, message, sizeof(message)),
	    "an explanation renders");
	if (strcmp(ncfg_buf_text(&buf), wanted) != 0) {
		printf("  got:\n%s  wanted:\n%s", ncfg_buf_text(&buf), wanted);
	}
	check(strcmp(ncfg_buf_text(&buf), wanted) == 0,
	    "and renders exactly the lines `ncfg explain` prints");
	ncfg_buf_free(&buf);
	ncfg_explanation_free(explanation);
	ncfg_document_free(document);
	ncfg_observed_free(observed);
}

/* A source is rendered in brackets after the detail, which the case above has
 * no fact to show. */
static void a_fact_with_a_place_renders_it_in_brackets(void)
{
	ncfg_document_t     *document = document_of(ETH0_STATIC);
	ncfg_observed_t     *observed = observed_of("\"links\":[" LINK_UP("eth0") "]");
	ncfg_proto_subject_t subject = about_interface("eth0");
	ncfg_buf_t           buf;
	char                 message[NCFG_ERROR_MAX];
	ncfg_explanation_t  *explanation;

	explanation = ncfg_explain(&subject, document, observed, NULL, message, sizeof(message));
	ncfg_buf_init(&buf, 0);
	check(explanation != NULL &&
	    ncfg_explanation_render(explanation, &buf, message, sizeof(message)),
	    "an explanation with a placed fact renders");
	check(strstr(ncfg_buf_text(&buf), "  observed  up, carrier, mtu 1500   [kernel]\n") != NULL,
	    "and the place goes in brackets after three spaces");
	ncfg_buf_free(&buf);
	ncfg_explanation_free(explanation);
	ncfg_document_free(document);
	ncfg_observed_free(observed);
}

/*
 * A route the configuration asks for, and one the kernel holds for somebody
 * else.
 *
 * The route subject has no case of its own in the Rust beyond the two report
 * ones, and the protocol tag is the whole of what says whose a route is.
 */
static void a_route_says_whose_the_protocol_tag_makes_it(void)
{
	ncfg_document_t     *document = document_of(
	    "\"devices\":[{\"name\":\"eth0\",\"kind\":{\"kind\":\"physical\"}}],"
	    "\"interfaces\":[{\"name\":\"eth0\",\"addressing\":[{\"source\":\"static\","
	    "\"address\":\"10.0.0.1/24\"}],\"routes\":[{\"destination\":\"default\","
	    "\"via\":\"10.0.0.254\"}]}]");
	ncfg_observed_t     *observed = observed_of("\"links\":[" LINK_UP("eth0") "],"
	    "\"routes\":[{\"interface\":\"eth0\",\"destination\":\"default\","
	    "\"via\":\"10.0.0.254\",\"proto\":16,\"ownership\":\"foreign\"}]");
	ncfg_proto_subject_t subject = about_route("eth0", "default");
	char                 message[NCFG_ERROR_MAX];
	ncfg_explanation_t  *explanation;

	explanation = ncfg_explain(&subject, document, observed, NULL, message, sizeof(message));
	if (explanation) {
		check(says(explanation, "desired", "asks for it via 10.0.0.254"),
		    "a route the configuration asks for says so, and names the next hop");
		check(says(explanation, "observed", "present via 10.0.0.254"),
		    "and the kernel's own answer says it is there");
		check(says(explanation, "ownership", "rtm_protocol 16 belongs to something else"),
		    "and a protocol tag that is not netcfgd's says whose it is not");
	} else {
		check(0, "a route the configuration asks for says so, and names the next hop");
	}
	ncfg_explanation_free(explanation);
	ncfg_document_free(document);
	ncfg_observed_free(observed);
}

/* A radio that will not associate says which switch is holding it off, before
 * the addresses it has none of. */
static void a_blocked_radio_says_which_switch_and_says_it_early(void)
{
	ncfg_document_t     *document = document_of(
	    "\"devices\":[{\"name\":\"wlan0\",\"kind\":{\"kind\":\"physical\"}}],"
	    "\"interfaces\":[{\"name\":\"wlan0\",\"addressing\":[{\"source\":\"static\","
	    "\"address\":\"10.0.0.1/24\"}]}]");
	ncfg_observed_t     *observed = observed_of(
	    "\"links\":[{\"name\":\"wlan0\",\"index\":3,\"mtu\":1500,\"up\":true,"
	    "\"carrier\":false,\"wireless\":true,\"ownership\":\"unknown\","
	    "\"rfkill\":{\"switch\":\"phy0\",\"soft\":false,\"hard\":true}}]");
	ncfg_proto_subject_t subject = about_interface("wlan0");
	char                 message[NCFG_ERROR_MAX];
	ncfg_explanation_t  *explanation;

	explanation = ncfg_explain(&subject, document, observed, NULL, message, sizeof(message));
	if (explanation) {
		check(says(explanation, "radio", "switched off at phy0 by hardware"),
		    "a hard-blocked radio names the switch and says nothing in software clears it");
		check(names_source(explanation, "rfkill"), "and says where that was read from");
	} else {
		check(0, "a hard-blocked radio names the switch and says nothing in software clears it");
	}
	ncfg_explanation_free(explanation);
	ncfg_document_free(document);
	ncfg_observed_free(observed);
}

/* A probe's verdict is the reason routes are missing, and is named with the
 * command that produced it. */
static void a_failing_probe_says_why_the_routes_are_not_there(void)
{
	ncfg_document_t     *document = document_of(
	    "\"devices\":[{\"name\":\"eth0\",\"kind\":{\"kind\":\"physical\"}}],"
	    "\"interfaces\":[{\"name\":\"eth0\",\"addressing\":[{\"source\":\"static\","
	    "\"address\":\"10.0.0.1/24\"}],\"probe\":{\"command\":\"/usr/bin/curl\","
	    "\"interval\":30,\"timeout\":5,\"down_after\":3,\"up_after\":1,\"hold_down\":0}}]");
	ncfg_observed_t     *observed = observed_of(
	    "\"links\":[{\"name\":\"eth0\",\"index\":2,\"mtu\":1500,\"up\":true,"
	    "\"carrier\":true,\"reachable\":false,\"ownership\":\"unknown\"}]");
	ncfg_proto_subject_t subject = about_interface("eth0");
	char                 message[NCFG_ERROR_MAX];
	ncfg_explanation_t  *explanation;

	explanation = ncfg_explain(&subject, document, observed, NULL, message, sizeof(message));
	if (explanation) {
		check(says(explanation, "probe", "/usr/bin/curl says it is not"),
		    "a failing probe names the program whose exit status was the answer");
		check(says(explanation, "probe", "routes are not installed"),
		    "and says what that costs the interface");
	} else {
		check(0, "a failing probe names the program whose exit status was the answer");
	}
	ncfg_explanation_free(explanation);
	ncfg_document_free(document);
	ncfg_observed_free(observed);
}

/* The drift policy an interface inherits says that it inherited it, because
 * `report` on the interface and `report` from globals are edited in different
 * files. */
static void an_inherited_drift_policy_says_it_was_inherited(void)
{
	ncfg_document_t     *document = document_of(ETH0_STATIC);
	ncfg_observed_t     *observed = observed_of("\"links\":[" LINK_UP("eth0") "]");
	ncfg_proto_subject_t subject = about_interface("eth0");
	char                 message[NCFG_ERROR_MAX];
	ncfg_explanation_t  *explanation;

	explanation = ncfg_explain(&subject, document, observed, NULL, message, sizeof(message));
	if (explanation) {
		check(says(explanation, "drift", "on_drift is reconcile (from globals)"),
		    "an interface that names no drift policy says whose it is using");
	} else {
		check(0, "an interface that names no drift policy says whose it is using");
	}
	ncfg_explanation_free(explanation);
	ncfg_document_free(document);
	ncfg_observed_free(observed);
}

int main(void)
{
	printf("== explain_test\n");
	an_address_we_installed_says_so_and_says_how_we_know();
	the_weaker_mechanism_is_named_as_weaker();
	a_lease_address_says_the_backend_owns_it();
	a_delegated_address_names_the_delegation_it_came_from();
	a_stale_backend_says_so_on_the_interface();
	a_reported_address_says_where_the_value_came_from();
	a_reported_gateway_explains_the_default_route_it_implies();
	a_report_the_document_never_asked_for_explains_nothing();
	a_guarded_interface_explains_what_is_blocked_and_how_to_allow_it();
	an_unmanaged_interface_says_it_is_unmanaged();
	explaining_without_a_configuration_still_answers();
	an_empty_table_is_said_rather_than_left_to_be_noticed();
	a_table_with_an_entry_names_the_file_and_the_line();
	the_compilers_own_table_is_the_one_explain_reads();
	a_report_spelled_another_way_is_still_the_same_address();
	the_ownership_of_the_second_address_is_about_the_second_address();
	an_explanation_is_bounded_and_says_how_many_there_were();
	a_subject_this_module_cannot_read_is_refused_by_name();
	the_rendering_is_the_rust_command_line_for_line();
	a_fact_with_a_place_renders_it_in_brackets();
	a_route_says_whose_the_protocol_tag_makes_it();
	a_blocked_radio_says_which_switch_and_says_it_early();
	a_failing_probe_says_why_the_routes_are_not_there();
	an_inherited_drift_policy_says_it_was_inherited();

	if (failures == 0) {
		printf("explain_test: all %d checks passed\n", checks);
	} else {
		printf("explain_test: %d of %d check(s) failed\n", failures, checks);
	}
	return failures == 0 ? 0 : 1;
}
