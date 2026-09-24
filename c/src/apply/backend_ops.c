/*
 * backend_ops.c -- starting, stopping and reloading the daemons netcfgd runs,
 * and delivering a resolver configuration.
 *
 * WHAT THIS BUILD CARRIES, AND WHAT IT REFUSES
 *   Five of the nine backend kinds have a module under `src/backend/`:
 *   `ncfg_hostapd_start`, `ncfg_ra_start`/`_reload`/`_stop`,
 *   `ncfg_openvpn_start`/`_stop`, `ncfg_dhcp_start`/`_stop` and
 *   `ncfg_supplicant_start`/`_stop`. Those are the ones this executes. A
 *   PPPoE session is started by code that is not ported and is **refused by
 *   name** rather than reported as done -- an executor that answered success
 *   for a session it did not start would have the planner satisfied about a
 *   machine with no address.
 *
 * STARTING A SUPPLICANT IS THE ONE START THAT IS NOT FINISHED WHEN IT RETURNS
 *   A supplicant that has just been launched knows nothing, by design (0015),
 *   and **filling it is part of starting it** rather than a later reconcile's
 *   work: a plan that reported success while leaving an empty supplicant would
 *   be reporting that a port is authenticated when it is not, and that a radio
 *   holds credentials it was never given. So the arm below calls
 *   `ncfg_service_set_profiles` -- the same op `wifi.set_profiles` carries out
 *   -- and a population that failed fails the start. That is the Rust's
 *   arrangement, where `populate_supplicant` is called from the `backend.start`
 *   arm and from the `WifiSetProfiles` arm and from nowhere else.
 *
 *   Which driver it is launched with comes from the same document lookup the
 *   population branches on. `service_internal.h` says why that matters: a
 *   radio started `-Dwired`, or a wired port started `-Dnl80211`, comes up and
 *   never authenticates, and nothing downstream can tell.
 *
 *   **The DHCPv6 half is a start this build refuses and a stop it carries**,
 *   which is not an accident of the porting order. Which v6 client can serve a
 *   document is decided by whether that document asked for a delegated prefix
 *   -- odhcp6c can report one and dhcpcd measurably cannot (0050) -- and a
 *   plain `backend.start` carries neither the request nor an odhcp6c.
 *
 *   **That last sentence used to read "The Rust refuses it in exactly the same
 *   words at the same point", and it was wrong.** The Rust has the sentence,
 *   in its `start_backend` free function -- and its executor never reaches it
 *   for DHCPv6: `Op::BackendStart` with that kind is intercepted one match arm
 *   earlier, looks the interface up in the `delegating` map `with_context`
 *   built from the document, and starts a client with the request. This port
 *   reproduced the dead arm and cited it as agreement. The pieces the start
 *   needs are in `dhcp.h` now -- `ncfg_dhcp6_client`,
 *   `ncfg_dhcp_prefix_request`, `ncfg_dhcp_odhcp6c_args` and
 *   `ncfg_dhcp_pd_script` -- and the refusal stands until there is a start to
 *   replace it with, because a `supported` that said yes to a start that
 *   cannot happen is worse than one that says no with a reason (project.md
 *   10.259). Stopping is a
 *   different question and is answerable: `dhcpcd -6 -k` and an odhcp6c's
 *   recorded pid are both this module's, so a v6 client that is running can be
 *   stopped whoever started it.
 *
 *   `ncfg_service_backend_supported` is that list, asked by
 *   `ncfg_apply_supported`, so "what can this carry out?" stays a value a test
 *   can ask about rather than a shape of the code.
 *
 * STOPPING AN ACCESS POINT IS THE ONE THING WRITTEN HERE RATHER THAN CALLED
 *   `hostapd.h` says in as many words that its `stop` is not carried yet,
 *   because it speaks the control socket and that client is the supplicant
 *   module's. What is below is that stop, built out of the supplicant client
 *   and hostapd's own path helpers, and **it belongs in `src/backend/hostapd/`
 *   the day a second caller wants it** -- which is the arrangement 0263
 *   records for the three things that live in the daemon's wifi module for the
 *   same reason. It is here and not there because this is the only caller, and
 *   because the instruction for this wave was that new code lands under
 *   `src/apply/`.
 *
 * WHY A START ASKS WHETHER ONE IS ALREADY RUNNING
 *   The same property the wifi ops are arranged around. A plan applied twice
 *   on a converged machine must not start a second radvd beside the first --
 *   and `ncfg_ra_running_pid` and `ncfg_openvpn_running_pid` both answer by
 *   checking `/proc/<pid>/cmdline` against a path netcfgd chose, so this is a
 *   claim about netcfgd's own process rather than a search for something that
 *   looks like one.
 */
#include "ncfg/service.h"

#include "service_internal.h"

#include "ncfg/base.h"
#include "ncfg/dhcp.h"
#include "ncfg/hostapd.h"
#include "ncfg/openvpn.h"
#include "ncfg/observed.h"
#include "ncfg/ra.h"
#include "ncfg/supplicant.h"

#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#define BACKEND_PATH_MAX 4352u

/* ------------------------------------------------------------------------ *
 * What this build can carry out
 * ------------------------------------------------------------------------ */

/* The word an operator would use, never `%d`. */
static const char *kind_word(int kind)
{
	const char *word = ncfg_backend_kind_name(kind);

	return word ? word : "an unknown";
}

int ncfg_service_backend_supported(const ncfg_op_t *op, char *err, size_t err_size)
{
	const char *name;
	int         kind;
	const char *iface;

	if (!op) {
		ncfg_error_set(err, err_size, "there is no op to carry out");
		return 0;
	}
	name = ncfg_op_name(op);
	kind = op->u.backend.kind;
	iface = op->u.backend.iface ? op->u.backend.iface : "?";

	/*
	 * **What the kind is comes before what the verb is.** Two of the nine
	 * name no daemon at all, and telling somebody who asked to reload
	 * WireGuard that "only a router advertisement daemon re-reads its
	 * configuration" answers a question about reload semantics they were not
	 * asking: there is nothing there to reload, start or stop, and that is
	 * the sentence for all three verbs. The refusal an operator reads has to
	 * name the thing that is actually wrong (0010), and until this the two
	 * kinds got the sharper sentence for `start` and `stop` and the generic
	 * one for `reload` (project.md 10.261).
	 */
	if (kind == NCFG_BACKEND_WIREGUARD) {
		ncfg_error_set(err, err_size,
		    "%s on %s names WireGuard, which is a kernel device rather than a "
		    "daemon: `link.create` makes it and `wg.set_device` configures it, so "
		    "there is no process here to start, stop or reload", name, iface);
		return 0;
	}
	if (kind == NCFG_BACKEND_DNS) {
		ncfg_error_set(err, err_size,
		    "%s on %s names DNS, which `dns.apply` delivers rather than a daemon "
		    "netcfgd runs: the resolver is somebody else's, so there is nothing here "
		    "to start, stop or reload", name, iface);
		return 0;
	}

	if (op->kind == NCFG_OP_BACKEND_RELOAD) {
		/*
		 * Only radvd has one. It re-reads its configuration on `SIGHUP`, so a
		 * changed prefix costs nothing on the wire -- where for an access
		 * point the same question means a restart and a deauthenticated LAN
		 * (0026). Nothing else is given a reload that stops and starts: that
		 * would hide the difference behind a word.
		 */
		if (kind == NCFG_BACKEND_ROUTER_ADVERT) {
			return 1;
		}
		ncfg_error_set(err, err_size,
		    "%s on %s has no reload: only a router advertisement daemon re-reads "
		    "its configuration, an access point's would be a restart, and a DHCP "
		    "client's is the client's own business", name, iface);
		return 0;
	}

	switch ((ncfg_backend_kind_t)kind) {
	case NCFG_BACKEND_ACCESS_POINT:
	case NCFG_BACKEND_ROUTER_ADVERT:
	case NCFG_BACKEND_OPENVPN:
	case NCFG_BACKEND_DHCP4:
	case NCFG_BACKEND_SUPPLICANT:
	case NCFG_BACKEND_PPPOE:
	/*
	 * **DHCPv6 was refused here and is not any more.** The refusal said the
	 * plain backend path carried neither the prefix request nor the odhcp6c
	 * it would need. It carries both now: `start_dhcp6` reads the request out
	 * of the document the service holds, and `ncfg_dhcp6_client` picks the
	 * client. What survives is the one refusal that is a fact about the
	 * machine rather than about this build -- a document asking for a prefix
	 * where only dhcpcd is installed -- and that belongs to the start, which
	 * can see what is installed, rather than to this predicate, which is pure
	 * (project.md 10.259, 0050).
	 */
	case NCFG_BACKEND_DHCP6:
		return 1;
	/* Answered above, before the verb was looked at, because the sentence is
	 * the kind's rather than the verb's. Named here rather than removed so
	 * that this switch stays exhaustive over the taxonomy -- which is what
	 * makes a kind added to it fail to compile instead of falling silently
	 * into a refusal that does not fit it. */
	case NCFG_BACKEND_WIREGUARD:
	case NCFG_BACKEND_DNS:
		break;
	}
	ncfg_error_set(err, err_size, "%s names a backend this build does not know", name);
	return 0;
}

/* ------------------------------------------------------------------------ *
 * What a backend op needs from the context
 * ------------------------------------------------------------------------ */

static int run_dir_of(const ncfg_service_t *service, const char *doing, const char *iface,
    const char **out, char *err, size_t err_size)
{
	if (!service) {
		ncfg_error_set(err, err_size,
		    "%s needs an executor that was given a service context, and this one has "
		    "none", doing);
		return 0;
	}
	if (!service->run_dir || service->run_dir[0] == '\0') {
		ncfg_error_set(err, err_size,
		    "%s on %s needs to be told where netcfgd's run directory is; this build "
		    "has no default for it, because a default is how a test comes to write "
		    "the machine's own", doing, iface ? iface : "?");
		return 0;
	}
	if (!iface || iface[0] == '\0') {
		ncfg_error_set(err, err_size, "%s names no interface to act on", doing);
		return 0;
	}
	*out = service->run_dir;
	return 1;
}

/* The access point block bound to this radio, or NULL.
 *
 * `access_points` is sorted by id, so where a document puts two on one radio
 * the first in id order wins -- which is the same answer the plan warned
 * about. One radio is one BSS in this build, and the two have to agree on
 * which one or the plan names one access point and the executor starts
 * another. */
static const ncfg_access_point_t *access_point_on(const ncfg_document_t *document,
    const char *device)
{
	size_t i;

	if (!document || !device) {
		return NULL;
	}
	for (i = 0; i < document->access_point_count; i++) {
		if (document->access_points[i].device &&
		    strcmp(document->access_points[i].device, device) == 0) {
			return &document->access_points[i];
		}
	}
	return NULL;
}

static const ncfg_service_advertise_t *advertising_on(const ncfg_service_t *service,
    const char *iface)
{
	size_t i;

	for (i = 0; i < service->advertise_count; i++) {
		if (service->advertising[i].iface &&
		    strcmp(service->advertising[i].iface, iface) == 0) {
			return &service->advertising[i];
		}
	}
	return NULL;
}

static const ncfg_service_tunnel_t *tunnel_on(const ncfg_service_t *service, const char *iface)
{
	size_t i;

	for (i = 0; i < service->tunnel_count; i++) {
		if (service->tunnels[i].iface && strcmp(service->tunnels[i].iface, iface) == 0) {
			return &service->tunnels[i];
		}
	}
	return NULL;
}

/* ------------------------------------------------------------------------ *
 * Starting
 * ------------------------------------------------------------------------ */

/* Whether netcfgd's own access point is answering on this radio.
 *
 * The control socket rather than the pid file, and that is 0078: a wedged
 * hostapd holds its socket, holds its pid and serves nobody, so a pid alone
 * answered `running` to every question netcfgd had. A start against one of
 * those should still be a start. */
static int access_point_answers(const char *run_dir, const char *device)
{
	char directory[BACKEND_PATH_MAX];
	char scratch[NCFG_ERROR_MAX];

	if (!ncfg_hostapd_ctrl_dir(run_dir, directory, sizeof(directory), scratch,
	    sizeof(scratch))) {
		return 0;
	}
	return ncfg_supplicant_answers(directory, device);
}

static int start_access_point(const ncfg_service_t *service, const char *run_dir,
    const char *iface, char *err, size_t err_size)
{
	const ncfg_access_point_t *access_point = access_point_on(service->document, iface);

	if (!access_point) {
		ncfg_error_set(err, err_size,
		    "backend.start asks for an access point on %s, and the document this "
		    "plan was built from has no `access_point` block bound to it", iface);
		return 0;
	}
	if (!service->secrets) {
		ncfg_error_set(err, err_size,
		    "starting the access point on %s needs a secret resolver; without one "
		    "hostapd would be handed a configuration with no passphrase in it",
		    iface);
		return 0;
	}
	if (access_point_answers(run_dir, iface)) {
		/* Already up and answering. Starting a second hostapd on one radio is
		 * two daemons fighting over one BSS, which is the failure this whole
		 * project is arranged against. */
		return 1;
	}
	return ncfg_hostapd_start(run_dir, access_point, service->secrets,
	    service->hostapd_program, err, err_size);
}

static int start_advertising(const ncfg_service_t *service, const char *run_dir,
    const char *iface, char *err, size_t err_size)
{
	const ncfg_service_advertise_t *advertise = advertising_on(service, iface);

	if (!advertise || !advertise->policy) {
		ncfg_error_set(err, err_size,
		    "backend.start asks %s to advertise, and this executor was given no "
		    "resolved `advertise` for it; the prefixes are an argument here because "
		    "`@pd:` resolution is the model's and `value.h` has no port of it",
		    iface);
		return 0;
	}
	if (ncfg_ra_running_pid(run_dir, iface) > 0) {
		return 1;
	}
	return ncfg_ra_start(run_dir, iface, advertise->policy, advertise->prefixes,
	    advertise->prefix_count, advertise->servers, advertise->server_count,
	    service->radvd_program, err, err_size);
}

/* The metric this interface's client is started with, or absent.
 *
 * `ncfg_service_client_metric_t` says why this is a list the caller resolved
 * rather than a field read out of the document: half the rule lives in the
 * observation, and an executor that rebuilt it from the document alone missed
 * `network { metric = N }` on every wifi lease. An interface with no entry is
 * a client started with no `-m`, which is not a refusal. */
static ncfg_optint_t client_metric_on(const ncfg_service_t *service, const char *iface)
{
	ncfg_optint_t none;
	size_t        i;

	none.has = 0;
	none.value = 0;
	for (i = 0; i < service->client_metric_count; i++) {
		if (service->client_metrics[i].iface &&
		    strcmp(service->client_metrics[i].iface, iface) == 0) {
			return service->client_metrics[i].metric;
		}
	}
	return none;
}

/*
 * The `-P` argument this interface's document asks for, or an empty string.
 *
 * Read from the document here rather than precomputed onto the service,
 * which is `ncfg_service_supplicant_driver`'s arrangement: the document is
 * held by the service and a second list of the same fact is a second thing to
 * keep in step. The Rust precomputes it into `with_context`'s `delegating`
 * because its executor is built once per apply; this one is asked per start,
 * and the walk is over the interfaces of one document.
 *
 * **Empty is not `0`.** No `-P` at all and `-P 0` are different requests: the
 * second solicits a delegation nobody wrote down, which is the defect
 * `ncfg_dhcp_odhcp6c_args` records.
 */
static void prefix_request_on(const ncfg_service_t *service, const char *iface, char *out,
    size_t out_size)
{
	size_t i;

	if (out_size) {
		out[0] = '\0';
	}
	if (!service->document) {
		return;
	}
	for (i = 0; i < service->document->interface_count; i++) {
		const ncfg_interface_t *one = &service->document->interfaces[i];
		size_t                  at;

		if (!one->name || strcmp(one->name, iface) != 0) {
			continue;
		}
		for (at = 0; at < one->addressing_count; at++) {
			const ncfg_address_source_t *source = &one->addressing[at];

			if (source->kind != (int)NCFG_ADDRESS_SOURCE_DHCP6 ||
			    !source->dhcp6.prefix_delegation) {
				continue;
			}
			(void)ncfg_dhcp_prefix_request(source->dhcp6.prefix_delegation, out, out_size);
			return;
		}
		return;
	}
}

/*
 * Start a DHCPv6 client, or adopt the one already there.
 *
 * `start_dhcp`'s arrangement -- the running question is `ncfg_dhcp6_start`'s
 * first two steps -- with the document's prefix request carried in, which is
 * the whole of what this build could not do until now (project.md 10.259).
 */
static int start_dhcp6(const ncfg_service_t *service, const char *run_dir, const char *iface,
    char *err, size_t err_size)
{
	char request[128];

	prefix_request_on(service, iface, request, sizeof(request));
	return ncfg_dhcp6_start(run_dir, iface, request[0] ? request : NULL, &service->dhcp, err,
	    err_size);
}

/* Start a DHCPv4 client, or adopt the one already there.
 *
 * **Nothing is asked here about whether one is running**, unlike the three
 * above. That question has two halves for a DHCP client -- a pid file with a
 * mark in it and a control socket reciting one -- and `ncfg_dhcp_start` asks
 * both as its first two steps, because the answer decides between adopting and
 * spawning rather than merely between starting and not. Asking a third time
 * here would be a second spelling of one rule. */
static int start_dhcp(const ncfg_service_t *service, const char *run_dir, const char *iface,
    char *err, size_t err_size)
{
	ncfg_optint_t metric = client_metric_on(service, iface);

	return ncfg_dhcp_start(run_dir, iface, &metric, &service->dhcp, err, err_size);
}

/* Where the control sockets are, or a refusal naming what is missing.
 *
 * `service.h`'s bargain: nothing here has a default and nothing here reads the
 * environment, because a default is how the difference between a check and an
 * outage becomes a variable somebody remembered to set. The wifi ops ask this
 * of themselves in `supplicant_context`; both verbs below need it too. */
static int supplicant_dir_of(const ncfg_service_t *service, const char *doing, const char *iface,
    const char **out, char *err, size_t err_size)
{
	if (!service->supplicant_dir || service->supplicant_dir[0] == '\0') {
		ncfg_error_set(err, err_size,
		    "%s on %s needs to be told where the supplicant control sockets are; this "
		    "build has no default for it, because a default is how a check comes to "
		    "start a supplicant on the machine's own radio", doing, iface);
		return 0;
	}
	*out = service->supplicant_dir;
	return 1;
}

/* Start a supplicant, or adopt the one already there, and give it its
 * networks.
 *
 * **Nothing is asked here about whether one is running**, unlike the three
 * above. That question has two halves for a supplicant -- a pid file with a
 * mark in it and a control socket that answers -- and `ncfg_supplicant_start`
 * asks both as its first steps, because the answer decides between adopting
 * and spawning rather than merely between starting and not. That is
 * `start_dhcp`'s arrangement and its reason. */
static int start_supplicant(const ncfg_service_t *service, const char *run_dir,
    const char *iface, char *err, size_t err_size)
{
	const char *dir;
	const char *driver;

	if (!supplicant_dir_of(service, "backend.start", iface, &dir, err, err_size) ||
	    !ncfg_service_supplicant_driver(service->document, iface, &driver, err, err_size)) {
		return 0;
	}
	if (!ncfg_supplicant_start(run_dir, dir, iface, driver, service->supplicant_program, err,
	    err_size)) {
		return 0;
	}
	/*
	 * **Filling it is part of starting it.** See the note at the top: a
	 * supplicant that has just started holds nothing, and reporting the start
	 * as done would report a port authenticated that is not. A failure here is
	 * a failed start even though a process is now running -- which is the Rust's
	 * behaviour too, and is the honest one: the action did not achieve what it
	 * said, and `backend.stop` is what takes the process away.
	 */
	return ncfg_service_set_profiles(service, iface, err, err_size);
}

static int start_tunnel(const ncfg_service_t *service, const char *run_dir, const char *iface,
    char *err, size_t err_size)
{
	const ncfg_service_tunnel_t *tunnel = tunnel_on(service, iface);

	if (!tunnel || !tunnel->config) {
		ncfg_error_set(err, err_size,
		    "backend.start asks for an openvpn tunnel on %s, and this executor was "
		    "given no configuration file for it", iface);
		return 0;
	}
	if (ncfg_openvpn_running_pid(run_dir, iface) > 0) {
		return 1;
	}
	return ncfg_openvpn_start(run_dir, iface, tunnel->config, tunnel->username,
	    tunnel->password, tunnel->report, service->openvpn_program, err, err_size);
}

static const ncfg_service_session_t *session_on(const ncfg_service_t *service, const char *iface)
{
	size_t i;

	for (i = 0; i < service->session_count; i++) {
		if (service->sessions[i].iface && strcmp(service->sessions[i].iface, iface) == 0) {
			return &service->sessions[i];
		}
	}
	return NULL;
}

/*
 * Dial a PPPoE session.
 *
 * **Configured from the document rather than from the op**, which is what
 * `start_access_point` and `start_tunnel` are: the op carries an interface and
 * a kind, and what pppd needs is a parent interface, a username and a
 * credential nobody would put in a plan (constraint 5).
 *
 * A session already running is success without dialling a second one, which is
 * the property every backend op here is arranged around: a plan applied twice
 * on a converged machine must not leave two pppds on one line. `pppoe.h` says
 * why the pid it finds has to prove whose it is.
 */
static int start_session(const ncfg_service_t *service, const char *run_dir, const char *iface,
    char *err, size_t err_size)
{
	const ncfg_service_session_t *session = session_on(service, iface);

	if (!session || !session->config) {
		ncfg_error_set(err, err_size,
		    "backend.start asks for a pppoe session on %s, and this executor was given "
		    "no configuration for it", iface);
		return 0;
	}
	if (ncfg_pppoe_running_pid(run_dir, iface, &service->pppoe) > 0) {
		return 1;
	}
	return ncfg_pppoe_start(run_dir, iface, session->config, session->password,
	    &service->pppoe, err, err_size);
}

int ncfg_service_backend_start(const ncfg_service_t *service, int kind, const char *iface,
    char *err, size_t err_size)
{
	const char *run_dir;
	int         adopted = 0;

	if (!run_dir_of(service, "backend.start", iface, &run_dir, err, err_size)) {
		return 0;
	}
	/*
	 * **Before every kind's own start, and for every kind.** Each of them
	 * asks whether one of its own is running by reading a pid file, which is
	 * the right first question and is useless in the case that happens:
	 * stopping the unit takes `/run/netcfgd` with it and leaves the daemons
	 * running. `backend_adopt.c` has the argument; what matters here is that
	 * it is one call rather than a recovery written into four of the five
	 * starts and missing from the rest.
	 */
	if (!ncfg_service_backend_adopt(service, kind, iface, &adopted, err, err_size)) {
		return 0;
	}
	if (adopted) {
		return 1;
	}
	switch ((ncfg_backend_kind_t)kind) {
	case NCFG_BACKEND_ACCESS_POINT:
		return start_access_point(service, run_dir, iface, err, err_size);
	case NCFG_BACKEND_ROUTER_ADVERT:
		return start_advertising(service, run_dir, iface, err, err_size);
	case NCFG_BACKEND_OPENVPN:
		return start_tunnel(service, run_dir, iface, err, err_size);
	case NCFG_BACKEND_DHCP4:
		return start_dhcp(service, run_dir, iface, err, err_size);
	case NCFG_BACKEND_DHCP6:
		return start_dhcp6(service, run_dir, iface, err, err_size);
	case NCFG_BACKEND_SUPPLICANT:
		return start_supplicant(service, run_dir, iface, err, err_size);
	case NCFG_BACKEND_PPPOE:
		return start_session(service, run_dir, iface, err, err_size);
	case NCFG_BACKEND_WIREGUARD:
	case NCFG_BACKEND_DNS:
		break;
	}
	/* Unreachable through `execute`, which asks `ncfg_apply_supported` first
	 * and therefore `ncfg_service_backend_supported`. Said rather than left as
	 * a fall-through, so a second caller finds a sentence instead of a success
	 * for a daemon nobody started. */
	ncfg_error_set(err, err_size,
	    "starting a %s backend on %s is not carried out by this build", kind_word(kind),
	    iface);
	return 0;
}

/* ------------------------------------------------------------------------ *
 * Stopping
 * ------------------------------------------------------------------------ */

/*
 * Stop an access point through its control socket.
 *
 * **Not by signal**, which is 0014's rule for every daemon here: killing by
 * name reaches an access point netcfgd did not start, and an operator's own
 * hostapd is an ordinary thing to have.
 *
 * Nothing listening is taken as nothing running, and that is safe *here*
 * because hostapd's `-B` returns only after the control interface is up.
 * **But only nothing listening**: a hostapd that has bound its socket and gone
 * silent fails here rather than at `TERMINATE`, because the connect opens with
 * a `PING` -- which is 0109, where a stop reported success without a byte
 * having been sent while the access point was still on the air.
 *
 * **Absence is the socket file not being there, and that is a divergence.**
 * The Rust asks `nothing_is_listening` of the error the connect failed with,
 * which forgives `ENOENT` *and* `ECONNREFUSED` -- the second being a socket
 * file a process that is gone left behind. `ncfg_supplicant_connect_within`
 * releases the half-built client before it returns NULL, and that release
 * closes and unlinks, so `errno` at the call site is the last of those calls
 * rather than the connect's; the predicate exists in `supplicant.h` and has no
 * C caller for exactly this reason. So the absence test here is whether the
 * socket is there at all, and a socket that is there and silent is a failure
 * naming it. That is the stricter half of 0109 and the safe direction: the
 * cost is that a hostapd killed outright, which leaves its socket file behind,
 * needs one refused stop before the file goes -- against a silent success
 * about an access point that is still on the air.
 *
 * The generated configuration goes whether or not the daemon answered, and
 * that is the case that matters most: it holds the passphrase in the clear,
 * hostapd having no indirection for one, and a daemon that died leaves it
 * behind in exactly the situation where nobody comes back to tidy up. The
 * `.acl` beside it stays -- it holds no secret and carries the policy record
 * 0039 gave it.
 */
static int stop_access_point(const char *run_dir, const char *device, int patience_ms,
    char *err, size_t err_size)
{
	char                      directory[BACKEND_PATH_MAX];
	char                      path[BACKEND_PATH_MAX];
	char                      detail[NCFG_ERROR_MAX];
	struct stat               about;
	ncfg_supplicant_client_t *client;
	int                       ok = 1;

	if (!ncfg_hostapd_ctrl_dir(run_dir, directory, sizeof(directory), err, err_size)) {
		return 0;
	}
	detail[0] = '\0';
	client = ncfg_supplicant_connect_within(directory, device,
	    patience_ms > 0 ? patience_ms : NCFG_SUPPLICANT_IMPATIENT_MS, detail, sizeof(detail));
	if (client) {
		ok = ncfg_supplicant_command(client, "TERMINATE", detail, sizeof(detail));
		if (!ok) {
			ncfg_error_set(err, err_size, "could not stop the access point on %s: %s",
			    device, detail);
		}
		ncfg_supplicant_client_free(client);
	} else if (snprintf(path, sizeof(path), "%s/%s", directory, device) > 0 &&
	    lstat(path, &about) == 0) {
		/*
		 * A timeout is deliberately not "nothing is listening":
		 * `supplicant.h` says so in as many words, and reading a wedged daemon
		 * as absent tells the operator an access point was stopped while it is
		 * still on the air with its passphrase in memory.
		 */
		ok = 0;
		ncfg_error_set(err, err_size,
		    "could not stop the access point on %s: its control socket at %s is "
		    "there and did not answer: %s", device, path, detail);
	}

	if (ncfg_hostapd_config_path(run_dir, device, path, sizeof(path), detail, sizeof(detail))) {
		(void)unlink(path);
	}
	/* And the pid file, for 0080's reason: hostapd removes its own on a clean
	 * exit, one that was killed leaves it, and a stale file would have the next
	 * observation asking about a pid that belongs to somebody else by then. */
	if (ncfg_hostapd_pid_path(run_dir, device, path, sizeof(path), detail, sizeof(detail))) {
		(void)unlink(path);
	}
	return ok;
}

int ncfg_service_backend_stop(const ncfg_service_t *service, int kind, const char *iface,
    char *err, size_t err_size)
{
	const ncfg_service_tunnel_t *tunnel;
	const char                  *run_dir;
	const char                  *supplicant_dir;

	if (!run_dir_of(service, "backend.stop", iface, &run_dir, err, err_size)) {
		return 0;
	}
	switch ((ncfg_backend_kind_t)kind) {
	case NCFG_BACKEND_ACCESS_POINT:
		return stop_access_point(run_dir, iface, service->patience_ms, err, err_size);
	case NCFG_BACKEND_ROUTER_ADVERT:
		return ncfg_ra_stop(run_dir, iface, err, err_size);
	case NCFG_BACKEND_OPENVPN:
		/*
		 * Through its own management socket, never by signalling a process
		 * found by name: an operator's own OpenVPN tunnels are common, and
		 * 0014's sentence about the supplicant applies here without changing a
		 * word. The report is the tunnel's and goes with it; a stop with no
		 * tunnel recorded still has a report to remove, so an absent entry is
		 * not a refusal.
		 */
		tunnel = tunnel_on(service, iface);
		return ncfg_openvpn_stop(run_dir, iface, tunnel ? tunnel->report : NULL, err,
		    err_size);
	case NCFG_BACKEND_DHCP4:
	case NCFG_BACKEND_DHCP6:
		/*
		 * The family is not optional and is not guessed: dhcpcd's pid file
		 * carries it, and a `-k` without one reports a client stopped that is
		 * still renewing the lease and holding the address (0070). The op's
		 * kind is what says which, which is the one place the two are joined.
		 */
		return ncfg_dhcp_stop(run_dir, iface,
		    kind == NCFG_BACKEND_DHCP4 ? NCFG_DHCP_FAMILY_V4 : NCFG_DHCP_FAMILY_V6,
		    &service->dhcp, err, err_size);
	case NCFG_BACKEND_SUPPLICANT:
		/*
		 * Through its own control socket, never by signalling a process found
		 * by name -- 0014's rule, which the tunnel above states and which
		 * `process.h` names this daemon in: an operator's own
		 * `wpa_supplicant` is an ordinary thing to have, and it would be
		 * reached along with netcfgd's.
		 *
		 * **This is the inverse `backend.start` declares**, which is why it is
		 * carried rather than left: `service.h` says a start inverts to a stop
		 * on the same kind and interface, and an inverse the executor refuses
		 * is a revert that silently skips an op.
		 */
		if (!supplicant_dir_of(service, "backend.stop", iface, &supplicant_dir, err,
		    err_size)) {
			return 0;
		}
		return ncfg_supplicant_stop(run_dir, supplicant_dir, iface, service->patience_ms,
		    err, err_size);
	case NCFG_BACKEND_PPPOE:
		/*
		 * **By pid, because pppd has no control socket** -- the one daemon
		 * here that is stopped that way, and `pppoe.h` argues what makes it
		 * defensible: the pid has to name a process whose `/proc` entry
		 * carries the options file netcfgd wrote for *this* interface, which
		 * an operator's own pppd cannot match.
		 *
		 * A session with no entry still has files and a report to take back,
		 * so an absent one is not a refusal here any more than it is for a
		 * tunnel.
		 */
		return ncfg_pppoe_stop(run_dir, iface, NULL, &service->pppoe, err, err_size);
	case NCFG_BACKEND_WIREGUARD:
	case NCFG_BACKEND_DNS:
		break;
	}
	ncfg_error_set(err, err_size,
	    "stopping a %s backend on %s is not carried out by this build", kind_word(kind),
	    iface);
	return 0;
}

int ncfg_service_backend_reload(const ncfg_service_t *service, int kind, const char *iface,
    char *err, size_t err_size)
{
	const ncfg_service_advertise_t *advertise;
	const char                     *run_dir;

	if (!run_dir_of(service, "backend.reload", iface, &run_dir, err, err_size)) {
		return 0;
	}
	if (kind != NCFG_BACKEND_ROUTER_ADVERT) {
		ncfg_error_set(err, err_size,
		    "reloading a %s backend on %s is not carried out by this build",
		    kind_word(kind), iface);
		return 0;
	}
	advertise = advertising_on(service, iface);
	if (!advertise || !advertise->policy) {
		ncfg_error_set(err, err_size,
		    "backend.reload asks %s to re-read what it advertises, and this "
		    "executor was given no resolved `advertise` for it", iface);
		return 0;
	}
	/* A daemon that is not running is **not** success here: `ncfg_ra_start` is
	 * what a stopped daemon needs, and quietly doing nothing would leave the
	 * document and the wire disagreeing with nothing to say so. That check is
	 * `ncfg_ra_reload`'s own and is not repeated. */
	return ncfg_ra_reload(run_dir, iface, advertise->policy, advertise->prefixes,
	    advertise->prefix_count, advertise->servers, advertise->server_count, err, err_size);
}

/* ------------------------------------------------------------------------ *
 * DNS
 * ------------------------------------------------------------------------ */

int ncfg_service_dns_apply(const ncfg_service_t *service, const char *scope,
    const ncfg_dns_policy_t *policy, char *err, size_t err_size)
{
	ncfg_dns_scope_t        alone;
	const ncfg_dns_scope_t *scopes;
	size_t                  count;

	if (!service) {
		ncfg_error_set(err, err_size,
		    "dns.apply needs an executor that was given a service context, and this "
		    "one has none");
		return 0;
	}
	if (!service->dns.run_dir || service->dns.run_dir[0] == '\0') {
		/*
		 * The record under `<run>/dns/` is not an extra: without it a plan
		 * cannot tell an already-applied policy from an unapplied one, so every
		 * run emits a `dns.apply` -- which is the plan-idempotence property
		 * failing. Refusing beats delivering and leaving no record.
		 */
		ncfg_error_set(err, err_size,
		    "dns.apply needs somewhere to record what it delivered, and this "
		    "executor was given no run directory; without the record every plan "
		    "would ask for this delivery again");
		return 0;
	}
	/*
	 * Every scope, not the one the op names, for the reason `service.h` gives
	 * and the Rust records: `ncfg_dns_flatten` is over a set, and delivering
	 * one scope would write a `resolv.conf` holding one interface's servers.
	 * Where the executor was given none -- a caller that built no context --
	 * the single scope is better than delivering nothing.
	 */
	if (service->dns_scopes && service->dns_scope_count > 0u) {
		scopes = service->dns_scopes;
		count = service->dns_scope_count;
	} else {
		if (!scope || !policy) {
			ncfg_error_set(err, err_size,
			    "dns.apply carries neither a scope list on the executor nor a "
			    "scope and a policy of its own, so there is nothing to deliver");
			return 0;
		}
		alone.name = scope;
		alone.policy = policy;
		scopes = &alone;
		count = 1u;
	}
	/*
	 * **The record is `ncfg_dns_deliver`'s own last step and is not written
	 * again here.** It reads as though it were a second thing to do -- `dns.h`
	 * declares `ncfg_dns_record` publicly and explains it separately -- and a
	 * call to it after the delivery looks like diligence. It is a duplicate:
	 * `deliver` ends in exactly that call. Found by sabotage, which is the
	 * point of the method: removing the second call turned no check red,
	 * because the first one had already written the file.
	 *
	 * What is left here is the *order*, which is this module's and is worth
	 * the check above: the run directory is demanded **before** anything is
	 * delivered. `deliver` writes `resolv.conf` and only then discovers it has
	 * nowhere to record what it did, which leaves the machine changed and the
	 * planner unable to tell -- so every following apply asks for the same
	 * delivery again, and that is the plan-idempotence property failing.
	 */
	return ncfg_dns_deliver(scopes, count, &service->dns, NULL, NULL, err, err_size);
}
