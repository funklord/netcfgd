/*
 * daemon_service.c -- what an open executor is given for the ops that are not
 * netlink.
 *
 * WHY THERE IS A FILE FOR THIS AND NOT THREE LINES IN `daemon_world.c`
 *   `ncfg_kernel_new` builds an executor out of a netlink socket, and until now
 *   that was the whole of what this daemon handed the reconcile pass -- so
 *   fourteen of the forty-eight ops refused by name on every apply, which is
 *   `dns.apply`, the four sysctls, the hostname, the six wifi ops and the three
 *   backend verbs. `ncfg_kernel_set_service` is the seam that answers them and
 *   it had no caller outside the tests. This is the caller.
 *
 *   It is its own file because filling `ncfg_service_t` is not plumbing: two of
 *   its members are **rules** rather than lookups -- which scopes a machine has
 *   and what route metric a DHCP client is started with -- and both are rules
 *   the Rust got wrong by answering them a second time in the executor. Put
 *   inside `daemon_world.c` they would be four more statics in a file about
 *   descriptors and locks.
 *
 * WHAT IS RESOLVED HERE AND WHAT IS DELIBERATELY LEFT NULL
 *   Resolved: the three directories, the document, the secret resolver, the
 *   resolver's delivery targets, **every** DNS scope, dhcpcd's machine paths
 *   and the per-interface route metrics.
 *
 *   Left as it was, so that the op refuses by name: `advertising`, because
 *   resolving `@pd:wan0` is `derive_from_delegation`'s arithmetic and `value.h`
 *   has no port of it -- `explain.c` already spells a private copy and says so,
 *   and a second one here would be the third reading of one rule; and
 *   `tunnels`, because an openvpn configuration file is a path nothing composes
 *   yet. `backend.start` on a radvd or an openvpn interface says exactly that.
 *
 *   The four programs are the world's, and a daemon leaves them NULL, which
 *   means "find the conventional name". For a daemon that is right rather than
 *   a gap: `service.h`'s argument for them being arguments is that a *test*
 *   must be able to put a stand-in in front of the machine's own, and the seam
 *   is where that happens.
 *
 * WHY EVERY SCOPE AND NOT THE ONE THE OP NAMES
 *   `dns.apply` carries one scope and a delivery writes the resolver file
 *   whole, so an executor that rebuilt the list from the op would write a file
 *   holding one interface's servers. That is the Rust's recorded defect and
 *   `dns_scopes_test.c` measures the gap: a machine with a converged host scope
 *   and a drifted interface scope has one `dns.apply` and two scopes.
 */
#include "loop_internal.h"

#include "ncfg/base.h"
#include "ncfg/log.h"

#include <string.h>

/* ------------------------------------------------------------------------ *
 * The route metric a DHCP client is started with
 * ------------------------------------------------------------------------ */

/* The metric of the network of that id, or absent. */
static ncfg_optint_t metric_of_network(const ncfg_document_t *desired, const char *id)
{
	ncfg_optint_t none;
	size_t        i;

	memset(&none, 0, sizeof(none));
	for (i = 0; id && i < desired->network_count; i++) {
		if (desired->networks[i].id && strcmp(desired->networks[i].id, id) == 0) {
			return desired->networks[i].metric;
		}
	}
	return none;
}

size_t ncfg_main_metrics_of(const ncfg_document_t *desired, const ncfg_observed_t *observed,
    ncfg_service_client_metric_t *out, size_t out_max, size_t *missed)
{
	size_t taken = 0;
	size_t i;

	if (missed) {
		*missed = 0;
	}
	if (!desired || !out) {
		return 0;
	}
	for (i = 0; i < desired->interface_count; i++) {
		const ncfg_interface_t     *interface = &desired->interfaces[i];
		const ncfg_observed_link_t *link = observed ?
		    ncfg_observed_link(observed, interface->name) : NULL;
		ncfg_optint_t               metric = metric_of_network(desired,
		    link ? link->network : NULL);

		/*
		 * The network's where the radio is associated to one that carries a
		 * metric, and the interface's own `preference` otherwise. **Not "the
		 * network's if there is a network"**: a network with no metric of its
		 * own falls through to the preference rather than erasing it, which is
		 * what `or` means in the rule and is the difference between honouring
		 * an operator's number and dropping it because they also named an SSID.
		 */
		if (!metric.has) {
			metric = interface->preference;
		}
		if (!metric.has) {
			continue;
		}
		if (taken == out_max) {
			if (missed) {
				(*missed)++;
			}
			continue;
		}
		out[taken].iface = interface->name;
		out[taken].metric = metric;
		taken++;
	}
	return taken;
}

/* ------------------------------------------------------------------------ *
 * The whole context
 * ------------------------------------------------------------------------ */

int ncfg_main_service_of(ncfg_main_world_t *world, char *err, size_t err_size)
{
	const ncfg_document_t *desired;
	const ncfg_observed_t *observed;
	size_t                 missed = 0;

	if (!world) {
		ncfg_error_set(err, err_size, "there is no world to take a service context from");
		return 0;
	}
	ncfg_main_service_release(world);
	desired = world->state ? world->state->desired : NULL;
	observed = world->state ? world->state->observed : NULL;
	/*
	 * The three directories as the world was given them, never as
	 * `ncfg_service_machine` would answer them. That function exists so a test
	 * can read what a daemon would use; calling it here would put the
	 * machine's real `/proc` and `/run/wpa_supplicant` into a world somebody
	 * pointed at a scratch tree, which is the one thing `service.h` says must
	 * not happen.
	 */
	world->service.run_dir = world->run_dir;
	world->service.proc_root = world->proc_root;
	world->service.supplicant_dir = world->supplicant_dir;
	world->service.document = desired;
	world->service.secrets = world->secrets.secrets_dir || world->secrets.materialise_dir ?
	    &world->secrets : NULL;
	/*
	 * Where a resolver configuration is delivered, exactly as the world was
	 * given it. **Not `dns.h`'s constants**, which are `/etc/resolv.conf` and
	 * the machine's two forwarder configurations: spelling them here would
	 * hand every test that opens an executor a `dns.apply` that rewrites the
	 * resolver of the workstation this suite is built on. The record of what
	 * was delivered does use this world's own run directory, so a daemon
	 * pointed at a scratch tree writes it beside everything else it wrote.
	 */
	world->service.dns.resolv_conf = world->resolv_conf;
	world->service.dns.dnsmasq_conf = world->dnsmasq_conf;
	world->service.dns.unbound_conf = world->unbound_conf;
	world->service.dns.run_dir = world->run_dir;
	/* And what a DHCP client is started with, again as the world was given it
	 * rather than from `ncfg_dhcp_machine`: that answer leaves the programs
	 * NULL, which means "find `dhcpcd` on `PATH`", and a test holding it could
	 * launch a real client on a real interface. */
	world->service.dhcp = world->dhcp;
	world->service.hostapd_program = world->hostapd_program;
	world->service.radvd_program = world->radvd_program;
	world->service.openvpn_program = world->openvpn_program;
	world->service.supplicant_program = world->supplicant_program;
	if (!desired) {
		/*
		 * A configuration that does not compile. Not a failure: the daemon
		 * holds no desired state and has nothing to apply, so what is wanted
		 * here is a service that refuses the ops needing a document by name
		 * rather than one that could not be built at all.
		 */
		return 1;
	}
	world->scopes = ncfg_dns_scopes_of(desired, observed, err, err_size);
	if (!world->scopes) {
		/* Left NULL, and `service.h` says what that costs: `dns.apply` falls
		 * back to the single scope the op carries, which is a resolver file
		 * holding one interface's servers. Said out loud for that reason. */
		ncfg_log_emitf("apply", NCFG_LOG_WARNING,
		    "the DNS scopes of this configuration could not be taken, so a delivery "
		    "would carry only the scope the op names: %s", err ? err : "");
		return 0;
	}
	world->service.dns_scopes = ncfg_dns_scopes_items(world->scopes,
	    &world->service.dns_scope_count);
	world->metric_count = ncfg_main_metrics_of(desired, observed, world->metrics,
	    (size_t)NCFG_MAIN_METRICS_MAX, &missed);
	world->service.client_metrics = world->metrics;
	world->service.client_metric_count = world->metric_count;
	if (missed > 0u) {
		ncfg_log_emitf("apply", NCFG_LOG_WARNING,
		    "%zu interface(s) of this configuration did not fit in the %d route "
		    "metrics an executor is given, so their DHCP clients will start with the "
		    "client's own default rather than the metric written down", missed,
		    NCFG_MAIN_METRICS_MAX);
	}
	return 1;
}

void ncfg_main_service_release(ncfg_main_world_t *world)
{
	if (!world) {
		return;
	}
	ncfg_dns_scopes_free(world->scopes);
	world->scopes = NULL;
	world->metric_count = 0;
	memset(&world->service, 0, sizeof(world->service));
}
