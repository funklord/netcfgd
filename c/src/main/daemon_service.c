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
 *   resolver's delivery targets, **every** DNS scope, dhcpcd's machine paths,
 *   the per-interface route metrics, what each interface advertises, and each
 *   tunnel with its credentials.
 *
 *   **Nothing is left as it was.** This list has been two items and then one;
 *   it is now none, and every member of `ncfg_service_t` is filled in -- the
 *   last of them being an openvpn tunnel's `.ovpn`, its username and its
 *   password, resolved through the world's own secret resolver and owned by
 *   the world so that closing an executor wipes the credential.
 *
 *   **`advertising` was on that list for a reason that was not true.** The
 *   comment said the arithmetic had no port in `value.h`; it has had
 *   `ncfg_address_from_delegation` since the planner needed it, and the
 *   resolution built on it is `ncfg_observed_prefix_of`, which the planner's
 *   own `advertise` pass calls. The claim was inherited from an older
 *   `service.h` and repeated here without being checked. Both are corrected,
 *   and this resolves the references through the same function the planner
 *   does -- which is the whole reason it was lifted into `observed.h`.
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
#include "ncfg/secrets.h"
#include "ncfg/state.h"

#include <string.h>

/* ------------------------------------------------------------------------ *
 * The route metric a DHCP client is started with
 * ------------------------------------------------------------------------ */

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
		const ncfg_interface_t *interface = &desired->interfaces[i];
		/*
		 * `observed.h`'s, and the planner's `with_metric` asks the same
		 * function. That pairing is the point: this starts the client with
		 * `-m` and the planner decides whether the route the client installs
		 * is the one the document asked for, so two readings of the rule is a
		 * lease whose route never matches and a plan that never converges.
		 */
		ncfg_optint_t metric = ncfg_observed_effective_metric(desired, observed,
		    interface);

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
 * What an interface advertises
 * ------------------------------------------------------------------------ */

/*
 * The IPv6 nameservers of this interface's own `dns` block, for `RDNSS`.
 *
 * **Its own block and not its DNS scope**, which is the Rust's choice and is
 * right: a scope absorbs what a lease handed out, and what an RA announces is
 * what this machine is offering the LAN. Announcing the upstream's resolvers to
 * every host on a downstream network is not the same statement at all.
 *
 * IPv6 only, because an RA is an IPv6 message and `RDNSS` carries v6 addresses.
 * A v4 server in the block is not an error -- the resolver delivery uses it --
 * it simply has nowhere to go here.
 */
static size_t servers_of(const ncfg_interface_t *interface, const char **out, size_t out_max,
    size_t *missed)
{
	size_t taken = 0;
	size_t i;

	if (!interface->dns) {
		return 0;
	}
	for (i = 0; i < interface->dns->server_count; i++) {
		const char    *addr = interface->dns->servers[i].addr;
		ncfg_address_t parsed;

		if (!addr || !ncfg_address_parse(addr, &parsed, NULL, 0) || !parsed.is_ipv6) {
			continue;
		}
		if (taken == out_max) {
			if (missed) {
				(*missed)++;
			}
			continue;
		}
		out[taken++] = addr;
	}
	return taken;
}

size_t ncfg_main_advertising_of(ncfg_main_world_t *world, const ncfg_document_t *desired,
    const ncfg_observed_t *observed, size_t *missed)
{
	size_t taken = 0;
	size_t i;

	if (missed) {
		*missed = 0;
	}
	if (!world || !desired) {
		return 0;
	}
	for (i = 0; i < desired->interface_count; i++) {
		const ncfg_interface_t *interface = &desired->interfaces[i];
		const ncfg_device_t    *device;
		size_t                  prefixes = 0;
		size_t                  which;

		if (!interface->advertise) {
			continue;
		}
		/* An unmanaged device is not netcfgd's to run a daemon on, which is
		 * the same question `ncfg_dns_scopes_of` asks and for the same reason:
		 * `backend.start` names the interface, but nothing between here and
		 * the executor asks whether netcfgd manages it. */
		device = ncfg_document_device(desired, interface->name);
		if (device && !device->managed) {
			continue;
		}
		if (taken == (size_t)NCFG_MAIN_ADVERTISE_MAX) {
			if (missed) {
				(*missed)++;
			}
			continue;
		}
		for (which = 0; which < interface->advertise->prefix_count; which++) {
			char *room = world->advertise_text[taken][prefixes];

			if (prefixes == (size_t)NCFG_MAIN_ADVERTISE_PREFIX_MAX) {
				if (missed) {
					(*missed)++;
				}
				continue;
			}
			if (!ncfg_observed_prefix_of(observed, &interface->advertise->prefixes[which],
			    room, (size_t)NCFG_ADDRESS_MAX)) {
				continue;
			}
			world->advertise_prefixes[taken][prefixes] = room;
			prefixes++;
		}
		/*
		 * Nothing resolved, so there is nothing to announce. Left out rather
		 * than entered with an empty list: `ncfg_ra_start` refuses a router
		 * with no prefix, and an entry here would turn that refusal into one
		 * about an empty list instead of the sentence
		 * `ncfg_service_backend_start` gives, which names the interface.
		 */
		if (prefixes == 0u) {
			continue;
		}
		world->advertising[taken].iface = interface->name;
		world->advertising[taken].policy = interface->advertise;
		world->advertising[taken].prefixes = world->advertise_prefixes[taken];
		world->advertising[taken].prefix_count = prefixes;
		world->advertising[taken].servers = world->advertise_servers[taken];
		world->advertising[taken].server_count = servers_of(interface,
		    world->advertise_servers[taken], (size_t)NCFG_MAIN_ADVERTISE_SERVER_MAX,
		    missed);
		taken++;
	}
	return taken;
}

/* ------------------------------------------------------------------------ *
 * What a tunnel is started with
 * ------------------------------------------------------------------------ */

size_t ncfg_main_tunnels_of(ncfg_main_world_t *world, const ncfg_document_t *desired,
    size_t *missed)
{
	size_t taken = 0;
	size_t i;

	if (missed) {
		*missed = 0;
	}
	if (!world || !desired) {
		return 0;
	}
	for (i = 0; i < desired->device_count; i++) {
		const ncfg_device_t         *device = &desired->devices[i];
		const ncfg_openvpn_config_t *config;
		ncfg_secret_t               *password = NULL;
		char                         message[NCFG_ERROR_MAX];

		if (device->kind.kind != NCFG_KIND_OPENVPN || !device->name) {
			continue;
		}
		/* An unmanaged device is not netcfgd's to run a tunnel on, which is
		 * the question `ncfg_dns_scopes_of` and `ncfg_main_advertising_of`
		 * both ask here for the same reason. */
		if (!device->managed) {
			continue;
		}
		config = &device->kind.openvpn;
		if (!config->config || !config->config[0]) {
			/* A tunnel with no `.ovpn` is a document that names nothing to
			 * start from. `backend.start` says so by name; an entry with a
			 * NULL config would reach `ncfg_openvpn_start` instead, which is
			 * one refusal further from the operator. */
			continue;
		}
		if (taken == (size_t)NCFG_MAIN_TUNNELS_MAX) {
			if (missed) {
				(*missed)++;
			}
			continue;
		}
		if (config->password) {
			/*
			 * **The world's own resolver, not `world->service.secrets`.** The
			 * service's copy is set by `ncfg_main_service_of`, so reading it
			 * here would make this function's answer depend on the order of
			 * assignments inside its caller -- which is how a helper comes to
			 * work only when called from one place. It caught this: the test
			 * calls this directly, every password came back unresolved, and
			 * the refusal path made that look like a missing credential.
			 */
			const ncfg_secret_resolver_t *resolver =
			    world->secrets.secrets_dir || world->secrets.materialise_dir ?
			    &world->secrets : NULL;

			message[0] = '\0';
			password = ncfg_secret_resolve(resolver, config->password, NULL, message,
			    sizeof(message));
			if (!password) {
				/*
				 * **No entry, so the refusal names the tunnel.** Starting
				 * openvpn without the credential its document names produces a
				 * daemon that authenticates, fails and retries, which reads to
				 * an operator as a network problem rather than as a secret
				 * netcfgd could not read. The sentence carries no value and
				 * `secrets.h` guarantees the resolver's does not either.
				 */
				ncfg_log_emitf("apply", NCFG_LOG_ERROR,
				    "the password for the tunnel on %s could not be resolved, so "
				    "this executor will refuse to start it rather than start one "
				    "that cannot authenticate: %s", device->name, message);
				continue;
			}
		}
		if (!ncfg_state_report_path(world->run_dir, device->name,
		    world->tunnel_reports[taken], (size_t)NCFG_MAIN_LOOP_PATH_MAX, message,
		    sizeof(message))) {
			ncfg_log_emitf("apply", NCFG_LOG_ERROR,
			    "the tunnel on %s has nowhere to report what it was given: %s",
			    device->name, message);
			ncfg_secret_free(password);
			continue;
		}
		world->tunnel_passwords[taken] = password;
		world->tunnels[taken].iface = device->name;
		world->tunnels[taken].config = config->config;
		world->tunnels[taken].username = config->username;
		/* `ncfg_secret_expose` is named so that every use of it is one grep
		 * away. This is one of them: the value goes into a struct the executor
		 * hands to `ncfg_openvpn_start`, which writes it to a file only it
		 * knows the name of -- which is the arrangement that keeps it off a
		 * command line. */
		world->tunnels[taken].password = password ? ncfg_secret_expose(password) : NULL;
		world->tunnels[taken].report = world->tunnel_reports[taken];
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
	missed = 0;
	world->tunnel_count = ncfg_main_tunnels_of(world, desired, &missed);
	world->service.tunnels = world->tunnels;
	world->service.tunnel_count = world->tunnel_count;
	if (missed > 0u) {
		ncfg_log_emitf("apply", NCFG_LOG_ERROR,
		    "%zu tunnel(s) of this configuration did not fit in the %d an executor "
		    "carries credentials for, so starting them will be refused rather than "
		    "attempted without the passwords their documents name", missed,
		    NCFG_MAIN_TUNNELS_MAX);
	}
	missed = 0;
	world->advertise_count = ncfg_main_advertising_of(world, desired, observed, &missed);
	world->service.advertising = world->advertising;
	world->service.advertise_count = world->advertise_count;
	if (missed > 0u) {
		/*
		 * Louder than the metrics' overflow, and that is the difference
		 * between them: a client with no `-m` takes its own default and works,
		 * while a router announcing part of a prefix list announces something
		 * nobody wrote to every host on the wire.
		 */
		ncfg_log_emitf("apply", NCFG_LOG_ERROR,
		    "%zu interface(s), prefix(es) or nameserver(s) of this configuration did "
		    "not fit in what an executor can advertise (%d interfaces of %d prefixes "
		    "and %d servers), so a router advertisement would carry less than the "
		    "configuration asks for", missed, NCFG_MAIN_ADVERTISE_MAX,
		    NCFG_MAIN_ADVERTISE_PREFIX_MAX, NCFG_MAIN_ADVERTISE_SERVER_MAX);
	}
	return 1;
}

void ncfg_main_service_release(ncfg_main_world_t *world)
{
	size_t at;

	if (!world) {
		return;
	}
	/*
	 * **The passwords first, and wiped.** `ncfg_secret_free` clears the bytes
	 * before freeing, which is the whole reason the world owns these rather
	 * than pointing at something the document holds: an executor's close wipes
	 * a tunnel's credential once per apply, instead of leaving it resident for
	 * the life of the daemon. The `ncfg_service_tunnel_t` beside it borrows
	 * the exposed pointer, so the `memset` below is what stops it being read
	 * after this.
	 */
	for (at = 0; at < world->tunnel_count; at++) {
		ncfg_secret_free(world->tunnel_passwords[at]);
		world->tunnel_passwords[at] = NULL;
	}
	world->tunnel_count = 0;
	ncfg_dns_scopes_free(world->scopes);
	world->scopes = NULL;
	world->metric_count = 0;
	world->advertise_count = 0;
	memset(&world->service, 0, sizeof(world->service));
}
