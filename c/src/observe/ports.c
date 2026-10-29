/*
 * ports.c -- a network card's physical ports, as devlink describes them, in
 * the same generic netlink round as the offloads, WireGuard and the
 * regulatory domain.
 *
 * WHY IT IS OBSERVED
 *   A VPI card runs each port as Ethernet or as InfiniBand, and one in
 *   InfiniBand mode has no Ethernet interface at all -- a configuration naming
 *   one meets an interface that is not there, and nothing else in the
 *   observation says why (`devlink.h`, project.md 10.586). One dump of every
 *   port of every device, so the cost is one message whatever the machine.
 *
 * A KERNEL THAT WILL NOT SAY IS NOT A FAILURE
 *   No devlink family, a refused dump, a port that will not read: the list is
 *   what could be read, a note says what could not, and the rest of the
 *   observation stands -- the offloads round's bargain, for its reason.
 */
#include "ncfg/observe.h"

#include "observe_internal.h"

#include "ncfg/devlink.h"
#include "ncfg/genl.h"
#include "ncfg/log.h"

#include <stdlib.h>
#include <string.h>

#include <linux/devlink.h>

/* A copy of `text`, or NULL for an empty one, which is the kernel not saying. */
static int copy_or_none(const char *text, char **out)
{
	*out = NULL;
	if (text[0] == '\0') {
		return 1;
	}
	*out = strdup(text);
	return *out != NULL;
}

static void clear(ncfg_observed_t *observed)
{
	size_t at;

	for (at = 0; at < observed->port_count; at++) {
		free(observed->ports[at].device);
		free(observed->ports[at].type);
		free(observed->ports[at].interface);
		free(observed->ports[at].rdma);
	}
	free(observed->ports);
	observed->ports = NULL;
	observed->port_count = 0;
}

/* One port onto the list. 0 only where memory ran out. */
static int append(ncfg_observed_t *observed, const ncfg_devlink_port_t *port)
{
	ncfg_observed_port_t *grown;
	ncfg_observed_port_t *added;

	grown = realloc(observed->ports, (observed->port_count + 1u) * sizeof(*grown));
	if (!grown) {
		return 0;
	}
	observed->ports = grown;
	added = &grown[observed->port_count];
	memset(added, 0, sizeof(*added));
	added->index = (int64_t)port->index;
	if (!copy_or_none(port->device, &added->device) ||
	    !copy_or_none(ncfg_devlink_port_type_name(port->type), &added->type) ||
	    !copy_or_none(port->netdev, &added->interface) ||
	    !copy_or_none(port->ibdev, &added->rdma)) {
		free(added->device);
		free(added->type);
		free(added->interface);
		free(added->rdma);
		return 0;
	}
	observed->port_count++;
	return 1;
}

int ncfg_observe_ports_from(const ncfg_observe_kernel_t *genl, ncfg_observed_t *observed,
    char *err, size_t err_size)
{
	ncfg_genl_family_t   family;
	ncfg_netlink_reply_t reply;
	ncfg_buf_t           message;
	char                 why[NCFG_ERROR_MAX];
	size_t               at;
	size_t               unread = 0;
	int                  ok;

	if (!observed) {
		ncfg_error_set(err, err_size, "there is no observation to read the card ports into");
		return 0;
	}
	clear(observed);
	if (!genl || !genl->exchange) {
		return 1;
	}
	why[0] = '\0';
	if (!observe_genl_family(genl, DEVLINK_GENL_NAME, &family, why, sizeof(why))) {
		ncfg_log_emitf("observe", NCFG_LOG_NOTE,
		    "devlink could not be resolved (%s), so this observation names no card ports",
		    why[0] ? why : "no sentence was given");
		ncfg_genl_family_free(&family);
		return 1;
	}
	memset(&reply, 0, sizeof(reply));
	ncfg_buf_init(&message, 0);
	ok = ncfg_devlink_ports_request(&message, &family, 0, why, sizeof(why)) &&
	    observe_genl_ask(genl, &message, &reply, why, sizeof(why));
	ncfg_buf_free(&message);
	ncfg_genl_family_free(&family);
	if (!ok) {
		ncfg_log_emitf("observe", NCFG_LOG_NOTE,
		    "the card ports could not be read: %s", why);
		return 1;
	}
	for (at = 0; at < reply.count; at++) {
		ncfg_devlink_port_t port;

		if (!ncfg_devlink_port_parse(reply.items[at].bytes, reply.items[at].length, &port,
		    why, sizeof(why))) {
			unread++;
			continue;
		}
		if (!port.physical) {
			continue;
		}
		if (!append(observed, &port)) {
			ncfg_netlink_reply_free(&reply);
			clear(observed);
			ncfg_error_set(err, err_size, "out of memory recording the card ports");
			return 0;
		}
	}
	ncfg_netlink_reply_free(&reply);
	if (unread > 0u) {
		/* Counted rather than one note each: a card that describes its ports in
		 * a way this build cannot read does it for every port. */
		ncfg_log_emitf("observe", NCFG_LOG_NOTE,
		    "%zu card port(s) could not be read and are left out; the last said: %s",
		    unread, why);
	}
	return 1;
}
