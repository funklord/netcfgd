/*
 * mesh.c -- each mesh point's peers, in the same generic netlink round as
 * four-address mode and the radios' capabilities (project.md 10.686).
 *
 * Asked only where the observation has a radio, for `regdom.c`'s reason. One
 * `GET_INTERFACE` dump says which interfaces are mesh points; each is then
 * asked for its stations, and the peers whose link is established are kept.
 * A kernel that will not say leaves the lists empty with a note, and the rest
 * of the observation stands -- the peers are something to show, and nothing
 * the planner decides from.
 */
#include "ncfg/observe.h"

#include "observe_internal.h"

#include "ncfg/genl.h"
#include "ncfg/genl_socket.h"
#include "ncfg/log.h"
#include "ncfg/mesh_peer.h"
#include "ncfg/wds.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <net/if.h>

#include <linux/nl80211.h>

static void forget_peers(ncfg_observed_link_t *link)
{
	size_t at;

	for (at = 0; at < link->mesh_peer_count; at++) {
		free(link->mesh_peers[at]);
	}
	free(link->mesh_peers);
	link->mesh_peers = NULL;
	link->mesh_peer_count = 0;
}

/* The established peers of interface `index`, into `link`. 0 where the dump
 * could not be asked; a peer that will not parse is passed over. */
static int ask_peers(const ncfg_observe_kernel_t *genl, const ncfg_genl_family_t *family,
    uint32_t index, ncfg_observed_link_t *link, char *why, size_t why_size)
{
	ncfg_netlink_reply_t reply;
	ncfg_buf_t           message;
	size_t               at;
	int                  ok;

	memset(&reply, 0, sizeof(reply));
	ncfg_buf_init(&message, 0);
	ok = ncfg_mesh_peers_request(&message, family, index, 0, why, why_size) &&
	    observe_genl_ask(genl, &message, &reply, why, why_size);
	ncfg_buf_free(&message);
	if (!ok) {
		return 0;
	}
	if (reply.count) {
		link->mesh_peers = calloc(reply.count, sizeof(*link->mesh_peers));
	}
	for (at = 0; at < reply.count && link->mesh_peers; at++) {
		ncfg_mesh_peer_t peer;
		char             skipped[NCFG_ERROR_MAX];

		if (!ncfg_mesh_peer_parse(reply.items[at].bytes, reply.items[at].length, &peer,
		        skipped, sizeof(skipped)) ||
		    !peer.has_plink_state || peer.plink_state != NCFG_MESH_PLINK_ESTAB) {
			continue;
		}
		link->mesh_peers[link->mesh_peer_count] = strdup(peer.mac);
		if (link->mesh_peers[link->mesh_peer_count]) {
			link->mesh_peer_count++;
		}
	}
	ncfg_netlink_reply_free(&reply);
	if (link->mesh_peer_count == 0u) {
		free(link->mesh_peers);
		link->mesh_peers = NULL;
	}
	return 1;
}

int ncfg_observe_kernel_stations(const char *interface, ncfg_hostapd_station_t **out,
    size_t *count)
{
	ncfg_netlink_t       socket;
	ncfg_genl_family_t   family;
	ncfg_netlink_reply_t reply;
	ncfg_buf_t           message;
	ncfg_buf_t           body;
	char                 why[NCFG_ERROR_MAX];
	unsigned int         index = interface ? if_nametoindex(interface) : 0u;
	uint16_t             kind = 0;
	uint16_t             flags = 0;
	size_t               at;
	int                  ok;

	*out = NULL;
	*count = 0u;
	if (index == 0u ||
	    !ncfg_genl_family_open(NL80211_GENL_NAME, &socket, &family, why, sizeof(why))) {
		return 0;
	}
	memset(&reply, 0, sizeof(reply));
	ncfg_buf_init(&message, 0);
	ncfg_buf_init(&body, 0);
	ok = ncfg_mesh_peers_request(&message, &family, (uint32_t)index, 0, why, sizeof(why)) &&
	    ncfg_wire_request_parts(&message, "generic netlink", &kind, &flags, &body, why,
	        sizeof(why)) &&
	    ncfg_netlink_request(&socket, kind, flags, &body, NULL, &reply, why, sizeof(why));
	ncfg_buf_free(&body);
	ncfg_buf_free(&message);
	ncfg_genl_family_free(&family);
	ncfg_netlink_close(&socket);
	if (!ok) {
		return 0;
	}
	if (reply.count) {
		*out = calloc(reply.count, sizeof(**out));
		if (!*out) {
			ncfg_netlink_reply_free(&reply);
			return 0;
		}
	}
	for (at = 0; at < reply.count; at++) {
		ncfg_mesh_peer_t peer;

		if (ncfg_mesh_peer_parse(reply.items[at].bytes, reply.items[at].length, &peer, why,
		        sizeof(why))) {
			(void)snprintf((*out)[*count].address, sizeof((*out)[*count].address), "%s",
			    peer.mac);
			(*out)[*count].authorized = peer.authorized;
			(*count)++;
		}
	}
	ncfg_netlink_reply_free(&reply);
	return 1;
}

int ncfg_observe_mesh_from(const ncfg_observe_kernel_t *genl, ncfg_observed_t *observed,
    char *err, size_t err_size)
{
	ncfg_genl_family_t   family;
	ncfg_netlink_reply_t reply;
	ncfg_buf_t           message;
	char                 why[NCFG_ERROR_MAX];
	size_t               at;
	size_t               link;
	int                  radios = 0;
	int                  ok;

	if (!observed) {
		ncfg_error_set(err, err_size, "there is no observation to read mesh peers into");
		return 0;
	}
	for (link = 0; link < observed->link_count; link++) {
		forget_peers(&observed->links[link]);
		radios |= observed->links[link].wireless;
	}
	if (!genl || !genl->exchange || !radios) {
		return 1;
	}
	why[0] = '\0';
	if (!observe_genl_family(genl, NL80211_GENL_NAME, &family, why, sizeof(why))) {
		ncfg_genl_family_free(&family);
		return 1;
	}
	memset(&reply, 0, sizeof(reply));
	ncfg_buf_init(&message, 0);
	ok = ncfg_wds_interfaces_request(&message, &family, 0, why, sizeof(why)) &&
	    observe_genl_ask(genl, &message, &reply, why, sizeof(why));
	ncfg_buf_free(&message);
	if (!ok) {
		ncfg_genl_family_free(&family);
		return 1;
	}
	for (at = 0; at < reply.count; at++) {
		ncfg_wds_interface_t radio;

		if (!ncfg_wds_interface_parse(reply.items[at].bytes, reply.items[at].length, &radio,
		        why, sizeof(why)) ||
		    !radio.has_iftype || radio.iftype != NL80211_IFTYPE_MESH_POINT) {
			continue;
		}
		for (link = 0; link < observed->link_count; link++) {
			if (observed->links[link].name &&
			    strcmp(observed->links[link].name, radio.name) == 0 &&
			    !ask_peers(genl, &family, radio.index, &observed->links[link], why,
			        sizeof(why))) {
				ncfg_log_emitf("observe", NCFG_LOG_NOTE,
				    "the mesh peers of %s could not be read: %s", radio.name, why);
			}
		}
	}
	ncfg_netlink_reply_free(&reply);
	ncfg_genl_family_free(&family);
	return 1;
}
