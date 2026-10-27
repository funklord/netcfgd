/*
 * genl_socket.h -- a generic netlink socket with one family resolved on it.
 *
 * `genl.h` builds and parses and opens nothing; `netlink.h` opens and parses
 * nothing. Resolving a family needs both, once per socket -- `genl.h` says why
 * an id is meaningless on any other -- so a caller that wants to talk to one
 * family asks here, and the request and the lookup are spelled in one place.
 */
#ifndef NCFG_GENL_SOCKET_H
#define NCFG_GENL_SOCKET_H

#include <stddef.h>

#include "ncfg/genl.h"
#include "ncfg/netlink.h"

/*
 * Open a generic netlink socket and resolve one family on it.
 *
 * On success the caller owns both and closes the socket with
 * `ncfg_netlink_close` and the family with `ncfg_genl_family_free`. On failure
 * neither is left open, and the sentence is `ncfg_genl_lookup_failed`'s where
 * the kernel refused the lookup -- for a missing family, that the module
 * providing it is probably not loaded.
 */
int ncfg_genl_family_open(const char *name, ncfg_netlink_t *socket, ncfg_genl_family_t *family,
    char *err, size_t err_size);

#endif /* NCFG_GENL_SOCKET_H */
