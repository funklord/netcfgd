/*
 * regdom.h -- the machine's wireless regulatory domain, asked of nl80211.
 *
 * WHERE IT IS ASKED
 *   By the observation, in `observe/regdom.c`, beside the offloads and
 *   WireGuard -- decision 0296 says what the domain is gets reported, the
 *   daemon takes the observation on every tick, and every client is answered
 *   from it. This file is the bytes: the request, and the reply read only as
 *   a country when it names one.
 *
 * WHAT THE KERNEL CANNOT SAY HERE
 *   Who set it. `NL80211_CMD_GET_REG` answers with the country and its rules,
 *   and the initiator -- a user, a driver, a beacon's country element -- is
 *   carried only by the `REG_CHANGE` notification at the moment of change.
 *
 * THE NUMBERS ARE THE KERNEL'S
 *   `NL80211_CMD_GET_REG` and `NL80211_ATTR_REG_ALPHA2` come from
 *   <linux/nl80211.h>, for `genl.h`'s reason.
 */
#ifndef NCFG_REGDOM_H
#define NCFG_REGDOM_H

#include <stddef.h>
#include <stdint.h>

#include "ncfg/base.h"
#include "ncfg/genl.h"

/* Two characters and the NUL: an ISO 3166-1 alpha-2 code, or one of the
 * kernel's own two-character names -- `00` the world domain, `98` an
 * intersection, `99` a driver's custom domain. */
#define NCFG_REGDOM_TEXT_MAX 3

/* Build a `GET_REG` for the global domain, to a family already resolved. */
int ncfg_regdom_request(ncfg_buf_t *out, const ncfg_genl_family_t *family, uint32_t seq,
    char *err, size_t err_size);

/*
 * The country out of one `GET_REG` reply payload.
 *
 * A reply with no `REG_ALPHA2`, or one that is not two characters of letters
 * and digits, is a refusal: an empty or truncated code printed as a domain is
 * a country nobody is in.
 */
int ncfg_regdom_parse(const void *payload, size_t length, char *out, size_t out_size,
    char *err, size_t err_size);

#endif /* NCFG_REGDOM_H */
