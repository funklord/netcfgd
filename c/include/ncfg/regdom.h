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
 * WHO SET IT IS A SECOND MESSAGE, HEARD RATHER THAN ASKED
 *   `NL80211_CMD_GET_REG` answers with the country and its rules, and the
 *   initiator -- a user, a driver, a beacon's country element -- is carried
 *   only by the `REG_CHANGE` notification at the moment of change. So the
 *   daemon subscribes to nl80211's `regulatory` group and keeps the last one
 *   it heard (`ncfg_daemon_state_heard_regdom`); this file reads it. A
 *   domain set before the daemon started has no notification anybody heard,
 *   and is reported with no setter rather than with a guess.
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

/*
 * Who set the domain, in the kernel's four answers.
 *
 * The kernel's names are `CORE`, `USER`, `DRIVER` and `COUNTRY_IE`; the words
 * here say who rather than how, because a client reads them. **`user` is
 * anything in user space** -- `iw reg set`, netcfgd's own `global { regdom }`
 * through the supplicant, and hostapd's `country_code` all arrive as the same
 * request, and the kernel does not tell them apart.
 */
typedef enum {
	/* The kernel's own: the world domain at boot, and the revert to it when
	 * the last station leaves its access point. */
	NCFG_REGDOM_SET_BY_KERNEL = 0,
	NCFG_REGDOM_SET_BY_USER,
	/* A driver's hint, from a country burned into the card. */
	NCFG_REGDOM_SET_BY_DRIVER,
	/* The country element of the access point a station associated to. */
	NCFG_REGDOM_SET_BY_ACCESS_POINT
} ncfg_regdom_setter_t;

/* One `REG_CHANGE`: the domain it moved to, and who moved it. */
typedef struct {
	char                 code[NCFG_REGDOM_TEXT_MAX];
	ncfg_regdom_setter_t set_by;
} ncfg_regdom_change_t;

/* The word for a setter, as the observation carries it. Never NULL. */
const char *ncfg_regdom_setter_name(ncfg_regdom_setter_t set_by);

/*
 * The last `REG_CHANGE` in one datagram from the `regulatory` group.
 *
 * `bytes` starts at a netlink header and may hold several messages; those
 * that are not nl80211's -- `family` is its resolved id -- or not a
 * `REG_CHANGE` are passed over, since the group carries the per-radio change
 * and the beacon hint as well. `*found` says whether one was read.
 *
 * **The code comes from the type where the kernel sends no country.** It
 * names `REG_ALPHA2` only for a country; the world domain, a driver's custom
 * world and an intersection travel as a type alone, and are `00`, `99` and
 * `98` here, the names `GET_REG` would answer with.
 *
 * A message that does not read is a refusal, and an initiator this build has
 * no word for is too: printing a guessed setter is worse than printing none.
 */
int ncfg_regdom_change_parse(const void *bytes, size_t length, uint16_t family, int *found,
    ncfg_regdom_change_t *out, char *err, size_t err_size);

#endif /* NCFG_REGDOM_H */
