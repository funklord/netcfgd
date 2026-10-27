/*
 * regdom.h -- the machine's wireless regulatory domain, asked of nl80211.
 *
 * WHY `ncfg status` ASKS
 *   Decision 0296 says the domain follows the machine and that what it is,
 *   and from what, is reported -- because a laptop that cannot see a network
 *   nobody can explain is the failure the decision exists for. project.md
 *   10.585 measured what that failure is: a country set by hand strands a
 *   machine exactly in that country's gaps (US has no channel 12 or 13, JP no
 *   149, CN none of 100 to 140), and an unset machine has no 6 GHz at all.
 *   Both are invisible from outside: the access point is simply not there.
 *   One line naming the domain turns "the network is missing" into "this
 *   machine is in US", which is the sentence somebody can act on.
 *
 *   **This reports; it does not decide.** Nothing here sets a domain, and
 *   nothing reads one into the observed model: `observed.json` is a witnessed
 *   document both programs write, and a field one of them lacks is a
 *   disagreement rather than a feature. So it is a note after the listing,
 *   which is what `ncfg status` already does with a fact about the machine
 *   that is not a member of the answer.
 *
 * WHAT THE KERNEL CANNOT SAY HERE
 *   Who set it. `NL80211_CMD_GET_REG` answers with the country and its rules,
 *   and the initiator -- a user, a driver, a beacon's country element -- is
 *   carried only by the `REG_CHANGE` notification at the moment of change.
 *   Knowing it means listening, which is a daemon's job and not a client's;
 *   0296's "and from what" is that, and it is not built.
 *
 * BYTES IN, STRUCTURES OUT, AND ONE CALL THAT OPENS A SOCKET
 *   The request and the parse are `genl.h`'s split: testable with no radio
 *   and no nl80211 loaded. `ncfg_regdom_read` is the round trip, kept apart so
 *   the half that can be silently wrong is the half the tests reach.
 *
 * THE NUMBERS ARE THE KERNEL'S
 *   `NL80211_GENL_NAME`, `NL80211_CMD_GET_REG` and `NL80211_ATTR_REG_ALPHA2`
 *   come from <linux/nl80211.h>, for `genl.h`'s reason.
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
 * Ask the kernel, on a socket of its own that lasts exactly this call.
 *
 * 0 with a sentence where it could not: no nl80211 is the ordinary answer on
 * a machine with no wireless at all, and `ncfg_genl_lookup_failed` already
 * says so in words an operator acts on.
 */
int ncfg_regdom_read(char *out, size_t out_size, char *err, size_t err_size);

#endif /* NCFG_REGDOM_H */
