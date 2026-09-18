/*
 * supplicant_internal.h -- what the three files of this backend share and
 * nobody else may have.
 *
 * ONE FUNCTION, AND IT EXISTS BECAUSE THE RUST LEAKS HERE
 *   `ncfg_supplicant_request` names the command it sent in every diagnostic it
 *   produces -- "cannot send `PING`", "no reply to `SCAN_RESULTS`" -- which is
 *   exactly what an operator needs and exactly what must not happen for
 *   `SET_NETWORK 0 psk "..."`.
 *
 *   **The Rust does it anyway.** `add_network` is careful to report
 *   `setting.redacted(id)` when a setting is refused, and then interpolates
 *   the `io::Error` from `Client::command`, whose own message is
 *   "`{command}` answered {other:?} rather than OK" with `command` being the
 *   line carrying the passphrase. So the redaction is undone one format string
 *   later, and the same is true of a timeout: `request` says "no reply to
 *   `{command}`". Nothing there is a decision; it is two functions each
 *   quoting what it was given.
 *
 *   So a command may be sent under a different name. The label is what every
 *   message says, the command is what goes on the wire, and for a setting the
 *   label is the redacted form -- which makes the rule structural rather than
 *   a thing each call site has to remember.
 */
#ifndef NCFG_SUPPLICANT_INTERNAL_H
#define NCFG_SUPPLICANT_INTERNAL_H

#include <stddef.h>

#include "ncfg/supplicant.h"

/*
 * Send `command` and read its reply, saying `label` in every diagnostic.
 *
 * `ncfg_supplicant_request` is this with the two the same.
 */
int ncfg_supplicant_request_labelled(ncfg_supplicant_client_t *client, const char *command,
    const char *label, char *body, size_t body_size, int *kind, char *err, size_t err_size);

#endif /* NCFG_SUPPLICANT_INTERNAL_H */
