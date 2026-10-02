/*
 * nmc/authorize.h -- who is calling, and whether they may write.
 *
 * THE CONFUSED DEPUTY, WHICH IS THE WHOLE REASON THIS FILE EXISTS
 *   netcfgd authorizes its SOCKET PEER. The adapter is that peer, so asking
 *   netcfgd "may this be done" answers for the ADAPTER and not for the client
 *   on the bus -- and the adapter is the more privileged of the two. A write
 *   forwarded on that answer is a deputy confused: every local process would
 *   get the adapter's rights.
 *
 *   **So `ncfg_client_tiers` must not be used here**, and it is the obvious
 *   wrong turn: it exists, it answers in one call, and what it answers is what
 *   this connection may do. The question is what the CALLER may do, and only
 *   the bus can say who the caller is.
 *
 * WHERE THE UID COMES FROM
 *   From the bus, never from the message. A sender name is whatever the client
 *   put in the header; `GetConnectionUnixUser` is the bus reporting what it
 *   knows about the connection it accepted. `settings.rs` says that distinction
 *   is the whole security of this, and it is.
 */
#ifndef NMC_AUTHORIZE_H
#define NMC_AUTHORIZE_H

#include <dbus/dbus.h>

#include <stddef.h>

typedef enum {
	NMC_PRINCIPAL_ROOT = 0,
	NMC_PRINCIPAL_ANY,
	NMC_PRINCIPAL_USER,
	NMC_PRINCIPAL_GROUP,
	/* A spelling this build does not know. Refused, never widened: an
	 * unrecognised principal must not read as `any`. */
	NMC_PRINCIPAL_UNKNOWN
} nmc_principal_kind_t;

typedef struct {
	nmc_principal_kind_t kind;
	char                 name[64];
} nmc_principal_t;

/*
 * netcfgd's spelling of a principal: `root`, `any`, `user:NAME`, `group:NAME`.
 *
 * Always fills `out`. An empty or unknown spelling becomes
 * `NMC_PRINCIPAL_UNKNOWN`, which `nmc_may_write` refuses -- **the one direction
 * this may fail in.** A parser that fell back to `any` would turn a typo in
 * netcfgd.conf into an open door.
 */
void nmc_principal_parse(const char *text, nmc_principal_t *out);

/*
 * The uid of whoever sent `call`, as the bus reports it.
 *
 * 1 having filled `uid`, or 0 with a sentence. A failure is a refusal: not
 * knowing who is asking is not permission to proceed.
 */
int nmc_caller_uid(DBusConnection *connection, DBusMessage *call, unsigned long *uid, char *err,
    size_t err_size);

/*
 * Whether `uid` may change the configuration, given the `admin` principal.
 *
 * 1 for yes, 0 with a sentence naming what the machine opens the tier to. The
 * sentence is for an operator, so it says how to change the answer.
 */
int nmc_may_write(unsigned long uid, const nmc_principal_t *admin, char *err, size_t err_size);

#endif /* NMC_AUTHORIZE_H */
