/* authorize.c -- the uid from the bus, and the policy from the document. */
#include "nmc/authorize.h"

#include <pwd.h>
#include <stdio.h>
#include <string.h>

void nmc_principal_parse(const char *text, nmc_principal_t *out)
{
	memset(out, 0, sizeof(*out));
	out->kind = NMC_PRINCIPAL_UNKNOWN;
	if (!text || text[0] == '\0') {
		return;
	}
	if (strcmp(text, "root") == 0) {
		out->kind = NMC_PRINCIPAL_ROOT;
		return;
	}
	if (strcmp(text, "any") == 0) {
		out->kind = NMC_PRINCIPAL_ANY;
		return;
	}
	if (strncmp(text, "user:", 5u) == 0) {
		out->kind = NMC_PRINCIPAL_USER;
		(void)snprintf(out->name, sizeof(out->name), "%s", text + 5);
		return;
	}
	if (strncmp(text, "group:", 6u) == 0) {
		out->kind = NMC_PRINCIPAL_GROUP;
		(void)snprintf(out->name, sizeof(out->name), "%s", text + 6);
		return;
	}
	/* Left UNKNOWN on purpose. See the header. */
}

int nmc_caller_uid(DBusConnection *connection, DBusMessage *call, unsigned long *uid, char *err,
    size_t err_size)
{
	const char *sender;
	DBusError   problem;
	unsigned long answered;

	*uid = (unsigned long)-1;
	if (!connection || !call) {
		(void)snprintf(err, err_size, "there is no connection to ask who is calling");
		return 0;
	}
	sender = dbus_message_get_sender(call);
	if (!sender) {
		/*
		 * No sender means a peer-to-peer connection with no bus to ask.
		 * **Refused rather than assumed**: this shim is only ever reached
		 * through a bus, so the absence is an arrangement nobody designed
		 * and is not an invitation to skip the check.
		 */
		(void)snprintf(err, err_size,
		    "the bus did not say who is calling, so this cannot decide whether they may "
		    "change the configuration");
		return 0;
	}
	dbus_error_init(&problem);
	/*
	 * **The bus is asked, not the message.** A sender name is whatever the
	 * client wrote; this is the bus reporting the credentials of the
	 * connection it accepted, which the client cannot choose.
	 */
	answered = (unsigned long)dbus_bus_get_unix_user(connection, sender, &problem);
	if (dbus_error_is_set(&problem)) {
		(void)snprintf(err, err_size, "the bus would not say who %s is: %s", sender,
		    problem.message);
		dbus_error_free(&problem);
		return 0;
	}
	dbus_error_free(&problem);
	*uid = answered;
	return 1;
}

int nmc_may_write(unsigned long uid, const nmc_principal_t *admin, char *err, size_t err_size)
{
	const struct passwd *who;

	/*
	 * Root may, whatever the document says. Not a shortcut: root can edit
	 * the file this would write, so refusing would be theatre.
	 */
	if (uid == 0u) {
		return 1;
	}
	switch (admin->kind) {
	case NMC_PRINCIPAL_ANY:
		return 1;
	case NMC_PRINCIPAL_USER:
		who = getpwnam(admin->name);
		if (who && (unsigned long)who->pw_uid == uid) {
			return 1;
		}
		(void)snprintf(err, err_size,
		    "not permitted: changing netcfgd's configuration needs the `admin` tier, "
		    "which this machine opens to the user `%s`",
		    admin->name);
		return 0;
	case NMC_PRINCIPAL_ROOT:
		(void)snprintf(err, err_size,
		    "not permitted: changing netcfgd's configuration needs the `admin` tier, "
		    "which this machine keeps to root. Open it in the `control` block, or edit "
		    "the configuration directly");
		return 0;
	case NMC_PRINCIPAL_GROUP:
		/*
		 * **The one refusal that is about this transport and not about the
		 * caller.** A message bus reports a connection's user and not its
		 * groups, so whether this caller is in the group cannot be known
		 * here -- and it will not be guessed. Reading `/etc/group` would
		 * miss supplementary groups from every other source, and
		 * `getgrouplist` answers for a NAME rather than for the process
		 * that is actually calling. `ncfg` sees the real credentials over
		 * a unix socket and can do this; a bus cannot.
		 */
		(void)snprintf(err, err_size,
		    "not permitted here: the `admin` tier is open to the group `%s`, and a "
		    "message bus reports a caller's user but not its groups -- so this cannot "
		    "tell whether you are in it, and will not guess. `ncfg` sees your groups "
		    "over the socket and can do this",
		    admin->name);
		return 0;
	case NMC_PRINCIPAL_UNKNOWN:
	default:
		(void)snprintf(err, err_size,
		    "not permitted: this build does not understand the `admin` principal in "
		    "netcfgd's `control` block, and an unrecognised one is refused rather than "
		    "widened");
		return 0;
	}
}
