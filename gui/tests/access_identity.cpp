/*
 * access_identity.cpp -- does `this user` mean this user?
 *
 * The access tab's `this user` row writes a principal naming whoever is
 * running the client, into a policy that grants access to configure the
 * network. It took that name from `$USER`, which is not identity: any parent
 * process may set it to anything, it survives an `su` that does not reset it,
 * and some session launches simply do not set it.
 *
 * So the label could say `this user` while the file said somebody else. This
 * checks the kernel is asked instead, and it checks it the only way that
 * proves anything -- by making the environment lie.
 */

#include "../src/access_view.h"

#include <QCoreApplication>
#include <QString>

#include <pwd.h>
#include <unistd.h>

#include <cstdio>
#include <cstdlib>

static int failures;

static void check(bool condition, const char *what)
{
	fprintf(stderr, "access_identity: %-48s %s\n", what, condition ? "ok" : "FAILED");
	if (!condition) {
		failures++;
	}
}

int main(int argc, char **argv)
{
	QCoreApplication application(argc, argv);

	const struct passwd *entry = getpwuid(getuid());
	if (!entry || !entry->pw_name) {
		fprintf(stderr, "access_identity: this account has no passwd entry, "
		        "so there is nothing to compare against -- not a pass\n");
		return 1;
	}
	const QString real = QString::fromLocal8Bit(entry->pw_name);

	check(ncfg_access_view::current_user() == real,
	    "agrees with the password database");

	/* The case that matters. Before this was fixed the answer followed the
	 * environment, so this assertion is the whole regression. */
	setenv("USER", "definitely-not-this-account", 1);
	check(ncfg_access_view::current_user() == real,
	    "USER naming somebody else does not change it");

	unsetenv("USER");
	check(ncfg_access_view::current_user() == real, "USER unset does not empty it");
	check(!ncfg_access_view::current_user().isEmpty(),
	    "and the name is never the empty principal `user:`");

	fprintf(stderr, "access_identity: kernel says %s, environment was made to say otherwise\n",
	    qPrintable(real));
	return failures ? 1 : 0;
}
