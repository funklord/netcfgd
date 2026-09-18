/*
 * radio_test.c -- "is this a radio", against a fixture rather than against
 * whatever hardware the developer's machine happens to contain.
 *
 * WHY THE FIXTURE ROOT EXISTS AT ALL
 *   A test that reads `/sys/class/net` passes on a build machine with no radio
 *   and does something else on a laptop, and neither run tells you the rule is
 *   right. So the predicate takes its root as a parameter and this file builds
 *   one: a directory it makes, fills, asserts against and removes by name.
 *
 * THE CASE THE OLD FIXTURE COULD NOT PRODUCE (0231)
 *   The Rust's first fixture made a `wireless` directory, which is what
 *   `CONFIG_CFG80211_WEXT` provides -- so it agreed with a predicate that asked
 *   for exactly that, and a kernel without the option was outside what it could
 *   describe. All three shapes are below: cfg80211 alone, both, and Wireless
 *   Extensions alone.
 *
 * WHAT IS ASKED OF THE MACHINE, AND WHAT IS NOT
 *   Two read-only things: that `lo` is not a radio, which is true on every
 *   machine and is the one negative case that can be asserted anywhere, and
 *   that every name the listing returns answers true to the predicate -- an
 *   invariant rather than a list, because the list is the machine's. Nothing
 *   here creates, writes or watches anything outside its own temporary
 *   directory, and every path it makes is removed by name at the end.
 */
#include "ncfg/base.h"
#include "ncfg/radio.h"

#include "tempdir.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

static int failures;

static void check(int condition, const char *what)
{
	printf("%-58s %s\n", what, condition ? "ok" : "FAILED");
	if (!condition) {
		failures++;
	}
}

/* Every directory this test makes, in the order it makes them, so that the
 * cleanup at the bottom removes exactly those and nothing by a pattern. */
#define MADE_MAX 16
static char made[MADE_MAX][512];
static size_t made_count;

/* `mkdir -p` for one interface's attribute, remembering both levels. */
static int make_attribute(const char *root, const char *link, const char *attribute)
{
	char path[512];

	if (made_count + 2u > MADE_MAX) {
		return 0;
	}
	if (snprintf(path, sizeof(path), "%s/%s", root, link) < 0) {
		return 0;
	}
	if (mkdir(path, 0700) != 0) {
		struct stat found;

		/* A second attribute under a link this test already made is
		 * ordinary; anything else is not. */
		if (stat(path, &found) != 0) {
			return 0;
		}
	} else {
		(void)snprintf(made[made_count++], sizeof(made[0]), "%s", path);
	}
	if (!attribute) {
		return 1;
	}
	if (snprintf(path, sizeof(path), "%s/%s/%s", root, link, attribute) < 0) {
		return 0;
	}
	if (mkdir(path, 0700) != 0) {
		return 0;
	}
	(void)snprintf(made[made_count++], sizeof(made[0]), "%s", path);
	return 1;
}

int main(void)
{
	char   root[256];
	char   real[NCFG_RADIO_ROOT_MAX];
	size_t at;

	if (!tempdir_make("radio", root, sizeof(root))) {
		printf("radio_test: could not make a fixture directory\n");
		return 1;
	}

	/* The three shapes a radio comes in, and a wired port, which has
	 * neither attribute. */
	{
		int built = 1;

		/* A modern kernel with the compatibility layer off: cfg80211's
		 * own attribute and nothing else. */
		built = built && make_attribute(root, "wlan0", "phy80211");
		/* The same kernel with the option on, which is what the
		 * reporting machine has: both attributes. */
		built = built && make_attribute(root, "wlan1", "phy80211");
		built = built && make_attribute(root, "wlan1", "wireless");
		/* A driver too old to have a cfg80211 device at all. This is
		 * the case `-Dnl80211,wext` exists for, and the two have to
		 * agree that it is a radio. */
		built = built && make_attribute(root, "wlan2", "wireless");
		built = built && make_attribute(root, "eth0", NULL);
		check(built, "a fixture root is built rather than the machine read");

		check(ncfg_radio_is_wireless(root, "wlan0"),
		    "a radio with no wireless-extensions attribute is still a radio");
		check(ncfg_radio_is_wireless(root, "wlan1"),
		    "a radio with both attributes is one");
		check(ncfg_radio_is_wireless(root, "wlan2"),
		    "and a driver with only the old attribute is one");
		check(!ncfg_radio_is_wireless(root, "eth0"), "a wired port is not");
		check(!ncfg_radio_is_wireless(root, "wlan9"),
		    "and an interface that is not there is not");
	}

	/* The listing: sorted, and every radio in it. */
	{
		ncfg_radio_links_t links;
		char               err[NCFG_ERROR_MAX];
		int                every = 1;
		int                sorted = 1;

		memset(&links, 0, sizeof(links));
		err[0] = '\0';
		check(ncfg_radio_links(root, &links, err, sizeof(err)), "the fixture lists");
		check(links.count == 3u, "and it lists exactly the three radios");
		for (at = 0; at < links.count; at++) {
			every = every && ncfg_radio_is_wireless(root, links.items[at]);
			if (at > 0) {
				sorted = sorted &&
				    strcmp(links.items[at - 1u], links.items[at]) < 0;
			}
		}
		check(every, "every name it lists is one it calls a radio");
		check(sorted, "and they come back in a stable order");
		if (links.count == 3u) {
			check(strcmp(links.items[0], "wlan0") == 0 &&
			    strcmp(links.items[1], "wlan1") == 0 &&
			    strcmp(links.items[2], "wlan2") == 0,
			    "and they are the three the fixture made");
		}
		ncfg_radio_links_free(&links);
		check(links.count == 0u && links.items == NULL,
		    "freeing a list leaves it usable and empty");
		/* Freeing something that was never filled in is nothing. */
		ncfg_radio_links_free(&links);
	}

	/*
	 * A name that would leave the root is refused rather than joined.
	 *
	 * These come from configuration files, and `..` in one would ask about a
	 * directory that has nothing to do with interfaces. `.` is the case a
	 * separator test alone lets through: it carries no slash and no `..`,
	 * and it asks whether the class directory itself is a radio.
	 */
	{
		check(!ncfg_radio_is_wireless(root, "../../dev/null"),
		    "a name that climbs out of the root is not a radio");
		check(!ncfg_radio_is_wireless(root, "wlan0/../eth0"),
		    "nor one with a separator in it");
		check(!ncfg_radio_is_wireless(root, ""), "nor the empty name");
		check(!ncfg_radio_is_wireless(root, "."), "nor the root itself");
		check(!ncfg_radio_is_wireless(root, "a-name-far-too-long-for-an-interface"),
		    "nor one longer than an interface name can be");
		check(!ncfg_radio_is_wireless(NULL, "wlan0"), "and a predicate with no root is 0");
	}

	/* A directory that is not there is an empty list and a success, not a
	 * refusal: a container and a machine with no radio are the same answer. */
	{
		ncfg_radio_links_t links;
		char               missing[600];

		(void)snprintf(missing, sizeof(missing), "%s/not-mounted", root);
		memset(&links, 0, sizeof(links));
		check(ncfg_radio_links(missing, &links, NULL, 0),
		    "a root that cannot be read is not a failure");
		check(links.count == 0u, "and it lists nothing");
		ncfg_radio_links_free(&links);
	}

	/* The default root, and the variable that overrides it. */
	{
		char err[NCFG_ERROR_MAX];

		check(ncfg_radio_class_net(real, sizeof(real), err, sizeof(err)),
		    "the sysfs root is answered");
		check(real[0] == '/', "and it is an absolute path");
		if (!getenv(NCFG_RADIO_CLASS_NET_ENV)) {
			check(strcmp(real, NCFG_RADIO_CLASS_NET) == 0,
			    "which with nothing in the environment is the kernel's");
		}
		check(!ncfg_radio_class_net(real, 8u, err, sizeof(err)),
		    "a buffer too small for a root is a refusal");
	}

	/*
	 * What can be asserted about the machine itself, which is two things.
	 *
	 * `lo` exists everywhere and is never a radio. And whatever the listing
	 * finds, it finds consistently -- the invariant a caller relies on when
	 * it uses the list to pick an interface. Neither reads anything but the
	 * existence of a file.
	 */
	{
		ncfg_radio_links_t links;
		int                every = 1;

		check(!ncfg_radio_is_wireless(real, "lo"), "loopback is not a radio");
		memset(&links, 0, sizeof(links));
		if (ncfg_radio_links(real, &links, NULL, 0)) {
			for (at = 0; at < links.count; at++) {
				every = every && ncfg_radio_is_wireless(real, links.items[at]);
			}
		}
		check(every, "every radio this machine lists answers the predicate");
		ncfg_radio_links_free(&links);
	}

	/* Removed by name, in reverse order, because the attribute is inside the
	 * link. Nothing here removes by pattern and nothing removes a path this
	 * test did not create. */
	for (at = made_count; at > 0; at--) {
		if (rmdir(made[at - 1u]) != 0) {
			printf("radio_test: could not remove %s\n", made[at - 1u]);
			failures++;
		}
	}
	if (rmdir(root) != 0) {
		printf("radio_test: could not remove %s\n", root);
		failures++;
	}

	if (failures == 0) {
		printf("radio_test: all checks passed\n");
	} else {
		printf("radio_test: %d check(s) failed\n", failures);
	}
	return failures == 0 ? 0 : 1;
}
