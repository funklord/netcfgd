/*
 * tun_test.c -- the request, the order, and the refusals -- with no device
 * made anywhere.
 *
 * WHAT CANNOT BE TESTED HERE, AND WHAT IS TESTED INSTEAD
 *   Making a tun device needs `CAP_NET_ADMIN` and a clone device, and this
 *   suite runs on the machine netcfgd is configuring: a device made here is a
 *   device left on somebody's workstation. So nothing below opens
 *   `/dev/net/tun`. What is checked instead is everything that decides what the
 *   kernel would be told:
 *
 *     * the bytes of the `TUNSETIFF` request, field by field, including
 *       `IFF_NO_PI`, whose absence is invisible until something attaches to the
 *       device and finds four bytes of protocol header it did not expect;
 *     * **the order of the ioctls**, which is the property decision 0254 is
 *       about and the one that is silent when wrong -- owner and group before
 *       persistence so a device that cannot be given its owner is not left
 *       behind, and persistence last because it is the reason the device
 *       survives the call at all;
 *     * the four request numbers, against the values 0254 measured against
 *       `ip tuntap` producing the same device. The header is the source of them
 *       now; this is the check that the header and the record still agree.
 *
 *   The one call that touches the filesystem hands `ncfg_tun_create` an
 *   ordinary file in this test's own temporary directory. The open succeeds and
 *   the first ioctl fails with `ENOTTY`, which exercises the failure path --
 *   the step is named, the descriptor is closed, nothing is left -- without a
 *   device, a privilege or the machine's clone device.
 */
#include "ncfg/base.h"
#include "ncfg/tun.h"

#include "tempdir.h"

#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

#include <linux/if_tun.h>

static int failures;

static void check(int condition, const char *what)
{
	printf("%-58s %s\n", what, condition ? "ok" : "FAILED");
	if (!condition) {
		failures++;
	}
}

int main(void)
{
	char root[256];
	char file[320] = "";

	if (!tempdir_make("tun", root, sizeof(root))) {
		printf("tun_test: could not make a temporary directory\n");
		return 1;
	}

	/* The two modes, and the name the configuration language gives each.
	 * The block's *name* is the mode, so a reader that answered `tun` for
	 * both would open a tap as a tun and save it as one -- a device
	 * silently replaced by the other sort. */
	{
		ncfg_tun_mode_t mode = NCFG_TUN_MODE_TAP;

		check(strcmp(ncfg_tun_mode_name(NCFG_TUN_MODE_TUN), "tun") == 0,
		    "a tun is spelled tun");
		check(strcmp(ncfg_tun_mode_name(NCFG_TUN_MODE_TAP), "tap") == 0,
		    "and a tap is spelled tap");
		check(ncfg_tun_mode_from_name("tun", &mode) && mode == NCFG_TUN_MODE_TUN,
		    "the name tun asks for a tun");
		check(ncfg_tun_mode_from_name("tap", &mode) && mode == NCFG_TUN_MODE_TAP,
		    "the name tap asks for a tap");
		check(!ncfg_tun_mode_from_name("tunnel", &mode),
		    "and anything else is refused rather than defaulted");
		check(!ncfg_tun_mode_from_name(NULL, &mode), "as is no name at all");
	}

	/* `IFF_NO_PI` always, which is what `ip tuntap add` does without saying
	 * so. Without it the device looks subtly broken to whatever attaches
	 * rather than failing to appear. */
	{
		check(ncfg_tun_flags(NCFG_TUN_MODE_TUN) == (int16_t)(IFF_TUN | IFF_NO_PI),
		    "a tun asks for IFF_TUN with IFF_NO_PI");
		check(ncfg_tun_flags(NCFG_TUN_MODE_TAP) == (int16_t)(IFF_TAP | IFF_NO_PI),
		    "a tap asks for IFF_TAP with the same");
		check((ncfg_tun_flags(NCFG_TUN_MODE_TUN) & IFF_NO_PI) != 0 &&
		    (ncfg_tun_flags(NCFG_TUN_MODE_TAP) & IFF_NO_PI) != 0,
		    "neither mode can be asked for without it");
	}

	/* The request the kernel reads. */
	{
		ncfg_tun_spec_t    spec;
		ncfg_tun_request_t request;
		int                padded = 1;
		size_t             at;

		memset(&spec, 0, sizeof(spec));
		spec.name = "tun0";
		spec.mode = NCFG_TUN_MODE_TAP;

		check(sizeof(request) == NCFG_TUN_REQUEST_LEN,
		    "a request is the forty bytes an ifreq is");
		memset(&request, 0xff, sizeof(request));
		check(ncfg_tun_request(&spec, &request, NULL, 0), "a request is built");
		check(strcmp(request.name, "tun0") == 0, "carrying the name");
		check(request.flags == (int16_t)(IFF_TAP | IFF_NO_PI), "and the mode's flags");
		for (at = 0; at < sizeof(request.padding); at++) {
			padded = padded && request.padding[at] == 0;
		}
		check(padded, "with a zeroed tail, whatever the buffer held before");
		check(request.name[sizeof(request.name) - 1u] == '\0',
		    "and a name array the kernel cannot read past");
	}

	/* The boundary the kernel's field has, which is a terminator short of
	 * the array. A name that filled it would come back as whatever the next
	 * field happens to hold. */
	{
		ncfg_tun_spec_t    spec;
		ncfg_tun_request_t request;
		char               err[NCFG_ERROR_MAX];

		memset(&spec, 0, sizeof(spec));
		spec.mode = NCFG_TUN_MODE_TUN;

		spec.name = "abcdefghijklmno";	/* fifteen, and its terminator */
		check(ncfg_tun_request(&spec, &request, NULL, 0),
		    "a name of fifteen bytes is one the kernel would take");
		check(strcmp(request.name, "abcdefghijklmno") == 0, "and arrives whole");

		spec.name = "abcdefghijklmnop";	/* sixteen */
		err[0] = '\0';
		check(!ncfg_tun_request(&spec, &request, err, sizeof(err)),
		    "one of sixteen is refused rather than truncated");
		check(strstr(err, "abcdefghijklmnop") != NULL, "and the refusal quotes it");

		spec.name = "";
		check(!ncfg_tun_request(&spec, &request, NULL, 0), "the empty name is refused");
		spec.name = NULL;
		check(!ncfg_tun_request(&spec, &request, NULL, 0), "as is no name at all");
		check(!ncfg_tun_request(&spec, NULL, NULL, 0),
		    "as is a request with nowhere to go");
	}

	/*
	 * The order, which is the whole of 0254.
	 *
	 * Asserted as a value rather than read out of the source, because the
	 * alternative is a machine with `CAP_NET_ADMIN` making a device and
	 * watching it disappear.
	 */
	{
		ncfg_tun_spec_t spec;
		ncfg_tun_step_t steps[NCFG_TUN_STEPS_MAX];
		size_t          count = 0;

		memset(&spec, 0, sizeof(spec));
		spec.name = "tun0";
		spec.mode = NCFG_TUN_MODE_TUN;
		spec.has_owner = 1;
		spec.owner = 1000;
		spec.has_group = 1;
		spec.group = 1001;

		check(ncfg_tun_plan(&spec, steps, NCFG_TUN_STEPS_MAX, &count, NULL, 0),
		    "a plan with an owner and a group is made");
		check(count == 4u, "and it is four ioctls");
		if (count == 4u) {
			check(steps[0].request == TUNSETIFF && steps[0].is_request_struct,
			    "the mode is asked for first, and by pointer");
			check(steps[1].request == TUNSETOWNER && steps[1].value == 1000u,
			    "then the owner, by value");
			check(steps[2].request == TUNSETGROUP && steps[2].value == 1001u,
			    "then the group");
			check(steps[3].request == TUNSETPERSIST && steps[3].value == 1u,
			    "and persistence last, which is why the device survives");
			check(!steps[1].is_request_struct && !steps[2].is_request_struct &&
			    !steps[3].is_request_struct,
			    "the three after the first take an integer, not a pointer");
			check(strcmp(steps[1].what, "TUNSETOWNER") == 0,
			    "each step is named for the sentence a failure becomes");
		}

		/* The ordering that matters is not "owner is second" but "owner
		 * is before persistence": a device that cannot be given its
		 * owner must not have been made to persist. */
		spec.has_owner = 1;
		spec.has_group = 0;
		check(ncfg_tun_plan(&spec, steps, NCFG_TUN_STEPS_MAX, &count, NULL, 0) &&
		    count == 3u, "a plan with an owner alone is three");
		check(steps[1].request == TUNSETOWNER &&
		    steps[2].request == TUNSETPERSIST,
		    "and the owner is still set before the device is made to persist");

		spec.has_owner = 0;
		check(ncfg_tun_plan(&spec, steps, NCFG_TUN_STEPS_MAX, &count, NULL, 0) &&
		    count == 2u, "a plan with neither is two");
		check(steps[0].request == TUNSETIFF && steps[1].request == TUNSETPERSIST,
		    "the mode and then persistence, and nothing skipped in between");

		spec.name = "";
		check(!ncfg_tun_plan(&spec, steps, NCFG_TUN_STEPS_MAX, &count, NULL, 0),
		    "a plan for a name the kernel would refuse is refused first");
		check(count == 0u, "and it plans nothing");
		spec.name = "tun0";
		check(!ncfg_tun_plan(&spec, steps, 2u, &count, NULL, 0),
		    "as is one with nowhere to put every step");
	}

	/*
	 * The four request numbers, against what 0254 measured.
	 *
	 * The Rust wrote these out because `libc` does not export them; this
	 * port takes them from <linux/if_tun.h>. The check is that the two
	 * agree -- a kernel header that disagreed with the numbers `ip tuntap`
	 * was compared against would be a device made by a different call.
	 */
	{
		check((unsigned long)TUNSETIFF == 0x400454caUL, "TUNSETIFF is _IOW('T', 202, int)");
		check((unsigned long)TUNSETPERSIST == 0x400454cbUL, "TUNSETPERSIST is 203");
		check((unsigned long)TUNSETOWNER == 0x400454ccUL, "TUNSETOWNER is 204");
		check((unsigned long)TUNSETGROUP == 0x400454ceUL, "TUNSETGROUP is 206");
	}

	/*
	 * The failure path, against an ordinary file rather than a clone device.
	 *
	 * The open succeeds, `TUNSETIFF` answers `ENOTTY`, and what is asserted
	 * is that the refusal names the step -- which is the whole reason the
	 * steps carry names.
	 */
	{
		char err[NCFG_ERROR_MAX];
		ncfg_tun_spec_t spec;
		int             made;

		(void)snprintf(file, sizeof(file), "%s/not-a-clone-device", root);
		made = open(file, O_RDWR | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
		check(made >= 0, "a file that is not a clone device is made to ask through");
		if (made >= 0) {
			(void)close(made);
		}

		memset(&spec, 0, sizeof(spec));
		spec.name = "ncfgtest0";
		spec.mode = NCFG_TUN_MODE_TUN;
		err[0] = '\0';
		check(!ncfg_tun_create(file, &spec, err, sizeof(err)),
		    "a clone device that is not one cannot make a device");
		check(strstr(err, "TUNSETIFF") != NULL, "and the refusal names the step");
		check(strstr(err, "ncfgtest0") != NULL, "and the device it was for");

		/* And the open itself, which is the third of the three things an
		 * operator would do something different about. */
		err[0] = '\0';
		check(!ncfg_tun_create("/nonexistent/net/tun", &spec, err, sizeof(err)),
		    "a clone device that is not there cannot either");
		check(strstr(err, "module") != NULL,
		    "and that refusal names the likely cause instead");

		/* The name is refused before anything is opened: the clone
		 * device here does not exist, so a message about the *name*
		 * proves the check came first. */
		spec.name = "abcdefghijklmnop";
		err[0] = '\0';
		check(!ncfg_tun_create("/nonexistent/net/tun", &spec, err, sizeof(err)),
		    "a name the kernel would refuse is refused too");
		check(strstr(err, "not a name") != NULL,
		    "before the clone device is so much as opened");

		check(!ncfg_tun_create(NULL, &spec, NULL, 0),
		    "and a create with no clone device is refused");
	}

	if (unlink(file) != 0) {
		printf("tun_test: could not remove %s\n", file);
		failures++;
	}
	if (rmdir(root) != 0) {
		printf("tun_test: could not remove %s\n", root);
		failures++;
	}

	if (failures == 0) {
		printf("tun_test: all checks passed\n");
	} else {
		printf("tun_test: %d check(s) failed\n", failures);
	}
	return failures == 0 ? 0 : 1;
}
