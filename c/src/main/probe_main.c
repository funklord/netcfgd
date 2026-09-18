/*
 * probe_main.c -- `netcfgd-probe`, which is four lines because the body is not.
 *
 * WHY THIS IS THE ONLY FINISHED ENTRY POINT HERE
 *   `ncfg_portal_helper` is the whole of the child: it sheds every privilege,
 *   sets the alarm it cannot outlive, fetches the URL, and answers the exit
 *   status and the one line to print. 0263 puts the division exactly there --
 *   a library never prints and never exits, so the call returns those two
 *   things and the caller does both. It is the only difference between this
 *   and the Rust's `helper_main`, and it is the reason `portal_test.c` can
 *   drive every exit status the parent must tell apart without a binary.
 *
 * WHY THE LINE GOES TO STDOUT
 *   Because the parent reads it. `ncfg_portal_probe` gives the child a pipe on
 *   descriptor 1 and `/dev/null` on 2, and what comes back on 1 is the verdict
 *   -- the status line the far side answered with, or the sentence saying
 *   there was no answer. Anything this printed to stderr would be discarded by
 *   the parent and is discarded here by not existing.
 */
#include "main_internal.h"

#include "ncfg/base.h"
#include "ncfg/log.h"
#include "ncfg/portal.h"

int ncfg_main_probe(int argc, char **argv)
{
	char said[NCFG_ERROR_MAX];
	int  status;

	if (argc < 2 || !argv[1]) {
		/*
		 * Reachable only by hand: the daemon always passes a URL, and nothing
		 * on disk is called this. It is still worth a usage line rather than a
		 * silent failure, because the person who reached it renamed a copy of
		 * netcfgd and is owed a sentence saying what it wanted.
		 */
		ncfg_out_line("usage: " NCFG_PORTAL_HELPER_NAME " <url>");
		return NCFG_MAIN_EXIT_FAILED;
	}
	/*
	 * **One-directional and past the point of return.** Everything after this
	 * call runs with no capabilities, under an alarm, in a process whose only
	 * remaining job is to print one line and end.
	 */
	status = ncfg_portal_helper(argv[1], said, sizeof(said));
	ncfg_out_line(said);
	return status;
}
