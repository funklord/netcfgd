/*
 * main.c -- the one place in the C port that decides an exit status.
 *
 * **A `main` is not a library, and this is the file that says so.** 0263's
 * third convention -- a library never exits, never asserts and never prints --
 * is what every file under `c/src/` is written to, and it only works because
 * something above them all turns a returned sentence into a line and a
 * returned 0 into a status. That something is this function, and it is
 * deliberately the smallest file in the directory: it chooses a program and
 * hands over. Nothing is decided here that a test could not otherwise reach,
 * because a test cannot have two `main`s.
 *
 * `src/main/` is kept out of `libncfg.a` for the same reason. An archive that
 * enforces "a library never exits" would otherwise have a `main` inside it.
 */
#include "loop_internal.h"
#include "main_internal.h"

#include "ncfg/log.h"
#include "ncfg/cli.h"

int main(int argc, char **argv)
{
	/*
	 * `argv[0]` may be absent entirely -- `execve` takes an empty vector, and
	 * a caller that wants to see what this does with one is exactly the caller
	 * that must not be guessed at. It arrives as no name, which is the arm
	 * that refuses.
	 */
	const char *called_as = argc > 0 ? argv[0] : "";

	switch (ncfg_main_program_for(called_as)) {
	case NCFG_MAIN_PROGRAM_CLIENT:
		/*
		 * **With a way to reach the machine, which only this program gives
		 * it.** `ncfg apply` is the one verb that changes anything, and
		 * `cli.h` keeps the library half unable to: a test drives the same
		 * command through a recorder, and an embedder that installs nothing
		 * gets a refusal rather than an apply. Which directories this run means
		 * is the command line's answer and arrives with the call, not this
		 * one's: a second parse of `argv` here is a second answer.
		 */
		/*
		 * **`NCFG_LOG` obeyed, and the level left where the log module puts
		 * it.** The client never read `NCFG_LOG` at all -- only the daemon
		 * did -- so `NCFG_LOG=debug ncfg status` turned nothing up, which is
		 * the first thing anybody would try. That half is this line.
		 *
		 * **The other half was a `WARNING` floor, and it is gone.** It was
		 * put here because `ncfg apply` printed every action twice, once as
		 * its own report and once as the apply engine's `INFO` line beside
		 * it -- and a floor silences a duplicate by silencing the whole
		 * level, which is two steps stricter than the Rust, whose default is
		 * `Info`. Everything the backends say at `INFO` went with it: the
		 * dhcp adoption notice is one, and `tests/live/dhcpcd_orphan.sh`
		 * reads it to tell adoption from a blind re-run because the client
		 * count cannot -- a second `dhcpcd -b` against a running one is a
		 * silent no-op, so the count is 1 either way.
		 *
		 * `ncfg_apply_silently` is the duplicate's actual fix: the engine
		 * withholds its own narration for the one caller that renders the
		 * journal, and nobody else's lines are taken. So the floor has no
		 * remaining reason and the levels agree across the two builds.
		 *
		 * Here and not in `ncfg_cli_main_on`, because reading the
		 * environment is a policy of the PROGRAM: a test driving the same
		 * entry point, or an embedder with its own logging, inherits
		 * nothing from it.
		 */
		ncfg_log_accept_from_env();
		return ncfg_cli_main_on(argc, argv, ncfg_main_cli_machine());
	case NCFG_MAIN_PROGRAM_DAEMON:
		return ncfg_main_netcfgd(argc, argv);
	case NCFG_MAIN_PROGRAM_PROBE:
		return ncfg_main_probe(argc, argv);
	case NCFG_MAIN_PROGRAM_NONE:
	default:
		return ncfg_main_miscalled(called_as);
	}
}
