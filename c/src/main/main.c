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
		 * **Quiet by default, and `NCFG_LOG` still obeyed.**
		 *
		 * Two things were wrong and one line fixes both. The client never
		 * read `NCFG_LOG` at all -- only the daemon did -- so
		 * `NCFG_LOG=debug ncfg status` turned nothing up, which is the
		 * first thing anybody would try. And the default is `INFO`, while
		 * a command's report is its STDOUT: now that applying an action
		 * logs one, `ncfg apply` would print every action twice, once as
		 * its own output and once as a log line beside it.
		 *
		 * So the floor is `WARNING` and `accept_from_env` overrides it when
		 * asked. A warning still reaches the operator, which is what the
		 * `!` lines on an unprivileged `ncfg status` are; what goes is the
		 * running commentary that duplicates the thing being printed.
		 *
		 * Here and not in `ncfg_cli_main_on`, because this is a policy of
		 * the PROGRAM: a test driving the same entry point, or an embedder
		 * with its own logging, inherits nothing from it.
		 */
		ncfg_log_accept(NCFG_LOG_WARNING);
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
