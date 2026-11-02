/*
 * schedule_test.c -- a firewall rule's schedule, written in local time and
 * expanded into what the kernel holds in UTC (project.md 10.663).
 *
 * The cases are the ones where the arithmetic can go wrong: a window past
 * local midnight, one pushed past UTC midnight by the offset in either
 * direction, a day that moves with it, and every day. Offsets are given
 * rather than read, so the expected pieces are written out by hand here and
 * do not depend on where the test runs.
 */
#include "ncfg/schedule.h"

#include <stdio.h>
#include <string.h>

static int failures;

static void check(int condition, const char *what)
{
	printf("%-62s %s\n", what, condition ? "ok" : "FAILED");
	if (!condition) {
		failures++;
	}
}

/* The pieces as one line, `"any 75600 86399; any 0 21599"`. */
static const char *pieces_of(const char *hours, const char *const *days, size_t day_count,
    long offset)
{
	static char           text[512];
	ncfg_schedule_piece_t pieces[NCFG_SCHEDULE_PIECES_MAX];
	size_t                count;
	size_t                at;

	count = ncfg_schedule_expand(hours, (char *const *)days, day_count, offset, pieces,
	    NCFG_SCHEDULE_PIECES_MAX);
	text[0] = '\0';
	for (at = 0; at < count; at++) {
		char one[NCFG_SCHEDULE_PIECE_TEXT];

		ncfg_schedule_piece_text(&pieces[at], one, sizeof(one));
		if (at) {
			strncat(text, "; ", sizeof(text) - strlen(text) - 1u);
		}
		strncat(text, one, sizeof(text) - strlen(text) - 1u);
	}
	return text;
}

static void the_hours_as_written(void)
{
	char normal[16];
	char why[256];
	long from = -1;
	long to = -1;

	printf("\n-- hours as written\n");
	check(ncfg_schedule_hours_parse("22:00-07:00", &from, &to, normal, sizeof(normal), why,
	          sizeof(why)) && from == 79200 && to == 25200 &&
	          strcmp(normal, "22:00-07:00") == 0,
	    "a window past midnight reads as written");
	check(ncfg_schedule_hours_parse("8:05-9:30", &from, &to, normal, sizeof(normal), why,
	          sizeof(why)) && strcmp(normal, "08:05-09:30") == 0,
	    "  and one with single-digit hours is spelled with two");
	check(ncfg_schedule_hours_parse("18:00-24:00", &from, &to, normal, sizeof(normal), why,
	          sizeof(why)) && to == 86400,
	    "24:00 ends a day");
	check(ncfg_schedule_hours_parse("18:00-00:00", &from, &to, NULL, 0, why, sizeof(why)) &&
	          to == 86400,
	    "  and so does 00:00, as the same instant");
	check(!ncfg_schedule_hours_parse("24:00-07:00", NULL, NULL, NULL, 0, why, sizeof(why)),
	    "24:00 does not start one");
	check(!ncfg_schedule_hours_parse("07:00-07:00", NULL, NULL, NULL, 0, why, sizeof(why)) &&
	          strstr(why, "whole day") != NULL,
	    "a window that starts where it ends is refused, saying why");
	check(!ncfg_schedule_hours_parse("00:00-24:00", NULL, NULL, NULL, 0, why, sizeof(why)),
	    "  including the whole day written out");
	check(!ncfg_schedule_hours_parse("25:00-07:00", NULL, NULL, NULL, 0, why, sizeof(why)) &&
	          !ncfg_schedule_hours_parse("22:60-07:00", NULL, NULL, NULL, 0, why, sizeof(why)) &&
	          !ncfg_schedule_hours_parse("22:00", NULL, NULL, NULL, 0, why, sizeof(why)) &&
	          !ncfg_schedule_hours_parse("22:00-07:00x", NULL, NULL, NULL, 0, why, sizeof(why)),
	    "an hour, a minute or a shape that is not one is refused");
}

static void the_days(void)
{
	const char *normal = NULL;

	printf("\n-- days\n");
	check(ncfg_schedule_day("mon", &normal) == 1 && strcmp(normal, "mon") == 0,
	    "mon is day 1, Sunday being 0 as the kernel counts");
	check(ncfg_schedule_day("saturday", &normal) == 6 && strcmp(normal, "sat") == 0,
	    "a whole name is read and spelled short");
	check(ncfg_schedule_day("Mon", NULL) == -1 && ncfg_schedule_day("mo", NULL) == -1,
	    "anything else is not a day");
}

static void what_the_kernel_holds(void)
{
	static const char *const monday[] = { "mon" };
	static const char *const weekend[] = { "sat", "sun" };
	static const char *const all[] = { "mon", "tue", "wed", "thu", "fri", "sat", "sun" };

	printf("\n-- what the kernel holds, in UTC\n");
	check(strcmp(pieces_of("08:00-09:30", NULL, 0, 0), "any 28800 34199") == 0,
	    "at UTC a window is itself, its end the second before");
	check(strcmp(pieces_of("08:00-09:30", NULL, 0, 3600), "any 25200 30599") == 0,
	    "an hour east, it is an hour earlier");
	check(strcmp(pieces_of("22:00-07:00", NULL, 0, 0), "any 0 25199; any 79200 86399") == 0,
	    "past midnight, two pieces of every day");
	check(strcmp(pieces_of("22:00-07:00", NULL, 0, 3600), "any 0 21599; any 75600 86399") ==
	          0,
	    "  and an hour east, the two still apart and both earlier");
	check(strcmp(pieces_of("23:30-23:45", NULL, 0, -3600), "any 1800 2699") == 0,
	    "an hour west pushes a late window past UTC midnight, whole");
	check(strcmp(pieces_of("23:30-00:30", NULL, 0, -3600), "any 1800 5399") == 0,
	    "  and one across local midnight is joined into one in UTC");
	check(strcmp(pieces_of("08:00-09:00", monday, 1, 0), "1 28800 32399") == 0,
	    "a day is matched where one is named");
	check(strcmp(pieces_of("00:30-01:30", monday, 1, 3600), "0 84600 86399; 1 0 1799") == 0,
	    "an hour east, early Monday begins on Sunday in UTC -- the day moves too");
	check(strcmp(pieces_of("23:00-23:30", monday, 1, -7200), "2 3600 5399") == 0,
	    "two hours west, late Monday is Tuesday in UTC");
	check(strcmp(pieces_of("22:00-07:00", monday, 1, 0), "1 79200 86399; 2 0 25199") == 0,
	    "a window past midnight on a day runs into the next day");
	check(strcmp(pieces_of(NULL, weekend, 2, 0), "0 0 86399; 6 0 86399") == 0,
	    "days alone are those whole days");
	check(strcmp(pieces_of(NULL, weekend, 2, 3600), "0 0 82799; 5 82800 86399; 6 0 86399") ==
	          0,
	    "  which an hour east begin on Friday's last hour");
	check(strcmp(pieces_of("08:00-09:00", all, 7, 0), pieces_of("08:00-09:00", NULL, 0, 0)) ==
	          0,
	    "all seven days is every day, with no day matched");
	check(strcmp(pieces_of("25:00-07:00", NULL, 0, 0), "") == 0,
	    "hours that do not parse expand to nothing");
}

static void pieces_as_text(void)
{
	ncfg_schedule_piece_t piece;
	char                  text[NCFG_SCHEDULE_PIECE_TEXT];

	printf("\n-- a piece as text, for the undo copy\n");
	check(ncfg_schedule_piece_read("any 75600 86399", &piece) && piece.day == -1 &&
	          piece.from == 75600 && piece.to == 86399,
	    "every day reads back");
	check(ncfg_schedule_piece_read("1 0 21599", &piece) && piece.day == 1,
	    "  and a day");
	ncfg_schedule_piece_text(&piece, text, sizeof(text));
	check(strcmp(text, "1 0 21599") == 0, "and writes as it read");
	ncfg_schedule_piece_describe(&piece, text, sizeof(text));
	check(strcmp(text, "mon 00:00-05:59:59 UTC") == 0,
	    "and for a person, the day, the clock and that it is UTC");
	check(!ncfg_schedule_piece_read("7 0 1", &piece) &&
	          !ncfg_schedule_piece_read("1 5 4", &piece) &&
	          !ncfg_schedule_piece_read("1 0 86400", &piece) &&
	          !ncfg_schedule_piece_read("1 0 1 x", &piece),
	    "a day, an order, an end or a tail that is not one is refused");
}

static void the_offset(void)
{
	printf("\n-- the offset\n");
	ncfg_schedule_offset_fix(1, 19800);
	check(ncfg_schedule_offset() == 19800, "a test may fix it");
	ncfg_schedule_offset_fix(0, 0);
	check(ncfg_schedule_offset() > -14L * 3600L && ncfg_schedule_offset() < 15L * 3600L,
	    "and otherwise it is the machine's, inside the world's range");
}

int main(void)
{
	the_hours_as_written();
	the_days();
	what_the_kernel_holds();
	pieces_as_text();
	the_offset();
	if (failures) {
		printf("\nschedule_test: %d check(s) FAILED\n", failures);
		return 1;
	}
	printf("\nschedule_test: all checks passed\n");
	return 0;
}
