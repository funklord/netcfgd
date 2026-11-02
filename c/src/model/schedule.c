/*
 * schedule.c -- the schedule described in schedule.h.
 *
 * THE ONE ARITHMETIC THAT MATTERS
 *   A local window [s, e) on day d is [s - offset, e - offset) in UTC, and
 *   either end can leave the day: a window late on Monday in Tokyo is Monday
 *   morning in UTC, an early one is Sunday's evening. So each local piece is
 *   moved by whole days until it starts inside one, its day moved with it,
 *   and split where it runs past UTC midnight. Every-day pieces move without
 *   a day to carry. That is the whole of what nft's own conversion leaves out.
 */
#include "ncfg/schedule.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static const char *const day_words[7] = { "sun", "mon", "tue", "wed", "thu", "fri", "sat" };
static const char *const day_names[7] = { "sunday", "monday", "tuesday", "wednesday",
	                                     "thursday", "friday", "saturday" };

static int offset_fixed;
static long offset_seconds;

static void say(char *why, size_t why_size, const char *text)
{
	if (why && why_size) {
		(void)snprintf(why, why_size, "%s", text);
	}
}

/* `H:MM` or `HH:MM`, 00:00 to 24:00, as seconds. Advances `*at`. */
static int clock_read(const char **at, long *out)
{
	const char *p = *at;
	long        hours = 0;
	long        minutes;
	int         digits = 0;

	while (*p >= '0' && *p <= '9' && digits < 2) {
		hours = hours * 10 + (*p - '0');
		p++;
		digits++;
	}
	if (digits == 0 || *p != ':' || p[1] < '0' || p[1] > '5' || p[2] < '0' || p[2] > '9') {
		return 0;
	}
	minutes = (p[1] - '0') * 10 + (p[2] - '0');
	if (hours > 24 || (hours == 24 && minutes != 0)) {
		return 0;
	}
	*out = hours * 3600L + minutes * 60L;
	*at = p + 3;
	return 1;
}

int ncfg_schedule_hours_parse(const char *text, long *from, long *to, char *normal,
    size_t normal_size, char *why, size_t why_size)
{
	const char *at = text;
	long        start;
	long        end;

	if (!text || !clock_read(&at, &start) || *at != '-' || (at++, !clock_read(&at, &end)) ||
	    *at != '\0') {
		say(why, why_size,
		    "is not a window of the day: write it as `22:00-07:00`, from and until, in "
		    "the machine's local time");
		return 0;
	}
	if (start == NCFG_SCHEDULE_DAY_SECONDS) {
		say(why, why_size, "starts at 24:00, which is the next day's 00:00: write that");
		return 0;
	}
	/* `24:00` ends a day; as a start it is refused above, and as an end it is
	 * the same instant as `00:00`, so the window is compared on that. */
	if (start == end % NCFG_SCHEDULE_DAY_SECONDS) {
		say(why, why_size,
		    "starts where it ends, which is a window of nothing or of the whole day: "
		    "for the whole day, leave `hours` out");
		return 0;
	}
	if (end == 0) {
		end = NCFG_SCHEDULE_DAY_SECONDS;
	}
	if (from) {
		*from = start;
	}
	if (to) {
		*to = end;
	}
	if (normal && normal_size) {
		(void)snprintf(normal, normal_size, "%02ld:%02ld-%02ld:%02ld", start / 3600L,
		    (start % 3600L) / 60L, end / 3600L, (end % 3600L) / 60L);
	}
	return 1;
}

int ncfg_schedule_day(const char *word, const char **normal)
{
	int day;

	for (day = 0; word && day < 7; day++) {
		if (strcmp(word, day_words[day]) == 0 || strcmp(word, day_names[day]) == 0) {
			if (normal) {
				*normal = day_words[day];
			}
			return day;
		}
	}
	return -1;
}

const char *ncfg_schedule_day_word(int day)
{
	return day >= 0 && day < 7 ? day_words[day] : "any";
}

long ncfg_schedule_offset(void)
{
	time_t    now;
	struct tm local;

	if (offset_fixed) {
		return offset_seconds;
	}
	now = time(NULL);
	if (!localtime_r(&now, &local)) {
		return 0;
	}
	return (long)local.tm_gmtoff;
}

void ncfg_schedule_offset_fix(int set, long seconds)
{
	offset_fixed = set;
	offset_seconds = seconds;
}

/* Floor division by a day, for a negative start as much as a positive one. */
static long whole_days(long seconds)
{
	return seconds >= 0 ? seconds / NCFG_SCHEDULE_DAY_SECONDS
	                    : -((-seconds + NCFG_SCHEDULE_DAY_SECONDS - 1) / NCFG_SCHEDULE_DAY_SECONDS);
}

static int add_piece(ncfg_schedule_piece_t *out, size_t out_cap, size_t *count, int day,
    long from, long to)
{
	if (*count >= out_cap) {
		return 0;
	}
	out[*count].day = day;
	out[*count].from = from;
	out[*count].to = to;
	(*count)++;
	return 1;
}

/* One local piece, [start, end) on `day`, moved to UTC: written as one or two
 * inclusive pieces. */
static int to_utc(int day, long start, long end, long offset, ncfg_schedule_piece_t *out,
    size_t out_cap, size_t *count)
{
	long shift;

	start -= offset;
	end -= offset;
	shift = whole_days(start);
	start -= shift * NCFG_SCHEDULE_DAY_SECONDS;
	end -= shift * NCFG_SCHEDULE_DAY_SECONDS;
	if (day >= 0) {
		day = (int)(((day + shift) % 7 + 7) % 7);
	}
	if (end <= NCFG_SCHEDULE_DAY_SECONDS) {
		return add_piece(out, out_cap, count, day, start, end - 1);
	}
	return add_piece(out, out_cap, count, day, start, NCFG_SCHEDULE_DAY_SECONDS - 1) &&
	    add_piece(out, out_cap, count, day >= 0 ? (day + 1) % 7 : -1, 0,
	        end - NCFG_SCHEDULE_DAY_SECONDS - 1);
}

static int piece_order(const void *a, const void *b)
{
	const ncfg_schedule_piece_t *left = a;
	const ncfg_schedule_piece_t *right = b;

	if (left->day != right->day) {
		return left->day < right->day ? -1 : 1;
	}
	if (left->from != right->from) {
		return left->from < right->from ? -1 : 1;
	}
	return left->to < right->to ? -1 : (left->to > right->to);
}

size_t ncfg_schedule_expand(const char *hours, char *const *days, size_t day_count,
    long utc_offset, ncfg_schedule_piece_t *out, size_t out_cap)
{
	ncfg_schedule_piece_t local[NCFG_SCHEDULE_PIECES_MAX];
	size_t                local_count = 0;
	size_t                count = 0;
	unsigned              mask = 0;
	long                  start = 0;
	long                  end = NCFG_SCHEDULE_DAY_SECONDS;
	size_t                at;
	size_t                kept;
	int                   day;

	if (hours && !ncfg_schedule_hours_parse(hours, &start, &end, NULL, 0, NULL, 0)) {
		return 0;
	}
	for (at = 0; at < day_count; at++) {
		day = ncfg_schedule_day(days[at], NULL);
		if (day >= 0) {
			mask |= 1u << day;
		}
	}
	/* All seven is every day, and every day needs no day match. */
	if (mask == 0x7fu) {
		mask = 0;
	}
	for (day = mask ? 0 : -1; day < (mask ? 7 : 0); day++) {
		if (mask && !(mask & (1u << day))) {
			continue;
		}
		if (end > start) {
			(void)add_piece(local, NCFG_SCHEDULE_PIECES_MAX, &local_count, day, start, end);
		} else {
			/* Past midnight: the rest of this day, then the start of the next. */
			(void)add_piece(local, NCFG_SCHEDULE_PIECES_MAX, &local_count, day, start,
			    NCFG_SCHEDULE_DAY_SECONDS);
			(void)add_piece(local, NCFG_SCHEDULE_PIECES_MAX, &local_count,
			    day >= 0 ? (day + 1) % 7 : -1, 0, end);
		}
	}
	for (at = 0; at < local_count; at++) {
		if (!to_utc(local[at].day, local[at].from, local[at].to, utc_offset, out, out_cap,
		        &count)) {
			return 0;
		}
	}
	if (count == 0) {
		return 0;
	}
	qsort(out, count, sizeof(*out), piece_order);
	/* Joined where one ends the second before the next begins on the same day,
	 * so a window that only crossed midnight in local time is one piece. */
	kept = 1;
	for (at = 1; at < count; at++) {
		ncfg_schedule_piece_t *last = &out[kept - 1];

		if (out[at].day == last->day && out[at].from <= last->to + 1) {
			if (out[at].to > last->to) {
				last->to = out[at].to;
			}
			continue;
		}
		out[kept++] = out[at];
	}
	return kept;
}

/* `HH:MM`, or `HH:MM:SS` where the seconds are not zero. */
static void clock_of(long seconds, char *out, size_t out_size)
{
	if (seconds % 60L) {
		(void)snprintf(out, out_size, "%02ld:%02ld:%02ld", seconds / 3600L,
		    (seconds % 3600L) / 60L, seconds % 60L);
	} else {
		(void)snprintf(out, out_size, "%02ld:%02ld", seconds / 3600L, (seconds % 3600L) / 60L);
	}
}

void ncfg_schedule_piece_describe(const ncfg_schedule_piece_t *piece, char *out,
    size_t out_size)
{
	char from[64];
	char to[64];

	clock_of(piece->from, from, sizeof(from));
	clock_of(piece->to, to, sizeof(to));
	(void)snprintf(out, out_size, "%s %s-%s UTC",
	    piece->day < 0 ? "every day" : ncfg_schedule_day_word(piece->day), from, to);
}

void ncfg_schedule_piece_text(const ncfg_schedule_piece_t *piece, char *out, size_t out_size)
{
	if (piece->day < 0) {
		(void)snprintf(out, out_size, "any %ld %ld", piece->from, piece->to);
	} else {
		(void)snprintf(out, out_size, "%d %ld %ld", piece->day, piece->from, piece->to);
	}
}

int ncfg_schedule_piece_read(const char *text, ncfg_schedule_piece_t *out)
{
	char tail;
	int  day;

	if (!text) {
		return 0;
	}
	if (strncmp(text, "any ", 4u) == 0) {
		day = -1;
		if (sscanf(text + 4, "%ld %ld%c", &out->from, &out->to, &tail) != 2) {
			return 0;
		}
	} else if (sscanf(text, "%d %ld %ld%c", &day, &out->from, &out->to, &tail) != 3 ||
	    day < 0 || day > 6) {
		return 0;
	}
	if (out->from < 0 || out->to < out->from || out->to >= NCFG_SCHEDULE_DAY_SECONDS) {
		return 0;
	}
	out->day = day;
	return 1;
}
