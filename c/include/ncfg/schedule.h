/*
 * schedule.h -- when a firewall rule applies, written in local time and held
 * by the kernel in UTC (project.md 10.663).
 *
 * THE LANGUAGE
 *   `hours = "22:00-07:00"` and `days = ["mon", "tue"]` on a firewall rule,
 *   in the machine's local time, because that is the clock the person writing
 *   "no internet after ten" is reading. A window that ends before it starts
 *   runs past midnight into the next day; `24:00` may end one. `days` alone
 *   is those whole days; `hours` alone is every day.
 *
 * WHAT THE KERNEL HOLDS
 *   nftables' `meta hour` and `meta day` read the kernel's clock, which is
 *   UTC wherever nothing set the kernel's own zone -- and nft's userspace
 *   converts the hour and leaves the day alone, so its own rules are a day
 *   wrong near midnight for half the world. So a schedule is expanded here
 *   into UTC pieces, each a day (or every day) and an inclusive range of
 *   seconds, using the UTC offset in force when the rules are built. A
 *   change of offset -- a summer-time change -- is a change of pieces, and
 *   the pieces are in the rule's digest, so the planner sees the firewall as
 *   not the document's and replaces it.
 *
 * WHY PIECES ARE ALSO TEXT ON A RULE
 *   An undo copy is rebuilt from what the kernel holds, and the local
 *   schedule cannot be recovered from UTC pieces. So a rebuilt rule carries
 *   its pieces as written here (`utc_pieces`), the builder takes them as
 *   they are, and the restored rules digest exactly as the ones they replace.
 */
#ifndef NCFG_SCHEDULE_H
#define NCFG_SCHEDULE_H

#include <stddef.h>

#define NCFG_SCHEDULE_DAY_SECONDS 86400L

/* At most seven days, each split once at local midnight and once at UTC
 * midnight, before merging. */
#define NCFG_SCHEDULE_PIECES_MAX 28u

/* `"any 75600 86399"` and its NUL, with room. */
#define NCFG_SCHEDULE_PIECE_TEXT 32u

typedef struct {
	int  day;  /* 0 Sunday to 6 Saturday, in UTC; -1 for every day */
	long from; /* seconds since UTC midnight, inclusive */
	long to;   /* inclusive, and never before `from` */
} ncfg_schedule_piece_t;

/*
 * `hours` as written: "H:MM-H:MM" or "HH:MM-HH:MM". Fills the window in
 * seconds since local midnight, `to` exclusive and in (0, 86400], and writes
 * the normal spelling, "HH:MM-HH:MM", to `normal` (at least 12 bytes).
 * Returns 0 with `why` set where it is not one, or where it starts where it
 * ends -- a window of nothing, or of the whole day, which is no `hours`.
 */
int ncfg_schedule_hours_parse(const char *text, long *from, long *to, char *normal,
    size_t normal_size, char *why, size_t why_size);

/* A day's word -- `mon` to `sun`, or the whole name -- as 0 Sunday to 6
 * Saturday, and its normal spelling. -1 where it is not one. */
int ncfg_schedule_day(const char *word, const char **normal);

/* The normal spelling of a day number, `sun` to `sat`. */
const char *ncfg_schedule_day_word(int day);

/*
 * The UTC pieces of a schedule, `utc_offset` seconds east of UTC. `hours`
 * NULL is the whole day; `days` empty is every day, and so are all seven.
 * Sorted by day then start, contiguous pieces of one day joined. Returns the
 * count, 0 where `hours` does not parse.
 */
size_t ncfg_schedule_expand(const char *hours, char *const *days, size_t day_count,
    long utc_offset, ncfg_schedule_piece_t *out, size_t out_cap);

/* The offset the builder uses: the machine's own, at this moment, unless a
 * test has set one. */
long ncfg_schedule_offset(void);
/* For a test: `set` non-zero fixes the offset at `seconds`; zero lets it
 * follow the machine again. */
void ncfg_schedule_offset_fix(int set, long seconds);

/* A piece for a person: `"mon 07:00-08:29:59 UTC"`, `"every day 21:00-23:59:59
 * UTC"` -- seconds shown only where they are not zero. */
void ncfg_schedule_piece_describe(const ncfg_schedule_piece_t *piece, char *out,
    size_t out_size);

/* A piece as text, `"any 75600 86399"` or `"1 0 21599"`, and back. */
void ncfg_schedule_piece_text(const ncfg_schedule_piece_t *piece, char *out, size_t out_size);
int ncfg_schedule_piece_read(const char *text, ncfg_schedule_piece_t *out);

#endif /* NCFG_SCHEDULE_H */
