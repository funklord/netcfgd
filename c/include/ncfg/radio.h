/*
 * radio.h -- which interfaces are radios, asked of the kernel.
 *
 * ONE FACT, IN ONE PLACE
 *   `/sys/class/net/<name>/phy80211` exists for a wireless interface and for
 *   nothing else. Three parts of netcfgd need to know: the observer fills in a
 *   link's `wireless`, the executor picks `nl80211` over `wired` when it starts
 *   a supplicant, and `ncfg wifi add` decides which radio to write
 *   configuration for on a machine with no daemon running. Each had -- or would
 *   have grown -- its own copy of the same existence test, which is how three
 *   copies of a fact end up disagreeing about one interface.
 *
 *   Cheaper and more reliable than asking `nl80211`, and it needs no
 *   privilege, which is what lets `ncfg wifi add` use it on the machine it is
 *   for: one with no network and nothing else running.
 *
 *   **A link kind cannot answer this.** A real wireless device is a plain
 *   device and reports an empty link kind, exactly as an ethernet port does.
 *
 * TWO ATTRIBUTES, AND THE OBVIOUS ONE IS THE WRONG ONE (0231)
 *   This asked only for `wireless`, which is the Wireless Extensions attribute
 *   -- and on a cfg80211 radio that attribute exists only when the kernel was
 *   built with `CONFIG_CFG80211_WEXT`. It is a config option, on by default in
 *   the big distributions and routinely off in the small ones, which is exactly
 *   the kind of kernel netcfgd is aimed at on a board.
 *
 *   On such a kernel a working radio answered "not a radio", and everything
 *   downstream followed: the supplicant was started with `-Dwired`, the radio
 *   was left out of the plan, the observation said false, and `ncfg wifi`
 *   refused to talk about it. No message anywhere named a cause, because from
 *   netcfgd's side there was no radio to have a problem with.
 *
 *   `phy80211` is the one to ask: cfg80211 creates it for every device it
 *   registers, with no config option in front of it. **`wireless` is still
 *   asked, second**, and it is not dead weight -- a driver old enough to have
 *   no cfg80211 device at all has that attribute and nothing else. That is the
 *   same case the supplicant's `-Dnl80211,wext` fallback exists for, and the
 *   two should agree about whether it is a radio.
 *
 * THE ROOT IS A PARAMETER
 *   Rather than read from the environment inside the predicate, because two
 *   tests setting one environment variable while running in parallel is a race,
 *   and a predicate whose answer depends on hidden global state is one nobody
 *   can test twice. `ncfg_radio_class_net` supplies the default and is where
 *   the environment is read -- which exists because a test of `ncfg wifi add`
 *   began reading the *host's* hardware, so it passed on a build machine with
 *   no radio and did something else on a laptop.
 */
#ifndef NCFG_RADIO_H
#define NCFG_RADIO_H

#include <stddef.h>

#include "ncfg/base.h"

/* Where the kernel publishes per-interface attributes. */
#define NCFG_RADIO_CLASS_NET "/sys/class/net"

/* The variable that overrides it, for the reason above. It is spelled the same
 * as the Rust's, because the tests of both halves set one name. */
#define NCFG_RADIO_CLASS_NET_ENV "NCFG_SYS_CLASS_NET"

/* Long enough for `NCFG_RADIO_CLASS_NET` and for anything a test points the
 * variable at. A longer value is refused rather than truncated: a truncated
 * root names a directory, just not that one. */
#define NCFG_RADIO_ROOT_MAX 4096u

/*
 * The directory to ask, which is the kernel's unless the environment says
 * otherwise.
 *
 * `out_size` must be at least `NCFG_RADIO_ROOT_MAX`.
 */
int ncfg_radio_class_net(char *out, size_t out_size, char *err, size_t err_size);

/*
 * Whether `name` under `root` is a radio.
 *
 * **A question rather than an operation**, so the answer is the return value
 * and there is no error buffer: 1 for a radio and 0 for everything else. An
 * interface that does not exist is 0, which is the same answer as "not a radio"
 * for every caller here -- none of them can do anything with a name the kernel
 * does not know.
 *
 * A name with a separator in it, or with `..` in it, is 0 without asking the
 * filesystem anything. These names come from a configuration file, and one
 * with a separator would escape `/sys/class/net` and ask about some other
 * directory entirely. The answer would usually be 0 anyway, which is what makes
 * it worth refusing explicitly: a check that is accidentally right is one that
 * stops being right when the filesystem changes.
 */
int ncfg_radio_is_wireless(const char *root, const char *name);

/*
 * Every radio the kernel reports, sorted.
 *
 * Sorted because a message listing them should read the same twice running;
 * directory order is the filesystem's and is not stable.
 *
 * Empty where the directory cannot be read, which is a container rather than a
 * machine with no radio -- the two are indistinguishable from here and the
 * callers treat them the same, because neither has a radio to configure. So
 * that is an empty list and a success, not a refusal.
 */
typedef struct {
	char **items;
	size_t count;
	size_t capacity;
} ncfg_radio_links_t;

int ncfg_radio_links(const char *root, ncfg_radio_links_t *out, char *err, size_t err_size);

/* Release what it holds, and leave it usable and empty. Freeing one that was
 * never filled in is nothing. */
void ncfg_radio_links_free(ncfg_radio_links_t *links);

#endif /* NCFG_RADIO_H */
