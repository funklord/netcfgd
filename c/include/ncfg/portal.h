/*
 * portal.h -- is something answering requests that were not meant for it?
 *
 * WHAT A CAPTIVE PORTAL DOES TO A MACHINE
 *   It hands out an address, a gateway and a DNS server, and then answers
 *   every request with its own login page. Everything looks configured and
 *   nothing works, which is the failure an operator spends twenty minutes on
 *   before thinking to open a browser.
 *
 * THE URL IS THE OPERATOR'S
 *   0061 refused a boolean with an address inside netcfgd and 0095 kept that:
 *   a daemon reaching out to a fixed host to decide whether the internet works
 *   is a third party being told when this machine joins a network. No URL, no
 *   probe -- which is every machine that did not ask. There is no default here
 *   and `ncfg_portal_probe` has nothing to fall back on.
 *
 * IN CLEAR, ALWAYS
 *   A portal detects by intercepting, and TLS exists to stop interception:
 *   over `https` a portal produces a certificate error rather than a redirect,
 *   so a check that cannot be intercepted cannot detect interception. The
 *   compiler refuses an `https` URL with that sentence, and `lower_device.c`
 *   is where it does it.
 *
 * NO HTTP LIBRARY
 *   The request is one line and the answer that matters is the status on the
 *   first line of the response. Reading further would mean parsing a body this
 *   does not care about, from a host it has already decided not to trust.
 *
 * THE WORK HAPPENS IN A CHILD, AND THE CHILD IS AN ARGUMENT
 *   Resolving the URL means the C library's resolver, its NSS modules, and a
 *   DNS response chosen by the network being probed. Running that in the
 *   process holding `CAP_NET_ADMIN` is the arrangement CVE-2015-7547 turned
 *   into a root compromise on a great many machines (0162), so the fetch
 *   happens in a child that has shed everything first -- and in a fresh image
 *   rather than a bare fork, because a child of a threaded process may call
 *   only async-signal-safe functions until it execs and `getaddrinfo`
 *   allocates.
 *
 *   **Which image is the caller's to name.** The Rust hard-codes
 *   `/proc/self/exe`, which is right for a multi-call binary and wrong for a
 *   library: whatever links this is not necessarily netcfgd, and a default
 *   would have a test binary re-exec itself. `NCFG_PORTAL_OWN_IMAGE` is the
 *   value the daemon passes, named here so that it is written once and can be
 *   read by a test that does not run it.
 *
 * WHERE THIS DIVERGES FROM THE RUST
 *   Each of these is in 0263's list with its reasoning; they are named here
 *   because this is where a caller meets them.
 *
 *     * The helper image is an argument with no default (above).
 *     * `ncfg_portal_split` answers the authority *and* the connect target
 *       separately, so the `Host:` header carries the authority the operator
 *       wrote. The Rust's own comment says that is what it does and its code
 *       sends the connect target instead, port and all.
 *     * An IPv6 literal in brackets is understood.
 *     * The helper's body is a function that returns its exit status and the
 *       line to print, rather than a `main` that prints and exits: a library
 *       here never prints and never exits.
 */
#ifndef NCFG_PORTAL_H
#define NCFG_PORTAL_H

#include <stddef.h>

#include "ncfg/base.h"

/*
 * The name the probe child answers to when netcfgd is its own helper.
 *
 * Never installed and never a symlink: the daemon execs its own image with
 * this in `argv[0]`, so the only way to reach it is to be netcfgd. A copy of
 * the binary renamed to it by hand resolves a URL and prints a status line
 * with no privileges, which is a thing anybody could already do with `curl`.
 */
#define NCFG_PORTAL_HELPER_NAME "netcfgd-probe"

/*
 * How a process finds its own image, which is what the daemon hands
 * `ncfg_portal_probe`.
 *
 * Written once, here, so that a test can assert what the daemon passes without
 * executing anything -- and so that a machine without `/proc` is a machine
 * where this cannot be done safely at all, rather than one where it is done
 * unsafely instead.
 */
#define NCFG_PORTAL_OWN_IMAGE "/proc/self/exe"

/*
 * How long the whole fetch may take.
 *
 * A portal answers immediately -- it is on the local network and it wants to
 * be found. A network with no route anywhere hangs, and this is what stops
 * that hanging anything else. Short enough that a laptop is not waiting on it,
 * long enough that a slow but working link is not called a portal.
 */
#define NCFG_PORTAL_DEADLINE_SECONDS 5

/*
 * How long the child may live, whatever it is doing.
 *
 * One second past the socket deadline, so that a stuck read is reported as a
 * read that did not finish rather than as a child that was killed.
 */
#define NCFG_PORTAL_CHILD_SECONDS 6

/* The longest `portal_check` this will look at. An operator's URL, not a
 * document, and a refusal names the ceiling rather than truncating. */
#define NCFG_PORTAL_URL_MAX 1024

/* Room for an authority, and for a host with an IPv6 literal's brackets
 * taken off. */
#define NCFG_PORTAL_AUTHORITY_MAX 256

/* A port is five digits, or the empty string is refused before it gets here. */
#define NCFG_PORTAL_PORT_MAX 8

/* What is left of the URL once the authority has been taken off it. */
#define NCFG_PORTAL_PATH_MAX 1024

/*
 * How much of a hostile answer is repeated, and the buffer that holds it.
 *
 * 64 characters and then an ellipsis: `HTTP/1.0 302 Found` survives intact,
 * which is the case an operator is actually reading this for, and 1024 bytes
 * of somebody else's choosing is not a diagnostic.
 */
#define NCFG_PORTAL_LEGIBLE_KEEP 64
#define NCFG_PORTAL_LEGIBLE_MAX  (NCFG_PORTAL_LEGIBLE_KEEP + 4)

/* The status line, and nothing more. Bounded because the far side is a host
 * this has already decided not to trust: a portal that answered forever would
 * otherwise be a portal that hung netcfgd. */
#define NCFG_PORTAL_STATUS_MAX 1025

/* The status a `generate_204` endpoint exists to give, which is what "nothing
 * is in the way" means by convention. */
#define NCFG_PORTAL_EXPECT_DEFAULT 204

/* What the probe found. */
typedef enum {
	/* The expected answer arrived: nothing is in the way. */
	NCFG_PORTAL_VERDICT_CLEAR,
	/* Something answered, and not with what was asked for. */
	NCFG_PORTAL_VERDICT_PORTAL,
	/* Nothing answered. Not a portal -- a portal is a thing that *replies*. */
	NCFG_PORTAL_VERDICT_UNREACHABLE
} ncfg_portal_verdict_t;

/* The word this verdict is written as. NULL outside the set, `value.h`'s
 * convention: a plausible word for a verdict that is not one is worse than no
 * word. */
const char *ncfg_portal_verdict_name(int verdict);

/*
 * A verdict and what to say about it.
 *
 * `detail` is what the operator and the hook are told. **It reaches a root
 * shell**: a `portal` verdict's detail becomes `NCFG_REASON` for the
 * `portal`-phase hooks, which netcfgd runs as root. See `ncfg_portal_legible`
 * for what that costs and what is done about it.
 *
 * Plain storage rather than an allocation, so that a caller can keep one on
 * the stack and there is nothing to free.
 */
typedef struct {
	int  verdict; /* ncfg_portal_verdict_t */
	char detail[NCFG_ERROR_MAX];
} ncfg_portal_result_t;

/*
 * Whether an address is one that could reach anything.
 *
 * **A link-local is not connectivity**, and this is the whole of why it
 * matters: every interface that is up has an `fe80::` address the moment the
 * kernel brings it up, so a check for "has an address" is true from the
 * instant the link exists and never changes. A probe that fired on that
 * transition would fire once, at startup, and never again on any real machine
 * -- which is what the first version of this did, and 0095 records how it was
 * found.
 *
 * An IPv4 link-local (`169.254.`) is the same statement in the other family:
 * the machine gave up on DHCP and picked an address, which is not a network
 * that can be behind a portal.
 *
 * The address may carry a prefix length; the family is decided by what is in
 * front of it.
 */
int ncfg_portal_is_routable(const char *address);

/* `http://host[:port]/path`, taken apart into what a request needs. */
typedef struct {
	/*
	 * The authority exactly as the URL wrote it, which is what the `Host:`
	 * header carries -- a server matching a name-based virtual host compares
	 * against what a browser would have sent, and a browser sends no `:80`.
	 */
	char authority[NCFG_PORTAL_AUTHORITY_MAX];
	/* The name or literal to resolve, with an IPv6 literal's brackets taken
	 * off, since `getaddrinfo` wants the address and not the URL syntax. */
	char host[NCFG_PORTAL_AUTHORITY_MAX];
	/* The port to connect to. `80` where the URL gave none. */
	char port[NCFG_PORTAL_PORT_MAX];
	/* What to ask for. `/` where the URL gave none, which is what a browser
	 * does. */
	char path[NCFG_PORTAL_PATH_MAX];
} ncfg_portal_url_t;

/*
 * Split a URL into what a request needs.
 *
 * Not a general URL parser: the compiler has already refused anything that is
 * not `http://` with a host, so this is the rest of that same shape. 0 with a
 * sentence for anything else, which is how a URL that reached here by another
 * route is refused rather than half-understood.
 */
int ncfg_portal_split(const char *url, ncfg_portal_url_t *out, char *err, size_t err_size);

/*
 * As much of a hostile answer as is safe to repeat, into `out`.
 *
 * **This string reaches a root shell.** A `portal` verdict's detail becomes
 * `NCFG_REASON` for the `portal`-phase hooks, and on that branch the content
 * is whatever answered on port 80 -- a machine on a network this has already
 * decided not to trust.
 *
 * An environment variable is not re-parsed by a shell, and an unquoted
 * expansion word-splits and globs rather than running anything, so this is not
 * command injection by itself. It is attacker-chosen text in a root script's
 * environment, which is a thing to hand somebody only if they asked for it --
 * and a hook that `eval`s its reason is a mistake netcfgd should not be making
 * possible.
 *
 * So: printable ASCII from a small set, everything else a dot, and
 * `NCFG_PORTAL_LEGIBLE_KEEP` characters with an ellipsis where there were
 * more. `out` is `NCFG_PORTAL_LEGIBLE_MAX` bytes and is always
 * NUL-terminated.
 */
void ncfg_portal_legible(const char *text, char *out, size_t out_size);

/*
 * A status line into a verdict.
 *
 * `expect` is the status that means nothing is in the way --
 * `NCFG_PORTAL_EXPECT_DEFAULT` by convention, which is what a `generate_204`
 * endpoint is for. Anything else that answers is a portal, **including an
 * answer that is not HTTP at all**: something is on port 80 and it is not what
 * was asked for, and reading that as clear would be the worst of the three.
 *
 * Never fails, and fills `out` on every path: a verdict is what reaches the
 * hook, so there is no way for this to decline to produce one.
 */
void ncfg_portal_verdict(const char *status_line, int expect, ncfg_portal_result_t *out);

/*
 * Resolve, connect, and read back the status line.
 *
 * **This reaches the network, and it is the one call here that does.** It is
 * meant to run in the child `ncfg_portal_helper` is the body of, after the
 * shed -- nothing in the daemon calls it directly. Nothing under `tests/`
 * calls it against anything but a server the test started on a loopback port
 * it chose.
 *
 * 1 with the first line of the response in `status_line`, or 0 with a sentence
 * saying which of resolution, connection or the exchange failed -- each
 * reported separately, because resolution is the first thing a portal
 * interferes with and the first thing that fails on a network with none.
 */
int ncfg_portal_fetch(const char *url, char *status_line, size_t status_size, char *err,
    size_t err_size);

/*
 * The child: give everything up, then do the hostile part.
 *
 * Returns the status the child exits with, and writes into `said` the one line
 * it prints:
 *
 *   0 -- `said` is the status line the far side answered with.
 *   1 -- `said` is why there was no answer.
 *   2 -- it could not shed privilege, so it did nothing else. `said` says why.
 *
 * **A library never prints and never exits** (0263), so this is the body and
 * the caller is a `main` that does `puts(said); return status;`. That is the
 * only difference from the Rust's `helper_main`.
 *
 * **It is one-directional and cannot be undone**, so it may be called only in
 * a child that is about to do the work and then end -- `ncfg_privilege_shed`
 * says why, at length. `said` is `NCFG_ERROR_MAX` bytes.
 */
int ncfg_portal_helper(const char *url, char *said, size_t said_size);

/*
 * Fetch the URL in a child that holds nothing, and say what answered.
 *
 * `helper_program` is the image to exec, run under `NCFG_PORTAL_HELPER_NAME`
 * with the URL as its one argument; the daemon passes
 * `NCFG_PORTAL_OWN_IMAGE`. There is no default -- see the header comment.
 *
 * Always produces a verdict: everything that can go wrong on this side, from a
 * helper that will not start to one that was killed, is `unreachable` with a
 * sentence, because a probe that could not be run has not found a portal.
 *
 * The child bounds itself with `ncfg_privilege_die_after`, so reading its
 * output to end of file cannot hang: end of file is the child exiting, and the
 * child cannot outlive its alarm.
 */
void ncfg_portal_probe(const char *helper_program, const char *url, int expect,
    ncfg_portal_result_t *out);

#endif /* NCFG_PORTAL_H */
