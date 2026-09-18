/*
 * socket.c -- the syscalls, and nothing that parses.
 *
 * Every descriptor in this module lives in this file, and every function here
 * that touches one hands the bytes straight to `wire.c`, which is entirely
 * arithmetic. That split is the whole point: the Rust this replaces confined
 * `unsafe` to one crate so that an audit was tractable, and in C the same
 * discipline has to be a rule instead -- so the rule is that the file holding
 * the socket does no parsing, and the file doing the parsing holds no socket.
 *
 * There are seven syscalls: socket, bind, setsockopt, send, recv, close, and
 * the recv again with `MSG_PEEK`. Everything else here is a loop around them.
 */
#include "ncfg/netlink.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

/*
 * What a netlink errno means here, beyond what `strerror` says.
 *
 * `strerror(EINVAL)` is "Invalid argument", which is true and useless: on this
 * socket it is what the kernel says when an attribute is one it does not know,
 * when a nest arrived without `NLA_F_NESTED`, and when a value is out of
 * range. The second sentence is the part an operator can act on, and the
 * spelled-out name is the part they can search for.
 */
static const struct {
	int         code;
	const char *name;
	const char *why;
} known_errnos[] = {
	{ EPERM, "EPERM", "netcfgd needs CAP_NET_ADMIN to change the network" },
	{ EACCES, "EACCES", "the kernel refused this process the operation" },
	{ EEXIST, "EEXIST", "the kernel already has an object by that name or address" },
	{ ENOENT, "ENOENT", "there is no such object for the kernel to change" },
	{ ENODEV, "ENODEV", "the interface this names is not on this machine" },
	{ EINVAL, "EINVAL",
	    "the kernel read the request and would not take it -- an attribute it does not "
	    "know, a nest without NLA_F_NESTED, or a value out of range" },
	{ EOPNOTSUPP, "EOPNOTSUPP",
	    "this kernel does not have what the request needs; a module may not be loaded" },
	{ EAFNOSUPPORT, "EAFNOSUPPORT", "this kernel has no support for that address family" },
	{ EADDRNOTAVAIL, "EADDRNOTAVAIL", "the address is not on the interface this names" },
	{ ENETDOWN, "ENETDOWN", "the interface is down" },
	{ ENETUNREACH, "ENETUNREACH", "the route has no interface that can reach it" },
	{ EBUSY, "EBUSY", "the object is in use and cannot be changed while it is" },
	{ ENOBUFS, "ENOBUFS",
	    "the kernel ran out of socket buffer and dropped messages; the next dump "
	    "catches up" },
	{ EMSGSIZE, "EMSGSIZE", "the message is larger than the socket will send" },
	{ EAGAIN, "EAGAIN", "the socket's receive timeout expired before the kernel answered" },
	{ ETIMEDOUT, "ETIMEDOUT",
	    "the socket's receive timeout expired before the kernel answered" },
	{ EINTR, "EINTR", "a signal arrived mid-syscall, which means call it again" },
	{ EPROTO, "EPROTO", "the kernel's reply was not one this port can read" },
	{ EBADF, "EBADF", "the socket is not open" }
};

const char *ncfg_netlink_errno_text(int code)
{
	size_t at;

	for (at = 0; at < sizeof(known_errnos) / sizeof(known_errnos[0]); at++) {
		if (known_errnos[at].code == code) {
			return known_errnos[at].why;
		}
	}
	return NULL;
}

/* The spelled-out name, or NULL. Kept beside `why` in one table so the two
 * cannot disagree about which errno they describe. */
static const char *errno_name(int code)
{
	size_t at;

	for (at = 0; at < sizeof(known_errnos) / sizeof(known_errnos[0]); at++) {
		if (known_errnos[at].code == code) {
			return known_errnos[at].name;
		}
	}
	return NULL;
}

const char *ncfg_netlink_kind_text(uint16_t kind)
{
	switch (kind) {
	case NLMSG_NOOP:
		return "NLMSG_NOOP";
	case NLMSG_ERROR:
		return "NLMSG_ERROR";
	case NLMSG_DONE:
		return "NLMSG_DONE";
	case NLMSG_OVERRUN:
		return "NLMSG_OVERRUN";
	case RTM_NEWLINK:
		return "RTM_NEWLINK";
	case RTM_DELLINK:
		return "RTM_DELLINK";
	case RTM_GETLINK:
		return "RTM_GETLINK";
	case RTM_SETLINK:
		return "RTM_SETLINK";
	case RTM_NEWADDR:
		return "RTM_NEWADDR";
	case RTM_DELADDR:
		return "RTM_DELADDR";
	case RTM_GETADDR:
		return "RTM_GETADDR";
	case RTM_NEWROUTE:
		return "RTM_NEWROUTE";
	case RTM_DELROUTE:
		return "RTM_DELROUTE";
	case RTM_GETROUTE:
		return "RTM_GETROUTE";
	case RTM_NEWRULE:
		return "RTM_NEWRULE";
	case RTM_DELRULE:
		return "RTM_DELRULE";
	case RTM_GETRULE:
		return "RTM_GETRULE";
	case RTM_NEWQDISC:
		return "RTM_NEWQDISC";
	case RTM_DELQDISC:
		return "RTM_DELQDISC";
	case RTM_GETQDISC:
		return "RTM_GETQDISC";
	case RTM_NEWTFILTER:
		return "RTM_NEWTFILTER";
	case RTM_DELTFILTER:
		return "RTM_DELTFILTER";
	case RTM_GETTFILTER:
		return "RTM_GETTFILTER";
	case RTM_NEWLINKPROP:
		return "RTM_NEWLINKPROP";
	case RTM_DELLINKPROP:
		return "RTM_DELLINKPROP";
	default:
		/* NULL rather than a formatted number, because a `const char *`
		 * return has nowhere to format one into that outlives the call.
		 * The caller that needs the number already has it. */
		return NULL;
	}
}

int ncfg_netlink_fail(char *err, size_t err_size, const char *doing, int code)
{
	char        text[128];
	const char *name = errno_name(code);
	const char *why = ncfg_netlink_errno_text(code);
	const char *what = doing ? doing : "a netlink operation";

	/*
	 * The XSI `strerror_r`, which `-D_DEFAULT_SOURCE` selects and which
	 * returns an int. Not `strerror`: this library is linked into a daemon
	 * with more than one thread, and `strerror` hands out a buffer they
	 * share -- so two failures at once produce one message, twice.
	 */
	if (strerror_r(code, text, sizeof(text)) != 0) {
		(void)snprintf(text, sizeof(text), "errno %d", code);
	}
	if (name && why) {
		ncfg_error_set(err, err_size, "%s failed: %s (%s) -- %s", what, text, name, why);
	} else if (name) {
		ncfg_error_set(err, err_size, "%s failed: %s (%s)", what, text, name);
	} else {
		ncfg_error_set(err, err_size, "%s failed: %s (errno %d)", what, text, code);
	}
	return 0;
}

void ncfg_netlink_init(ncfg_netlink_t *netlink)
{
	if (!netlink) {
		return;
	}
	netlink->fd = -1;
	/* The first request uses 2: the counter moves before it is read, and a
	 * request numbered 0 could not be told from an unsolicited message. */
	netlink->seq = 1;
	netlink->dropped = 0;
}

int ncfg_netlink_open_protocol(ncfg_netlink_t *netlink, int protocol, uint32_t groups,
    char *err, size_t err_size)
{
	struct sockaddr_nl address;
	int                fd;

	if (!netlink) {
		ncfg_error_set(err, err_size, "a netlink socket needs somewhere to live");
		return 0;
	}
	ncfg_netlink_init(netlink);
	/* `SOCK_CLOEXEC` and not a later `fcntl`: netcfgd spawns children --
	 * dhcpcd, wpa_supplicant, a dns script -- and a descriptor that survives
	 * one exec is a descriptor some other program holds the daemon's netlink
	 * socket on. Set at open, so there is no window. */
	fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, protocol);
	if (fd < 0) {
		/* On a kernel built without netlink this is the failure a caller
		 * sees, and it is worth reporting as it is rather than
		 * translating into something about netcfgd. */
		return ncfg_netlink_fail(err, err_size, "opening a netlink socket", errno);
	}
	memset(&address, 0, sizeof(address));
	address.nl_family = AF_NETLINK;
	address.nl_groups = groups;
	if (bind(fd, (const struct sockaddr *)&address, (socklen_t)sizeof(address)) < 0) {
		int saved = errno;

		/* Closed before reporting, and the errno saved first: `close`
		 * may set its own and would otherwise overwrite the one that
		 * explains the failure. */
		(void)close(fd);
		return ncfg_netlink_fail(err, err_size, "binding a netlink socket", saved);
	}
	netlink->fd = fd;
	return 1;
}

int ncfg_netlink_open_groups(ncfg_netlink_t *netlink, uint32_t groups, char *err, size_t err_size)
{
	return ncfg_netlink_open_protocol(netlink, NETLINK_ROUTE, groups, err, err_size);
}

int ncfg_netlink_open(ncfg_netlink_t *netlink, char *err, size_t err_size)
{
	return ncfg_netlink_open_groups(netlink, 0, err, err_size);
}

void ncfg_netlink_close(ncfg_netlink_t *netlink)
{
	if (!netlink || netlink->fd < 0) {
		return;
	}
	(void)close(netlink->fd);
	netlink->fd = -1;
}

int ncfg_netlink_set_timeout(const ncfg_netlink_t *netlink, long seconds, char *err,
    size_t err_size)
{
	struct timeval timeout;

	if (!netlink || netlink->fd < 0) {
		ncfg_error_set(err, err_size, "a timeout needs an open socket to be set on");
		return 0;
	}
	memset(&timeout, 0, sizeof(timeout));
	timeout.tv_sec = (time_t)seconds;
	if (setsockopt(netlink->fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, (socklen_t)sizeof(timeout))
	    < 0) {
		return ncfg_netlink_fail(err, err_size, "setting the netlink receive timeout",
		    errno);
	}
	return 1;
}

/* The sequence number for the next request. */
static uint32_t next_seq(ncfg_netlink_t *netlink)
{
	netlink->seq++;
	if (netlink->seq == 0) {
		/*
		 * Zero is the sequence number of an *unsolicited* message, and
		 * the reply filter lets one through on that basis -- so a
		 * counter that wrapped onto it would make every stray multicast
		 * message part of the next dump. Four billion requests away, and
		 * one line to make unreachable.
		 */
		netlink->seq = 1;
	}
	return netlink->seq;
}

uint32_t ncfg_netlink_take_seq(ncfg_netlink_t *netlink)
{
	if (!netlink) {
		return 0;
	}
	return next_seq(netlink);
}

void ncfg_netlink_reply_free(ncfg_netlink_reply_t *reply)
{
	size_t at;

	if (!reply) {
		return;
	}
	for (at = 0; at < reply->count; at++) {
		free(reply->items[at].bytes);
	}
	free(reply->items);
	reply->items = NULL;
	reply->count = 0;
	reply->capacity = 0;
	reply->dropped = 0;
}

/*
 * Keep one message's payload.
 *
 * Copied rather than pointed into the read buffer, which is reused and
 * reallocated for the next datagram of the same multipart reply -- a record
 * pointing into it would change under the caller between one message and the
 * next, and a `realloc` that moved would leave it pointing at freed memory.
 */
static int push_payload(ncfg_netlink_reply_t *reply, const uint8_t *bytes, size_t length,
    char *err, size_t err_size)
{
	uint8_t *copy;

	if (reply->count == reply->capacity) {
		size_t                  wanted = reply->capacity ? reply->capacity * 2u : 16u;
		ncfg_netlink_payload_t *grown;

		if (wanted < reply->capacity) {
			ncfg_error_set(err, err_size, "a netlink reply of %zu messages is past "
			    "anything this can hold", reply->count);
			return 0;
		}
		grown = realloc(reply->items, wanted * sizeof(*grown));
		if (!grown) {
			ncfg_error_set(err, err_size,
			    "no memory for a netlink reply of %zu messages", wanted);
			return 0;
		}
		reply->items = grown;
		reply->capacity = wanted;
	}
	/* One byte for an empty payload, so that a kept message always has an
	 * address: `free` of it is the same either way, and a NULL that means
	 * "kept, but empty" is a NULL somebody dereferences. */
	copy = malloc(length ? length : 1u);
	if (!copy) {
		ncfg_error_set(err, err_size, "no memory for a %zu-byte netlink message", length);
		return 0;
	}
	if (length) {
		memcpy(copy, bytes, length);
	}
	reply->items[reply->count].bytes = copy;
	reply->items[reply->count].length = length;
	reply->count++;
	return 1;
}

/* The errno an `NLMSG_ERROR` payload carries, or `EPROTO` where it carries
 * nothing readable -- which is exactly what a payload with an impossible code
 * in it is. */
static int32_t reply_error_code(const ncfg_wire_message_t *message)
{
	int32_t code;

	if (!ncfg_wire_error_code(message->payload, message->payload_length, &code, NULL, 0)) {
		return EPROTO;
	}
	return code;
}

/*
 * The name of the request the kernel is refusing, out of its own echo of it.
 *
 * An `NLMSG_ERROR` payload is the code and then the header of the message that
 * caused it, which is the only place a reply loop can learn what failed --
 * "RTM_NEWLINK failed" is a sentence an operator can look up and "a netlink
 * request failed" is where they start guessing.
 */
static const char *refused_request(const ncfg_wire_message_t *message)
{
	ncfg_wire_header_t original;
	const char        *name;

	if (message->payload_length < 4u + NCFG_WIRE_NLMSG_HDR_LEN) {
		return "a netlink request";
	}
	if (!ncfg_wire_header_decode(message->payload + 4, message->payload_length - 4u,
	    &original, NULL, 0)) {
		return "a netlink request";
	}
	name = ncfg_netlink_kind_text(original.kind);
	return name ? name : "a netlink request";
}

/* What one datagram did to a reply in progress. */
typedef enum {
	ABSORB_BAD = 0,
	ABSORB_MORE = 1,
	ABSORB_DONE = 2
} absorb_t;

/*
 * Take every message in one datagram that belongs to `seq`.
 *
 * **A message for another sequence number is skipped and not refused.** A
 * socket that subscribed to a group receives unsolicited messages between the
 * halves of a reply, and they carry sequence number 0 -- so 0 is let through
 * as well, which is netlink's way of saying "nobody asked for this".
 */
static absorb_t absorb_reply(ncfg_netlink_reply_t *reply, const uint8_t *bytes, size_t length,
    uint32_t seq, char *err, size_t err_size)
{
	ncfg_wire_messages_t walk;
	ncfg_wire_message_t  message;
	absorb_t             outcome = ABSORB_MORE;

	ncfg_wire_messages_start(&walk, bytes, length);
	for (;;) {
		ncfg_wire_step_t step = ncfg_wire_messages_next(&walk, &message, err, err_size);

		if (step == NCFG_WIRE_END) {
			return outcome;
		}
		if (step == NCFG_WIRE_BAD) {
			/*
			 * The Rust's iterator stops here and the caller keeps
			 * whatever it had, which reads a truncated datagram as a
			 * finished one. The wire layer exists to refuse exactly
			 * that confusion, so a malformed datagram fails the
			 * request instead: `err` already says how.
			 */
			return ABSORB_BAD;
		}
		if (message.header.seq != seq && message.header.seq != 0) {
			continue;
		}
		if (message.header.kind == NLMSG_ERROR) {
			int32_t code = reply_error_code(&message);

			if (code != 0) {
				(void)ncfg_netlink_fail(err, err_size,
				    refused_request(&message), (int)code);
				return ABSORB_BAD;
			}
			/* A zero code is an acknowledgement -- netlink's least
			 * obvious convention -- and it ends a single-shot
			 * request. */
			outcome = ABSORB_DONE;
			continue;
		}
		if (message.header.kind == NLMSG_DONE) {
			outcome = ABSORB_DONE;
			continue;
		}
		if (!push_payload(reply, message.payload, message.payload_length, err, err_size)) {
			return ABSORB_BAD;
		}
	}
}

/*
 * The same for a batch, where the question is which sequence number was
 * acknowledged rather than whether this request is done.
 *
 * No sequence filter: every message in a transaction is the caller's, and the
 * kernel answers each one that asked for an acknowledgement.
 */
static absorb_t absorb_batch(ncfg_netlink_reply_t *reply, const uint8_t *bytes, size_t length,
    uint32_t last_acked, char *err, size_t err_size)
{
	ncfg_wire_messages_t walk;
	ncfg_wire_message_t  message;

	ncfg_wire_messages_start(&walk, bytes, length);
	for (;;) {
		ncfg_wire_step_t step = ncfg_wire_messages_next(&walk, &message, err, err_size);

		if (step == NCFG_WIRE_END) {
			return ABSORB_MORE;
		}
		if (step == NCFG_WIRE_BAD) {
			return ABSORB_BAD;
		}
		if (message.header.kind == NLMSG_ERROR) {
			int32_t code = reply_error_code(&message);

			if (code != 0) {
				/* The first errno any message replied with. One
				 * failure means the whole transaction was rolled
				 * back, so the first is the cause. */
				(void)ncfg_netlink_fail(err, err_size,
				    refused_request(&message), (int)code);
				return ABSORB_BAD;
			}
			if (message.header.seq >= last_acked) {
				return ABSORB_DONE;
			}
			continue;
		}
		if (message.header.kind == NLMSG_DONE) {
			return ABSORB_DONE;
		}
		if (!push_payload(reply, message.payload, message.payload_length, err, err_size)) {
			return ABSORB_BAD;
		}
	}
}

/*
 * Take the next datagram whole, growing the buffer first if it will not fit.
 *
 * See the note on `ncfg_netlink_collect`: the peek is what makes this
 * recoverable, and nothing here re-sends anything.
 *
 * **A `*length` of 0 on success means a datagram was discarded** -- it did not
 * come from the kernel -- and the caller should ask again. It cannot mean a
 * kernel datagram of no bytes, because that is refused below with a sentence of
 * its own.
 */
static int take_datagram(ncfg_netlink_recv_t source, void *context, uint8_t **buffer,
    size_t *size, size_t *length, size_t *dropped, char *err, size_t err_size)
{
	ssize_t  peeked;
	ssize_t  got;
	size_t   needed;
	uint32_t from;

	for (;;) {
		peeked = source(context, *buffer, *size, 1, &from);
		if (peeked < 0) {
			return ncfg_netlink_fail(err, err_size,
			    "asking the size of the kernel's reply", errno);
		}
		if (from == 0) {
			break;
		}
		/*
		 * Somebody local. Consumed and discarded here, *before* the
		 * buffer is grown and before the ceiling is checked, so a forged
		 * datagram claiming a megabyte costs nothing and cannot end a
		 * dump by tripping the refusal below. The read discards the whole
		 * datagram whatever its size, since one recv takes a datagram
		 * entire, and the loop then asks for the next -- which is the
		 * kernel's, still queued behind it.
		 */
		got = source(context, *buffer, *size, 0, &from);
		if (got < 0) {
			return ncfg_netlink_fail(err, err_size, "reading the kernel's reply",
			    errno);
		}
		(*dropped)++;
	}
	needed = (size_t)peeked;
	if (needed > *size) {
		uint8_t *grown;

		if (needed > NCFG_NETLINK_MAX_REPLY) {
			/* Reported with its size, which is the number whoever
			 * raises this needs. */
			ncfg_error_set(err, err_size,
			    "a netlink reply of %zu bytes is past the %u this will hold",
			    needed, (unsigned)NCFG_NETLINK_MAX_REPLY);
			return 0;
		}
		grown = realloc(*buffer, needed);
		if (!grown) {
			ncfg_error_set(err, err_size,
			    "no memory to read a %zu-byte netlink reply", needed);
			return 0;
		}
		*buffer = grown;
		*size = needed;
	}
	got = source(context, *buffer, *size, 0, &from);
	if (got < 0) {
		return ncfg_netlink_fail(err, err_size, "reading the kernel's reply", errno);
	}
	if (from != 0) {
		/*
		 * Asked again on the call that actually delivered the bytes, and
		 * not only on the peek before it. The peek's answer is about a
		 * datagram that was still queued; this one is about the bytes now
		 * in the buffer, and it is those the caller is going to parse.
		 * Nothing this process does can make the two differ -- it is the
		 * only reader of this socket -- which is exactly why the check
		 * costs one comparison and is worth making where it cannot be
		 * argued about.
		 */
		(*dropped)++;
		*length = 0;
		return 1;
	}
	if ((size_t)got > *size) {
		/*
		 * `MSG_TRUNC` makes the return value the datagram's true size
		 * rather than a count of bytes written, so this says the
		 * datagram grew between the peek and the read -- which cannot
		 * happen to a queue only this process reads, and means the bytes
		 * in hand are a piece of a message. Refused rather than clamped:
		 * a piece of a dump read as a whole one is an observation
		 * missing interfaces with nothing anywhere saying so.
		 */
		ncfg_error_set(err, err_size,
		    "a netlink datagram of %zu bytes arrived in a %zu-byte buffer",
		    (size_t)got, *size);
		return 0;
	}
	if (got == 0) {
		/*
		 * The kernel does not answer a request with an empty datagram.
		 * Something else on this machine can send one -- any process may
		 * unicast to a netlink socket whose port id it read out of
		 * `/proc/net/netlink` -- and reading on would attribute the rest
		 * of the answer to a conversation that had been interrupted.
		 */
		ncfg_error_set(err, err_size, "a netlink datagram with no bytes in it");
		return 0;
	}
	*length = (size_t)got;
	return 1;
}

int ncfg_netlink_collect(ncfg_netlink_recv_t source, void *context, uint32_t seq,
    uint16_t request_flags, size_t initial, ncfg_netlink_reply_t *out, char *err,
    size_t err_size)
{
	uint8_t *buffer;
	size_t   size = initial ? initial : 1u;

	if (!source || !out) {
		ncfg_error_set(err, err_size, "a netlink reply needs a source and somewhere to go");
		return 0;
	}
	memset(out, 0, sizeof(*out));
	buffer = malloc(size);
	if (!buffer) {
		ncfg_error_set(err, err_size, "no memory for a %zu-byte netlink buffer", size);
		return 0;
	}
	for (;;) {
		size_t   length = 0;
		absorb_t step;

		if (!take_datagram(source, context, &buffer, &size, &length, &out->dropped, err,
		    err_size)) {
			break;
		}
		if (length == 0) {
			/* Something local was discarded. The kernel's reply is
			 * still queued behind it, so this is a re-ask and not a
			 * failure. */
			continue;
		}
		step = absorb_reply(out, buffer, length, seq, err, err_size);
		if (step == ABSORB_BAD) {
			break;
		}
		if (step == ABSORB_DONE) {
			free(buffer);
			return 1;
		}
		/*
		 * A reply without `NLM_F_MULTI` is complete on its own. Without
		 * this a single-shot request that gets no acknowledgement blocks
		 * until the socket's timeout, and reports a timeout for an
		 * operation that worked.
		 */
		if ((request_flags & NLM_F_DUMP) == 0 && out->count > 0) {
			free(buffer);
			return 1;
		}
	}
	free(buffer);
	{
		size_t discarded = out->dropped;

		/* The count outlives the refusal. An answer that came back empty
		 * having discarded three forgeries is a different fact from one
		 * that came back empty, and the sentence in `err` cannot say so
		 * on its own. */
		ncfg_netlink_reply_free(out);
		out->dropped = discarded;
	}
	return 0;
}

int ncfg_netlink_collect_batch(ncfg_netlink_recv_t source, void *context, uint32_t last_acked,
    size_t initial, ncfg_netlink_reply_t *out, char *err, size_t err_size)
{
	uint8_t *buffer;
	size_t   size = initial ? initial : 1u;

	if (!source || !out) {
		ncfg_error_set(err, err_size, "a netlink reply needs a source and somewhere to go");
		return 0;
	}
	memset(out, 0, sizeof(*out));
	buffer = malloc(size);
	if (!buffer) {
		ncfg_error_set(err, err_size, "no memory for a %zu-byte netlink buffer", size);
		return 0;
	}
	for (;;) {
		size_t   length = 0;
		absorb_t step;

		if (!take_datagram(source, context, &buffer, &size, &length, &out->dropped, err,
		    err_size)) {
			break;
		}
		if (length == 0) {
			continue;
		}
		step = absorb_batch(out, buffer, length, last_acked, err, err_size);
		if (step == ABSORB_BAD) {
			break;
		}
		if (step == ABSORB_DONE) {
			free(buffer);
			return 1;
		}
	}
	free(buffer);
	{
		size_t discarded = out->dropped;

		/* The count outlives the refusal. An answer that came back empty
		 * having discarded three forgeries is a different fact from one
		 * that came back empty, and the sentence in `err` cannot say so
		 * on its own. */
		ncfg_netlink_reply_free(out);
		out->dropped = discarded;
	}
	return 0;
}

/*
 * The real datagram source: this module's own socket.
 *
 * `recvfrom` and not `recv`, which is the whole of the sender check. The
 * address costs one struct on the stack per receive and is the only way to find
 * out that a datagram came from a process on this machine rather than from the
 * kernel -- see the note in `netlink.h` about why that is a question anybody
 * can force, and why the answer is to drop.
 */
static ssize_t socket_recv(void *context, void *bytes, size_t length, int peek, uint32_t *from)
{
	const ncfg_netlink_t *netlink = context;
	struct sockaddr_nl    sender;
	socklen_t             sender_size = (socklen_t)sizeof(sender);
	int                   flags = MSG_TRUNC;
	ssize_t               read;

	/* Not the kernel, until the kernel is what the address says. Set before
	 * the call and left alone on every path that does not learn better,
	 * including the failing one. */
	*from = UINT32_MAX;
	if (peek) {
		flags |= MSG_PEEK;
	}
	memset(&sender, 0, sizeof(sender));
	read = recvfrom(netlink->fd, bytes, length, flags, (struct sockaddr *)&sender,
	    &sender_size);
	if (read < 0) {
		return read;
	}
	/* A short or truncated address is "I do not know", which lands on the
	 * safe side of the caller's one comparison rather than on zero. */
	if (sender_size >= (socklen_t)sizeof(sender) && sender.nl_family == AF_NETLINK) {
		*from = sender.nl_pid;
	}
	return read;
}

static int send_bytes(const ncfg_netlink_t *netlink, const void *bytes, size_t length,
    char *err, size_t err_size)
{
	/*
	 * A datagram socket sends all of it or none, so there is no partial
	 * send to loop over. Flags are 0: the Rust passes `MSG_TRUNC`, which is
	 * a *receive* flag and does nothing on a send -- carried across it would
	 * be one more thing a reader has to look up to find out it means
	 * nothing.
	 */
	if (send(netlink->fd, bytes, length, 0) < 0) {
		return ncfg_netlink_fail(err, err_size, "sending a netlink request", errno);
	}
	return 1;
}

int ncfg_netlink_request_from(ncfg_netlink_t *netlink, uint16_t kind, uint16_t flags,
    const ncfg_buf_t *body, const ncfg_buf_t *attrs, size_t initial,
    ncfg_netlink_reply_t *out, char *err, size_t err_size)
{
	ncfg_buf_t message;
	uint32_t   seq;
	int        sent;
	int        collected;

	if (!netlink || netlink->fd < 0 || !out) {
		ncfg_error_set(err, err_size, "a netlink request needs an open socket");
		return 0;
	}
	memset(out, 0, sizeof(*out));
	seq = next_seq(netlink);
	ncfg_buf_init(&message, 0);
	if (!ncfg_wire_build_request(&message, kind, flags, seq, body, attrs, err, err_size)) {
		ncfg_buf_free(&message);
		return 0;
	}
	sent = send_bytes(netlink, message.data, message.length, err, err_size);
	ncfg_buf_free(&message);
	if (!sent) {
		return 0;
	}
	collected = ncfg_netlink_collect(socket_recv, netlink, seq, flags, initial, out, err,
	    err_size);
	/* Carried up to the socket whether the request succeeded or not, since
	 * the count survives a refusal for exactly the case where the forgery is
	 * what went wrong. */
	netlink->dropped += (uint32_t)out->dropped;
	return collected;
}

int ncfg_netlink_request(ncfg_netlink_t *netlink, uint16_t kind, uint16_t flags,
    const ncfg_buf_t *body, const ncfg_buf_t *attrs, ncfg_netlink_reply_t *out, char *err,
    size_t err_size)
{
	return ncfg_netlink_request_from(netlink, kind, flags, body, attrs,
	    NCFG_NETLINK_REPLY_INITIAL, out, err, err_size);
}

int ncfg_netlink_send_batch(ncfg_netlink_t *netlink, const void *bytes, size_t length,
    uint32_t last_acked, ncfg_netlink_reply_t *out, char *err, size_t err_size)
{
	int collected;

	if (!netlink || netlink->fd < 0 || !out) {
		ncfg_error_set(err, err_size, "a netlink batch needs an open socket");
		return 0;
	}
	memset(out, 0, sizeof(*out));
	if (!send_bytes(netlink, bytes, length, err, err_size)) {
		return 0;
	}
	collected = ncfg_netlink_collect_batch(socket_recv, netlink, last_acked,
	    NCFG_NETLINK_REPLY_INITIAL, out, err, err_size);
	netlink->dropped += (uint32_t)out->dropped;
	return collected;
}

int ncfg_netlink_change_from(ssize_t read, int code, int *changed, char *err, size_t err_size)
{
	if (!changed) {
		ncfg_error_set(err, err_size, "a watch needs somewhere to report a change");
		return 0;
	}
	*changed = 0;
	if (read >= 0) {
		/* A zero-length message is still a message: something woke the
		 * socket, and the daemon's answer to that is to look again. */
		*changed = 1;
		return 1;
	}
	if (code == EAGAIN || code == EWOULDBLOCK || code == ETIMEDOUT) {
		/* SO_RCVTIMEO expiring, which the caller uses as its own tick.
		 * Both spellings, because which one a platform returns is not
		 * fixed. */
		return 1;
	}
	if (code == EINTR) {
		/* **The one this function exists for.** Not a failure, and not a
		 * change either -- nothing has been read and the caller should
		 * ask again. Treating it as fatal cost a machine its network
		 * configuration for fifty-two minutes (0233). */
		return 1;
	}
	if (code == ENOBUFS) {
		/* The buffer overflowed and messages were dropped. A change,
		 * because the daemon re-reads rather than applying deltas -- a
		 * watcher that stopped here would stop when the most was
		 * happening. */
		*changed = 1;
		return 1;
	}
	return ncfg_netlink_fail(err, err_size, "watching netlink for a change", code);
}

int ncfg_netlink_wait_for_change(ncfg_netlink_t *netlink, int *changed, char *err,
    size_t err_size)
{
	/*
	 * The bytes are read and thrown away on purpose: a multicast message is
	 * "something moved, look again" rather than a delta to apply. Deltas can
	 * be lost -- `ENOBUFS` is a gap -- so a full re-read is the only version
	 * that cannot drift.
	 */
	uint8_t  buffer[8192];
	ssize_t  read;
	uint32_t from = UINT32_MAX;
	int      saved;

	if (!netlink || netlink->fd < 0 || !changed) {
		ncfg_error_set(err, err_size, "a watch needs an open socket");
		return 0;
	}
	read = socket_recv(netlink, buffer, sizeof(buffer), 0, &from);
	saved = errno;
	if (read >= 0 && from != 0) {
		/*
		 * Local, so discarded -- and reported as "nothing yet" rather
		 * than as a change. The bytes are thrown away either way, so the
		 * only thing a forged message could do here is *wake the
		 * daemon*: reported as news, any local process could make a root
		 * daemon re-read every link, address and route on the machine as
		 * fast as it cared to send. The caller's loop asks again, which
		 * is what it already does for a signal.
		 */
		netlink->dropped++;
		*changed = 0;
		return 1;
	}
	return ncfg_netlink_change_from(read, saved, changed, err, err_size);
}
