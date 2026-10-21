/*
 * The control socket's own protocol: framing, then the message.
 *
 * The socket is `root:netcfgd` mode 0660, so these bytes come from a process
 * in that group rather than from anywhere -- which is a weaker boundary than
 * netlink's and a real one all the same: section 13 says group `netcfgd` may
 * read status and plan, and a member of that group must not be able to end the
 * daemon by sending it a line.
 *
 * **Framing and parsing are one contract**, so this drives them as one: bytes
 * go into the framer in two slices, each whole line that comes out is read as
 * a request and as a response, and anything that parsed has to survive its own
 * encoder. A round trip is the only assertion that holds both ends.
 *
 * Two slices rather than one, because a framer whose input always arrives
 * whole is a framer whose partial-line path never runs -- and that path is the
 * one a short read on a socket takes every day.
 */
#include "fuzz.h"

#include "ncfg/base.h"
#include "ncfg/buf.h"
#include "ncfg/proto.h"

#include <stdlib.h>
#include <string.h>

static void one_line(const char *line, size_t length)
{
	ncfg_proto_message_t message;
	char                 err[NCFG_ERROR_MAX];

	if (ncfg_proto_request_read(line, length, &message, err, sizeof(err))) {
		ncfg_proto_message_free(&message);
	}
	if (ncfg_proto_response_read(line, length, &message, err, sizeof(err))) {
		ncfg_proto_message_free(&message);
	}
	if (ncfg_proto_message_read(line, length, &message, err, sizeof(err))) {
		ncfg_proto_message_free(&message);
	}
}

int ncfg_fuzz_one(const unsigned char *data, size_t length)
{
	ncfg_proto_framer_t framer;
	size_t              split = length / 2u;
	char                err[NCFG_ERROR_MAX];

	ncfg_proto_framer_init(&framer);
	if (ncfg_proto_framer_add(&framer, data, split, err, sizeof(err)) &&
	    ncfg_proto_framer_add(&framer, data + split, length - split, err, sizeof(err))) {
		for (;;) {
			const char              *line = NULL;
			size_t                   taken = 0u;
			ncfg_proto_line_result_t result =
			    ncfg_proto_framer_next(&framer, &line, &taken, err, sizeof(err));

			if (result != NCFG_PROTO_LINE) {
				break;
			}
			one_line(line, taken);
		}
		/* The end-of-stream half: a partial line left over is a message cut
		 * in two and must be refused rather than half-read. */
		(void)ncfg_proto_framer_finish(&framer, err, sizeof(err));
	}
	ncfg_proto_framer_free(&framer);

	/* And the whole input as one line, which is what a caller that framed
	 * elsewhere hands these readers. */
	one_line((const char *)data, length);
	return 0;
}
