/*
 * An mDNS query, as netrescue's responder reads one (0326, project.md
 * 10.880).
 *
 * WHY THIS DESERVES A TARGET OF ITS OWN
 *   netrescue runs as root and answers whatever arrives on UDP 5353 from
 *   any host on any port's link, before anything else is known about the
 *   network -- which is the point of it. `ncfg_rescue_mdns_answer` is the
 *   only code that reads those bytes, and its names may hold compression
 *   pointers, which is where a parser loops or reads past its end.
 *
 * THE INVARIANTS WORTH ASSERTING
 *   An answer is never longer than its buffer, says it is a response with
 *   ID zero, and counts at least one record; the same query against a
 *   buffer too small for its answer is refused rather than cut. Reads past
 *   the input are the sanitizers' to catch.
 */
#include "fuzz.h"

#include "ncfg/rescue.h"

#include <stdlib.h>
#include <string.h>

int ncfg_fuzz_one(const unsigned char *data, size_t length)
{
	static const uint32_t ipv4[2] = { 0xfa00000au, 0x0102a8c0u };
	static const uint8_t  ipv6[1][16] = { { 0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 7 } };
	uint8_t               answer[1500];
	uint8_t               small[24];
	size_t                answered;

	answered = ncfg_rescue_mdns_answer(data, length, "rescue", ipv4, 2, ipv6, 1, answer,
	    sizeof(answer));
	if (answered > sizeof(answer)) {
		abort(); /* written past the buffer */
	}
	if (answered != 0u) {
		if (answered < 12u || answer[0] != 0 || answer[1] != 0 || answer[2] != 0x84 ||
		    (answer[6] == 0 && answer[7] == 0)) {
			abort(); /* not a response, or one that answers nothing */
		}
	}
	if (ncfg_rescue_mdns_answer(data, length, "rescue", ipv4, 2, ipv6, 1, small, sizeof(small)) >
	    sizeof(small)) {
		abort();
	}
	return 0;
}
