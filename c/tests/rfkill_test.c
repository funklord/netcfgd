/*
 * rfkill_test.c -- the kill switch record, against bytes rather than against a
 * machine with a radio.
 *
 * WHY THIS EXISTS
 *   The reading is a `read` in a loop; the part that can be silently wrong is
 *   the record, and it is wrong in ways nothing reports: a byte order mistake
 *   makes switch 258 look like switch 2, and a reassembly mistake makes every
 *   record after an extended one describe a switch that is not there. Neither
 *   needs a device to check, and neither would be noticed on a machine with one
 *   radio and no kill switch.
 *
 *   Nothing here opens `/dev/rfkill`. The one case that needs a descriptor is
 *   the refusal for a device that is not there, and that is asked of a path
 *   under this test's own temporary directory rather than of the machine's.
 *
 * WHERE THE FIXTURE CAME FROM
 *   The four-record capture below is the Rust's, which was taken by opening
 *   the device on the machine netcfgd was written on: four switches, one `ADD`
 *   each, two WLAN and two Bluetooth, none blocked. A fixture written by hand
 *   would agree with whatever this file believes; these are bytes a kernel
 *   produced.
 */
#include "ncfg/base.h"
#include "ncfg/rfkill.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int failures;

static void check(int condition, const char *what)
{
	printf("%-58s %s\n", what, condition ? "ok" : "FAILED");
	if (!condition) {
		failures++;
	}
}

/*
 * A copy whose last byte is the last byte of an allocation.
 *
 * A short record tested as a prefix of a longer buffer is not tested at all:
 * an overread lands in the rest of the allocation and ASan has nothing to say.
 * wire_test.c has the long version of this note.
 */
static uint8_t *exact_copy(const void *bytes, size_t length)
{
	uint8_t *copy;

	if (!bytes || length == 0) {
		return NULL;
	}
	copy = malloc(length);
	if (!copy) {
		return NULL;
	}
	memcpy(copy, bytes, length);
	return copy;
}

int main(void)
{
	/* The kernel's layout, byte for byte. */
	{
		/* idx = 1, type = 1 (WLAN), op = 2 (CHANGE), soft = 1, hard = 0. */
		const uint8_t one[] = { 0x01, 0x00, 0x00, 0x00, 0x01, 0x02, 0x01, 0x00 };
		/* And a multi-byte index, which is where a byte order mistake
		 * shows: read big-endian this is 0x02010000 rather than 0x0102. */
		const uint8_t two[] = { 0x02, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 };
		ncfg_rfkill_event_t event;

		check(ncfg_rfkill_parse(one, sizeof(one), &event, NULL, 0), "a record parses");
		check(event.index == 1u, "and its index is the one the kernel wrote");
		check(event.kind == RFKILL_TYPE_WLAN, "its type is WLAN");
		check(event.op == RFKILL_OP_CHANGE, "its operation is CHANGE");
		check(event.soft && !event.hard, "soft blocked and not hard blocked");

		check(ncfg_rfkill_parse(two, sizeof(two), &event, NULL, 0), "a second record parses");
		check(event.index == 0x0102u, "a multi-byte index is read in host order");
		check(!event.soft && event.hard, "hard blocked and not soft blocked");
	}

	/* What a real kernel handed over, replayed. */
	{
		const uint8_t seen[4][NCFG_RFKILL_RECORD] = {
			{ 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00 },
			{ 0x01, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00 },
			{ 0x02, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00 },
			{ 0x03, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00 }
		};
		ncfg_rfkill_event_t event;
		int                 indices = 1;
		int                 added = 1;
		int                 unblocked = 1;
		size_t              at;

		for (at = 0; at < 4; at++) {
			if (!ncfg_rfkill_parse(seen[at], NCFG_RFKILL_RECORD, &event, NULL, 0)) {
				indices = 0;
				break;
			}
			indices = indices && event.index == (uint32_t)at;
			added = added && event.op == RFKILL_OP_ADD;
			unblocked = unblocked && !event.soft && !event.hard;
		}
		check(indices, "a real kernel's four switches read back in order");
		check(added, "every one of them was an ADD");
		check(unblocked, "and none of them was blocked");

		(void)ncfg_rfkill_parse(seen[0], NCFG_RFKILL_RECORD, &event, NULL, 0);
		check(event.kind == RFKILL_TYPE_WLAN, "the first switch is the wlan one");
		(void)ncfg_rfkill_parse(seen[1], NCFG_RFKILL_RECORD, &event, NULL, 0);
		check(event.kind == RFKILL_TYPE_BLUETOOTH, "and the second is bluetooth");
	}

	/*
	 * A longer record is one event, and the surplus is ignored.
	 *
	 * A kernel with `rfkill_event_ext` writes nine bytes. This is the case
	 * the Rust's first version got wrong: it buffered whatever a read
	 * returned and cut records at eight, so the ninth byte became the first
	 * byte of the next one and every event after it was wrong.
	 */
	{
		const uint8_t extended[] = {
			0x01, 0x00, 0x00, 0x00, 0x01, 0x02, 0x01, 0x00, 0xff
		};
		uint8_t            *exact = exact_copy(extended, sizeof(extended));
		ncfg_rfkill_event_t event;

		check(exact != NULL, "the extended record is allocated to its own size");
		if (exact) {
			check(ncfg_rfkill_parse(exact, sizeof(extended), &event, NULL, 0),
			    "an extended record is still one event");
			check(event.index == 1u && event.op == RFKILL_OP_CHANGE && event.soft,
			    "and it is the event the first eight bytes describe");
			free(exact);
		}
	}

	/* A record shorter than the eight bytes every version has is a refusal
	 * with a sentence, not a partly-filled event. */
	{
		const uint8_t short_record[] = { 0x01, 0x00, 0x00, 0x00, 0x01, 0x02, 0x01 };
		uint8_t            *exact = exact_copy(short_record, sizeof(short_record));
		ncfg_rfkill_event_t event;
		char                err[NCFG_ERROR_MAX];

		memset(&event, 0xff, sizeof(event));
		err[0] = '\0';
		if (exact) {
			check(!ncfg_rfkill_parse(exact, sizeof(short_record), &event, err,
			    sizeof(err)), "seven bytes are not a record");
			free(exact);
		}
		check(err[0] != '\0', "and the refusal says so");
		check(event.index == 0u && event.kind == 0u && !event.soft && !event.hard,
		    "a refused record leaves the event zeroed rather than half filled");
		check(!ncfg_rfkill_parse(NULL, NCFG_RFKILL_RECORD, &event, NULL, 0),
		    "and no bytes at all are refused too");
		check(!ncfg_rfkill_parse(short_record, sizeof(short_record), NULL, NULL, 0),
		    "as is a parse with nowhere to put the answer");
	}

	/*
	 * The device that is not there.
	 *
	 * A machine with no radio has no `/dev/rfkill`, and the sentence says
	 * which. Asked of a path that cannot exist rather than of the machine's
	 * own device: this suite does not open the workstation's.
	 */
	{
		ncfg_rfkill_t rfkill;
		char          err[NCFG_ERROR_MAX];

		ncfg_rfkill_init(&rfkill);
		err[0] = '\0';
		check(!ncfg_rfkill_open(&rfkill, "/nonexistent/ncfg-rfkill-test", err, sizeof(err)),
		    "a device that is not there is a refusal");
		check(strstr(err, "no radio") != NULL, "and the sentence names what it means");
		check(rfkill.fd < 0, "a refused open leaves nothing open");
		/* Closing one that was never opened is nothing, which is what
		 * makes a failure path cheap. */
		ncfg_rfkill_close(&rfkill);
		ncfg_rfkill_close(&rfkill);
		check(rfkill.fd < 0, "and closing it twice is still nothing");

		check(!ncfg_rfkill_open(NULL, NCFG_RFKILL_DEVICE, NULL, 0),
		    "an open with nowhere to put the descriptor is refused");
	}

	/* A read from a reader that was never opened is a refusal rather than a
	 * read from descriptor -1, and `got` is cleared before anything else can
	 * fail -- a caller that checks `got` on a failure must not see a stale
	 * 1 from the last call. */
	{
		ncfg_rfkill_t       rfkill;
		ncfg_rfkill_event_t event;
		int                 got = 1;

		ncfg_rfkill_init(&rfkill);
		check(!ncfg_rfkill_next(&rfkill, &event, &got, NULL, 0),
		    "reading from a reader that was never opened is refused");
		check(got == 0, "and the refusal clears whether an event came out");
	}

	if (failures == 0) {
		printf("rfkill_test: all checks passed\n");
	} else {
		printf("rfkill_test: %d check(s) failed\n", failures);
	}
	return failures == 0 ? 0 : 1;
}
