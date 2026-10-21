/*
 * The settings dictionary a client sends, from the wire.
 *
 * WHY THIS IS THE ONE PARSER IN THE SHIM WORTH FUZZING
 *   `AddConnection` takes `a{sa{sv}}` -- a dictionary of dictionaries of
 *   variants -- and the renderer walks it looking for groups and keys it
 *   knows, with every value a type it has to check before reading. It is 1,200
 *   lines of exactly the code a fuzzer is for, and it runs as a privileged
 *   service's handler on the system bus: anything the bus policy lets send to
 *   `org.freedesktop.NetworkManager` can call it with any dictionary that
 *   types.
 *
 * WHAT THE INPUT IS, AND WHY IT IS THE WHOLE MESSAGE
 *   `dbus_message_demarshal` turns the bytes into a message, and the target
 *   then renders it. **The alternative was to build a dictionary from the
 *   bytes with a generator**, which reaches the renderer on nearly every input
 *   and is structure-aware -- but a generator can only produce what somebody
 *   thought to write, and the question here is what a client can send. This
 *   way the corpus is real marshalled calls (`fuzz/make_seeds.c`), the
 *   mutations are of a real message, and nothing stands between the fuzzer and
 *   the API the shim actually exposes.
 *
 *   It fuzzes libdbus's demarshaller as well as our reader, which is somebody
 *   else's code and already fuzzed upstream. That is a cost rather than a
 *   benefit and it is the price of using the real entry point; a crash inside
 *   libdbus is a finding to report there, not here.
 *
 * WHAT IS DRIVEN
 *   Both arms of `nmc_block_render` -- `stored` 0 and 1, which is the
 *   difference between an add and an update of a profile whose credential is
 *   already on disk -- then the agent reply reader over the same message,
 *   since 0031's reply is the same shape read for the opposite purpose. The
 *   two pure functions are driven from the bytes as well, because they are
 *   cheap and `nmc_block_stem` builds a filename out of a client's id.
 */
#include "fuzz.h"

#include "shape.h"

#include "nmc/block.h"
#include "nmc/bus.h"

#include <dbus/dbus.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int ncfg_fuzz_one(const unsigned char *data, size_t length)
{
	DBusError    problem;
	DBusMessage *call;
	nmc_block_t  block;
	char         err[NMC_ERROR_MAX];
	char         passphrase[96];
	char         stem[96];

	/* `nmc_block_stem` and `nmc_block_priority` need no message: the first
	 * makes a filename out of whatever a client called its profile, and the
	 * second is the inverse of a scaling whose other half lives in the
	 * renderer (0207). Driven first, so they run on every input rather than
	 * only on the ones that demarshal. */
	{
		char *id = ncfg_fuzz_text(data, length);

		if (id) {
			nmc_block_stem(id, stem, sizeof(stem));
			free(id);
		}
	}
	if (length >= sizeof(int)) {
		int metric;

		memcpy(&metric, data, sizeof(metric));
		(void)nmc_block_priority(metric);
	}

	dbus_error_init(&problem);
	call = dbus_message_demarshal((const char *)data, (int)length, &problem);
	if (!call) {
		dbus_error_free(&problem);
		return 0;
	}
	dbus_error_free(&problem);

	/* An add: no stored credential, so a secured network with no `psk` is
	 * refused rather than written without one. */
	memset(&block, 0, sizeof(block));
	if (nmc_block_render(call, 0, &block, err, sizeof(err))) {
		/*
		 * **The invariants a successful render promises**, asserted because a
		 * fuzzer that only checks for crashes would pass a renderer that
		 * wrote a block with no label or leaked a passphrase into one.
		 */
		if (block.label[0] == '\0') {
			abort(); /* a rendered block with no label */
		}
		if (block.stem[0] == '\0') {
			abort(); /* nothing to file it under */
		}
		if (block.has_secret) {
			char needle[128];

			if (block.secret[0] == '\0') {
				abort(); /* a credential promised and not carried */
			}
			/*
			 * **The credential must never be the VALUE of `psk`.** This said
			 * "the secret appears nowhere in the text", which is a stronger
			 * claim than the code owes and it fired on a passphrase that
			 * happened to equal a group name the dropped-settings note lists
			 * -- a false positive that cost an investigation. What 0042 and
			 * 0229 actually require is that the file carries a REFERENCE: the
			 * octets live in the secret store, and `psk` says `@secret:`.
			 */
			(void)snprintf(needle, sizeof(needle), "psk = \"%s\"", block.secret);
			if (strstr(block.text, needle) != NULL) {
				abort(); /* the passphrase itself was written into the file */
			}
			if (strstr(block.text, "@secret:") == NULL) {
				abort(); /* a credential, and nothing pointing at it */
			}
		}
		/* And the shape, which is the invariant a crash-only fuzzer cannot
		 * see: the text has to still be ONE network block (`fuzz/shape.c`). */
		nmc_fuzz_check_shape(block.text);
	}
	nmc_block_forget(&block);

	/* An update of a profile that already has one by reference, which is the
	 * arm a client's read-modify-write takes. */
	memset(&block, 0, sizeof(block));
	(void)nmc_block_render(call, 1, &block, err, sizeof(err));
	nmc_block_forget(&block);

	/* An agent's reply, read out of the same shape. */
	(void)nmc_block_passphrase_in(call, passphrase, sizeof(passphrase));
	memset(passphrase, 0, sizeof(passphrase));

	dbus_message_unref(call);
	return 0;
}
