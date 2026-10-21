/*
 * The leaf parsers, where a value stops being text.
 *
 * WHY THESE DESERVE A TARGET OF THEIR OWN
 *   Every one of them is reachable through `config_parse` or
 *   `document_json` already, and reaching a function is not the same as
 *   exercising it: a parser three layers down sees only what the layers above
 *   let through, and the lexer's rules are not the key parser's. Driving them
 *   directly is the difference between fuzzing the DSL and fuzzing the thing
 *   the DSL hands a string to.
 *
 *   They are also where a wrong answer is worst. A key that parses to the
 *   wrong bytes is a tunnel to nobody; a MAC that parses to the wrong octets
 *   is a filter that passes somebody else; an SSID whose hex decodes short is
 *   a network joined under a name nobody typed.
 *
 * THE ONE INVARIANT WORTH ASSERTING
 *   A key that parses must RE-RENDER to the text it came from, modulo the
 *   encoding's own canonical form. `ncfg_key_render` is the other half of
 *   `ncfg_key_parse` and the two have to be inverses -- a WireGuard key goes
 *   into a config file, out to the kernel, and back into a document a client
 *   reads, so a round trip that loses a bit is a tunnel that comes up once
 *   and never again.
 */
#include "fuzz.h"

#include "ncfg/base.h"
#include "ncfg/cli.h"
#include "ncfg/document.h"
#include "ncfg/ops.h"

#include <stdlib.h>
#include <string.h>

int ncfg_fuzz_one(const unsigned char *data, size_t length)
{
	unsigned char   key[NCFG_KEY_LEN];
	uint8_t         mac[6];
	ncfg_ssid_t     ssid;
	ncfg_principal_t principal;
	char            err[NCFG_ERROR_MAX];
	char           *text = ncfg_fuzz_text(data, length);

	if (!text) {
		return 0;
	}
	/* A WireGuard key: 44 characters of base64 for 32 bytes. */
	if (ncfg_key_parse(text, length, key, err, sizeof(err))) {
		char rendered[NCFG_KEY_TEXT_LEN + 1u];
		unsigned char again[NCFG_KEY_LEN];

		if (!ncfg_key_render(key, rendered, sizeof(rendered), err, sizeof(err))) {
			abort(); /* a key that parsed must render */
		}
		if (!ncfg_key_parse(rendered, strlen(rendered), again, err, sizeof(err))) {
			abort(); /* and its own rendering must parse */
		}
		if (memcmp(key, again, sizeof(key)) != 0) {
			abort(); /* the two are not inverses */
		}
	}

	/* A hardware address out of a config file or a client's request. */
	(void)ncfg_ops_parse_mac(text, mac, err, sizeof(err));

	/* An SSID as the model carries it: hex, because an SSID is octets and not
	 * text (0229's argument, one layer down). */
	memset(&ssid, 0, sizeof(ssid));
	(void)ncfg_ssid_parse_hex(text, length, &ssid, err, sizeof(err));

	/*
	 * A principal, which is a CLI argument and therefore somebody's typing.
	 *
	 * **The name is the caller's to free**, which `cli.h` says and this target
	 * did not do -- LeakSanitizer reported seven bytes on the first run, which
	 * is the third bug the sanitizers found in a harness rather than in what
	 * it drives. A reader that leaks on the success path is exactly what a
	 * million executions turns into a machine with no memory, so the target
	 * has to be as careful with ownership as the program is.
	 */
	memset(&principal, 0, sizeof(principal));
	if (ncfg_cli_principal_parse(text, &principal, err, sizeof(err))) {
		char rendered[256];

		(void)ncfg_cli_principal_render(&principal, rendered, sizeof(rendered));
		free(principal.name);
	}
	free(text);
	return 0;
}
