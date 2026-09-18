/*
 * cli_internal.h -- what the `ncfg` sources share and nobody outside needs.
 *
 * Small on purpose. `cli.h` is the face this program presents to its own
 * `main` and to the tests that drive its output; anything in here is either a
 * convenience over the protocol's counted strings or a piece of the dispatch
 * that has no reader outside `src/cli/`.
 */
#ifndef NCFG_CLI_INTERNAL_H
#define NCFG_CLI_INTERNAL_H

#include "ncfg/cli.h"

#include <stddef.h>

/*
 * A counted protocol string as a NUL-terminated one.
 *
 * The protocol carries `{bytes, length}` because absent, empty and null are
 * three answers and a `char *` can only carry two. Printing needs one string,
 * so this copies into a caller's buffer -- bounded, because the text came off
 * a socket and its length is whoever is on the other end's choice. An absent
 * string reads back as the empty one, which is what every call site here wants:
 * they have already asked `ncfg_proto_str_present` where the difference
 * matters.
 */
const char *ncfg_cli_text(ncfg_proto_str_t text, char *out, size_t out_size);

/*
 * The longest single value this program renders into a stack buffer.
 *
 * An SSID is 32 octets, a name is a name, and a daemon's sentence is a
 * sentence; nothing the CLI puts in one of these is a payload. `buf.h` carries
 * the ceiling for text a client composes.
 */
#define NCFG_CLI_TEXT_MAX 512

/*
 * The longest sentence this program builds for stderr.
 *
 * Longer than one value, because a sentence carries two of them and its own
 * words. Where a value comes from `argv` it is bounded at the format with
 * `%.*s` and `NCFG_CLI_TEXT_MAX` rather than trusted: an interface name a
 * caller chose the length of would otherwise decide how much of the sentence
 * survives, and the half that gets cut is the half that says what to do.
 */
#define NCFG_CLI_SENTENCE_MAX 1024

/*
 * Subscribe to the daemon's event stream and print until it ends.
 *
 * There is no exit condition on this side by design: `monitor` is something
 * you leave running in another window and interrupt when you are done. It
 * returns 1 when the daemon stopped sending, which is an ordinary end and not
 * a failure, and 0 with a sentence otherwise.
 *
 * **`json` prints the line the daemon sent rather than a rendering of it**,
 * which is the one place `--json` is a passthrough rather than a writer. The
 * events are already JSON, one value per line, and `doc/schema/socket.json`
 * pins the five shapes; re-composing them from `ncfg_proto_event_t` would
 * drop every member this build does not know about, on the one verb whose
 * whole argument for existing is that an event it does not recognise is
 * printed rather than swallowed.
 */
int ncfg_cli_stream(const char *socket_path, int json, char *err, size_t err_size);

#endif /* NCFG_CLI_INTERNAL_H */
