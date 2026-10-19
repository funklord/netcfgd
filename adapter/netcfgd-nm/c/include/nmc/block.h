/*
 * nmc/block.h -- the netcfgd block a client's settings dictionary becomes.
 *
 * `emit.rs`'s `network_block`, which is the write direction of design section
 * 9.4: a GUI is another editor of configuration files, so what comes out of
 * `AddConnection` has to be a block an operator could have typed. The file it
 * lands in is ordinary netcfgd configuration -- removing this shim leaves it
 * behind, still valid -- and that is the whole argument for rendering text
 * rather than keeping a profile store of our own.
 *
 * WHY A REFUSAL RATHER THAN A PARTIAL BLOCK
 *   Everything a client can send that netcfgd's language cannot say is refused
 *   BY NAME, before anything is written, so the client shows a sentence instead
 *   of a generic failure and no file exists to clean up. The exception is a
 *   setting that is merely absent from netcfgd's vocabulary -- an MTU on a
 *   network -- which is written into the file as a comment: 0034's rule that
 *   what cannot be expressed is named rather than dropped.
 *
 * WHERE THE CREDENTIAL GOES, AND WHY NOT IN THE BLOCK
 *   A passphrase never reaches `text`. What goes in the block is
 *   `psk = "@secret:<id>"`, and the value comes back separately in `secret`
 *   for the caller to hand to netcfgd's secret provider -- 0030 and 0031's
 *   bridge, inbound only, with nothing reading one back out. That is why this
 *   renders two things rather than one: a function returning a block with the
 *   passphrase in it would have put a credential in a file that is read,
 *   diffed and committed.
 *
 *   The caller forgets it with `nmc_block_forget` as soon as it has been
 *   handed over. 0042 calls a credential the one thing on a machine nobody
 *   can get back; the matching rule for a process is that it holds one for as
 *   few lines as it can.
 */
#ifndef NMC_BLOCK_H
#define NMC_BLOCK_H

#include "nmc/bus.h"

#include <stddef.h>

/*
 * Big enough for a block with every key this writes and a dropped-settings
 * note listing what a client sent beside them; far below the daemon's
 * `NCFG_CONFIG_FILE_MAX`, which is a limit on a hand-written file rather than
 * on this. Overflow is a refusal, never a truncated block -- half a block is a
 * file that will not compile, and the loader reads the directory as one
 * document, so it would take every other network down with it.
 */
#define NMC_BLOCK_MAX 8192u

typedef struct {
	/* The block's label, which is the profile's id. Sized to the buffer the
	 * renderer reads the id into rather than to the 64 the label rule allows,
	 * so that the copy cannot be a truncation of a value that was refused. */
	char label[256];
	/* The drop-in's stem under `conf.d`, which is the label sanitised. */
	char stem[96];
	char text[NMC_BLOCK_MAX];
	/*
	 * The passphrase, where the client sent one -- 1 in `has_secret`, and the
	 * value under the profile's own name, which is what the `@secret:`
	 * reference in `text` points at. A passphrase is at most 63 octets (0229),
	 * so this is sized for one and not for whatever a client felt like
	 * sending: a value that does not fit is refused rather than stored short.
	 */
	int  has_secret;
	char secret[96];
} nmc_block_t;

/*
 * Render the settings dictionary in `call` as a netcfgd `network` block.
 *
 * `call`'s first argument is the `a{sa{sv}}` NM's `AddConnection` takes. Answers
 * 1 with `out` filled, or 0 with `err` carrying the sentence a client is shown.
 */
int nmc_block_render(DBusMessage *call, nmc_block_t *out, char *err, size_t err_size);

/*
 * Forget a rendered block, credential included.
 *
 * Called on every path out of a write, which is why it takes a block in any
 * state and says nothing: a caller that has to decide whether to wipe is one
 * that will get it wrong on the error path.
 */
void nmc_block_forget(nmc_block_t *block);

/*
 * The drop-in stem a profile's id is filed under: `nm-` and the id sanitised
 * into something a filename can be.
 *
 * The same answer `nmc_block_render` puts in `stem`, exported because removing
 * a profile needs it without rendering one -- and because the name is what
 * says the shim wrote the file, so there must be exactly one rule for it.
 */
void nmc_block_stem(const char *id, char *out, size_t cap);

#endif /* NMC_BLOCK_H */
