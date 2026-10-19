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
 * WHAT THIS SLICE WILL NOT DO
 *   A security group carrying a passphrase is refused, naming `ncfg wifi add`.
 *   Writing one means putting a credential in the secret provider and a
 *   `@secret:` reference in the block (0030, 0031), and a renderer that wrote
 *   the open case while silently dropping a `psk` would hand a client a secured
 *   network with no credential and no error.
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
} nmc_block_t;

/*
 * Render the settings dictionary in `call` as a netcfgd `network` block.
 *
 * `call`'s first argument is the `a{sa{sv}}` NM's `AddConnection` takes. Answers
 * 1 with `out` filled, or 0 with `err` carrying the sentence a client is shown.
 */
int nmc_block_render(DBusMessage *call, nmc_block_t *out, char *err, size_t err_size);

#endif /* NMC_BLOCK_H */
