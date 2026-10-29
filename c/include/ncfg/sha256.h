/*
 * sha256.h -- the one digest in the C port, in `base` where everything may
 * reach it.
 *
 * It lived in `host` beside the hook runner, its first caller, and `hooks.h`
 * declared it. The model needed it once fast roaming derived a mobility domain
 * from an SSID (project.md 10.587), and a model including a host header is the
 * layering 0263 forbids -- `tool/module_order_gate.py` said so. A digest is a
 * primitive with no opinion about hooks, so it moved down rather than the
 * derivation moving up. `hooks.h` includes this, so its callers are unchanged.
 */
#ifndef NCFG_SHA256_H
#define NCFG_SHA256_H

#include <stddef.h>

/* 64 hex digits and the terminator. */
#define NCFG_SHA256_HEX_SIZE 65

/*
 * SHA-256 of `length` bytes, as lowercase hex, NUL-terminated.
 *
 * `out` is `NCFG_SHA256_HEX_SIZE` bytes. Never fails: there is nothing to
 * allocate and no input it refuses.
 */
void ncfg_sha256_hex(const void *bytes, size_t length, char *out);

#endif /* NCFG_SHA256_H */
