/*
 * nmc/uuid.h -- a profile's UUID, derived from its identity.
 *
 * The identity is `network:<id>` or `interface:<name>`, prefixed by kind so that
 * a `network "wlan0"` and an `interface wlan0` are two profiles rather than one.
 * Without the prefix the collision would be unlikely and baffling.
 */
#ifndef NMC_UUID_H
#define NMC_UUID_H

#include <stddef.h>

/*
 * `UUIDv5` of this project's namespace and `identity`, as 36 characters plus a
 * terminator. `out_size` below 37 truncates.
 */
void nmc_uuid_of(const char *identity, char *out, size_t out_size);

/*
 * The SHA-1 behind it, exposed for the test that checks it against FIPS 180's
 * published vectors rather than against itself.
 *
 * **Not a general-purpose digest.** SHA-1 is broken for anything needing
 * collision resistance; a UUIDv5 needs only that the same name gives the same
 * answer everywhere, which is what the standard asks SHA-1 for here.
 */
void nmc_sha1(const void *bytes, size_t count, unsigned char out[20]);

#endif /* NMC_UUID_H */
