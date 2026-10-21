/*
 * shape.h -- what a rendered block is allowed to look like.
 *
 * The invariant a fuzz target asserts after every successful render, and the
 * one that makes configuration injection a crash rather than a quiet success.
 * `fuzz/shape.c` says why it is a line rule rather than a parse.
 */
#ifndef NMC_FUZZ_SHAPE_H
#define NMC_FUZZ_SHAPE_H

/* Aborts, loudly and with the offending line, when `text` is not a block this
 * renderer could legitimately have written. */
void nmc_fuzz_check_shape(const char *text);

#endif /* NMC_FUZZ_SHAPE_H */
