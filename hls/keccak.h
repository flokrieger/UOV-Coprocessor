/////////////////////////////////////////////////////////////////////
// Part of the UOV-Coprocessor artifact:
// https://github.com/flokrieger/UOV-Coprocessor
/////////////////////////////////////////////////////////////////////
//
// Derived from the UOV reference implementation (pqov):
// URL: https://github.com/pqov/pqov
// See utils/fips202.c for the original SHAKE-256 implementation, which is
// itself based on the public domain implementation by Ronny Van Keer
// (SUPERCOP, crypto_hash/keccakc512/simple) and the public domain
// TweetFips202 code by Gilles Van Assche, Daniel J. Bernstein and
// Peter Schwabe.
//
// SPDX-License-Identifier: CC0-1.0 OR Apache-2.0
//
/////////////////////////////////////////////////////////////////////
//
// SHAKE-256 based on the Keccak-f[1600] permutation. Used for hashing
// and for sampling vinegar vectors.
//
/////////////////////////////////////////////////////////////////////

#pragma once
#include "uov.h"

#define SHAKE_MEM_DEPTH (256) // Max number of words in memory to be hashed

// Computes Shake256 Hash/XOF
void shake256(bit_t target_output,
              word_t out_a[SHAKE_MEM_DEPTH],
              word_t out_b[SHAKE_MEM_DEPTH],
              uint32_t outlen,
              const word_t in[SHAKE_MEM_DEPTH],
              uint32_t inlen);
