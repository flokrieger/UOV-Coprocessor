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
