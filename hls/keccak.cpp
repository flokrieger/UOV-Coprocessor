/////////////////////////////////////////////////////////////////////
// Derived from the UOV reference implementation (pqov):
// URL: https://github.com/pqov/pqov
// See utils/fips202.c for the original SHAKE-256 implementation, which is
// itself based on the public domain implementation by Ronny Van Keer
// (SUPERCOP, crypto_hash/keccakc512/simple) and the public domain
// TweetFips202 code by Gilles Van Assche, Daniel J. Bernstein and
// Peter Schwabe.
//
// SPDX-License-Identifier: CC0-1.0 OR Apache-2.0
/////////////////////////////////////////////////////////////////////

// SHAKE-256 based on the Keccak-f[1600] permutation. Used for hashing
// and for sampling vinegar vectors.

#include "keccak.h"

#define KECCAK_NROUNDS (24)
#define KECCAK_LANES (25)
#define SHAKE256_RATE (136) // bytes

typedef ap_uint<64> lane_t;

// Keccak Round Constants
static const lane_t KECCAK_RC[KECCAK_NROUNDS] = {
    0x0000000000000001ULL, 0x0000000000008082ULL, 0x800000000000808aULL,
    0x8000000080008000ULL, 0x000000000000808bULL, 0x0000000080000001ULL,
    0x8000000080008081ULL, 0x8000000000008009ULL, 0x000000000000008aULL,
    0x0000000000000088ULL, 0x0000000080008009ULL, 0x000000008000000aULL,
    0x000000008000808bULL, 0x800000000000008bULL, 0x8000000000008089ULL,
    0x8000000000008003ULL, 0x8000000000008002ULL, 0x8000000000000080ULL,
    0x000000000000800aULL, 0x800000008000000aULL, 0x8000000080008081ULL,
    0x8000000000008080ULL, 0x0000000080000001ULL, 0x8000000080008008ULL};

// rho[x][y]
static const ap_uint<6> KECCAK_RHO[5][5] = {{0, 36, 3, 41, 18},
                                            {1, 44, 10, 45, 2},
                                            {62, 6, 43, 15, 61},
                                            {28, 55, 25, 21, 56},
                                            {27, 20, 39, 8, 14}};

// Rotate left
static inline lane_t ROL(lane_t a, ap_uint<6> o) {
  #pragma HLS INLINE
  return (o == 0) ? a : lane_t((a << o) | (a >> (64 - o)));
}

// One round of Keccak-f[1600] permutation
void KeccakRound(lane_t s[KECCAK_LANES], uint8_t round) {
  #pragma HLS pipeline II = 1

  lane_t C[5], D[5], B[KECCAK_LANES];
  #pragma HLS ARRAY_PARTITION variable = C complete dim = 1
  #pragma HLS ARRAY_PARTITION variable = D complete dim = 1
  #pragma HLS ARRAY_PARTITION variable = B complete dim = 1

  // theta
  for (int x = 0; x < 5; x++) {
    #pragma HLS UNROLL
    C[x] = s[x] ^ s[x + 5] ^ s[x + 10] ^ s[x + 15] ^ s[x + 20];
  }

  for (int x = 0; x < 5; x++) {
    #pragma HLS UNROLL
    D[x] = C[(x + 4) % 5] ^ ROL(C[(x + 1) % 5], 1);
  }

  for (int x = 0; x < 5; x++) {
    #pragma HLS UNROLL
    for (int y = 0; y < 5; y++) {
      #pragma HLS UNROLL
      s[x + 5 * y] ^= D[x];
    }
  }

  // rho + pi
  for (int x = 0; x < 5; x++) {
    #pragma HLS UNROLL
    for (int y = 0; y < 5; y++) {
      #pragma HLS UNROLL
      B[y + 5 * ((2 * x + 3 * y) % 5)] = ROL(s[x + 5 * y], KECCAK_RHO[x][y]);
    }
  }

  // chi
  for (int x = 0; x < 5; x++) {
    #pragma HLS UNROLL
    for (int y = 0; y < 5; y++) {
      #pragma HLS UNROLL
      s[x + 5 * y] = B[x + 5 * y] ^ ((~B[(x + 1) % 5 + 5 * y]) & B[(x + 2) % 5 + 5 * y]);
    }
  }

  // iota
  s[0] ^= KECCAK_RC[round];
}

void KeccakF1600(lane_t s[KECCAK_LANES]) {
  #pragma HLS pipeline II = KECCAK_NROUNDS + 1
  #pragma HLS ARRAY_PARTITION variable = s complete dim = 1

  #pragma HLS BIND_STORAGE variable = KECCAK_RHO type = rom_np impl = lutram
  #pragma HLS BIND_STORAGE variable = KECCAK_RC type = rom_np impl = lutram

  for (int round = 0; round < KECCAK_NROUNDS; round++) {
    #pragma HLS unroll factor = 1
    KeccakRound(s, round);
  }
}

void shake256(bit_t target_output,
              word_t out_a[SHAKE_MEM_DEPTH],
              word_t out_b[SHAKE_MEM_DEPTH],
              uint32_t outlen,
              const word_t in[SHAKE_MEM_DEPTH],
              uint32_t inlen) {
  #pragma HLS INTERFACE bram port = out_a latency = 2 depth = SHAKE_MEM_DEPTH
  #pragma HLS INTERFACE bram port = out_b latency = 2 depth = SHAKE_MEM_DEPTH
  #pragma HLS INTERFACE bram port = in latency = 2 depth = SHAKE_MEM_DEPTH
  #pragma HLS INTERFACE ap_none port = outlen
  #pragma HLS INTERFACE ap_none port = inlen

  lane_t s[KECCAK_LANES];
  #pragma HLS ARRAY_PARTITION variable = s complete dim = 1

  #pragma HLS ALLOCATION function instances = KeccakF1600 limit = 1

  // init
  for (int i = 0; i < KECCAK_LANES; i++) {
    #pragma HLS UNROLL
    s[i] = 0;
  }

  const uint32_t R = SHAKE256_RATE; // Shake256 absorbrate

  // Absorb:
  const uint16_t ABSORB_WORDS = (R + 15) / 16;
  const uint16_t in_words = (inlen + 15) >> 4;
  uint16_t off = 0;
  bool done = false;
  
  absorb_loop:
  while (!done) {
    #pragma HLS LOOP_TRIPCOUNT min = 1 max = SHAKE_MEM_DEPTH * sizeof(word_t) / SHAKE256_RATE + 1
    bool is_final = (inlen - off < R);
    uint16_t rem = inlen - off;
    uint16_t data_bytes = is_final ? rem : (uint16_t)R;
    uint16_t base_word = off >> 4;
    uint16_t base_byte = base_word << 4;
    ap_uint<1> phase8 = (off >> 3) & 1;

    block_word_loop:
    for (uint16_t j = 0; j < ABSORB_WORDS; j++) {
      #pragma HLS PIPELINE II = 1
      uint16_t ra = base_word + j;
      uint16_t ra_safe = (ra < in_words) ? ra : (uint16_t)0;
      word_t wrd = in[ra_safe];

      lane_t acc[2] = {0, 0};
      word_byte_loop:
      for (uint16_t k = 0; k < 16; k++) {
        #pragma HLS UNROLL
        uint16_t bytepos = base_byte + (j << 4) + k;
        ap_uint<8> v = 0;
        
        if (bytepos >= off) {
          uint16_t i = bytepos - off;
          if (i < data_bytes)
            v = (ap_uint<8>)wrd.range(8 * k + 7, 8 * k);
          if (is_final && i == rem)
            v ^= ap_uint<8>(0x1F);
          if (is_final && i == R - 1)
            v ^= ap_uint<8>(0x80);
        }
        acc[k >> 3].range(8 * (k & 7) + 7, 8 * (k & 7)) = v;
      }

      int8_t base_lane = (int8_t)(2 * j) - (int8_t)phase8;
      ap_uint<5> lane_lo = (base_lane < 0) ? 24u : (uint16_t)base_lane;
      ap_uint<5> lane_hi = (uint16_t)(base_lane + 1);
      
      lane_t s_tmp_lo = s[lane_lo];
      lane_t s_tmp_hi = s[lane_hi];
      s[lane_lo] = s_tmp_lo ^ acc[0];
      s[lane_hi] = s_tmp_hi ^ acc[1];
    }

    if (is_final)
      done = true;
    else {
      KeccakF1600(s);
      off += R;
    }
  }


  // Squeeze:
  const uint16_t RATE_LANES = R / 8;            
  const uint16_t out_words = (outlen + 15) >> 4;
  uint16_t w = 0;                               
  bool have_carry = false;
  lane_t carry = 0;
  squeeze_block_loop:
  while (w < out_words) {
    #pragma HLS LOOP_TRIPCOUNT min = 1 max = 2 * SHAKE_MEM_DEPTH / (SHAKE256_RATE / 8) + 1
    KeccakF1600(s);

    uint16_t words_this = have_carry ? ABSORB_WORDS : (uint16_t)(ABSORB_WORDS - 1);
    int base = have_carry ? -1 : 0;
    bool incoming = have_carry;
    
    squeeze_word_loop:
    for (uint16_t j = 0; j < ABSORB_WORDS; j++) {
      #pragma HLS PIPELINE II = 1
      if (j < words_this && w < out_words) {
        int lo_idx = 2 * (int)j + base;
        int hi_idx = 2 * (int)j + 1 + base;
        uint16_t lo_sidx = (lo_idx < 0) ? 0u : (uint16_t)lo_idx;
        lane_t lo = (lo_idx < 0) ? carry : s[lo_sidx];
        lane_t hi = s[hi_idx];

        word_t outbuf;
        outbuf.range(63, 0) = lo;
        outbuf.range(127, 64) = hi;
        if (target_output)
          out_b[w] = outbuf;
        else
          out_a[w] = outbuf;
        w++;
      }
    }

    if (incoming)
      have_carry = false;
    else {
      carry = s[RATE_LANES - 1];
      have_carry = true;
    }
  }
}
