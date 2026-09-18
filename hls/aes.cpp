/////////////////////////////////////////////////////////////////////
// Derived from the UOV reference implementation (pqov):
// URL: https://github.com/pqov/pqov
// The AES-128-CTR based expansion of the public key follows pqov; the
// AES-128 block cipher itself follows FIPS 197.
//
// SPDX-License-Identifier: CC0-1.0 OR Apache-2.0
/////////////////////////////////////////////////////////////////////

// AES-128 and AES-128-CTR implementation in HLS. Used to expand the
// public key matrices P1 and P2 from the public key seed. Also used
// to sample the blinding matrices.

#include "aes.h"
#include "uov.h"

// SBox lookup table
static const uint8_t SBOX[256] = {
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b,
    0xfe, 0xd7, 0xab, 0x76, 0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0,
    0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0, 0xb7, 0xfd, 0x93, 0x26,
    0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2,
    0xeb, 0x27, 0xb2, 0x75, 0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0,
    0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84, 0x53, 0xd1, 0x00, 0xed,
    0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f,
    0x50, 0x3c, 0x9f, 0xa8, 0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5,
    0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2, 0xcd, 0x0c, 0x13, 0xec,
    0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14,
    0xde, 0x5e, 0x0b, 0xdb, 0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c,
    0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79, 0xe7, 0xc8, 0x37, 0x6d,
    0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f,
    0x4b, 0xbd, 0x8b, 0x8a, 0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e,
    0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e, 0xe1, 0xf8, 0x98, 0x11,
    0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f,
    0xb0, 0x54, 0xbb, 0x16};

// Round constants
static const uint8_t RCON[11] = {0x00, 0x01, 0x02, 0x04, 0x08, 0x10,
                                 0x20, 0x40, 0x80, 0x1b, 0x36};

// Multiply by x in the AES field
#define XTIME(a) ((uint8_t)(((a) << 1) ^ ((((a) >> 7) & 1u) * 0x1bu)))

static void sub_bytes(uint8_t s[16]) {
  #pragma HLS INLINE
  #pragma HLS BIND_STORAGE variable = SBOX type = rom_np impl = lutram
  int i;
  for (i = 0; i < 16; i++) {
    #pragma HLS UNROLL
    s[i] = SBOX[s[i]];
  }
}

static void shift_rows(uint8_t s[16]) {
  uint8_t t;
  t = s[1]; s[1] = s[5]; s[5] = s[9]; s[9] = s[13]; s[13] = t;
  t = s[2]; s[2] = s[10]; s[10] = t;
  t = s[6]; s[6] = s[14]; s[14] = t;
  t = s[15]; s[15] = s[11]; s[11] = s[7]; s[7] = s[3]; s[3] = t;
}

static void mix_columns(uint8_t s[16]) {
  int c;
  uint8_t a0, a1, a2, a3;
  for (c = 0; c < 4; c++) {
    a0 = s[4 * c];
    a1 = s[4 * c + 1];
    a2 = s[4 * c + 2];
    a3 = s[4 * c + 3];
    s[4 * c + 0] = XTIME(a0) ^ XTIME(a1) ^ a1 ^ a2 ^ a3;
    s[4 * c + 1] = a0 ^ XTIME(a1) ^ XTIME(a2) ^ a2 ^ a3;
    s[4 * c + 2] = a0 ^ a1 ^ XTIME(a2) ^ XTIME(a3) ^ a3;
    s[4 * c + 3] = XTIME(a0) ^ a0 ^ a1 ^ a2 ^ XTIME(a3);
  }
}

static void add_round_key(uint8_t s[16], const uint8_t rkey[16]) {
  int i;
  for (i = 0; i < 16; i++) {
    s[i] ^= rkey[i];
  }
}

// Computes the round key schedule and stores the round keys in rkeys
void aes128_keyschedule(const uint8_t key[16], uint8_t rkeys[AES128_NRKEYS][16]) {
  int i, j;
  for (j = 0; j < 16; j++) {
    #pragma HLS UNROLL
    rkeys[0][j] = key[j];
  }

  for (i = 1; i < AES128_NRKEYS; i++) {
    #pragma HLS UNROLL
    rkeys[i][0] = rkeys[i - 1][0] ^ SBOX[rkeys[i - 1][13]] ^ RCON[i];
    rkeys[i][1] = rkeys[i - 1][1] ^ SBOX[rkeys[i - 1][14]];
    rkeys[i][2] = rkeys[i - 1][2] ^ SBOX[rkeys[i - 1][15]];
    rkeys[i][3] = rkeys[i - 1][3] ^ SBOX[rkeys[i - 1][12]];
    for (j = 4; j < 16; j++) {
      #pragma HLS UNROLL
      rkeys[i][j] = rkeys[i - 1][j] ^ rkeys[i][j - 4];
    }
  }
}

// Computes AES block encryption
void aes128_encrypt_block(const uint8_t in[16],
                          const uint8_t rkeys[AES128_NRKEYS][16],
                          uint8_t out[16]) {
  int i, r;
  uint8_t s[16];
  for (i = 0; i < 16; i++) {
    s[i] = in[i];
  }

  add_round_key(s, rkeys[0]);
  for (r = 1; r <= 9; r++) {
    sub_bytes(s);
    shift_rows(s);
    mix_columns(s);
    add_round_key(s, rkeys[r]);
  }

  sub_bytes(s);
  shift_rows(s);
  add_round_key(s, rkeys[10]);
  for (i = 0; i < 16; i++) {
    out[i] = s[i];
  }
}

// Computes an AES-128-CTR output based on nonce and ctr
void aes128_ctr_block(const uint8_t nonce[12], uint32_t ctr,
                      const uint8_t rkeys[AES128_NRKEYS][16], uint8_t out[16]) {
  #pragma HLS PIPELINE II = 1
  #pragma HLS ARRAY_PARTITION variable = out complete dim = 1

  int i;
  uint8_t in[16];
  for (i = 0; i < 12; i++) {
    in[i] = nonce[i];
  }
  in[12] = (uint8_t)(ctr >> 24);
  in[13] = (uint8_t)(ctr >> 16);
  in[14] = (uint8_t)(ctr >> 8);
  in[15] = (uint8_t)(ctr);
  aes128_encrypt_block(in, rkeys, out);
}

// Register arrays holding the precomputed round keys for public key sampling
// and blinding
static uint8_t rkeys[AES128_NRKEYS][16];
static uint8_t rkeys_blinding[AES128_NRKEYS][16];

// Precomputes the round keys
void computeRoundKeys(uint8_t seed_pk[16], uint8_t seed_blinding[16]) {
  #pragma HLS ALLOCATION function instances = aes128_keyschedule limit = 1
  aes128_keyschedule(seed_pk, rkeys);
  aes128_keyschedule(seed_blinding, rkeys_blinding);
}

// Computes the elements of the P matrices from AES based on the input indices
void getPElement(const bit_t p1_p2_sel, const bit_t do_blinding,
                 const ap_uint<3> slice_idx, const addr_t row_idx,
                 const addr_t col_idx, const addr_t uov_m, const addr_t uov_v,
                 const uint32_t p1_bytes, uint8_t generated_elements[16]) {
  #pragma HLS PIPELINE II = 1
  #pragma HLS INLINE off
  #pragma HLS ARRAY_PARTITION variable = generated_elements complete dim = 1

  int i;
  ap_uint<22> byte_off;
  uint8_t zero_nonce[12];

  for (i = 0; i < 12; i++) {
    zero_nonce[i] = 0;
  }

  if (p1_p2_sel == 0) {
    ap_uint<14> entry = (uint32_t)uov_v * col_idx -
                        (uint32_t)col_idx * (col_idx + 1) / 2 + row_idx;
    byte_off = entry * (uint32_t)uov_m + (uint32_t)slice_idx * 16;
  } else {
    ap_uint<14> entry = (uint32_t)col_idx * (uint32_t)uov_m + (uint32_t)row_idx;
    byte_off = p1_bytes + entry * (uint32_t)uov_m + (uint32_t)slice_idx * 16;
  }

  ap_uint<18> aes0_block_n = byte_off >> 4;
  ap_uint<18> aes1_block_n = aes0_block_n + 1;
  ap_uint<4> merge_shift = ap_uint<4>(byte_off & 0xF);

  uint8_t aes0_generated_elements[16];
  uint8_t aes1_generated_elements[16];
  uint8_t merged_generated_elements[16];
  #pragma HLS ARRAY_PARTITION variable = aes0_generated_elements complete dim = 1
  #pragma HLS ARRAY_PARTITION variable = aes1_generated_elements complete dim = 1
  #pragma HLS ARRAY_PARTITION variable = merged_generated_elements complete dim = 1

  // two instances of AES-128-CTR:
  aes128_ctr_block(zero_nonce, aes0_block_n,
                   do_blinding ? rkeys_blinding : rkeys,
                   aes0_generated_elements);
  aes128_ctr_block(zero_nonce, aes1_block_n, rkeys, aes1_generated_elements);

  for (i = 0; i < 16; i += 4) {
    #pragma HLS UNROLL
    ap_uint<5> b = merge_shift + i;
    bit_t from1 = (b >= 16);
    merged_generated_elements[i] = from1 ? aes1_generated_elements[b & 0xF]
                                         : aes0_generated_elements[b & 0xF];
    merged_generated_elements[i + 1] =
        from1 ? aes1_generated_elements[(b + 1) & 0xF]
              : aes0_generated_elements[(b + 1) & 0xF];
    merged_generated_elements[i + 2] =
        from1 ? aes1_generated_elements[(b + 2) & 0xF]
              : aes0_generated_elements[(b + 2) & 0xF];
    merged_generated_elements[i + 3] =
        from1 ? aes1_generated_elements[(b + 3) & 0xF]
              : aes0_generated_elements[(b + 3) & 0xF];
  }

  ap_uint<8> valid = uov_m - (ap_uint<8>)slice_idx * 16;
  for (i = 0; i < 16; i++) {
    #pragma HLS UNROLL
    generated_elements[i] = (i < valid) ? merged_generated_elements[i] : (uint8_t)0;
  }
}