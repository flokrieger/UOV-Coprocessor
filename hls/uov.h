/////////////////////////////////////////////////////////////////////
// UOV-Coprocessor - 2026
// Lightweight UOV Co-processor with Oil Space Blinding
// Florian Krieger, Maciej Czuprynko, Sujoy Sinha Roy
// Graz University of Technology
// Contact: florian.krieger (at) tugraz.at
// URL: https://github.com/flokrieger/UOV-Coprocessor
//
// Licensed under the MIT License.
/////////////////////////////////////////////////////////////////////
//
// Common parameters, data types and function declarations shared across HLS
// sources of the UOV co-processor.
//
/////////////////////////////////////////////////////////////////////

#pragma once
#include "field.h"
#include <ap_int.h>
#include <hls_stream.h>

// Parameters for different security levels (NIST round 2):
#define UOV_LVL_Ip_M (44)
#define UOV_LVL_Ip_V (68)
#define UOV_LVL_Ip_N (UOV_LVL_Ip_M + UOV_LVL_Ip_V)
#define UOV_LVL_Ip_N_PADDED (112)

#define UOV_LVL_Is_M (64)
#define UOV_LVL_Is_V (96)
#define UOV_LVL_Is_N (UOV_LVL_Is_M + UOV_LVL_Is_V)
#define UOV_LVL_Is_N_PADDED (96)

#define UOV_LVL_III_M (72)
#define UOV_LVL_III_V (112)
#define UOV_LVL_III_N (UOV_LVL_III_M + UOV_LVL_III_V)
#define UOV_LVL_III_N_PADDED (192)

#define UOV_LVL_V_M (96)
#define UOV_LVL_V_V (148)
#define UOV_LVL_V_N (UOV_LVL_V_M + UOV_LVL_V_V)
#define UOV_LVL_V_N_PADDED (256)

// Toy parameter set for TVLA (This is not secure to use in production!)
#define UOV_LVL_TOY_M (32)
#define UOV_LVL_TOY_V (48)
#define UOV_LVL_TOY_N (UOV_LVL_TOY_M + UOV_LVL_TOY_V)
#define UOV_LVL_TOY_N_PADDED (80)

// Security-level independent parameters:
#define UOV_SEED_SK_BYTES (256 / 8)
#define UOV_SEED_PK_BYTES (128 / 8)
#define UOV_SALT_BYTES (128 / 8)

// Internal enumeration of security levels in UOV
#define UOV_LVL_Ip  (1)
#define UOV_LVL_Is  (2)
#define UOV_LVL_III (3)
#define UOV_LVL_V   (5)
#define UOV_LVL_TOY (7)

// Implementation-specific:
#define AES_BITS (128) // Bits per AES-128-CTR output
#define FE_BITS (8)    // Bits per field element

#define W_BITS (AES_BITS)         // Memory word bit size
#define W_FE   (W_BITS / FE_BITS) // Field elements per memory word, 16 in our supported parameter sets

#define NR_SLICES(uov_m) ((uov_m + W_FE - 1) / W_FE)
#define ACC_REG_DEPTH NR_SLICES(UOV_LVL_V_M)
#define P1_BYTES(uov_m, uov_v) ((uint32_t)uov_m * (uint32_t)uov_v * ((uint32_t)uov_v + 1) / 2)

// The supported UOV parameters use GF(256)
#define FMUL gf256_mul
#define FADD gf256_add
#define FINV gf256_inv

// Custom data types
typedef enum { IDLE, OL, OLU, vPv, vP, vPO, Ox, sPs } op_t;
typedef ap_uint<W_BITS> word_t;
typedef ap_uint<11> addr_t;
typedef ap_uint<4> boffset_t;
typedef ap_uint<1> bit_t;
typedef ap_uint<3> acc_sel_t;

// BRAM sizes
#define BRAM_O_DEPTH (UOV_LVL_V_N_PADDED * UOV_LVL_V_M / W_FE) // = 1536
#define BRAM_T_DEPTH (BRAM_O_DEPTH)                            // = 1536
#define BRAM_LR_DEPTH (UOV_LVL_V_M * UOV_LVL_V_M / W_FE)       // =  576
#define BRAM_vs_DEPTH (512)
#define BRAM_ty_DEPTH BRAM_vs_DEPTH

// BRAM offsets
#define BRAM_T_L_OFFSET (512)
#define BRAM_T_y_OFFSET (1024 + 128)


// Compact datapath module as used in GE
void datapath(field_t A, field_t B, word_t C, word_t INIT, uint8_t init_en, word_t *O);

// Multiplication layer of the datapath as used in matrixSubsystem
word_t datapath_mul(field_t A, field_t B, word_t C);

// Accumulation layer of the datapath as used in matrixSubsystem
word_t datapath_acc(word_t prod, word_t INIT, bit_t init_en, acc_sel_t acc_sel, word_t acc[ACC_REG_DEPTH]);

// Converts an array of field_t into a word_t
void fieldsToWord(field_t in[W_FE], word_t *out);

// Converts a word_t into an array of field_t
void wordToFields(word_t in, field_t out[W_FE]);

// Selects the i-th field_t element within in and returns it in out
void wordToFieldElement(word_t in, uint8_t i, field_t *out);

// Top level of the UOV co-processor. Runs UOV signing or verification for the
// security level given by the runtime parameters. The BRAM memories are not
// part of this HLS IP module and must be instantiated outside of the IP.
void uov(uint16_t msg_len_bytes,             // message length in bytes
         addr_t uov_m,                       // UOV runtime parameter config
         addr_t uov_v,                       // UOV runtime parameter config
         addr_t uov_n,                       // UOV runtime parameter config
         addr_t uov_n_padded,                // UOV runtime parameter config
         uint32_t p1_bytes,                  // UOV runtime parameter config
         ap_uint<3> nr_slices,               // UOV runtime parameter config 
         bit_t rng_en,                       // enable / disable the PRNG for blinding
         bit_t do_verif,                     // 1 for verification, 0 for signing operation
         bit_t do_blinding,                  // enable / disable blinding
         uint8_t seed_pk[UOV_SEED_PK_BYTES], // input seed for public key P1 and P2
         uint8_t seed_bl[UOV_SEED_PK_BYTES], // input seed for AES during blinding
         word_t bram_O[BRAM_O_DEPTH],        // external BRAM interface for Ob matrix
         word_t bram_LR[BRAM_LR_DEPTH],      // external BRAM interface for L (system) matrix
         word_t bram_T[BRAM_T_DEPTH],        // external BRAM interface for scratch data
         word_t bram_ty[BRAM_ty_DEPTH],      // external BRAM interface for t and y vectors
         word_t bram_vs_a[BRAM_vs_DEPTH],    // external BRAM interface (true dual port) for v and vectors
         word_t bram_vs_b[BRAM_vs_DEPTH],    // external BRAM interface (true dual port) for v and vectors
         hls::stream<word_t> &p3key,         // streaming input for public key P3
         volatile bit_t *trigger_uov);       // trigger signal for TVLA