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
// Package holding the parameters for the UOV co-processor.
// These values must match the definitions in the HLS code.
//
/////////////////////////////////////////////////////////////////////

package uov_pkg;

  // UOV parameters. Must match with HLS code:
  localparam UOV_LVL_Ip          = 3'd1;
  localparam UOV_LVL_Is          = 3'd2;
  localparam UOV_LVL_III         = 3'd3;
  localparam UOV_LVL_V           = 3'd5;
  localparam UOV_LVL_TOY         = 3'd7;

  localparam UOV_LVL_Ip_M        = 44;
  localparam UOV_LVL_Ip_V        = 68;
  localparam UOV_LVL_Ip_N        = UOV_LVL_Ip_M+UOV_LVL_Ip_V;
  localparam UOV_LVL_Ip_N_PADDED = 112;

  localparam UOV_LVL_III_M        = 72;
  localparam UOV_LVL_III_V        = 112;
  localparam UOV_LVL_III_N        = UOV_LVL_III_M+UOV_LVL_III_V;
  localparam UOV_LVL_III_N_PADDED = 192;

  localparam UOV_LVL_V_M        = 96;
  localparam UOV_LVL_V_V        = 148;
  localparam UOV_LVL_V_N        = UOV_LVL_V_M+UOV_LVL_V_V;
  localparam UOV_LVL_V_N_PADDED = 256;

  // Toy parameter set for TVLA
  localparam UOV_LVL_TOY_M        = 32;
  localparam UOV_LVL_TOY_V        = 48;
  localparam UOV_LVL_TOY_N        = UOV_LVL_TOY_M+UOV_LVL_TOY_V;
  localparam UOV_LVL_TOY_N_PADDED = 80;

  // Security-level independent parameters:
  localparam UOV_SEED_PK_BYTES    = 16;
  localparam UOV_SEED_SK_BYTES    = 32;
  localparam UOV_SALT_BYTES       = 16;

  // Implementation-specific:
  localparam AES_BITS = 128;
  localparam FE_BITS  = 8;
  localparam W_BITS   = AES_BITS;
  localparam W_FE     = W_BITS/FE_BITS;

  localparam SEED_PK_BITS         = AES_BITS;
  localparam BRAM_DWIDTH_BITS     = W_BITS;
  localparam BRAM_AWIDTH_EXT_BITS = 32;

  
  // Custom data types
  typedef logic[FE_BITS-1:0]   field_t;
  typedef logic[W_BITS-1:0]    word_t;
  typedef logic[10:0]          addr_t;
  typedef logic[3:0]           boffset_t;

  // BRAM sizes
  localparam BRAM_O_DEPTH  = UOV_LVL_V_N_PADDED * UOV_LVL_V_M / W_FE; // 1536 elements, 11-bit addresses
  localparam BRAM_LR_DEPTH = UOV_LVL_V_M * UOV_LVL_V_M / W_FE;        //  576 elements, 10-bit addresses
  localparam BRAM_T_DEPTH  = UOV_LVL_V_N_PADDED * UOV_LVL_V_M / W_FE; // 1536 elements, 11-bit addresses
  localparam BRAM_vs_DEPTH = 512;                                     //  512 elements,  9-bit addresses
  localparam BRAM_ty_DEPTH = 512;                                     //  512 elements,  9-bit addresses

  // BRAM IDs
  localparam BRAM_O_SEL  = 0;
  localparam BRAM_LR_SEL = 1;
  localparam BRAM_T_SEL  = 2;
  localparam BRAM_ty_SEL = 3;
  localparam BRAM_vs_SEL = 4;

  // BRAM read latency:
  localparam BRAM_RD_LAT = 2;
endpackage