#include "uov.h"
#include "aes.h"
#include "ge.h"
#include "keccak.h"
#include "hls_stream.h"

void datapath(field_t A, field_t B, word_t C, word_t INIT, uint8_t init_en, word_t *O) {
  #pragma HLS INLINE off
  
  static field_t accumulator[W_FE];
  #pragma HLS ARRAY_PARTITION variable = accumulator complete dim = 1
  
  int i;

  field_t axb = FMUL(A, B);

  field_t c_fld[W_FE];
  field_t init_fld[W_FE];
  field_t out_fld[W_FE];
  wordToFields(C, c_fld);
  wordToFields(INIT, init_fld);
  for (i = 0; i < W_FE; i++) {
    #pragma HLS UNROLL
    if (init_en) {
      accumulator[i] = init_fld[i];
    }

    field_t axbxc = FMUL(axb, c_fld[i]);
    accumulator[i] = FADD(axbxc, accumulator[i]);

    out_fld[i] = accumulator[i];
  }
  fieldsToWord(out_fld, O);
}

word_t datapath_mul(field_t A, field_t B, word_t C) {
  #pragma HLS INLINE off
  #pragma HLS PIPELINE II = 1

  int i;

  field_t axb = FMUL(A, B);

  field_t c_fld[W_FE];
  field_t out_fld[W_FE];
  wordToFields(C, c_fld);
  for (i = 0; i < W_FE; i++) {
    #pragma HLS UNROLL
    out_fld[i] = FMUL(axb, c_fld[i]);
  }

  word_t prod;
  fieldsToWord(out_fld, &prod);
  return prod;
}

word_t datapath_acc(word_t prod, word_t INIT, bit_t init_en, acc_sel_t acc_sel, word_t acc[ACC_REG_DEPTH]) {
  #pragma HLS INLINE
  #pragma HLS ARRAY_PARTITION variable = acc complete dim = 1

  word_t base = init_en ? INIT : acc[acc_sel];
  word_t out = prod ^ base;
  acc[acc_sel] = out;

  return out;
}

void fieldsToWord(field_t in[W_FE], word_t *out) {
  #pragma HLS INLINE
  int i;
  word_t w = 0;
  for (i = 0; i < W_FE; i++) {
    #pragma HLS UNROLL
    w.range(FE_BITS * i + FE_BITS - 1, FE_BITS * i) = in[i];
  }
  *out = w;
}

void wordToFields(word_t in, field_t out[W_FE]) {
  #pragma HLS INLINE
  int i;
  for (i = 0; i < W_FE; i++) {
    #pragma HLS UNROLL
    out[i] = in.range(FE_BITS * i + FE_BITS - 1, FE_BITS * i);
  }
}

void wordTouint8(word_t in, uint8_t out[AES_BITS / 8]) {
  #pragma HLS INLINE
  int i;
  for (i = 0; i < AES_BITS / 8; i++) {
    #pragma HLS UNROLL
    out[i] = in.range(8 * i + 7, 8 * i);
  }
}

void wordToFieldElement(word_t in, uint8_t i, field_t *out) {
  #pragma HLS INLINE
  *out = in.range(FE_BITS * i + FE_BITS - 1, FE_BITS * i);
}

void matrixCore(
    const op_t operation,
    const ap_uint<3> slice_idx,
    const addr_t row_idx,
    const addr_t col_idx,
    const ap_uint<5> dest_row_idx,
    const ap_uint<7> dest_col_idx,
    const ap_uint<7> acc_idx,
    const addr_t uov_m,
    const addr_t uov_v,
    const addr_t uov_n,
    const addr_t uov_n_padded,
    const uint32_t p1_bytes,
    const bit_t rng_en,
    word_t bram_O[BRAM_O_DEPTH],
    word_t bram_LR[BRAM_LR_DEPTH],
    word_t bram_T[BRAM_T_DEPTH],
    word_t bram_ty[BRAM_ty_DEPTH],
    word_t bram_vs_a[BRAM_vs_DEPTH],
    word_t bram_vs_b[BRAM_vs_DEPTH],
    hls::stream<word_t> &p3key) {

  #pragma HLS PIPELINE II = 1
  #pragma HLS DEPENDENCE variable = bram_O inter false
  #pragma HLS DEPENDENCE variable = bram_LR inter false
  #pragma HLS DEPENDENCE variable = bram_T inter false
  #pragma HLS DEPENDENCE variable = bram_ty inter false
  #pragma HLS DEPENDENCE variable = bram_vs_a inter false
  #pragma HLS DEPENDENCE variable = bram_vs_b inter false

  // control signals derived from state
  bit_t p1_p2_sel = 0;
  bit_t is_p3 = 0;
  addr_t aes_r_idx = 0;
  addr_t aes_c_idx = 0;
  bit_t aes_zero_out = 0;

  bit_t datapath_init_en = 0;

  addr_t wr_addr = 0;
  bit_t wen = 0;

  addr_t bram_O_rd_addr = 0;
  boffset_t bram_O_rd_byte_offset = 0;

  addr_t bram_LR_rd_addr = 0;
  boffset_t bram_LR_rd_byte_offset = 0;

  addr_t bram_T_rd_addr = 0;
  boffset_t bram_T_rd_byte_offset = 0;

  addr_t bram_ty_rd_addr = 0;
  boffset_t bram_ty_rd_byte_offset = 0;

  addr_t bram_vs_rda_addr = 0;
  boffset_t bram_vs_rda_byte_offset = 0;
  addr_t bram_vs_rdb_addr = 0;
  boffset_t bram_vs_rdb_byte_offset = 0;

  // control signals assignments
  if (operation == OL) {
    bram_O_rd_addr = acc_idx * (uov_n_padded / W_FE) + dest_row_idx;

    p1_p2_sel = 0;
    aes_r_idx = acc_idx;
    aes_c_idx = dest_col_idx;

    datapath_init_en = (acc_idx == dest_col_idx);

    wr_addr = dest_col_idx * (uov_n_padded / W_FE) + dest_row_idx;
    wen = (acc_idx == uov_m - 1);

  } else if (operation == OLU) {
    bram_T_rd_addr = acc_idx * (uov_n_padded / W_FE) + dest_row_idx;

    p1_p2_sel = 1;
    aes_r_idx = acc_idx;
    aes_c_idx = dest_col_idx;

    datapath_init_en = (acc_idx == 0);
    
    wr_addr = dest_col_idx * (uov_n_padded / W_FE) + dest_row_idx;
    wen = (acc_idx == dest_col_idx);

  } else if (operation == vP) {
    bram_vs_rda_addr = row_idx / W_FE;
    bram_vs_rda_byte_offset = row_idx % W_FE;
    datapath_init_en = (row_idx == 0);
    wr_addr = col_idx;

    p1_p2_sel = (col_idx >= uov_v) ? 1 : 0;
    aes_zero_out = row_idx == col_idx;
    if (row_idx > col_idx) {
      aes_r_idx = row_idx; // P1^T lower-triangle
      aes_c_idx = col_idx;
    } else if (p1_p2_sel == 1) {
      aes_r_idx = col_idx - uov_v; // P2
      aes_c_idx = row_idx;
    } else {
      aes_r_idx = col_idx; // P1 upper-triangle
      aes_c_idx = row_idx;
    }
    wen = (row_idx == uov_v - 1);

  } else if (operation == vPO) {
    uint16_t flat_o = (uint32_t)col_idx * uov_n_padded + (uint32_t)row_idx;

    bram_T_rd_addr = row_idx;
    bram_O_rd_addr = flat_o / W_FE;
    bram_O_rd_byte_offset = flat_o % W_FE;
    datapath_init_en = (row_idx == 0);
    wr_addr = slice_idx * uov_m + col_idx;
    wen = (row_idx == uov_n - 1);
  
  } else if (operation == vPv) {
    uint16_t vs_idx_a = col_idx;
    uint16_t vs_idx_b = row_idx;

    bram_vs_rda_addr = vs_idx_a / W_FE;
    bram_vs_rda_byte_offset = vs_idx_a % W_FE;
    bram_vs_rdb_addr = vs_idx_b / W_FE;
    bram_vs_rdb_byte_offset = vs_idx_b % W_FE;
    bram_ty_rd_addr = slice_idx + BRAM_ty_DEPTH / 2;
    datapath_init_en = (row_idx == 0 && col_idx == 0);
    wr_addr = slice_idx;

    p1_p2_sel = 0;
    aes_r_idx = col_idx;
    aes_c_idx = row_idx;
    wen = (col_idx == uov_v - 1 && row_idx == uov_v - 1);

  } else if (operation == Ox) {
    uint16_t flat_o = dest_row_idx * W_FE + acc_idx * uov_n_padded;

    bram_O_rd_addr = flat_o / W_FE;
    bram_vs_rda_addr = dest_row_idx;
    bram_ty_rd_addr = acc_idx / W_FE;
    bram_ty_rd_byte_offset = acc_idx % W_FE;
    datapath_init_en = (acc_idx == 0);
    wr_addr = dest_row_idx;
    wen = (acc_idx == uov_m - 1);

  } else if (operation == sPs) {
    uint16_t vs_idx_a = col_idx;
    uint16_t vs_idx_b = row_idx;

    bram_vs_rda_addr = vs_idx_a / W_FE;
    bram_vs_rda_byte_offset = vs_idx_a % W_FE;
    bram_vs_rdb_addr = vs_idx_b / W_FE;
    bram_vs_rdb_byte_offset = vs_idx_b % W_FE;

    bit_t sps_first = (row_idx == 0 && col_idx == 0);

    bram_ty_rd_addr = slice_idx + BRAM_ty_DEPTH / 2;
    datapath_init_en = sps_first;
    wr_addr = slice_idx;

    p1_p2_sel = col_idx < uov_v ? 0 : 1;
    is_p3 = row_idx >= uov_v;
    if (p1_p2_sel == 1) {
      aes_r_idx = col_idx - uov_v;
      aes_c_idx = row_idx;
    } else {
      aes_r_idx = col_idx;
      aes_c_idx = row_idx;
    }
    wen = 1;
  }

  // Instance of the AES cores
  field_t aes_P_out_tmp[W_FE];
  word_t aes_P_out;
  getPElement(p1_p2_sel, operation == OL || operation == OLU ? 1 : 0, slice_idx, aes_r_idx, aes_c_idx, uov_m, uov_v, p1_bytes, aes_P_out_tmp);
  fieldsToWord(aes_P_out_tmp, &aes_P_out);
  field_t nonzero_fe = aes_P_out_tmp[0] != field_t(0) ? aes_P_out_tmp[0] :
                       aes_P_out_tmp[1] != field_t(0) ? aes_P_out_tmp[1] :
                       aes_P_out_tmp[2] != field_t(0) ? aes_P_out_tmp[2] :
                       aes_P_out_tmp[3] != field_t(0) ? aes_P_out_tmp[3] :
                       field_t(0xc5);

  // BRAM write enable assignment:
  bit_t bram_O_wen  = (operation == OLU && wen) ? 1 : 0;
  bit_t bram_LR_wen = (operation == vPO && wen) ? 1 : 0;
  bit_t bram_T_wen  = ((operation == vP || operation == OL) && wen) ? 1 : 0;
  bit_t bram_ty_wen = ((operation == vPv || operation == sPs) && wen) ? 1 : 0;
  bit_t bram_vs_wen = (operation == Ox && wen) ? 1 : 0;

  // BRAM read port assignment:
  word_t bram_O_rd_data    = bram_O[bram_O_rd_addr];
  word_t bram_LR_rd_data   = bram_LR[bram_LR_rd_addr];
  word_t bram_T_rd_data    = bram_T[bram_T_rd_addr];
  word_t bram_ty_rd_data   = bram_ty[bram_ty_rd_addr];
  word_t bram_vs_rd_data_a = bram_vs_a[bram_vs_rda_addr];
  word_t bram_vs_rd_data_b = bram_vs_b[bram_vs_rdb_addr];

  field_t bram_O_rd_byte;
  field_t bram_LR_rd_byte;
  field_t bram_T_rd_byte;
  field_t bram_ty_rd_byte;
  field_t bram_vs_rd_byte_a;
  field_t bram_vs_rd_byte_b;
  wordToFieldElement(bram_O_rd_data,    bram_O_rd_byte_offset,   &bram_O_rd_byte);
  wordToFieldElement(bram_LR_rd_data,   bram_LR_rd_byte_offset,  &bram_LR_rd_byte);
  wordToFieldElement(bram_T_rd_data,    bram_T_rd_byte_offset,   &bram_T_rd_byte);
  wordToFieldElement(bram_ty_rd_data,   bram_ty_rd_byte_offset,  &bram_ty_rd_byte);
  wordToFieldElement(bram_vs_rd_data_a, bram_vs_rda_byte_offset, &bram_vs_rd_byte_a);
  wordToFieldElement(bram_vs_rd_data_b, bram_vs_rdb_byte_offset, &bram_vs_rd_byte_b);

  // P3 stream read end:
  word_t p3key_word;
  if (is_p3) {
    if (!p3key.read_nb(p3key_word)) {
      p3key_word = word_t(0);
    }
  }

  // Datapath port assignment:
  word_t datapath_inc, datapath_out, datapath_init;
  field_t datapath_ina, datapath_inb;
  switch (operation) {
  case OL: {
    datapath_ina = (acc_idx == dest_col_idx) ? (field_t)1 : 
                   (rng_en ? aes_P_out_tmp[0] : (field_t)0);
    datapath_inb = 1;
  } break;

  case OLU: {
    datapath_ina = (acc_idx == dest_col_idx) ? (rng_en ? nonzero_fe : (field_t)1) : 
                   (rng_en ? aes_P_out_tmp[0] : (field_t)0);
    datapath_inb = 1;
  } break;

  case vP: {
    datapath_ina = bram_vs_rd_byte_a;
    datapath_inb = 1;
  } break;

  case vPO: {
    datapath_ina = bram_O_rd_byte;
    datapath_inb = 1;
  } break;

  case vPv: {
    datapath_ina = bram_vs_rd_byte_a;
    datapath_inb = bram_vs_rd_byte_b;
  } break;

  case sPs: {
    datapath_ina = bram_vs_rd_byte_a;
    datapath_inb = bram_vs_rd_byte_b;
  } break;

  case Ox: {
    datapath_ina = bram_ty_rd_byte;
    datapath_inb = 1;
  } break;

  default: {
    datapath_ina = 1;
    datapath_inb = 1;
  } break;
  }

  switch (operation) {
  case OL: {
    datapath_inc = bram_O_rd_data;
    datapath_init = word_t(0);
  } break;

  case OLU: {
    datapath_inc = bram_T_rd_data;
    datapath_init = word_t(0);
  } break;

  case vP: {
    datapath_inc = aes_zero_out ? word_t(0) : aes_P_out;
    datapath_init = word_t(0);
  } break;

  case vPO: {
    datapath_inc = bram_T_rd_data;
    datapath_init = word_t(0);
  } break;

  case vPv: {
    datapath_inc = aes_P_out;
    datapath_init = bram_ty_rd_data;
  } break;

  case sPs: {
    datapath_inc = is_p3 ? p3key_word : aes_P_out;
    datapath_init = bram_ty_rd_data;
  } break;

  case Ox: {
    datapath_inc = bram_O_rd_data;
    datapath_init = (bram_vs_rda_addr < uov_v / W_FE) ? bram_vs_rd_data_a : 
                    bram_vs_rda_addr == uov_v / W_FE  ? (bram_vs_rd_data_a & word_t((word_t(1) << FE_BITS * (uov_v - (uov_v / W_FE) * W_FE)) - 1)) :
                    word_t(0);
  } break;

  default: {
    datapath_inc = word_t(0);
    datapath_init = word_t(0);
  } break;
  }

  // Datapath instance:
  static word_t datapath_accum[ACC_REG_DEPTH];
  #pragma HLS ARRAY_PARTITION variable = datapath_accum complete dim = 1
  acc_sel_t datapath_acc_sel = operation == sPs ? acc_sel_t(slice_idx) : acc_sel_t(0);
  word_t datapath_prod = datapath_mul(datapath_ina, datapath_inb, datapath_inc);
  datapath_out = datapath_acc(datapath_prod, datapath_init, datapath_init_en, datapath_acc_sel, datapath_accum);

  // BRAM write port:
  word_t wr_data = datapath_out;
  if (bram_O_wen)  bram_O[wr_addr]    = wr_data;
  if (bram_LR_wen) bram_LR[wr_addr]   = wr_data;
  if (bram_ty_wen) bram_ty[wr_addr]   = wr_data;
  if (bram_vs_wen) bram_vs_a[wr_addr] = wr_data;
  if (bram_vs_wen) bram_vs_b[wr_addr] = wr_data;

  addr_t bram_T_wr_addr = wr_addr;
  bit_t bram_T_any_wen = bram_T_wen;
  if (bram_LR_wen) {
    // mirror L
    bram_T_wr_addr = BRAM_T_L_OFFSET + wr_addr;
    bram_T_any_wen = 1;
  }
  if (bram_ty_wen) {
    // mirror y
    bram_T_wr_addr = BRAM_T_y_OFFSET + wr_addr;
    bram_T_any_wen = 1;
  }
  if (bram_T_any_wen)
    bram_T[bram_T_wr_addr] = wr_data;
}

void matrixSubsystem(
    bit_t do_Ox,
    bit_t do_verif,
    bit_t do_blinding,

    const addr_t uov_m,
    const addr_t uov_v,
    const addr_t uov_n,
    const addr_t uov_n_padded,
    const uint32_t p1_bytes,
    const ap_uint<3> nr_slices,
    const uint8_t ctr,
    const bit_t rng_en,

    uint8_t seed_pk[UOV_SEED_PK_BYTES],
    word_t bram_O[BRAM_O_DEPTH],
    word_t bram_LR[BRAM_LR_DEPTH],
    word_t bram_T[BRAM_T_DEPTH],
    word_t bram_ty[BRAM_ty_DEPTH],
    word_t bram_vs_a[BRAM_vs_DEPTH],
    word_t bram_vs_b[BRAM_vs_DEPTH],
    hls::stream<word_t> &p3key ) {

  #pragma HLS INTERFACE ap_none port = seed_pk
  #pragma HLS ARRAY_RESHAPE variable = seed_pk complete dim = 1
  #pragma HLS INTERFACE bram port = bram_O latency = 2 depth = BRAM_O_DEPTH
  #pragma HLS INTERFACE bram port = bram_LR latency = 2 depth = BRAM_LR_DEPTH
  #pragma HLS INTERFACE bram port = bram_T latency = 2 depth = BRAM_T_DEPTH
  #pragma HLS INTERFACE bram port = bram_ty latency = 2 depth = BRAM_ty_DEPTH
  #pragma HLS INTERFACE bram port = bram_vs_a latency = 2 depth = BRAM_vs_DEPTH
  #pragma HLS INTERFACE bram port = bram_vs_b latency = 2 depth = BRAM_vs_DEPTH

  op_t operation = do_Ox ? Ox : do_verif ? sPs : do_blinding ? OL : vPv;
  ap_uint<3> slice_idx = 0;
  bit_t done = 0;

  addr_t row_idx = 0;
  addr_t col_idx = 0;
  ap_uint<5> dest_row_idx = 0;
  ap_uint<7> dest_col_idx = 0;
  ap_uint<7> acc_idx = 0;

  state_machine_loop:
  while (done == 0) {
    #pragma HLS pipeline II = 1

    bit_t was_empty = p3key.empty();
    matrixCore(operation, slice_idx, row_idx, col_idx, dest_row_idx,
               dest_col_idx, acc_idx, uov_m, uov_v, uov_n, uov_n_padded,
               p1_bytes, rng_en, bram_O, bram_LR, bram_T, bram_ty,
               bram_vs_a, bram_vs_b, p3key);

    if (operation == OL) {
      
      slice_idx = ap_uint<3>(ctr);
      if (acc_idx != uov_m - 1) {
        acc_idx++;
      } else if (dest_row_idx != uov_n_padded / W_FE - 1) {
        dest_row_idx++;
        acc_idx = dest_col_idx;
      } else if (dest_col_idx != uov_m - 1) {
        dest_row_idx = 0;
        dest_col_idx++;
        acc_idx = dest_col_idx;
      } else {
        dest_row_idx = 0;
        dest_col_idx = 0;
        acc_idx = 0;
        operation = OLU;
      }

    } else if (operation == OLU) {
      slice_idx = ap_uint<3>(ctr);
      if (acc_idx != dest_col_idx) {
        acc_idx++;
      } else if (dest_row_idx != uov_n_padded / W_FE - 1) {
        dest_row_idx++;
        acc_idx = 0;
      } else if (dest_col_idx != uov_m - 1) {
        dest_row_idx = 0;
        dest_col_idx++;
        acc_idx = 0;
      } else {
        dest_row_idx = 0;
        dest_col_idx = 0;
        acc_idx = 0;
        slice_idx = 0;
        operation = vPv;
      }

    } else if (operation == vPv) {
      row_idx++;
      if (row_idx > col_idx || row_idx == uov_v) {
        row_idx = 0;
        col_idx++;
      }
      if (col_idx == uov_v) {
        col_idx = 0;
        if (slice_idx == nr_slices - 1) {
          slice_idx = 0;
          operation = vP;
        } else {
          slice_idx++;
        }
      }

    } else if (operation == vP) {
      row_idx++;
      if (row_idx == uov_v) {
        row_idx = 0;
        col_idx++;
      }
      if (col_idx == uov_n) {
        col_idx = 0;
        operation = vPO;
      }

    } else if (operation == vPO) {
      row_idx++;
      if (row_idx == uov_n) {
        row_idx = 0;
        col_idx++;
      }
      if (col_idx == uov_m) {
        col_idx = 0;
        if (slice_idx == nr_slices - 1) {
          done = 1;
        } else {
          slice_idx++;
          operation = vP;
        }
      }

    } else if (operation == Ox) {
      acc_idx++;
      if (acc_idx == uov_m) {
        dest_row_idx++;
        acc_idx = 0;
      }
      if (dest_row_idx == uov_n_padded / W_FE) {
        done = 1;
      }

    } else if (operation == sPs) {
      if (was_empty && row_idx >= uov_v) {
        // stall
      } else if (slice_idx != nr_slices - 1) {
        slice_idx++;
      } else if (col_idx != uov_n - 1) {
        slice_idx = 0;
        col_idx++;
      } else if (row_idx != uov_n - 1) {
        slice_idx = 0;
        col_idx = row_idx + 1;
        row_idx++;
      } else {
        done = 1;
      }
    }
  }
}

void hashSubsystem(const bit_t op,
                   const addr_t uov_m,
                   const addr_t uov_v,
                   uint16_t msg_len_bytes,
                   word_t bram_ty[BRAM_ty_DEPTH],
                   word_t bram_vs_a[BRAM_vs_DEPTH]) {

  #pragma HLS INTERFACE bram port = bram_ty latency = 2 depth = BRAM_ty_DEPTH
  #pragma HLS INTERFACE bram port = bram_vs_a latency = 2 depth = BRAM_vs_DEPTH

  uint16_t hash_input_bytes = op ? msg_len_bytes + UOV_SALT_BYTES + UOV_SEED_SK_BYTES + 1 : msg_len_bytes + UOV_SALT_BYTES;
  uint16_t hash_output_bytes = op ? uov_v : uov_m;
  shake256(op, bram_ty + BRAM_ty_DEPTH / 2, bram_vs_a, hash_output_bytes, bram_vs_a + BRAM_ty_DEPTH / 2, hash_input_bytes);
}

void uov(uint16_t msg_len_bytes,
         addr_t uov_m,
         addr_t uov_v,
         addr_t uov_n,
         addr_t uov_n_padded,
         uint32_t p1_bytes,
         ap_uint<3> nr_slices,
         bit_t rng_en,
         bit_t do_verif,
         bit_t do_blinding,
         uint8_t seed_pk[UOV_SEED_PK_BYTES],
         uint8_t seed_bl[UOV_SEED_PK_BYTES],
         word_t bram_O[BRAM_O_DEPTH],
         word_t bram_LR[BRAM_LR_DEPTH],
         word_t bram_T[BRAM_T_DEPTH],
         word_t bram_ty[BRAM_ty_DEPTH],
         word_t bram_vs_a[BRAM_vs_DEPTH],
         word_t bram_vs_b[BRAM_vs_DEPTH],
         hls::stream<word_t> &p3key,
         volatile bit_t *trigger_uov) {

  // Port interfaces:
  #pragma HLS INTERFACE ap_none port = msg_len_bytes
  #pragma HLS INTERFACE ap_none port = uov_m
  #pragma HLS INTERFACE ap_none port = uov_v
  #pragma HLS INTERFACE ap_none port = uov_n
  #pragma HLS INTERFACE ap_none port = uov_n_padded
  #pragma HLS INTERFACE ap_none port = p1_bytes
  #pragma HLS INTERFACE ap_none port = nr_slices
  #pragma HLS INTERFACE ap_none port = rng_en
  #pragma HLS INTERFACE ap_none port = seed_pk
  #pragma HLS ARRAY_RESHAPE variable = seed_pk complete dim = 1
  #pragma HLS INTERFACE ap_none port = seed_bl
  #pragma HLS ARRAY_RESHAPE variable = seed_bl complete dim = 1
  #pragma HLS INTERFACE bram port = bram_O latency = 2 depth = BRAM_O_DEPTH
  #pragma HLS INTERFACE bram port = bram_LR latency = 2 depth = BRAM_LR_DEPTH
  #pragma HLS INTERFACE bram port = bram_T latency = 2 depth = BRAM_T_DEPTH
  #pragma HLS INTERFACE bram port = bram_ty latency = 2 depth = BRAM_ty_DEPTH
  #pragma HLS INTERFACE bram port = bram_vs_a latency = 2 depth = BRAM_vs_DEPTH
  #pragma HLS INTERFACE bram port = bram_vs_b latency = 2 depth = BRAM_vs_DEPTH
  #pragma HLS INTERFACE axis port = p3key
  #pragma HLS INTERFACE ap_none port = trigger_uov

  #pragma HLS ALLOCATION function instances = matrixSubsystem limit = 1
  #pragma HLS ALLOCATION function instances = hashSubsystem limit = 1

  uint8_t ctr = 0;
  bit_t singular_internal = 1;
  *trigger_uov = 0;

  computeRoundKeys(seed_pk, seed_bl);

  // Sample target vector. Input message is located in bram_ty[BRAM_ty_DEPTH/2:*]
  hashSubsystem(0, uov_m, uov_v, msg_len_bytes, bram_ty, bram_vs_a);

  if (do_verif) {
    // Verification:
    matrixSubsystem(0, 1, do_blinding, uov_m, uov_v, uov_n, uov_n_padded, p1_bytes,
                 nr_slices, ctr, rng_en, seed_pk, bram_O, bram_LR, bram_T,
                 bram_ty, bram_vs_a, bram_vs_b, p3key);
    return;
  }

  const uint32_t v_hash_input_bytes = msg_len_bytes + UOV_SALT_BYTES + UOV_SEED_SK_BYTES + 1;
  const uint32_t v_hash_input_ctr_base = (v_hash_input_bytes - 1) / sizeof(word_t);
  const uint32_t v_hash_input_ctr_offset = (v_hash_input_bytes - 1) % sizeof(word_t);

  // Signing:
  main_uov_loop:
  while (singular_internal) {
    // sample vinegar vector:
    hashSubsystem(1, uov_m, uov_v, msg_len_bytes, bram_ty, bram_vs_a);

    // compute linear equation system:
    *trigger_uov = 1;
    matrixSubsystem(0, 0, do_blinding, uov_m, uov_v, uov_n, uov_n_padded, p1_bytes,
                 nr_slices, ctr, rng_en, seed_pk, bram_O, bram_LR, bram_T,
                 bram_ty, bram_vs_a, bram_vs_b, p3key);
    *trigger_uov = 0;

    // solve linear equation system:
    geSubsystem(uov_m, bram_LR, bram_T, bram_ty, &singular_internal);

    if (singular_internal) {
      // Singular system!

      ctr++;
      word_t ctr_word = bram_vs_a[BRAM_vs_DEPTH / 2 + v_hash_input_ctr_base];
      ctr_word.range(v_hash_input_ctr_offset * 8 + 7, v_hash_input_ctr_offset * 8) = ctr;
      bram_vs_a[BRAM_vs_DEPTH / 2 + v_hash_input_ctr_base] = ctr_word; // update ctr in hashing input
      continue;
    }

    // compute signature:
    matrixSubsystem(1, 0, do_blinding, uov_m, uov_v, uov_n, uov_n_padded, p1_bytes,
                 nr_slices, ctr, rng_en, seed_pk, bram_O, bram_LR, bram_T,
                 bram_ty, bram_vs_a, bram_vs_b, p3key);
  }
}
