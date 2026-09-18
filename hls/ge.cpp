// Gaussian elimination. Brings the linear system into echelon form and solves it
// by back substitution during signing.

#include "ge.h"

void ef_datapath(const ge_state_t state,
                 const addr_t pivot_row_idx,
                 const addr_t slice_idx,
                 const addr_t row_idx,
                 const addr_t uov_m,
                 word_t bram_LR[BRAM_LR_DEPTH],
                 word_t bram_T[BRAM_T_DEPTH],
                 word_t bram_ty[BRAM_ty_DEPTH],
                 const bit_t wait,
                 const bit_t setup, 
                 bit_t *singular_out) {
  #pragma HLS PIPELINE II = 1
  #pragma HLS DEPENDENCE variable = bram_LR inter false
  #pragma HLS DEPENDENCE variable = bram_T inter false
  #pragma HLS DEPENDENCE variable = bram_ty inter false

  int i;

  addr_t bram_rd_addr_a = 0;
  boffset_t bram_rd_byte_offset_a = 0;
  addr_t bram_rd_addr_b = 0;
  boffset_t bram_rd_byte_offset_b = 0;
  bit_t bram_LR_wen = 0;
  addr_t bram_wr_addr = 0;

  addr_t bram_ty_rd_addr_a = 0;
  boffset_t bram_ty_rd_byte_offset_a = 0;
  addr_t bram_ty_rd_addr_b = 0;
  boffset_t bram_ty_rd_byte_offset_b = 0;
  bit_t bram_ty_wen = 0;
  addr_t bram_ty_wr_addr = 0;

  static addr_t taken_idx = -1;
  static addr_t taken_idx_reg = -1;
  static bit_t singular = 0;

  bit_t is_ty = slice_idx == uov_m;

  if (state == PIVOT_SEARCH) {
    bram_rd_addr_a = (row_idx / W_FE) * uov_m + pivot_row_idx;
    bram_rd_byte_offset_a = row_idx % W_FE;

  } else if (state == PIVOT_SEARCH_DONE) {
    bram_rd_addr_a = (pivot_row_idx / W_FE) * uov_m + pivot_row_idx;
    bram_rd_byte_offset_a = pivot_row_idx % W_FE;
    bram_wr_addr = bram_rd_addr_a;

  } else if (state == REMAINING_SLICES) {
    bram_rd_addr_a = (pivot_row_idx / W_FE) * uov_m + slice_idx;
    bram_rd_byte_offset_a = pivot_row_idx % W_FE;

    bram_ty_rd_addr_a = pivot_row_idx / W_FE;
    bram_ty_rd_byte_offset_a = pivot_row_idx % W_FE;

    addr_t taken_row = (taken_idx_reg != (addr_t)-1) ? taken_idx_reg : (addr_t)0;
    bram_rd_addr_b = (taken_row / W_FE) * uov_m + slice_idx;
    bram_rd_byte_offset_b = taken_row % W_FE;

    bram_ty_rd_addr_b = taken_row / W_FE;
    bram_ty_rd_byte_offset_b = taken_row % W_FE;

    bram_wr_addr = bram_rd_addr_a;
    bram_ty_wr_addr = bram_ty_rd_addr_a;

  } else if (state == LOAD_MUL) {
    bram_rd_addr_a = (pivot_row_idx / W_FE) * uov_m + slice_idx;
    bram_rd_byte_offset_a = pivot_row_idx % W_FE;
    bram_wr_addr = bram_rd_addr_a;

    bram_ty_rd_addr_a = pivot_row_idx / W_FE;
    bram_ty_rd_byte_offset_a = pivot_row_idx % W_FE;
    bram_ty_wr_addr = bram_ty_rd_addr_a;

    bram_rd_addr_b = (pivot_row_idx / W_FE) * uov_m + pivot_row_idx;

  } else if (state == MUL) {
    bram_rd_addr_a = (row_idx / W_FE) * uov_m + slice_idx;
    bram_rd_byte_offset_a = row_idx % W_FE;

    bram_ty_rd_addr_a = row_idx / W_FE;
    bram_ty_rd_byte_offset_a = row_idx % W_FE;

    bram_rd_addr_b = (row_idx / W_FE) * uov_m + pivot_row_idx;

    bram_wr_addr = bram_rd_addr_a;
    bram_ty_wr_addr = bram_ty_rd_addr_a;
  }

  addr_t bramT_rd_addr = is_ty ? (BRAM_T_y_OFFSET + bram_ty_rd_addr_b)
                               : (BRAM_T_L_OFFSET + bram_rd_addr_a);
  word_t bramT_rd_data     = bram_T[bramT_rd_addr];
  word_t bram_rd_data_a    = bramT_rd_data;
  word_t bram_ty_rd_data_b = bramT_rd_data;
  word_t bram_rd_data_b    = bram_LR[bram_rd_addr_b];
  word_t bram_ty_rd_data_a = bram_ty[bram_ty_rd_addr_a];

  field_t bram_rd_byte_a;
  field_t bram_rd_byte_b;
  field_t bram_ty_rd_byte_a;
  field_t bram_ty_rd_byte_b;

  wordToFieldElement(bram_rd_data_a, bram_rd_byte_offset_a, &bram_rd_byte_a);
  wordToFieldElement(bram_rd_data_b, bram_rd_byte_offset_b, &bram_rd_byte_b);
  wordToFieldElement(bram_ty_rd_data_a, bram_ty_rd_byte_offset_a, &bram_ty_rd_byte_a);
  wordToFieldElement(bram_ty_rd_data_b, bram_ty_rd_byte_offset_b, &bram_ty_rd_byte_b);

  field_t a[W_FE];
  field_t b[W_FE];
  wordToFields(is_ty ? bram_ty_rd_data_a : bram_rd_data_a, a);
  wordToFields(bram_rd_data_b, b);

  static field_t acc = 0;
  static field_t piv_inverse;
  static field_t principal;

  if (setup) {
    acc = 0;
    singular = 0;
  }

  switch (state) {
  case PIVOT_SEARCH: {

    boffset_t pivot_lane = pivot_row_idx % W_FE;
    bit_t is_pivot_group = (row_idx == (pivot_row_idx / W_FE) * W_FE);

    bit_t r_found[W_FE];
    field_t r_val[W_FE];
    boffset_t r_lane[W_FE];
    for (i = 0; i < W_FE; i++) {
      #pragma HLS unroll
      r_found[i] = (a[i] != 0) & (is_pivot_group ? (bit_t)(i >= pivot_lane) : (bit_t)1);
      r_val[i] = a[i];
      r_lane[i] = i;
    }

    for (int s = 1; s < W_FE; s <<= 1) {
      #pragma HLS unroll
      for (i = 0; i + s < W_FE; i += (s << 1)) {
        #pragma HLS unroll
        if (!r_found[i]) {
          r_found[i] = r_found[i + s];
          r_val[i] = r_val[i + s];
          r_lane[i] = r_lane[i + s];
        }
      }
    }

    if (setup)
      taken_idx = -1;
    if (acc == 0 && r_found[0]) {
      acc = r_val[0];
      if (!is_pivot_group || r_lane[0] > pivot_lane)
        taken_idx = addr_t((row_idx / W_FE) * W_FE + r_lane[0]);
    }

  } break;

  case PIVOT_SEARCH_DONE:
    taken_idx_reg = taken_idx;
    piv_inverse = FINV(acc);
    singular = (bit_t)(singular | (bit_t)(acc == 0));
    bram_LR_wen = wait ? 0 : 1;
    break;

  case REMAINING_SLICES:
    bram_LR_wen = wait ? 0 : (is_ty ? 0 : 1);
    bram_ty_wen = wait ? 0 : (is_ty ? 1 : 0);
    break;

  case LOAD_MUL:
    taken_idx = -1;
    acc = 0;
    principal = is_ty ? bram_ty_rd_byte_a : bram_rd_byte_a;
    bram_LR_wen = wait ? 0 : (is_ty ? 0 : 1);
    bram_ty_wen = wait ? 0 : (is_ty ? 1 : 0);
    break;

  case MUL:
    bram_LR_wen = wait ? 0 : (is_ty ? 0 : 1);
    bram_ty_wen = wait ? 0 : (is_ty ? 1 : 0);
    break;
  }

  field_t c[W_FE];
  field_t init[W_FE];
  field_t A = 1;
  field_t B = 1;
  word_t C = 0;
  word_t INIT = 0;
  uint8_t init_en = 0;
  word_t O;

  switch (state) {
  case PIVOT_SEARCH_DONE: {
    init_en = 1;
    for (i = 0; i < W_FE; i++) {
      #pragma HLS unroll
      if (i == bram_rd_byte_offset_a)
        init[i] = singular ? 0 : 1;
      else
        init[i] = a[i];
    }
    fieldsToWord(init, &INIT);
  } break;

  case REMAINING_SLICES: {
    A = FADD(is_ty ? bram_ty_rd_byte_a : bram_rd_byte_a,
             taken_idx_reg == addr_t(-1) ? 0 : (is_ty ? bram_ty_rd_byte_b : bram_rd_byte_b));
    B = piv_inverse;
    init_en = 1;
    for (i = 0; i < W_FE; i++) {
      #pragma HLS unroll
      if (i == bram_rd_byte_offset_a) {
        c[i] = 1;
        init[i] = 0;
      } else {
        c[i] = 0;
        init[i] = a[i];
      }
    }

    fieldsToWord(c, &C);
    fieldsToWord(init, &INIT);
  } break;

  case LOAD_MUL:
  case MUL: {
    A = principal;
    init_en = 1;
    for (i = 0; i < W_FE; i++) {
      #pragma HLS unroll
      init[i] = a[i];
      c[i] = state == MUL || i > bram_rd_byte_offset_a ? b[i] : 0;
    }

    fieldsToWord(c, &C);
    fieldsToWord(init, &INIT);
  } break;

  default: {
    A = 1;
    B = 1;
    C = 0;
    INIT = 0;
    init_en = 0;
  } break;
  }

  datapath(A, B, C, INIT, init_en, &O);

  word_t wr_data = O;
  if (bram_LR_wen)
    bram_LR[bram_wr_addr] = wr_data;
  if (bram_ty_wen)
    bram_ty[bram_ty_wr_addr] = wr_data;

  bit_t bramT_wen = bram_LR_wen | bram_ty_wen;
  addr_t bramT_wr_addr = bram_LR_wen ? (BRAM_T_L_OFFSET + bram_wr_addr)
                                     : (BRAM_T_y_OFFSET + bram_ty_wr_addr);
  if (bramT_wen)
    bram_T[bramT_wr_addr] = wr_data;

  *singular_out = singular;
}

void ef(const addr_t uov_m,
        word_t bram_LR[BRAM_LR_DEPTH],
        word_t bram_T[BRAM_T_DEPTH],
        word_t bram_ty[BRAM_ty_DEPTH],
        bit_t *singular) {
  #pragma HLS inline

  const addr_t WAITS = 9;
  const addr_t nr_groups = (uov_m + W_FE - 1) / W_FE;

  addr_t pivot_row_idx = 0;
  addr_t slice_idx = 0;
  addr_t row_idx = pivot_row_idx / W_FE;
  addr_t wait_ctr = 0;
  bit_t wait = 0;
  ge_state_t state = PIVOT_SEARCH;

  bit_t done = 0, setup = 1;
  while (done == 0) {
    addr_t slice_start_idx = pivot_row_idx;
    ef_datapath(state, pivot_row_idx, slice_idx, row_idx * W_FE, uov_m, bram_LR,
                bram_T, bram_ty, wait, setup, singular);
    setup = 0;

    if (state == PIVOT_SEARCH) {
      row_idx++;
      if (row_idx == nr_groups) {
        state = PIVOT_SEARCH_DONE;
      }

    } else if (state == PIVOT_SEARCH_DONE) {
      slice_idx = uov_m;
      state = REMAINING_SLICES;

    } else if (state == REMAINING_SLICES) {
      wait_ctr++;
      if (slice_idx == pivot_row_idx + 1) {
        if (wait_ctr >= WAITS) {
          wait_ctr = 0;
          wait = 0;
          slice_idx = uov_m;
          if (pivot_row_idx + 1 == uov_m)
            done = 1;
          else
            state = LOAD_MUL;
        } else {
          wait = 1;
        }
      } else {
        slice_idx--;
      }

    } else if (state == LOAD_MUL) {
      wait_ctr++;
      row_idx = pivot_row_idx / W_FE + 1;
      if (row_idx == nr_groups) {
        slice_idx--;
        if (slice_idx == (addr_t)(slice_start_idx - 1)) {
          pivot_row_idx++;
          if (pivot_row_idx == uov_m) {
            done = 1;
          } else {
            if (wait_ctr >= WAITS) {
              wait = 0;
              wait_ctr = 0;
              row_idx = pivot_row_idx / W_FE;
              state = PIVOT_SEARCH;
            } else {
              wait = 1;
              slice_idx++;
              pivot_row_idx--;
            }
          }
        } else {
          if (wait_ctr >= WAITS) {
            wait = 0;
            wait_ctr = 0;
            state = LOAD_MUL;
          } else {
            wait = 1;
            slice_idx++;
          }
        }
      } else {
        if (wait_ctr >= WAITS) {
          wait = 0;
          wait_ctr = 0;
          state = MUL;
        } else {
          wait = 1;
        }
      }

    } else if (state == MUL) {
      wait_ctr++;
      row_idx++;
      if (row_idx == nr_groups) {
        slice_idx--;
        if (slice_idx == (addr_t)(slice_start_idx - 1)) {
          pivot_row_idx++;
          if (pivot_row_idx == uov_m) {
            done = 1;
          } else {
            if (wait_ctr >= WAITS) {
              wait = 0;
              wait_ctr = 0;
              row_idx = pivot_row_idx / W_FE;
              state = PIVOT_SEARCH;
            } else {
              wait = 1;
              row_idx--;
              slice_idx++;
              pivot_row_idx--;
            }
          }
        } else {
          if (wait_ctr >= WAITS) {
            wait = 0;
            wait_ctr = 0;
            state = LOAD_MUL;
          } else {
            wait = 1;
            slice_idx++;
            row_idx--;
          }
        }
      }
    }
  }
}

void bs_datapath(const addr_t slice_idx,
                 const addr_t row_idx,
                 const addr_t uov_m,
                 word_t bram_LR[BRAM_LR_DEPTH],
                 word_t bram_T[BRAM_T_DEPTH],
                 word_t bram_ty[BRAM_ty_DEPTH],
                 const bit_t wait) {
  #pragma HLS PIPELINE II = 1
  #pragma HLS DEPENDENCE variable = bram_LR inter false
  #pragma HLS DEPENDENCE variable = bram_T inter false
  #pragma HLS DEPENDENCE variable = bram_ty inter false

  int i;

  addr_t bram_LR_rd_addr = 0;
  boffset_t bram_LR_rd_byte_offset = 0;

  addr_t bram_ty_rd_addr_a = 0;
  addr_t bram_ty_rd_addr_b = 0;
  boffset_t bram_ty_rd_byte_offset_b = 0;
  addr_t bram_ty_wr_addr = 0;
  bit_t bram_ty_wen = wait ? 0 : 1;

  bram_LR_rd_addr = row_idx * uov_m + slice_idx;
  bram_LR_rd_byte_offset = slice_idx % W_FE;
  bram_ty_rd_addr_a = row_idx;
  bram_ty_wr_addr = row_idx;

  bram_ty_rd_addr_b = slice_idx / W_FE;
  bram_ty_rd_byte_offset_b = slice_idx % W_FE;

  word_t bram_LR_rd_data_a = bram_LR[bram_LR_rd_addr];
  word_t bram_ty_rd_data_a = bram_ty[bram_ty_rd_addr_a];
  word_t bram_ty_rd_data_b = bram_T[BRAM_T_y_OFFSET + bram_ty_rd_addr_b];

  field_t bram_ty_rd_byte_b;
  wordToFieldElement(bram_ty_rd_data_b, bram_ty_rd_byte_offset_b, &bram_ty_rd_byte_b);

  field_t A = bram_ty_rd_byte_b;
  field_t B = 1;
  word_t C;
  word_t INIT = bram_ty_rd_data_a;
  uint8_t init_en = 1;
  word_t O;

  bit_t is_pivot_group = (row_idx == slice_idx / W_FE);
  field_t bram_LR_rd_data_bytes[W_FE];
  field_t c[W_FE];
  wordToFields(bram_LR_rd_data_a, bram_LR_rd_data_bytes);
  for (i = 0; i < W_FE; i++) {
    #pragma HLS unroll
    c[i] = (is_pivot_group && i == bram_LR_rd_byte_offset) ? 0 : bram_LR_rd_data_bytes[i];
  }
  fieldsToWord(c, &C);

  datapath(A, B, C, INIT, init_en, &O);

  if (bram_ty_wen)
    bram_ty[bram_ty_wr_addr] = O;
  if (bram_ty_wen)
    bram_T[BRAM_T_y_OFFSET + bram_ty_wr_addr] = O;
}

void bs(const addr_t uov_m,
        word_t bram_LR[BRAM_LR_DEPTH],
        word_t bram_T[BRAM_T_DEPTH],
        word_t bram_ty[BRAM_ty_DEPTH]) {
  #pragma HLS inline

  const addr_t WAITS = 10; // RAW hazard control

  addr_t slice_idx = uov_m - 1;
  addr_t row_idx = 0;
  addr_t wait_ctr = 0;

  bit_t wait = 0;
  bit_t done = 0;
  while (done == 0) {
    bs_datapath(slice_idx, row_idx, uov_m, bram_LR, bram_T, bram_ty, wait);

    if (row_idx == slice_idx / W_FE) {
      if (slice_idx == 0) {
        done = 1;
      } else if (wait_ctr >= WAITS) {
        wait_ctr = 0;
        wait = 0;
        slice_idx--;
        row_idx = 0;
      } else {
        wait_ctr++;
        wait = 1;
      }
    } else {
      row_idx++;
      wait_ctr++;
    }
  }
}

void geSubsystem(const addr_t uov_m,
                 word_t bram_LR[BRAM_LR_DEPTH],
                 word_t bram_T[BRAM_T_DEPTH],
                 word_t bram_ty[BRAM_ty_DEPTH],
                 bit_t *singular) {
  #pragma HLS INTERFACE bram port = bram_LR latency = 2 depth = BRAM_LR_DEPTH
  #pragma HLS INTERFACE bram port = bram_T latency = 2 depth = BRAM_T_DEPTH
  #pragma HLS INTERFACE bram port = bram_ty latency = 2 depth = BRAM_ty_DEPTH

  bit_t singular_internal;

  ef(uov_m, bram_LR, bram_T, bram_ty, &singular_internal);

  *singular = singular_internal;

  if (singular_internal)
    return;

  bs(uov_m, bram_LR, bram_T, bram_ty);
}