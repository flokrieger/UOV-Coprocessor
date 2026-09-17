#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "uov.h"
#include "aes.h"
#include "hls_stream.h"

// Location of prepared reference data
#define DATA_DIR "../../../../../uov_ref/data/"

// Struct holding the test cases for each security level:
typedef struct {
  const char *name;
  ap_uint<3> sec_lvl;
  uint32_t uov_m;
  uint32_t uov_v;
  uint32_t uov_n;
  uint32_t uov_n_padded;
} uov_level_t;

// Tested security levels:
static const uov_level_t LEVELS[] = {
    {"uov-Ip",  UOV_LVL_Ip,  UOV_LVL_Ip_M,  UOV_LVL_Ip_V,  UOV_LVL_Ip_N,  UOV_LVL_Ip_N_PADDED},
    {"uov-III", UOV_LVL_III, UOV_LVL_III_M, UOV_LVL_III_V, UOV_LVL_III_N, UOV_LVL_III_N_PADDED},
    {"uov-V",   UOV_LVL_V,   UOV_LVL_V_M,   UOV_LVL_V_V,   UOV_LVL_V_N,   UOV_LVL_V_N_PADDED},
    {"uov-toy", UOV_LVL_TOY, UOV_LVL_TOY_M, UOV_LVL_TOY_V, UOV_LVL_TOY_N, UOV_LVL_TOY_N_PADDED},
};

// Arrays for input and reference data
field_t v_ref[UOV_LVL_V_V];
field_t O_ref[UOV_LVL_V_N][UOV_LVL_V_M];
field_t Ob_ref[UOV_LVL_V_N][UOV_LVL_V_M];
field_t R_ref[UOV_LVL_V_M][UOV_LVL_V_M];
field_t s_ref[UOV_LVL_V_N];
field_t y_ref[UOV_LVL_V_M];
field_t t_ref[UOV_LVL_V_M];
uint8_t seed_pk_ref[UOV_SEED_PK_BYTES];
uint8_t seed_bl_ref[UOV_SEED_PK_BYTES];
uint8_t hash_in[BRAM_ty_DEPTH / 2 * W_FE];

// Loading from input and reference files:
static int load_flat(const char *path, field_t *arr, int n) {
  FILE *f = fopen(path, "r");
  int i;
  unsigned int val;
  if (!f) {
    printf("load_flat: cannot open %s\n", path);
    return -1;
  }
  for (i = 0; i < n; i++) {
    if (fscanf(f, "%x", &val) != 1) {
      printf("load_flat: unexpected EOF at element %d in %s\n", i, path);
      fclose(f);
      return -1;
    }
    arr[i] = (field_t)val;
  }
  fclose(f);
  return 0;
}

static int load_bytes(const char *path, uint8_t *buf, int maxn) {
  FILE *f = fopen(path, "r");
  int n = 0;
  unsigned int val;
  if (!f) {
    printf("load_bytes: cannot open %s\n", path);
    return -1;
  }
  while (n < maxn && fscanf(f, "%x", &val) == 1)
    buf[n++] = (uint8_t)val;
  fclose(f);
  return n;
}

int load_indexed_vec(const char *path, field_t *arr, int n) {
  FILE *f = fopen(path, "r");
  unsigned int idx, val;
  if (!f) {
    printf("load_indexed_vec: cannot open %s\n", path);
    return -1;
  }
  while (fscanf(f, "%u %x", &idx, &val) == 2) {
    if ((int)idx < n)
      arr[idx] = (field_t)val;
  }
  fclose(f);
  return 0;
}

int load_matrix_T(const char *path, field_t *arr, int cols) {
  FILE *f = fopen(path, "r");
  unsigned int sage_col, sage_row, val;
  if (!f) {
    printf("load_matrix_T: cannot open %s\n", path);
    return -1;
  }
  while (fscanf(f, "%u %u %x", &sage_col, &sage_row, &val) == 3) {
    arr[sage_row * cols + sage_col] = (field_t)val;
  }
  fclose(f);
  return 0;
}

static int load_p3_stream(const char *path, hls::stream<word_t> &s) {
  FILE *f = fopen(path, "r");
  unsigned int slice_base, r, c, val;
  int count = 0;
  if (!f) {
    printf("load_p3_stream: cannot open %s\n", path);
    return -1;
  }
  while (fscanf(f, "%u %u %u", &slice_base, &r, &c) == 3) {
    field_t coeffs[W_FE];
    for (int i = 0; i < W_FE; i++) {
      if (fscanf(f, "%x", &val) != 1) {
        printf("load_p3_stream: unexpected EOF in coeffs (line %d) of %s\n",
               count, path);
        fclose(f);
        return -1;
      }
      coeffs[i] = (field_t)val;
    }
    word_t word;
    fieldsToWord(coeffs, &word);
    s.write(word);
    count++;
  }
  fclose(f);
  return count;
}

static int load_seed_pk(const char *path, uint8_t *dst) {
  FILE *f = fopen(path, "r");
  int i;
  unsigned int val;
  if (!f) {
    printf("load_seed_pk: cannot open %s\n", path);
    return -1;
  }
  for (i = 0; i < UOV_SEED_PK_BYTES; i++) {
    if (fscanf(f, "%x", &val) != 1) {
      printf("load_seed_pk: unexpected EOF at byte %d\n", i);
      fclose(f);
      return -1;
    }
    dst[i] = (uint8_t)val;
  }
  fclose(f);
  return 0;
}

static void write_bytes(word_t *mem, uint32_t base_word, const uint8_t *src, int n) {
  for (int j = 0; j < n; j++) {
    uint32_t wi = base_word + (j >> 4);
    uint32_t lane = j & 15;
    word_t w = mem[wi];
    w.range(8 * lane + 7, 8 * lane) = src[j];
    mem[wi] = w;
  }
}

static int load_hash_input(const char *path, uint8_t *hash_in, int *msg_len_bytes) {
  memset(hash_in, 0, BRAM_ty_DEPTH / 2 * W_FE);
  int hash_in_len = load_bytes(path, hash_in, BRAM_ty_DEPTH / 2 * W_FE - 1);

  if (hash_in_len < 0) {
    printf("uov_tb: failed to load hash input\n");
    return -1;
  }

  *msg_len_bytes = hash_in_len - UOV_SALT_BYTES - UOV_SEED_SK_BYTES;
  if (*msg_len_bytes < 0) {
    printf("uov_tb: hash input too short (%d bytes < salt+seed_sk = %d)\n", hash_in_len, UOV_SALT_BYTES + UOV_SEED_SK_BYTES);
    return -1;
  }
  return 0;
}


static int test_uov_sign(const uov_level_t *L) {
  const char *lvl = L->name;
  const uint32_t uov_m = L->uov_m;
  const uint32_t uov_v = L->uov_v;
  const uint32_t uov_n = L->uov_n;
  const uint32_t uov_n_padded = L->uov_n_padded;

  int errors = 0;
  uint32_t w, i;
  char path[256];
  int msg_len_bytes;

  printf("---------------- uov sign test for %s ----------------\n", lvl);

  memset(O_ref, 0, sizeof(O_ref));
  memset(Ob_ref, 0, sizeof(Ob_ref));
  memset(R_ref, 0, sizeof(R_ref));
  memset(v_ref, 0, sizeof(v_ref));
  memset(s_ref, 0, sizeof(s_ref));
  memset(y_ref, 0, sizeof(y_ref));
  memset(t_ref, 0, sizeof(t_ref));

  // Load reference and input data
  snprintf(path, sizeof(path), DATA_DIR "hash_in_ref_%s.txt", lvl);
  if (load_hash_input(path, hash_in, &msg_len_bytes) < 0)
    errors++;
  snprintf(path, sizeof(path), DATA_DIR "O_ref_%s.txt", lvl);
  if (load_matrix_T(path, (field_t *)O_ref, UOV_LVL_V_M) < 0)
    errors++;
  snprintf(path, sizeof(path), DATA_DIR "v_ref_%s.txt", lvl);
  if (load_flat(path, v_ref, uov_v) < 0)
    errors++;
  snprintf(path, sizeof(path), DATA_DIR "Ob_ref_%s.txt", lvl);
  if (load_matrix_T(path, (field_t *)Ob_ref, UOV_LVL_V_M) < 0)
    errors++;
  snprintf(path, sizeof(path), DATA_DIR "R_ref_%s.txt", lvl);
  if (load_matrix_T(path, (field_t *)R_ref, UOV_LVL_V_M) < 0)
    errors++;
  snprintf(path, sizeof(path), DATA_DIR "s_ref_%s.txt", lvl);
  if (load_indexed_vec(path, s_ref, uov_n) < 0)
    errors++;
  snprintf(path, sizeof(path), DATA_DIR "y_ref_%s.txt", lvl);
  if (load_indexed_vec(path, y_ref, uov_m) < 0)
    errors++;
  snprintf(path, sizeof(path), DATA_DIR "t_ref_%s.txt", lvl);
  if (load_flat(path, t_ref, uov_m) < 0)
    errors++;
  snprintf(path, sizeof(path), DATA_DIR "seed_pk_%s.txt", lvl);
  if (load_seed_pk(path, seed_pk_ref) < 0)
    errors++;
  snprintf(path, sizeof(path), DATA_DIR "seed_bl_%s.txt", lvl);
  if (load_seed_pk(path, seed_bl_ref) < 0)
    errors++;

  if (errors) {
    printf("uov_tb[%s]: failed to load reference vectors\n", lvl);
    return errors;
  }

  printf("uov_tb[%s]: vectors loaded (m=%u v=%u n=%u, msg=%d bytes)\n", lvl, uov_m, uov_v, uov_n, msg_len_bytes);

  // Fill bram_O
  word_t bram_O[BRAM_O_DEPTH];
  for (w = 0; w < (uint32_t)BRAM_O_DEPTH; w++) {
    field_t b[W_FE];
    for (i = 0; i < (uint32_t)W_FE; i++) {
      uint32_t flat = w * W_FE + i;
      uint32_t col = flat / uov_n_padded;
      uint32_t row = flat % uov_n_padded;
      b[i] = (row < uov_n && col < uov_m) ? O_ref[row][col] : 0;
    }
    fieldsToWord(b, &bram_O[w]);
  }

  // Fill bram_vs (true dual port memory emulation):
  word_t bram_vs_a[BRAM_vs_DEPTH] = {};
  word_t bram_vs_b[BRAM_vs_DEPTH];
  for (w = 0; w < (uint32_t)BRAM_vs_DEPTH; w++) {
    field_t b[W_FE];
    for (i = 0; i < (uint32_t)W_FE; i++) {
      uint32_t flat = w * W_FE + i;
      b[i] = (flat < uov_v) ? v_ref[flat] : 0;
    }
    fieldsToWord(b, &bram_vs_b[w]);
  }

  write_bytes(bram_vs_a, BRAM_vs_DEPTH / 2, hash_in, msg_len_bytes + UOV_SALT_BYTES + UOV_SEED_SK_BYTES + 1);

  word_t bram_T[BRAM_T_DEPTH];
  word_t bram_LR[BRAM_LR_DEPTH];
  word_t bram_ty[BRAM_ty_DEPTH];
  bit_t trng_en = 1;
  bit_t trigger_uov;
  bit_t do_verif = 0;
  bit_t do_blinding = 1;
  hls::stream<word_t> data_in; // not used in signing
  uov((uint16_t)msg_len_bytes, uov_m, uov_v, uov_n, uov_n_padded,
      P1_BYTES(uov_m, uov_v), NR_SLICES(uov_m), trng_en, do_verif, do_blinding,
      seed_pk_ref, seed_bl_ref, bram_O, bram_LR, bram_T, bram_ty, bram_vs_a,
      bram_vs_b, data_in, &trigger_uov);

  printf("uov_tb[%s]: uov returned\n", lvl);

  // Verify Ob:
  int mismatches = 0;
  for (uint32_t row = 0; row < uov_n; row++) {
    for (uint32_t col = 0; col < uov_m; col++) {
      uint32_t flat = row + col * uov_n_padded;
      field_t got;
      wordToFieldElement(bram_O[flat / W_FE], (uint8_t)(flat % W_FE), &got);
      field_t ref = Ob_ref[row][col];
      if (got != ref) {
        if (mismatches < 10)
          printf("uov_tb[%s] Ob mismatch [%u][%u]: got %02x ref %02x\n", lvl, row, col, got, ref);
        mismatches++;
      }
    }
  }
  if (mismatches)
    printf("uov_tb[%s]: Ob result has %d mismatches\n", lvl, mismatches);
  else
    printf("uov_tb[%s]: Ob matches\n", lvl);
  errors += (mismatches > 0);

  // Verify y
  mismatches = 0;
  for (uint32_t k = 0; k < uov_m; k++) {
    field_t got;
    wordToFieldElement(bram_ty[k / W_FE], (uint8_t)(k % W_FE), &got);
    field_t ref = y_ref[k];
    if (got != ref) {
      if (mismatches < 100)
        printf("uov_tb[%s] y mismatch [%u]: got %02x ref %02x\n", lvl, k, got, ref);
      mismatches++;
    }
  }
  if (mismatches)
    printf("uov_tb[%s]: y result has %d mismatches\n", lvl, mismatches);
  else
    printf("uov_tb[%s]: y matches\n", lvl);
  errors += (mismatches > 0);

  // Verify t:
  mismatches = 0;
  for (uint32_t k = 0; k < uov_m; k++) {
    field_t got;
    wordToFieldElement(bram_ty[BRAM_ty_DEPTH / 2 + k / W_FE],
                        (uint8_t)(k % W_FE), &got);
    field_t ref = t_ref[k];
    if (got != ref) {
      if (mismatches < 100)
        printf("uov_tb[%s] t mismatch [%u]: got %02x ref %02x\n", lvl, k, got, ref);
      mismatches++;
    }
  }
  if (mismatches)
    printf("uov_tb[%s]: t result has %d mismatches\n", lvl, mismatches);
  else
    printf("uov_tb[%s]: t matches\n", lvl);
  errors += (mismatches > 0);

  // Verify s:
  mismatches = 0;
  for (uint32_t k = 0; k < uov_n; k++) {
    field_t got;
    wordToFieldElement(bram_vs_a[k / W_FE], (uint8_t)(k % W_FE), &got);
    field_t ref = s_ref[k];
    if (got != ref) {
      if (mismatches < 10)
        printf("uov_tb[%s] s mismatch [%u]: got %02x ref %02x\n", lvl, k, got, ref);
      mismatches++;
    }
  }
  if (mismatches)
    printf("uov_tb[%s]: s result has %d mismatches\n", lvl, mismatches);
  else
    printf("uov_tb[%s]: s matches\n", lvl);
  errors += (mismatches > 0);

  return errors;
}

static int test_uov_verif(const uov_level_t *L, const int invalid) {
  const char *lvl = L->name;
  const uint32_t uov_m = L->uov_m;
  const uint32_t uov_v = L->uov_v;
  const uint32_t uov_n = L->uov_n;
  const uint32_t uov_n_padded = L->uov_n_padded;

  int errors = 0;
  uint32_t w, i;
  char path[256];
  int msg_len_bytes;

  hls::stream<word_t> data_in; // streaming input for P3 matrices

  printf("---------------- uov verif test for %s ----------------\n", lvl);

  memset(O_ref, 0, sizeof(O_ref));
  memset(Ob_ref, 0, sizeof(Ob_ref));
  memset(R_ref, 0, sizeof(R_ref));
  memset(v_ref, 0, sizeof(v_ref));
  memset(s_ref, 0, sizeof(s_ref));
  memset(y_ref, 0, sizeof(y_ref));
  memset(t_ref, 0, sizeof(t_ref));

  // Load input and reference data:
  snprintf(path, sizeof(path), DATA_DIR "hash_in_ref_%s.txt", lvl);
  if (load_hash_input(path, hash_in, &msg_len_bytes) < 0)
    errors++;

  if (invalid)
    snprintf(path, sizeof(path), DATA_DIR "signature_invalid%d_%s.txt", invalid, lvl);
  else
    snprintf(path, sizeof(path), DATA_DIR "s_ref_%s.txt", lvl);

  if (load_indexed_vec(path, s_ref, uov_n) < 0)
    errors++;
  snprintf(path, sizeof(path), DATA_DIR "t_ref_%s.txt", lvl);
  if (load_flat(path, t_ref, uov_m) < 0)
    errors++;
  snprintf(path, sizeof(path), DATA_DIR "seed_pk_%s.txt", lvl);
  if (load_seed_pk(path, seed_pk_ref) < 0)
    errors++;

  // Fill data_in stream with P3 data
  snprintf(path, sizeof(path), DATA_DIR "p3_ref_%s_normalOrder.txt", lvl);
  int p3_words = load_p3_stream(path, data_in);
  if (p3_words < 0)
    errors++;
  else {
    const uint32_t nr_slices = NR_SLICES(uov_m);
    const uint32_t expected = nr_slices * (uov_m * (uov_m + 1) / 2);
    if ((uint32_t)p3_words != expected) {
      printf("uov_verif_tb[%s]: P3 word count mismatch: file=%d, expected=%u\n", lvl, p3_words, expected);
      errors++;
    }
  }

  if (errors) {
    printf("uov_verif_tb[%s]: failed to load reference vectors\n", lvl);
    return errors;
  }

  printf("uov_verif_tb[%s]: vectors loaded (m=%u v=%u n=%u, msg=%d bytes)\n", lvl, uov_m, uov_v, uov_n, msg_len_bytes);

  // Fill bram_vs (true dual port memory emulation):
  word_t bram_vs_a[BRAM_vs_DEPTH] = {};
  word_t bram_vs_b[BRAM_vs_DEPTH];
  for (w = 0; w < (uint32_t)BRAM_vs_DEPTH; w++) {
    field_t b[W_FE];
    for (i = 0; i < (uint32_t)W_FE; i++) {
      uint32_t flat = w * W_FE + i;
      b[i] = (flat < uov_n) ? s_ref[flat] : 0;
    }
    fieldsToWord(b, &bram_vs_b[w]);
    bram_vs_a[w] = bram_vs_b[w];
  }
  write_bytes(bram_vs_a, BRAM_vs_DEPTH / 2, hash_in, msg_len_bytes + UOV_SALT_BYTES + UOV_SEED_SK_BYTES + 1);

  word_t bram_O[BRAM_O_DEPTH];
  word_t bram_T[BRAM_T_DEPTH];
  word_t bram_LR[BRAM_LR_DEPTH];
  word_t bram_ty[BRAM_ty_DEPTH];
  bit_t trng_en = 1;
  bit_t trigger_uov;
  bit_t do_verif = 1, do_blinding = 1;
  uov((uint16_t)msg_len_bytes, uov_m, uov_v, uov_n, uov_n_padded,
      P1_BYTES(uov_m, uov_v), NR_SLICES(uov_m), trng_en, do_verif, do_blinding,
      seed_pk_ref, seed_bl_ref, bram_O, bram_LR, bram_T, bram_ty, bram_vs_a,
      bram_vs_b, data_in, &trigger_uov);

  printf("uov_verif_tb[%s]: uov verif returned\n", lvl);

  // Verify t:
  int mismatches = 0;
  for (uint32_t k = 0; k < uov_m; k++) {
    field_t got;
    wordToFieldElement(bram_ty[BRAM_ty_DEPTH / 2 + k / W_FE], (uint8_t)(k % W_FE), &got);
    field_t ref = t_ref[k];
    if (got != ref) {
      if (mismatches < 100)
        printf("uov_verif_tb[%s] hash mismatch [%u]: got %02x ref %02x\n", lvl, k, got, ref);
      mismatches++;
    }
  }
  if (mismatches)
    printf("uov_verif_tb[%s]: hash result has %d mismatches\n", lvl, mismatches);
  else
    printf("uov_verif_tb[%s]: hash matches\n", lvl);
  errors += (mismatches > 0);

  mismatches = 0;
  int inv = 0;
  for (uint32_t k = 0; k < uov_m; k++) {
    field_t got;
    wordToFieldElement(bram_ty[k / W_FE], (uint8_t)(k % W_FE), &got);
    field_t ref = 0;
    if (got != ref) {
      if (!invalid) {
        if (mismatches < 100)
          printf("uov_verif_tb[%s] t mismatch [%u]: got %02x ref %02x\n", lvl, k, got, ref);
        mismatches++;
      }
      inv++;
    }
  }
  if (!invalid) {
    if (mismatches)
      printf("uov_verif_tb[%s]: t result has %d mismatches\n", lvl, mismatches);
    else
      printf("uov_verif_tb[%s]: t matches\n", lvl);
    errors += (mismatches > 0);
  } else {
    if (inv == 0)
      printf("uov_verif_tb[%s]: invalid t is accepted: FAIL\n", lvl);
    else
      printf("uov_verif_tb[%s]: invalid t is rejected: OK\n", lvl);
    errors += inv == 0 ? 1 : 0;
  }

  return errors;
}

// top testbench function
int main() {
  int errors = 0;

  for (unsigned li = 0; li < sizeof(LEVELS) / sizeof(LEVELS[0]); li++) {
    errors += test_uov_sign(&LEVELS[li]);
  }

  for (unsigned li = 0; li < sizeof(LEVELS) / sizeof(LEVELS[0]); li++) {
    for (int invalid = 0; invalid < 3; invalid++)
      errors += test_uov_verif(&LEVELS[li], invalid);
  }

  if (errors)
    printf("================ ERRORS IN uov_tb ===================\n");
  else
    printf("================ uov_tb OK ===================\n");

  return errors;
}
