#include "uov.h"

// States of the Gaussian Elimination FSM
typedef enum {
  PIVOT_SEARCH,
  PIVOT_SEARCH_DONE,
  REMAINING_SLICES,
  LOAD_MUL,
  MUL
} ge_state_t;

// Computes Echelon Form
void ef(const addr_t uov_m,
        word_t bram_LR[BRAM_LR_DEPTH],
        word_t bram_T[BRAM_T_DEPTH],
        word_t bram_ty[BRAM_ty_DEPTH],
        bit_t *singular);

// Computes Back Substitution
void bs(const addr_t uov_m,
        word_t bram_LR[BRAM_LR_DEPTH],
        word_t bram_T[BRAM_T_DEPTH],
        word_t bram_ty[BRAM_ty_DEPTH]);

// Computes the whole Gaussian Elimination (ef + bs)
void geSubsystem(const addr_t uov_m,
        word_t bram_LR[BRAM_LR_DEPTH],
        word_t bram_T[BRAM_T_DEPTH],
        word_t bram_ty[BRAM_ty_DEPTH],
        bit_t *singular);
