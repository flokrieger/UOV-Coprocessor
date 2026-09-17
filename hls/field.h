#pragma once
#include <inttypes.h>

typedef uint8_t field_t;

#define POLY_GF256 (0x11B) // x^8 + x^4 + x^3 + x + 1

// GF(2^8) arithmetic
field_t gf256_add(field_t a, field_t b);
field_t gf256_mul(field_t a, field_t b);
field_t gf256_inv(field_t a);
