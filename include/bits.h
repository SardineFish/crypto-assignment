#pragma once
#include <bitset>

#define bitof(X, I) (((X) >> I) & 1)
#define bit_to(BIT, INDEX) ((BIT & 1) << INDEX)
#define n16_at(X, I) (X >> (I << 2) & 0xF)
#define get_box(X, I) n16_at(X, I)
#define set_box(X, I) ((X & 0xF) << (I << 2))
#define xor_bits(X) (bitof((X), 0) ^ bitof((X), 1) ^ bitof((X), 2) ^ bitof((X), 3))
#define xor_bits_16(X) \
    xor_bits(get_box((X), 0)) ^ xor_bits(get_box((X), 1)) ^ xor_bits(get_box((X), 2)) ^ xor_bits(get_box((X), 3))