#pragma once
#include <cstdlib>
#include <cstdint>
#include <array>
#include <bitset>
#include <bits.h>

const int PermutateMap[] = {0, 4, 8, 12, 1, 5, 9, 13, 2, 6, 10, 14, 3, 7, 11, 15};
const uint16_t SubstituteMap[] = {0xe, 0x4, 0xd, 0x1, 0x2, 0xf, 0xb, 0x8, 0x3, 0xa, 0x6, 0xc, 0x5, 0x9, 0x0, 0x7};
const uint16_t ReverseSubstituteMap[] = {0xe, 0x3, 0x4, 0x8, 0x1, 0xc, 0xa, 0xf, 0x7, 0xd, 0x9, 0x6, 0xb, 0x2, 0x0, 0x5};

uint16_t encryptSPN(uint16_t plainText, uint32_t key);
uint16_t encryptSPN(uint16_t plainText, uint64_t key);

uint16_t decryptSPN(uint16_t cipher, uint32_t key);
uint16_t decryptSPN(uint16_t cipher, uint64_t key);

uint16_t substitute(uint16_t in);
uint8_t substituteBox(uint8_t in);
#define fastSubstituteBox(IN) SubstituteMap[IN]
#define fastSBox fastSubstituteBox
#define fastSubstitute(IN)\
    (set_box(SubstituteMap[get_box(IN, 0)], 0)\
   | set_box(SubstituteMap[get_box(IN, 1)], 1)\
   | set_box(SubstituteMap[get_box(IN, 2)], 2)\
   | set_box(SubstituteMap[get_box(IN, 3)], 3))

uint16_t reverseSubstitute(uint16_t in);
#define fastReverseSubstituteBox(IN) ReverseSubstituteMap[IN]
#define fastReverseSubstitute(IN)\
    (set_box(ReverseSubstituteMap[get_box(IN, 0)], 0)\
   | set_box(ReverseSubstituteMap[get_box(IN, 1)], 1)\
   | set_box(ReverseSubstituteMap[get_box(IN, 2)], 2)\
   | set_box(ReverseSubstituteMap[get_box(IN, 3)], 3))

uint16_t permutate(uint16_t in);
#define fastPermutate(X)            \
    (bit_to(bitof(X, 0x0), 0x0)     \
   | bit_to(bitof(X, 0x1), 0x4)     \
   | bit_to(bitof(X, 0x2), 0x8)     \
   | bit_to(bitof(X, 0x3), 0xc)     \
   | bit_to(bitof(X, 0x4), 0x1)     \
   | bit_to(bitof(X, 0x5), 0x5)     \
   | bit_to(bitof(X, 0x6), 0x9)     \
   | bit_to(bitof(X, 0x7), 0xd)     \
   | bit_to(bitof(X, 0x8), 0x2)     \
   | bit_to(bitof(X, 0x9), 0x6)     \
   | bit_to(bitof(X, 0xa), 0xa)     \
   | bit_to(bitof(X, 0xb), 0xe)     \
   | bit_to(bitof(X, 0xc), 0x3)     \
   | bit_to(bitof(X, 0xd), 0x7)     \
   | bit_to(bitof(X, 0xe), 0xb)     \
   | bit_to(bitof(X, 0xf), 0xf))


uint16_t reversePermutate(uint16_t in);
#define fastReversePermutate(X)     \
    (bit_to(bitof(X, 0x0), 0x0)     \ 
   | bit_to(bitof(X, 0x4), 0x1)     \ 
   | bit_to(bitof(X, 0x8), 0x2)     \ 
   | bit_to(bitof(X, 0xc), 0x3)     \ 
   | bit_to(bitof(X, 0x1), 0x4)     \ 
   | bit_to(bitof(X, 0x5), 0x5)     \ 
   | bit_to(bitof(X, 0x9), 0x6)     \ 
   | bit_to(bitof(X, 0xd), 0x7)     \ 
   | bit_to(bitof(X, 0x2), 0x8)     \ 
   | bit_to(bitof(X, 0x6), 0x9)     \ 
   | bit_to(bitof(X, 0xa), 0xa)     \ 
   | bit_to(bitof(X, 0xe), 0xb)     \ 
   | bit_to(bitof(X, 0x3), 0xc)     \ 
   | bit_to(bitof(X, 0x7), 0xd)     \ 
   | bit_to(bitof(X, 0xb), 0xe)     \ 
   | bit_to(bitof(X, 0xf), 0xf))

uint16_t btol(uint16_t in);

uint16_t ltob(uint16_t in);

uint64_t stob(uint16_t x);

bool encrypt_spn_cbc(const uint8_t* plaintext, size_t len, const uint8_t* key, size_t keylen, uint16_t iv,
                     uint8_t* cipher, size_t* cipherLen);

bool decrypt_spn_cbc(const uint8_t* cipher, size_t len, const uint8_t* key, size_t keylen, uint16_t iv,
                     uint8_t* plaintext, size_t* plainLen);