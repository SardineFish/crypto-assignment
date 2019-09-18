#pragma once
#include <cstdlib>
#include <cstdint>
#include <array>

uint16_t encryptSPN(uint16_t plainText, uint32_t key);
uint16_t encryptSPN(uint16_t plainText, uint64_t key);

uint16_t decryptSPN(uint16_t cipher, uint32_t key);
uint16_t decryptSPN(uint16_t cipher, uint64_t key);

uint16_t substitute(uint16_t in);

uint16_t reverseSubstitute(uint16_t in);

uint16_t permutate(uint16_t in);

uint16_t reversePermutate(uint16_t in);

uint16_t btol(uint16_t in);

uint16_t ltob(uint16_t in);

uint64_t stob(uint16_t x);