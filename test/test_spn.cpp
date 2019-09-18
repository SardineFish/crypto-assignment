#include "spn.h"
#include <iostream>
#include <assert.h>
#include <stdio.h>

using namespace std;
int main()
{
    assert(10110101100110 == stob(0b0010110101100110));
    assert(0b0100010111010001 == substitute(0b0001110000100011));
    assert(0b0110101011101001 == substitute(0b1010100100001101));
    assert(permutate(0b0100010111010001) == 0b0010111000000111);
    const uint16_t u[] = {
        0b0001110000100011,
        0b1000011101001010,
        0b1101010101101110,
        0b1010100100001101
    };
    const uint16_t v[] = {
        0b0100010111010001,
        0b0011100000100110,
        0b1001111110110000,
        0b0110101011101001
    };
    const uint16_t w[] = {
        0b0010111000000111,
        0b0100000110111000,
        0b1110010001101110,
    };
    for (int i = 0; i < 4;i++)
    {
        assert(substitute(u[i]) == v[i]);
        assert(reverseSubstitute(substitute(u[i])) == u[i]);
    }
    for (int i = 0; i < 3;i++)
    {
        assert(permutate(v[i]) == w[i]);
        assert(reversePermutate(permutate(v[i])) == v[i]);
    }

    uint16_t plainText = 0b0010011010110111;
    uint32_t key = 0b00111010100101001101011000111111;
    auto cipher = encryptSPN(plainText, key);
    assert(decryptSPN(cipher, key) == plainText);

    return 0;
}