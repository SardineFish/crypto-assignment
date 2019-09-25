#include "spn.h"
#include <iostream>
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <fstream>

using namespace std;

#define N 100000;

uint8_t buffer[67108864];
uint8_t cipherBuffer[67108864];

int main(int argc, char** argv)
{
    if(argc < 3)
    {
        srand(time(nullptr));
        assert(10110101100110 == stob(0b0010110101100110));
        assert(0b0100010111010001 == substitute(0b0001110000100011));
        assert(0b0110101011101001 == substitute(0b1010100100001101));
        assert(permutate(0b0100010111010001) == 0b0010111000000111);
        const uint16_t u[] = {0b0001110000100011, 0b1000011101001010, 0b1101010101101110, 0b1010100100001101};
        const uint16_t v[] = {0b0100010111010001, 0b0011100000100110, 0b1001111110110000, 0b0110101011101001};
        const uint16_t w[] = {
            0b0010111000000111,
            0b0100000110111000,
            0b1110010001101110,
        };
        for (int i = 0; i < 100000; i++)
        {
            uint16_t in = rand();
            assert(substitute(in) == fastSubstitute(in));
            assert(reverseSubstitute(in) == fastReverseSubstitute(in));
            assert(permutate(in) == fastPermutate(in));
            assert(reversePermutate(in) == fastReversePermutate(in));
        }
        for (int i = 0; i < 4; i++)
        {
            assert(substitute(u[i]) == v[i]);
            assert(reverseSubstitute(substitute(u[i])) == u[i]);
        }
        for (int i = 0; i < 3; i++)
        {
            assert(permutate(v[i]) == w[i]);
            assert(permutate(v[i]) == fastPermutate(v[i]));
            assert(reversePermutate(permutate(v[i])) == fastReversePermutate(fastPermutate(v[i])));
            assert(fastReversePermutate(fastPermutate(v[i])) == v[i]);
        }

        uint16_t plainText = 0b0010011010110111;
        uint32_t key = 0b00111010100101001101011000111111;
        uint64_t key64 = 0x123456789ABCDEF0;
        auto cipher = encryptSPN(plainText, key);
        assert(decryptSPN(cipher, key) == plainText);
        assert(decryptSPN(encryptSPN(plainText, key64), key64) == plainText);
        cout << "All tests pass." << endl;
    }
    else
    {
        FILE* fp = fopen(argv[1], "rb");
        size_t fsize;
        fseek(fp, 0, SEEK_END);
        fsize = ftell(fp);
        rewind(fp);
        fsize = fread(buffer, 1, fsize, fp);

        size_t len;
        uint8_t keyStr[1024];
        uint16_t iv = 0;
        printf("Key:");
        scanf("%s", keyStr);

        encrypt_spn_cbc(buffer, fsize, keyStr, sizeof(keyStr), iv, cipherBuffer, &len);

        fclose(fp);
        fp = fopen(argv[2], "wb");
        fwrite(cipherBuffer, 1, len, fp);
        fclose(fp);

        //decrypt_spn_cbc(cipher, len, keyStr, sizeof(keyStr), iv, buffer, &len);

    }

    return 0;
}