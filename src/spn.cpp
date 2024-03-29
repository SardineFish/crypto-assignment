#include "spn.h"
#include "math.h"
#include "stdio.h"
#include <zlib.h>

using namespace std;

uint16_t encryptSPN(uint16_t plainText, uint32_t key)
{
    uint16_t cipher = plainText;
    for (int i = 0; i < 4; i++)
    {
        //printf("W%d=%016lld\n", i, stob(cipher));
        uint16_t subKey = (key >> (i << 2)) & 0xFFFF;
        //printf("K%d=%016lld\n", i, stob(subKey));
        cipher = subKey ^ cipher;
        //printf("U%d=%016lld\n", i, stob(cipher));
        cipher = substitute(cipher);
        //printf("V%d=%016lld\n", i, stob(cipher));
        if(i < 3)
            cipher = permutate(cipher);
    }
    uint16_t finalKey = (key >> 16) & 0xFFFF;
    cipher = cipher ^ finalKey;
    //printf("Y =%016lld\n", stob(cipher));
    return cipher;
}
uint16_t encryptSPN(uint16_t plainText, uint64_t key)
{
    uint16_t cipher = plainText;
    for (int i = 0; i < 12; i++)
    {
        uint16_t subKey = (key >> (i << 2)) & 0xFFFF;
        cipher = subKey ^ cipher;
        cipher = substitute(cipher);
        if (i < 11)
            cipher = permutate(cipher);
    }
    uint16_t finalKey = (key >> 48) & 0xFFFF;
    cipher = cipher ^ finalKey;
    //printf("Y =%016lld\n", stob(cipher));
    return cipher;
}

uint16_t decryptSPN(uint16_t cipher, uint32_t key)
{
    uint16_t plain = cipher;
    uint16_t firstKey = (key >> 16) & 0xFFFF;
    plain = plain ^ firstKey;

    for (int i = 0; i < 4; i++)
    {
        uint16_t subKey = (key >> ((3 - i) << 2)) & 0xFFFF;
        if (i > 0)
            plain = fastReversePermutate(plain);
        plain = reverseSubstitute(plain);
        plain = plain ^ subKey;
    }
    return plain;
}

uint16_t decryptSPN(uint16_t cipher, uint64_t key)
{
    uint16_t plain = cipher;
    uint16_t firstKey = (key >> 48) & 0xFFFF;
    plain = plain ^ firstKey;

    for (int i = 0; i < 12; i++)
    {
        uint16_t subKey = (key >> ((11 - i) << 2)) & 0xFFFF;
        if (i > 0)
            plain = reversePermutate(plain);
        plain = reverseSubstitute(plain);
        plain = plain ^ subKey;
    }
    return plain;
}

uint16_t substitute(uint16_t in)
{
    const uint8_t map[] = {0xe, 0x4, 0xd, 0x1, 0x2, 0xf, 0xb, 0x8, 0x3, 0xa, 0x6, 0xc, 0x5, 0x9, 0x0, 0x7};
    uint16_t out = 0;
    for (int i = 0; i < 4; i++)
    {
        int w = (in >> (i << 2)) & 0xF;
        w = map[w];
        out |= w << (i << 2);
    }
    return out;
}

uint8_t substituteBox(uint8_t in)
{
    const uint8_t map[] = {0xe, 0x4, 0xd, 0x1, 0x2, 0xf, 0xb, 0x8, 0x3, 0xa, 0x6, 0xc, 0x5, 0x9, 0x0, 0x7};
    return map[in];
}

uint16_t reverseSubstitute(uint16_t in)
{
    const uint8_t map[] = {0xe, 0x3, 0x4, 0x8, 0x1, 0xc, 0xa, 0xf, 0x7, 0xd, 0x9, 0x6, 0xb, 0x2, 0x0, 0x5};
    uint16_t out = 0;
    for (int i = 0; i < 4; i++)
    {
        int w = (in >> (i << 2)) & 0xF;
        w = map[w];
        out |= w << (i << 2);
    }
    return out;
}

uint16_t permutate(uint16_t in)
{
    const uint8_t map[] = {0, 4, 8, 12, 1, 5, 9, 13, 2, 6, 10, 14, 3, 7, 11, 15};
    uint16_t out = 0;
    for (int i = 0; i < 16; i++)
    {
        out |= ((in >> i) & 1) << map[i];
    }
    return out;
}

uint16_t reversePermutate(uint16_t in)
{
    const uint8_t map[] = {0, 4, 8, 12, 1, 5, 9, 13, 2, 6, 10, 14, 3, 7, 11, 15};
    uint16_t out = 0;
    for (int i = 0; i < 16; i++)
    {
        out |= ((in >> map[i]) & 1) << i;
    }
    return out;
}


uint16_t btol(uint16_t in)
{
    
}

uint64_t stob(uint16_t x)
{
    uint64_t bits = 0;
    for (int i = 0; i < 16;i++)
    {
        bits += ((x >> i) & 1) * pow(10, i);
    }
    return bits;
}

bool encrypt_spn_cbc(const uint8_t* plaintext, size_t len, const uint8_t* key, size_t keylen, uint16_t iv, uint8_t* cipher, size_t* cipherLen)
{
    uint32_t key32 = crc32(0, key, keylen);

    uint16_t lb = iv;

    *cipherLen = 0;
    for (int i = 0; i < len; i += 2)
    {
        uint16_t block = 0;
        if (i + 1 == len)
            block = cipher[i] | 0xFF00;
        else
            block = *(uint16_t*)(void*)(plaintext + i);
        block = block ^ lb;
        block = encryptSPN(block, key32);
        lb = block;
        *(uint16_t*)(void*)(cipher + i) = block;
        *cipherLen += 2;
    }
    return true;
}

bool decrypt_spn_cbc(const uint8_t* cipher, size_t len, const uint8_t* key, size_t keylen, uint16_t iv, uint8_t* plaintext, size_t* plainLen)
{
    uint32_t key32 = crc32(0, key, keylen);
    uint16_t lb = iv;
    *plainLen = 0;

    for (int i = 0; i < len; i+=2)
    {
        uint16_t block = *(uint16_t*)(void*)(cipher + i);
        uint16_t plain = decryptSPN(block, key32);
        plain = plain ^ lb;
        lb = block;
        if(i + 2 == len && (plain & 0xFF00) == 0xFF)
        {
            plaintext[i] = plain & 0XFF;
            *plainLen = len - 1;
            return true;
        }
        else
            *(uint16_t*)(void*)(plaintext + i) = plain;
    }
    *plainLen = len;
    return true;
}