#pragma once
#include <stdint.h>
#include <array>
#include <string>

using namespace std;

struct Message
{
    uint8_t IV[32];
};

bool encryptAES256(uint8_t* plaintext, size_t plainLen, array<uint8_t, 32>& key, array<uint8_t, 32>& iv,
                   uint8_t* cipher, size_t* cipherLen);

bool decryptAES256(uint8_t* cipher, size_t cipherLen, array<uint8_t, 32>& key, array<uint8_t, 32> iv,
                   uint8_t* plaintext, uint8_t* plainLen);

bool sha256(const char* message, size_t len, array<uint8_t, 32>& hash);
string hex(uint8_t* buffer, size_t len);