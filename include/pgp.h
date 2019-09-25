#pragma once
#include "ecc.h"
#include <array>
#include <linux/random.h>
#include <stdint.h>
#include <string>
#include <sys/syscall.h>
#include <unistd.h>
#define getrandom(buf, len, flag) syscall(SYS_getrandom, buf, len, flag);

using namespace std;

struct PGPMessage
{
    uint8_t iv[32];
    size_t epublen;
    
    uint8_t* epubkey;
    size_t msglen;
    uint8_t* msg;
};

struct PGPPubkey
{
    uint8_t* pubkey;
    size_t publen;
    int curve;
};

struct PGPPrvkey
{
    EC_KEY* key;
    int curve;
    uint8_t* prvkey;
    size_t prvlen;
};

bool encryptAES256(const uint8_t* plaintext, size_t plainLen, const uint8_t (&key)[32], const uint8_t (&iv)[32],
                   uint8_t* cipher, size_t* cipherLen);

bool decryptAES256(const uint8_t* cipher, size_t cipherLen, const uint8_t (&key)[32], const uint8_t (&iv)[32], uint8_t* plaintext,
                   size_t* plainLen);

bool sha256(const uint8_t* message, size_t len, uint8_t (&hash)[32]);
string hex(uint8_t* buffer, size_t len);
