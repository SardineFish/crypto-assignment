#pragma once
#include "pgp.h"
#include <stdint.h>
#include <openssl/ec.h>

struct PGPMessage;
struct ECCPubkey
{
    int curve;
    uint8_t* pubkey;
    size_t publen;
};
struct ECCPrvkey
{
    int curve;
    EC_KEY* key;
};

bool encryptECC(const uint8_t* msg, size_t msgLen, ECCPubkey& key, PGPMessage& msgCipher);

bool decryptECC(const PGPMessage* msg, EC_KEY* eckey, uint8_t* plaintext, size_t* len);

bool generateECCKey(EC_KEY** key);

bool ecprv2bin(const EC_KEY* key, uint8_t** buffer, size_t* len);

bool ecpub2bin(const EC_KEY* key, uint8_t** buffer, size_t* len);

ECCPubkey toECCPubkey(EC_KEY* eckey);

ECCPrvkey toECCPrvkey(EC_KEY* key);