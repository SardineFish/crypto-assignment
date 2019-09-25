#pragma once
#include "pgp.h"
#include <stdint.h>
#include <openssl/ec.h>

struct PGPMessage;

PGPMessage encryptECC(const uint8_t* msg, size_t msgLen, int curve, const uint8_t* pubkey, const size_t keylen);

bool decryptECC(const PGPMessage* msg, EC_KEY* eckey, uint8_t* plaintext, size_t* len);

bool generateECCKey(EC_KEY** key);

bool ecprv2bin(const EC_KEY* key, uint8_t** buffer, size_t* len);

bool ecpub2bin(const EC_KEY* key, uint8_t** buffer, size_t* len);