#include "pgp.h"
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/ecdh.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <stdint.h>
#include <stdlib.h>
#include <experimental/array>
#include <memory.h>
#include <iostream>

bool ecpub2bin(const EC_KEY* key, uint8_t** buffer, size_t* len)
{
    auto ecGroup = EC_KEY_get0_group(key);
    auto pub = EC_KEY_get0_public_key(key);
    auto pubBN = BN_new();
    auto ctx = BN_CTX_new();

    BN_CTX_start(ctx);

    EC_POINT_point2bn(ecGroup, pub, POINT_CONVERSION_UNCOMPRESSED, pubBN, ctx);

    *len = BN_num_bytes(pubBN);
    *buffer = (uint8_t*)OPENSSL_malloc(*len);

    if (BN_bn2bin(pubBN, *buffer) != *len)
        return false; // Failed to decode pubkey

    BN_CTX_end(ctx);
    BN_CTX_free(ctx);
    BN_clear_free(pubBN);

    return true;
}

bool ecprv2bin(const EC_KEY* key, uint8_t** buffer, size_t* len)
{
    auto prv = EC_KEY_get0_private_key(key);
    *len = BN_num_bytes(prv);
    *buffer = (uint8_t*)OPENSSL_malloc(*len);
    if (BN_bn2bin(prv, *buffer) != *len)
        return false; // failed to decode prvkey
    return true;
}

bool bin2ecprv(EC_KEY* key, const uint8_t* buffer, const size_t len)
{

    auto bn = BN_bin2bn(buffer, len, NULL);

    if(1 != EC_KEY_set_private_key(key, bn))
        return false;
    return true;
}

bool bin2ecpub(const EC_GROUP* ecGroup, const uint8_t* buffer, const size_t len, EC_POINT** pub)
{
    BIGNUM *pubBN;
    BN_CTX *ctx;
    *pub = EC_POINT_new(ecGroup);

    pubBN = BN_bin2bn(buffer, len, NULL);
    ctx = BN_CTX_new();
    BN_CTX_start(ctx);

    EC_POINT_bn2point(ecGroup, pubBN, *pub, ctx);

    BN_CTX_end(ctx);
    BN_CTX_free(ctx);
    BN_clear_free(pubBN);
    return true;
}

bool loadKey(const char* filename, EC_KEY** key, int* curve)
{
    const EC_GROUP* ecGroup = nullptr;
    BIO* bioKey = nullptr;
    BIO* bioOut = nullptr;

    bioKey = BIO_new_file(filename, "r");

    if(!bioKey)
        return false; // failed to read EC key file.

    *key = d2i_ECPrivateKey_bio(bioKey, nullptr);
    if(*key == nullptr)
        return false; // failed to parse EC key file.

    BIO_free(bioKey);
    ecGroup = EC_KEY_get0_group(*key);
    bioOut = BIO_new_fp(stdout, BIO_NOCLOSE);

    EC_KEY_set_conv_form(*key, POINT_CONVERSION_UNCOMPRESSED);

    *curve = EC_GROUP_get_curve_name(ecGroup);

    return true;
}

bool generateSymkey(const int curve, const uint8_t* pubkey, const size_t keylen, uint8_t (&skey)[32], uint8_t** epub, size_t* epubLen)
{
    EC_KEY* ecKey = nullptr;
    const EC_GROUP* ecGroup = nullptr;
    EC_POINT* pubkeyPoint = nullptr;

    // Generate a ephemeral key.
    ecKey = EC_KEY_new_by_curve_name(curve);
    EC_KEY_generate_key(ecKey);
    ecGroup = EC_KEY_get0_group(ecKey);

    auto skeyLen = ((EC_GROUP_get_degree(ecGroup) + 7) / 8);
    if(skeyLen != 32)
        return false; // invalid symkey size.

    bin2ecpub(ecGroup, pubkey, keylen, &pubkeyPoint);

    // Genrerate the shared symmetric key
    skeyLen = ECDH_compute_key(skey, skeyLen, pubkeyPoint, ecKey, NULL);

    ecpub2bin(ecKey, epub, epubLen);

    return true;
}

bool generateSymkey(const EC_KEY* ecKey, const uint8_t* epubkey, size_t epublen, uint8_t (&skey)[32])
{
    const EC_GROUP* ecGroup = EC_KEY_get0_group(ecKey);
    EC_POINT* epubPoint = nullptr;

    if(((EC_GROUP_get_degree(ecGroup) + 7) / 8) != 32)
        return false; // Invalid symkey length.

    // ephemeral key to EC point
    bin2ecpub(ecGroup, epubkey, epublen, &epubPoint);

    size_t skeylen = 32;

    skeylen = ECDH_compute_key(skey, skeylen, epubPoint, (EC_KEY*)ecKey, NULL);

    return true;
}

PGPMessage encryptECC(const uint8_t* msg, size_t msgLen, int curve, const uint8_t* pubkey, const size_t keylen)
{
    uint8_t skey[32];
    uint8_t iv[32];
    uint8_t buffer[8192];
    size_t bufferLen = sizeof(buffer);
    size_t skeyLen = 0;
    uint8_t* epub = nullptr;
    size_t epubLen = 0;
    generateSymkey(curve, pubkey, keylen, skey, &epub, &epubLen);
    cout << "skey " << hex(skey, 32) << endl;

    encryptAES256(msg, msgLen, skey, iv, buffer, &bufferLen);

    PGPMessage msgCipher;
    memcpy(msgCipher.iv, iv, 32);
    msgCipher.epublen = epubLen;
    msgCipher.epubkey = epub;
    msgCipher.msglen = bufferLen;
    msgCipher.msg = (uint8_t*)malloc(sizeof(uint8_t) * bufferLen);
    memcpy(msgCipher.msg, buffer, bufferLen);
    return msgCipher;
}

bool decryptECC(const PGPMessage* msg, EC_KEY* eckey, uint8_t* plaintext, size_t* len)
{
    uint8_t skey[32];
    size_t skeylen = 0;
    uint8_t buffer[8192];
    size_t bufferLen = sizeof(buffer);

    generateSymkey(eckey, msg->epubkey, msg->epublen, skey);
    cout << "skey " << hex(skey, 32) << endl;

    decryptAES256(msg->msg, msg->msglen, skey, msg->iv, buffer, &bufferLen);

    return true;
}

bool generateECCKey(EC_KEY** key)
{
    *key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    if(1 != EC_KEY_generate_key(*key))
        return false;
}