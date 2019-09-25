#include "pgp.h"
#include <array>
#include <gzip/compress.hpp>
#include <gzip/config.hpp>
#include <gzip/decompress.hpp>
#include <gzip/utils.hpp>
#include <gzip/version.hpp>
#include <iomanip>
#include <memory.h>
#include <openssl/conf.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <sstream>

using namespace std;

void initOpenSSL()
{
    ERR_load_crypto_strings();
    OpenSSL_add_all_algorithms();
    OPENSSL_config(NULL);
}

void cleanup()
{
    EVP_cleanup();
    CRYPTO_cleanup_all_ex_data();
    ERR_free_strings();
}

bool encryptAES256(const uint8_t* plaintext, size_t plainLen, const uint8_t(&key)[32], const uint8_t(&iv)[32],
                       uint8_t* cipher, size_t* cipherLen)
{
    EVP_CIPHER_CTX* ctx;
    int len;
    if (!(ctx = EVP_CIPHER_CTX_new()))
        return false;

    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
        return false;

        if (1 != EVP_EncryptUpdate(ctx, cipher, &len, plaintext, plainLen))
            return false;
        *cipherLen = len;

        if (1 != EVP_EncryptFinal_ex(ctx, cipher + len, &len))
            return false;
        *cipherLen += len;

        EVP_CIPHER_CTX_free(ctx);

        return true;
}

bool decryptAES256(const uint8_t* cipher, size_t cipherLen, const uint8_t (&key)[32], const uint8_t (&iv)[32], uint8_t* plaintext, size_t* plainLen)
{
    EVP_CIPHER_CTX* ctx;
    int len;
    if (!(ctx = EVP_CIPHER_CTX_new()))
        return false;

    if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
        return false;

    if(1 != EVP_DecryptUpdate(ctx, plaintext, &len, cipher, cipherLen))
        return false;
    *plainLen = len;

    if (!EVP_DecryptFinal_ex(ctx, plaintext + len, &len))
        return false;
    
    *plainLen += len;

    EVP_CIPHER_CTX_free(ctx);
    return true;
}

bool sha256(const uint8_t* message, size_t len, uint8_t (&hash)[32])
{
    EVP_MD_CTX* mdctx;

    if ((mdctx = EVP_MD_CTX_create()) == NULL)
        return false;

    if (1 != EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL))
        return false;

    if (1 != EVP_DigestUpdate(mdctx, message, len))
        return false;
    uint32_t hashLen = 32;
    if (1 != EVP_DigestFinal_ex(mdctx, hash, &hashLen))
        return false;

    EVP_MD_CTX_destroy(mdctx);
}

string hex(uint8_t* buffer, size_t len)
{
    ostringstream oss;
    oss << std::hex;
    oss << setw(2) << setfill('0');
    for (size_t i=0;i<len;i++)
    {
        oss << (int)buffer[i];
    }
    return oss.str();
}

PGPMessage encryptPGP(ECCPubkey& pubkey,const uint8_t* buffer,const size_t len)
{
    PGPMessage msg;
    auto ziped = gzip::compress((const char*)buffer, len);
    sha256((uint8_t*)(ziped.data()), ziped.size(), msg.hash);
    getrandom(msg.iv, 32, 0);
    encryptECC((uint8_t*)(ziped.data()), ziped.size(), pubkey, msg);
    return msg;
}

bool decryptPGP(PGPMessage& msg, ECCPrvkey& prvkey, uint8_t* plaintext, size_t* len)
{
    uint8_t hash[32];
    uint8_t buffer[8192];
    size_t bufferLen = sizeof(buffer);
    decryptECC(&msg, prvkey.key, buffer, &bufferLen);
    sha256(buffer, bufferLen, hash);
    
    if(memcmp(hash, msg.hash, 32) != 0)
    {
        return false; // verify failed.
    }

    auto unziped = gzip::decompress((char*)buffer, bufferLen);
    mempcpy(plaintext, unziped.data(), unziped.size());
    *len = unziped.size();

    return true;
}