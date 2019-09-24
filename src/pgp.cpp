#include "pgp.h"
#include <array>
#include <openssl/conf.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <sstream>
#include <iomanip>

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

bool encryptAES256(uint8_t* plaintext, size_t plainLen, array<uint8_t, 32>& key, array<uint8_t, 32>& iv,
                   uint8_t* cipher, size_t* cipherLen)
{
    EVP_CIPHER_CTX* ctx;
    int len;
    if (!(ctx = EVP_CIPHER_CTX_new()))
        return false;

    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key.data(), iv.data()))
        return false;

    if(1 != EVP_EncryptUpdate(ctx, cipher, &len, plaintext, plainLen))
        return false;
    *cipherLen = len;

    if(1 != EVP_EncryptFinal_ex(ctx, cipher + len, &len))
        return false;
    *cipherLen += len;

    EVP_CIPHER_CTX_free(ctx);

    return true;
}

bool decryptAES256(uint8_t* cipher, size_t cipherLen, array<uint8_t, 32>& key, array<uint8_t, 32>iv, uint8_t* plaintext, uint8_t* plainLen)
{
    EVP_CIPHER_CTX* ctx;
    int len;
    if (!(ctx = EVP_CIPHER_CTX_new()))
        return false;

    if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key.data(), iv.data()))
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

bool sha256(const char* message, size_t len, array<uint8_t, 32>& hash)
{
    EVP_MD_CTX* mdctx;

    if ((mdctx = EVP_MD_CTX_create()) == NULL)
        return false;

    if (1 != EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL))
        return false;

    if (1 != EVP_DigestUpdate(mdctx, message, len))
        return false;
    uint32_t hashLen = 32;
    if (1 != EVP_DigestFinal_ex(mdctx, hash.data(), &hashLen))
        return false;

    EVP_MD_CTX_destroy(mdctx);
}

string hex(uint8_t* buffer, size_t len)
{
    ostringstream oss;
    oss << setw(2) << setfill('0') << std::hex;
    for (size_t i = 0; i < len; i++)
    {
        oss << (int)(buffer[i]);
    }
    return oss.str();
}