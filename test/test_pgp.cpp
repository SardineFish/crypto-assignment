#include "pgp.h"
#include <stdlib.h>
#include <iostream>
#include <openssl/ec.h>

int main(int argc, char** argv)
{
    cout << hex << 236 << endl;
    cout.flush();
    string key = "password";
    string plaintext = "Hello World!\n";
    uint8_t buffer[8192];
    uint8_t anotherBuf[8192];
    uint8_t randBuf[32];
    size_t length = sizeof(buffer);
    uint8_t buf256[32];
    getrandom(randBuf, 32, 0);

    sha256((const uint8_t*)(key.c_str()), key.size(), buf256);
    cout << hex(buf256, 32) << endl;

    encryptAES256((const uint8_t*)plaintext.c_str(), plaintext.size() + 1, buf256, randBuf, buffer, &length);

    decryptAES256(buffer, length, buf256, randBuf, anotherBuf, &length);
    plaintext = string((char*)anotherBuf);

    EC_KEY* ecKey = nullptr;
    const EC_GROUP* ecGroup = nullptr;
    uint8_t *pubkey, *prvkey;
    size_t publen, prvlen;

    generateECCKey(&ecKey);
    ecGroup = EC_KEY_get0_group(ecKey);
    int curve = EC_GROUP_get_curve_name(ecGroup);
    ecpub2bin(ecKey, &pubkey, &publen);
    ecprv2bin(ecKey, &prvkey, &prvlen);

    auto msg = encryptECC((const uint8_t*)plaintext.c_str(), plaintext.size() + 1, curve, pubkey, publen);

    decryptECC(&msg, ecKey, buffer, &length);

    }