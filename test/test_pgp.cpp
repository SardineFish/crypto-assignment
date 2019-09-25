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

    generateECCKey(&ecKey);
    auto pubkey = toECCPubkey(ecKey);
    auto prvkey = toECCPrvkey(ecKey);

    auto msg = encryptPGP(pubkey, (uint8_t*)plaintext.data(), plaintext.size());

    decryptPGP(msg, prvkey, buffer, &length);
}