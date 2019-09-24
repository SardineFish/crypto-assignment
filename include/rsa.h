#pragma once
#include <x86_64-linux-gnu/gmp.h>
#include <string>

using namespace std;

struct RSAPrvKey
{
    mpz_t d, p, q, phi, n;
};

struct RSAPubKey
{
    mpz_t n, e;
};

class RSAKey
{
public:
    RSAPubKey pubkey;
    RSAPrvKey prvkey;
    RSAKey();
};

RSAKey genRSAKey();

void encryptRSA(mpz_t cipher, mpz_t plaintext, RSAPubKey key);
void decryptRSA(mpz_t plaintext, mpz_t cipher, RSAPrvKey key);

void encodeMPZ(mpz_t output, string str);
string decodeMPZ(mpz_t input);
void printValue(string name, mpz_t v);

void chineseRemainder(mpz_t output, mpz_t c, mpz_t d, mpz_t p, mpz_t q, mpz_t n);
void repeatMod(mpz_t output, mpz_t base, mpz_t exp, mpz_t mod);