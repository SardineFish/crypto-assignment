#pragma once
#include <x86_64-linux-gnu/gmp.h>

struct RSAPrvKey
{
    mpz_t d, p, q, phi;
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