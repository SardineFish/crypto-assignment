#include <x86_64-linux-gnu/gmp.h>
#include <stdint.h>
#include <iostream>
#include "rsa.h"
#include <string>

using namespace std;

bool primeTest(mpz_t num, gmp_randstate_t rand, int reps);
void printValue(string name, mpz_t v);

RSAKey genRSAKey()
{
    mp_bitcnt_t bit = 512;
    RSAKey key;
    gmp_randstate_t rand;
    gmp_randinit_mt(rand);
    mpz_t p, q, N;
    mpz_inits(p, q, N, NULL);
    do
        mpz_urandomb(p, rand, bit);
    while (!primeTest(p, rand, 13));
    do
        mpz_urandomb(q, rand, bit);
    while (!primeTest(q, rand, 13));
    printValue("p", p);
    printValue("q", q);
    mpz_mul(N, p, q);
    mpz_set(key.prvkey.p, p);
    mpz_set(key.prvkey.q, q);
    mpz_sub_ui(p, p, 1);
    mpz_sub_ui(q, q, 1);
    mpz_mul(key.prvkey.phi, p, q); // phi = phi(N) = (p - 1) * (q - 1)
    printValue("phi", key.prvkey.phi);
    mpz_set(key.pubkey.n, N);
    mpz_set_ui(key.pubkey.e, 17);
    mpz_invert(key.prvkey.d, key.pubkey.e, key.prvkey.phi); // d = e ^ -1 (mod phi(N))
    printValue("d", key.prvkey.d);
    return key;
}


bool primeTest(mpz_t num, gmp_randstate_t rand, int reps)
{
    if(mpz_cmp_ui(num, 1) == 0)
        return false;
    printValue("n", num);
    for (int i = 0; i < reps; i++)
    {
        if (mpz_scan0(num, 0) == 0)
            return false;
        mpz_t a, b, n_1, t;
        mpz_inits(a, b, n_1, t, NULL);
        mpz_sub_ui(n_1, num, 1);
        mpz_urandomm(a, rand, num);
        auto s = mpz_scan1(n_1, 0);
        mpz_div_2exp(t, n_1, s); // t = n-1 >> s
        mpz_powm(b, a, t, num);  // b = a ^ t % n;
        if (mpz_cmp_ui(b, 1) == 0)
            goto NextTest;
        mpz_t mod;
        mpz_inits(mod, NULL);
        for (int i = 0; i < s; i++)
        {
            mpz_mod(mod, b, num);
            if (mpz_cmp(mod, n_1) == 0)
                goto NextTest;
            else
            {
                mpz_powm_ui(b, b, 2, num); // b = b ^ 2 % n;
            }
        }
        return false;
    NextTest:
        int x;
    }
    return true;
}

RSAKey::RSAKey()
{
    mpz_inits(prvkey.d, prvkey.p, prvkey.phi, prvkey.q, pubkey.e, pubkey.n, NULL);
}

void printValue(string name, mpz_t v)
{
    char buffer[8192];
    mpz_get_str(buffer, 10, v);
    cout << name << " = " << buffer << endl;
}

