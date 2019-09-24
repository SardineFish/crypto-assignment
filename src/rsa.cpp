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
    mpz_set(key.prvkey.n, N);
    mpz_set_ui(key.pubkey.e, 17);
    printValue("e", key.pubkey.e);
    mpz_invert(key.prvkey.d, key.pubkey.e, key.prvkey.phi); // d = e ^ -1 (mod phi(N))
    printValue("d", key.prvkey.d);
    return key;
}


bool primeTest(mpz_t num, gmp_randstate_t rand, int reps)
{
    if(mpz_cmp_ui(num, 1) == 0)
        return false;
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
    mpz_inits(prvkey.d, prvkey.p, prvkey.phi, prvkey.q, prvkey.n, pubkey.e, pubkey.n, NULL);
}

void printValue(string name, mpz_t v)
{
    char buffer[8192];
    mpz_get_str(buffer, 10, v);
    cout << name << " = " << buffer << endl;
}

void encryptRSA(mpz_t cipher, mpz_t plaintext, RSAPubKey key)
{
    mpz_powm(cipher, plaintext, key.e, key.n);
}

void decryptRSA(mpz_t plaintext, mpz_t cipher, RSAPrvKey key)
{
    chineseRemainder(plaintext, cipher, key.d, key.p, key.q, key.n);
    printValue("chinese remainder", plaintext);
    //mpz_powm(plaintext, cipher, key.d, key.n);
}

void encodeMPZ(mpz_t output, string str)
{
    mpz_t t;
    mpz_inits(t, NULL);
    mpz_set_ui(output, 0);
    auto size = str.size();
    for (size_t i = 0; i < str.size(); i++)
    {
        auto ch = str[i];
        mpz_set_ui(t, ch);
        mpz_mul_2exp(t, t, i * sizeof(ch) * 8);
        mpz_ior(output, output, t);
    }
}

string decodeMPZ(mpz_t input)
{
    mpz_t t, mask;
    mpz_inits(t, mask, NULL);
    mpz_set_ui(mask, 0xFF);
    auto size = mpz_sizeinbase(input, 2);
    size = (size + 7) / 8;
    char buffer[size + 1];
    for (size_t i = 0; i < size;i++)
    {
        mpz_and(t, input, mask);
        mpz_div_2exp(t, t, i * 8);
        buffer[i] = mpz_get_ui(t);
        mpz_mul_2exp(mask, mask, 8);
    }
    buffer[size] = 0;
    return string(buffer);
}