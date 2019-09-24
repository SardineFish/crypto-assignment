#include "rsa.h"
#include <time.h>
#include <iostream>
#include <stdlib.h>
#include <assert.h>

using namespace std;

int main()
{
    for (int i = 0; i < 1000;i++)
    {
        size_t bits = 256;
        gmp_randstate_t rand;
        gmp_randinit_mt(rand);
        mpz_t a, b, mod, op, expect;
        mpz_inits(a, b, mod, op, expect, NULL);
        mpz_urandomb(a, rand, bits);
        mpz_urandomb(b, rand, bits);
        mpz_urandomb(mod, rand, bits);
        repeatMod(op, a, b, mod);
        mpz_powm(expect, a, b, mod);
        assert(mpz_cmp(op, expect) == 0);
    }

    timespec start, end;
    clock_gettime(CLOCK_MONOTONIC, &start);

    auto keypair = genRSAKey();

    clock_gettime(CLOCK_MONOTONIC, &end);
    double time = end.tv_sec - start.tv_sec;
    time += (end.tv_nsec - start.tv_nsec) / 1000000000.0;

    string str = "Hello World!\n";
    mpz_t plaintext, cipher;
    mpz_inits(plaintext, cipher, NULL);
    encodeMPZ(plaintext, str);
    str = decodeMPZ(plaintext);
    printValue("encode(string)", plaintext);
    cout << "decode(mpz_t) = " << str << endl;

    encryptRSA(cipher, plaintext, keypair.pubkey);
    printValue("RSA(P, K)", cipher);
    decryptRSA(plaintext, cipher, keypair.prvkey);
    printValue("RSA(C, K)", plaintext);

    printf("Completed in %lfs\n", time);
    exit(0);
}