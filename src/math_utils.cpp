#include <gmp.h>

mpz_t mont(mpz_t base, mpz_t exp, mpz_t mod)
{
    mpz_t r, r_inv, result, A, B;
    mpz_inits(r, r_inv, result, A, B, NULL);
    size_t bits = mpz_sizeinbase(bits, 2);
    mpz_ui_pow_ui(r, 2, bits);
    mpz_invert(r_inv, r, mod);
    mpz_mul(A, base, r);
    mpz_mod(A, A, N);
    mpz_mul(B, exp, r);
    mpz_mod(B, B, N);
}

void repeatMod(mpz_t output, mpz_t base, mpz_t exp, mpz_t mod)
{
    size_t bits = mpz_sizeinbase(exp, 2);
    mpz_t a;
    mpz_inits(a, NULL);
    mpz_set_ui(output, 1);
    for (int i = 0; i < bits; i++)
    {
        mpz_mul_2exp(output, base, i) * mpz_tstbit(exp, i);
        mpz_mod(output, output, mod);
    }
}

void chineseRemainder(mpz_t e, mpz_t d, mpz_t p, mpz_t q, mpz_t n, mpz_t m)
{
    mpz_t a, b, p_1, q_1, t;
    mpz_inits(a, b, p_1, q_1, NULL);
    mpz_powm(a, e, d, p);
    mpz_powm(b, e, d, q);
    mpz_invert(p_1, p, q); // p' = p ^ -1 (mod q)
    mpz_invert(q_1, q, p);
    mpz_set_ui(m, 0);
    mpz_mul(t, a, q);
    mpz_mul(t, t, q_1);
    mpz_add(m, m, t);
    mpz_mul(t, b, p);
    mpz_mul(t, t, p_1);
    mpz_add(m, m, t);
    mpz_mod(m, m, n);
}