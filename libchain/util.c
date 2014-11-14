#include <stdint.h>
#include <stdlib.h>
#include <sys/time.h>

#include <gmp.h>

#include "util.h"
#include "vector.h"

uint64_t microtime(void)
{
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (uint64_t)tv.tv_sec * 1000000ULL + (uint64_t)tv.tv_usec;
}

void bits_to_target(unsigned int bits, mpz_t v)
{
    unsigned int r = bits & 0x007FFFFF;
    unsigned int mant = ( bits >> 24 ) & 0xFF;
    int neg = ((bits & 0x00800000) != 0) ? -1 : 1;

    if(mant <= 3) {
        mpz_init_set_ui(v, r);
        mpz_tdiv_q_2exp(v, v, 8 * (3 - mant));
        mpz_mul_si(v, v, neg);
    } else {
        mpz_init_set_ui(v, r);
        mpz_mul_2exp(v, v, 8 * (mant - 3));
        mpz_mul_si(v, v, neg);
    }
}

unsigned int target_to_bits(mpz_t target)
{
    // TODO this function should be improved
    struct vector v;
    vector_init(&v);

    mpz_t m;
    mpz_init(m);

    while(mpz_cmp_ui(target, 0) != 0) {
        mpz_mod_ui(m, target, 256);
        mpz_tdiv_q_ui(target, target, 256);

        unsigned int mv = mpz_get_ui(m);
        vector_add(&v, (uintptr_t)mv);
    }

    mpz_clear(m);

    size_t c = vector_count(&v);
    unsigned int last = vector_get(&v, c - 1);
    if(last > 0x7f) vector_add(&v, (uintptr_t)0);

    unsigned int ret = 0;
    c = vector_count(&v);
    if(c == 0) {
        ret = (c << 24);
    } else if(c == 1) {
        ret = (c << 24) | ((unsigned int)vector_get(&v, c - 1) << 16);
    } else if(c == 2) {
        ret = (c << 24) | ((unsigned int)vector_get(&v, c - 1) << 16) | ((unsigned int)vector_get(&v, c - 2) << 8);
    } else {
        ret = (c << 24) | ((unsigned int)vector_get(&v, c - 1) << 16) | ((unsigned int)vector_get(&v, c - 2) << 8) | (unsigned int)vector_get(&v, c - 3);
    }

    vector_free(&v);
    return ret;
}

