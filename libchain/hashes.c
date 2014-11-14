#include <stdio.h>

#include <tomcrypt.h>

unsigned char const HASH_ZERO[32] = { 0, };

void sha256(unsigned char* in, size_t in_size, unsigned char* out)
{
    hash_state h;
    sha256_init(&h);
    sha256_process(&h, in, (unsigned long)in_size);
    sha256_done(&h, out);
}

void ripemd160(unsigned char const* in, size_t in_size, unsigned char* out)
{
    hash_state h;
    rmd160_init(&h);
    rmd160_process(&h, in, (unsigned long)in_size);
    rmd160_done(&h, out);
}
